/* Prefix ID Table and Index
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
#include <zebra.h>

#include "prefix_id.h"
#include "prefix.h"
#include "memory.h"
#include "vhash.h"
#include "vector.h"
#include "list_util.h"

/*==============================================================================
 * Prefix ID Table and Index.
 *
 * Stores known prefixes, so can map a prefix, with or without a Route
 * Distinguisher, to a prefix_id_t and back again.
 *
 * This provides a convenient short form for prefixes of all types.  The
 * prefix_id_t may also be used with an ihash table, to provide for collections
 * of prefixes.
 *
 * Each prefix_id_t has a prefix_id_entry associated with it, complete with a
 * reference count.  The reference count may be used as follows:
 *
 *   * when a prefix_id_entry is looked up, the pointer returned "owns" a
 *     lock on the entry.
 *
 *     The entry cannot disappear, or move or change while there is a lock
 *     on it.
 *
 *   * when the
 *
 *
 *
 *
 * Each unique Route Distinguisher has a prefix_rd_id_t.  RDs are preserved
 * while there is at least one prefix_id_entry which refers to it.
 *
 * The Prefix ID table comprises a vhash_table for looking up prefixes "by
 * value" and a vector to map the prefix_id_t to its value.
 *
 * The prefix_id_table and index are "Private" -- used in some Inline
 * functions.
 *
 * The Route Distinguisher ID table similarly comprises a vhash_table for
 * looking up RDs "by value" and a vector to map the prefix_rd_id_t to its
 * value.
 *
 *------------------------------------------------------------------------------
 * Route Distinguishers
 *
 */
vhash_table  prefix_id_table ;          /* lookup by value              */
vector       prefix_id_index ;          /* lookup by peer-id            */

static vhash_table prefix_rd_id_table ; /* lookup by value              */
vector       prefix_rd_id_index ;       /* lookup by rd-id              */

enum
{
  prefix_id_unit    = 1024,     /* allocate many at a time      */
  prefix_rd_id_unit =   64,     /* allocate a few at a time     */
} ;

typedef struct prefix_id_chunk  prefix_id_chunk_t ;
typedef struct prefix_id_chunk* prefix_id_chunk ;

typedef struct prefix_rd_id_chunk  prefix_rd_id_chunk_t ;
typedef struct prefix_rd_id_chunk* prefix_rd_id_chunk ;

struct prefix_id_chunk
{
  prefix_id_chunk  next ;

  prefix_id_entry_t entries[prefix_id_unit] ;
} ;

struct prefix_rd_id_chunk
{
  prefix_rd_id_chunk  next ;

  prefix_rd_id_entry_t entries[prefix_rd_id_unit] ;
} ;

static prefix_id_chunk prefix_id_chunks ;

static struct dl_base_pair(prefix_id_entry) prefix_id_free_base ;

static prefix_rd_id_chunk prefix_rd_id_chunks;

static struct dl_base_pair(prefix_rd_id_entry) prefix_rd_id_free_base ;

/*==============================================================================
 * The vhash Prefix ID and Prefix RD ID Table mechanics
 */

/*------------------------------------------------------------------------------
 * The vhash table magic for prefix_id
 */
static vhash_hash_func  prefix_id_vhash_hash ;
static vhash_equal_func prefix_id_vhash_equal ;
static vhash_new_func   prefix_id_vhash_new ;
static vhash_free_func  prefix_id_vhash_free ;

static const vhash_params_t prefix_id_vhash_params =
{
  .hash   = prefix_id_vhash_hash,
  .equal  = prefix_id_vhash_equal,
  .new    = prefix_id_vhash_new,
  .free   = prefix_id_vhash_free,
  .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * The vhash table magic for prefix_rd_id
 */
static vhash_hash_func  prefix_rd_id_vhash_hash ;
static vhash_equal_func prefix_rd_id_vhash_equal ;
static vhash_new_func   prefix_rd_id_vhash_new ;
static vhash_free_func  prefix_rd_id_vhash_free ;

static const vhash_params_t prefix_rd_id_vhash_params =
{
  .hash   = prefix_rd_id_vhash_hash,
  .equal  = prefix_rd_id_vhash_equal,
  .new    = prefix_rd_id_vhash_new,
  .free   = prefix_rd_id_vhash_free,
  .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * Forward references
 */
static void prefix_id_table_make_ids(void) ;
static void prefix_rd_id_table_make_ids(void) ;

/*------------------------------------------------------------------------------
 * Initialise the Prefix ID and Prefix RD ID tables and indexes.
 *
 * This is done early in the morning as part of the qlib_init_first_stage(),
 * but in any case MUST be done before any prefixes are stored in the table !
 */
extern void
prefix_id_init(void)
{
  /* We start the Prefix ID stuff expecting at moderately large numbers of
   * prefixes -- so start with vhash table ready for prefix_id_unit * 2 entries
   * (at 200% density).
   *
   * We don't, however, allocate any prefix_id_chunks at this stage.
   */
  prefix_id_table = vhash_table_new(
          NULL,
          prefix_id_unit,               /* ready for some prefixes      */
          200,                          /* moderate density             */
          &prefix_id_vhash_params) ;

  prefix_id_index = vector_init_new(NULL, 0) ;  /* none, yet    */
  prefix_id_chunks = NULL ;                     /* ditto        */
  dsl_init(prefix_id_free_base) ;               /* ditto        */

  /* We start the Prefix RD ID stuff without necessarily expecting any -- these
   * are required only for BGP MPLS VPN.
   *
   * We don't allocate any prefix_rd_id_chunks at this stage.
   */
  prefix_rd_id_table = vhash_table_new(
          NULL,
          0,                            /* may never happen     */
          200,                          /* moderate density     */
          &prefix_rd_id_vhash_params) ;

  prefix_rd_id_index = vector_init_new(NULL, 0) ;       /* none, yet    */
  prefix_rd_id_chunks = NULL ;                          /* ditto        */
  dsl_init(prefix_rd_id_free_base) ;                    /* ditto        */
} ;

/*------------------------------------------------------------------------------
 * Second stage initialisation.
 */
extern void
prefix_id_init_r(void)
{
#if 0
  prefix_id_mutex = qpt_mutex_new(qpt_mutex_recursive, "Peer Index") ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Shut down the Prefix ID Table and Index -- freeing all memory and mutex.
 *
 * This is done late in the termination process as part of qexit(), but in any
 * case MUST be done after all interest in Prefix IDs has waned.
 *
 * NB: discards the ID Table and Index and all prefix_id_entries, no matter
 *     what the reference counts may be, along with the RD ID Table and index,
 *     similarly.
 *
 *     SO: any attempt to use a dangling reference to a prefix_id or a
 *         prefix_id_entry WILL end in tears.
 */
extern void
prefix_id_finish(void)
{
  prefix_id_chunk pc ;
  prefix_rd_id_chunk rdc ;

//qassert(!qpthreads_active) ;

  /* Ream out and discard vhash tables.  Expect the tables to be empty at this
   * point, however if not any remaining items will be orphaned.  The items
   * are freed en-masse when the chunks are freed, below.
   */
  prefix_id_table    = vhash_table_reset(prefix_id_table, free_it) ;
  prefix_rd_id_table = vhash_table_reset(prefix_rd_id_table, free_it) ;

  /* Reset the indexes.
   */
  prefix_id_index    = vector_reset(prefix_id_index, free_it) ;
  prefix_rd_id_index = vector_reset(prefix_rd_id_index, free_it) ;

  /* Forget the free lists
   */
  dsl_init(prefix_id_free_base) ;
  dsl_init(prefix_rd_id_free_base) ;

  /* Discard the empty chunks of entries
   */
  while ((pc = ssl_pop(&pc, prefix_id_chunks, next)) != NULL)
    XFREE(MTYPE_PREFIX_ID_CHUNK, pc) ; ;

  while ((rdc = ssl_pop(&rdc, prefix_rd_id_chunks, next)) != NULL)
    XFREE(MTYPE_PREFIX_RD_ID_CHUNK, rdc) ; ;

//prefix_id_mutex = qpt_mutex_destroy(prefix_id_mutex) ;
} ;

/*------------------------------------------------------------------------------
 * Construct hash for given prefix -- vhash call-back
 */
static vhash_hash_t
prefix_id_vhash_hash(vhash_data_c data)
{
  vhash_hash_t hash ;
  prefix_c     pfx ;
  uint         pl ;

  pfx = data ;
  pl  = pfx->prefixlen ;

  hash = ((((vhash_hash_t)pfx->family) << 16) + pl) ^ pfx->rd_id ^ 314159265 ;

  return vhash_hash_bytes_cont(pfx->u.b, PSIZE(pl), hash) ;
} ;

/*------------------------------------------------------------------------------
 * Construct hash for given route discriminator -- vhash call-back
 */
static vhash_hash_t
prefix_rd_id_vhash_hash(vhash_data_c data)
{
  return vhash_hash_bytes(((prefix_rd_c)data)->val, prefix_rd_len) ;
} ;

/*------------------------------------------------------------------------------
 * Are the given prefix_id_entry and prefix equal ? -- vhash call-back
 *
 * NB: this is only called if the hash values are equal, so the odds are, the
 *     answer is "yes" (0)
 */
static int
prefix_id_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  prefix_c pi, pd ;

  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ;

  pi = ((prefix_id_entry_c)item)->pfx ;
  pd = data ;

  if (pi->rd_id != pd->rd_id)
    return 1 ;

  return prefix_equal(pi, pd) ;
} ;

/*------------------------------------------------------------------------------
 * Are the given prefix_rd_id_entry and prefix_rd equal ? -- vhash call-back
 */
static int
prefix_rd_id_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  return memcmp(((prefix_rd_id_entry_c)item)->rd.val, ((prefix_rd_c)data)->val,
                                                                prefix_rd_len) ;
} ;

/*------------------------------------------------------------------------------
 * Create a new entry in the prefix id table -- vhash call-back
 *
 * Allocates the next prefix_id -- creating more if required.
 *
 * If the prefix has a Route Distinguisher, then count reference to same.
 */
static vhash_item
prefix_id_vhash_new(vhash_table table, vhash_data_c data)
{
  prefix_id_entry pie ;
  prefix_rd_id_t  rd_id ;

  /* Allocate prefix_id_entry complete with prefix_id.
   */
  if (dsl_head(prefix_id_free_base) == NULL)
    prefix_id_table_make_ids() ;

  pie = dsl_pop(&pie, prefix_id_free_base, rt.next) ;
  qassert(vector_get_item(prefix_id_index, pie->id) == pie) ;

  *pie->pfx = *(prefix_c)data ;

  /* If this has a Route Distinguisher, then count the reference to that
   */
  rd_id = pie->pfx->rd_id ;

  if (rd_id != prefix_rd_id_null)
    {
      prefix_rd_id_entry rd_ie ;

      rd_ie = vector_get_item(prefix_rd_id_index, rd_id) ;
      qassert((rd_ie != NULL) && (rd_ie->id == rd_id)) ;

      vhash_inc_ref(rd_ie) ;
    } ;

  /* Done -- return the new entry
   */
  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ;
  return pie ;
} ;

/*------------------------------------------------------------------------------
 * Create a new entry in the prefix rd id table -- vhash call-back
 *
 * Allocates the next prefix_rd_id -- creating more if required.
 */
static vhash_item
prefix_rd_id_vhash_new(vhash_table table, vhash_data_c data)
{
  prefix_rd_id_entry rd_ie ;

  /* Allocate prefix_rd_id_entry complete with prefix_rd_id.
   */
  if (dsl_head(prefix_rd_id_free_base) == NULL)
    prefix_rd_id_table_make_ids() ;

  rd_ie = dsl_pop(&rd_ie, prefix_rd_id_free_base, rt.next) ;
  qassert(vector_get_item(prefix_rd_id_index, rd_ie->id) == rd_ie) ;

  rd_ie->rd = *((prefix_rd_c)data) ;

  confirm(offsetof(prefix_rd_id_entry_t, rt.vhash) == 0) ;
  return rd_ie ;
} ;

/*------------------------------------------------------------------------------
 * Free a prefix id table entry -- vhash call-back
 */
static vhash_item
prefix_id_vhash_free(vhash_item item, vhash_table table)
{
  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ;

  qassert(vector_get_item(prefix_id_index, ((prefix_id_entry)item)->id)
                                                                      == item) ;

  dsl_push(prefix_id_free_base, (prefix_id_entry)item, rt.next) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Free a prefix rd id table entry -- vhash call-back
 */
static vhash_item
prefix_rd_id_vhash_free(vhash_item item, vhash_table table)
{
  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ;

  qassert(vector_get_item(prefix_id_index, ((prefix_id_entry)item)->id)
                                                                      == item) ;

  dsl_push(prefix_id_free_base, (prefix_id_entry)item, rt.next) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Make a new set of free prefix_ids.
 */
static void
prefix_id_table_make_ids(void)
{
  prefix_id_chunk chunk ;
  prefix_id_t     pid ;
  prefix_id_entry pie ;

  chunk = XCALLOC(MTYPE_PREFIX_ID_CHUNK, sizeof(prefix_id_chunk_t)) ;
  ssl_push(prefix_id_chunks, chunk, next) ;

  pie = &chunk->entries[0] ;

  /* Special case to avoid id == 0 being used.  Is not set in vector.
   */
  pid = vector_end(prefix_id_index) ;

  if (pid == 0)
    {
      confirm(prefix_id_null == 0) ;

      pid  = 1 ;                /* avoid setting pid == 0 free  */
      pie += 1 ;                /* step past pid == 0 entry     */
    } ;

  vector_extend(prefix_id_index, pid + prefix_id_unit) ;

  /* Complete the creation of the new chunk of prefix ids by "freeing" all the
   * new entries.
   */
  while (pid < vector_end(prefix_id_index))
    {
      pie->id = pid ;
      dsl_append(prefix_id_free_base, pie, rt.next) ;

      vector_set_item(prefix_id_index, pid, pie) ;

      pid += 1 ;
      pie += 1 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Make a new set of free prefix_rd_ids.
 */
static void
prefix_rd_id_table_make_ids(void)
{
  prefix_rd_id_t     rd_id ;
  prefix_rd_id_entry rd_ie ;
  prefix_rd_id_chunk chunk ;

  chunk = XCALLOC(MTYPE_PREFIX_RD_ID_CHUNK, sizeof(prefix_rd_id_chunk_t)) ;
  ssl_push(prefix_rd_id_chunks, chunk, next) ;

  rd_ie = &chunk->entries[0] ;

  /* Special case to avoid rd id == 0 being used.  Is not set in vector.
   */
  rd_id = vector_end(prefix_rd_id_index) ;

  if (rd_id == 0)
    {
      confirm(prefix_rd_id_null == 0) ;

      rd_id  = 1 ;              /* avoid setting rd id == 0 free        */
      rd_ie += 1 ;              /* step past rd id == 0 entry           */
    } ;

  vector_extend(prefix_rd_id_index, rd_id + prefix_rd_id_unit) ;

  /* Complete the creation of the new chunk of rd ids by "freeing" all the
   * new entries.
   */
  while (rd_id < vector_end(prefix_rd_id_index))
    {
      rd_ie->id = rd_id ;
      dsl_append(prefix_rd_id_free_base, rd_ie, rt.next) ;

      vector_set_item(prefix_rd_id_index, rd_id, rd_ie) ;

      rd_id += 1 ;
      rd_ie += 1 ;
    } ;
} ;

/*==============================================================================
 * Looking up and storing prefixes with or without route distinguisher
 */

/*------------------------------------------------------------------------------
 * Find entry in the Prefix ID table for the given prefix -- creating an entry
 * if required.
 *
 * NB: sets the pfx->rd_id in the given prefix.
 *
 * NB: it is *essential* at this point that the pfx->prefixlen is valid, and
 *     that any trailing bits in the last byte of the prefix body are
 *     zero.
 *
 * Returns:  the entry -- with the reference count incremented.
 *
 * NB: it is the caller's responsibility to prefix_id_entry_dec_ref().
 */
extern prefix_id_entry
prefix_id_find_entry(prefix pfx, const byte* rd_val)
{
  prefix_id_entry pie ;
  bool   added ;

// Lock the prefix_id_table and prefix_rd_id_table here....

  if (rd_val == NULL)
    {
      /* If there is no Route Distinguisher, make sure the pfx->rd_id reflects
       * that.
       */
      pfx->rd_id = prefix_rd_id_null ;
    }
  else
    {
      /* Lookup or create Route Distinguisher entry.
       *
       * If creates the Route Distinguisher, that implies that the given prefix
       * does not currently exist.  When it is created, the reference count on
       * the prefix_rd_id_entry will be incremented.
       *
       * Note that we currently have the prefix_id_table and prefix_rd_id_table
       * locked.
       */
      prefix_rd_id_entry rd_ie ;

      rd_ie = vhash_lookup(prefix_rd_id_table, rd_val, &added) ;
      qassert(vector_get_item(prefix_rd_id_index, rd_ie->id) == rd_ie) ;

      pfx->rd_id = rd_ie->id ;
    } ;

  pie = vhash_lookup(prefix_id_table, pfx, &added) ;
  qassert(vector_get_item(prefix_id_index, pie->id) == pie) ;
  qassert(pie->pfx->rd_id == pfx->rd_id) ;

  return prefix_id_entry_inc_ref(pie) ;

// Unlock the prefix_id_table and prefix_rd_id_table here....
} ;

/*------------------------------------------------------------------------------
 * Seek entry in the Prefix ID table for the given prefix
 *                                                   (with Route Discriminator).
 *
 * This is for use when trying to discover whether the given prefix (with RD)
 * exists and is in use somewhere, and if so returns the prefix_id_entry.
 *
 * Does *not* create an entry if the prefix (with RD) does not exist.
 *
 * Does *not* return the entry if its reference count is zero.  A reference
 * count of zero means that the prefix (with RD) is not in use anywhere, and
 * may be garbage collected.
 *
 * NB: uses the pfx->rd_id in the given prefix.
 *
 * NB: it is *essential* at this point that the pfx->prefixlen is valid, and
 *     that any trailing bits in the last byte of the prefix body are
 *     zero.
 *
 * Returns:  the entry -- with reference count *unchanged* and *not*zero*.
 *       or: NULL <=> no entry exists (or exists but with reference count == 0)
 */
extern prefix_id_entry
prefix_id_seek_entry(prefix pfx)
{
  prefix_id_entry pie ;

// Lock the prefix_id_table here....

  pie = vhash_lookup(prefix_id_table, pfx, NULL) ;

  if (pie != NULL)
    {
      qassert(vector_get_item(prefix_id_index, pie->id) == pie) ;
      qassert(pie->pfx->rd_id == pfx->rd_id) ;

      if (pie->rt.vhash.ref_count == 0)
        pie = NULL ;
    } ;

// Unlock the prefix_id_table here....

  return pie ;
} ;

/*------------------------------------------------------------------------------
 * Seek entry in the Prefix RD ID table for the given Route Distinguisher.
 *
 * This is for use when trying to discover whether the given RD exists and is
 * in use somewhere, and if so returns the prefix_rd_id_entry.
 *
 * Does *not* create an entry if the RD does not exist.
 *
 * Does *not* return the entry if its reference count is zero.  A reference
 * count of zero means that the RD is not in use anywhere, and may be garbage
 * collected.
 *
 * Returns:  the entry -- with reference count *unchanged* and *not*zero*.
 *       or: NULL <=> no entry exists (or exists but with reference count == 0)
 */
extern prefix_rd_id_entry
prefix_rd_id_seek_entry(const byte* rd_val)
{
// Lock the prefix_rd_id_table here....

  /* Lookup Route Distinguisher entry -- do not create.
   */
  prefix_rd_id_entry rd_ie ;

  rd_ie = vhash_lookup(prefix_rd_id_table, rd_val, NULL) ;

  return rd_ie ;

// Unlock the prefix_rd_id_table here....
} ;

/*==============================================================================
 * Other functions
 */
extern int prefix_id_entry_cmp(prefix_id_entry_c a, prefix_id_entry_c b) ;

/*------------------------------------------------------------------------------
 * Compare two prefixes by their prefix-ids
 */
extern int
prefix_id_cmp(prefix_id_t a_id, prefix_id_t b_id)
{
  if (a_id == b_id)
    return 0 ;

  return prefix_id_entry_cmp(prefix_id_get_entry(a_id),
                             prefix_id_get_entry(b_id)) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two prefix_id entries
 */
extern int
prefix_id_p_entry_cmp(prefix_id_entry_c* p_a, prefix_id_entry_c* p_b)
{
  return prefix_id_entry_cmp(*p_a, *p_b) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two prefix_id entries
 */
extern int
prefix_id_entry_cmp(prefix_id_entry_c a, prefix_id_entry_c b)
{
  if (a->pfx->rd_id == b->pfx->rd_id)
    return prefix_sort_cmp(a->pfx, b->pfx) ;
  else
    return prefix_rd_id_entry_cmp(prefix_rd_id_get_entry(a->pfx->rd_id),
                                  prefix_rd_id_get_entry(b->pfx->rd_id)) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two Route Discriminators by their route-discriminator-ids
 */
extern int
prefix_rd_id_cmp(prefix_rd_id_t a_id, prefix_rd_id_t b_id)
{
  if (a_id == b_id)
    return 0 ;

  return prefix_rd_id_entry_cmp(prefix_rd_id_get_entry(a_id),
                                prefix_rd_id_get_entry(b_id)) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two prefix_id entries
 */
extern int
prefix_rd_id_p_entry_cmp(prefix_rd_id_entry_c* p_a, prefix_rd_id_entry_c* p_b)
{
  return prefix_rd_id_entry_cmp(*p_a, *p_b) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two prefix_rd_id entries
 */
extern int
prefix_rd_id_entry_cmp(prefix_rd_id_entry_c a, prefix_rd_id_entry_c b)
{
  if (a == b)
    return 0 ;

  if (a == NULL)
    return -1 ;

  if (b == NULL)
    return +1 ;

  return memcmp(a->rd.val, b->rd.val, prefix_rd_len) ;
} ;

