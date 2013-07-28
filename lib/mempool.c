/* Memory Pool System
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

#include "qlib_init.h"
#include "mempool.h"
#include "memory.h"
#include "qpthreads.h"
#include "avl.h"

#include <stdio.h>
#include "command.h"

/*==============================================================================
 * Memory Pools
 *
 * A qmem_pool is designed to hold numbers of fixed size memory items, where
 * there is a (reasonably) rapid turn-over of items, so there is a desire to
 * reduce the memory allocation overhead.
 *
 * Memory is allocated for each pool in "clutches".  Where a clutch is a
 * reasonable number of items so that (a) each new allocation does not
 * require a malloc(), and (b) to amortise the clutch overhead.  On a 64 bit
 * machine, the malloc overhead M is 8..16 bytes on an allocation of S bytes.
 * So, the malloc and qmem break even at n items, where:
 *
 *   n * (S + M) = ((n + c - 1) / c) * ((S * c) + Q + M)
 *
 * where there are c items per clutch and the clutch overhead is Q.  So at:
 *
 *   n = (c - 1) * ((S * c) + Q + M) / (((c - 1) * M) - Q)
 *
 * so, for c=128, S=256, Q=64 and M=16, this breaks even at 2120 items.  For
 * c=128, S=32 this breaks even at 269 items -- and as the number of items
 * grows, the worst case *saving* in this case is about 32% -- at 4097 items,
 * which is worst case because there are 127 unused items allocated, the saving
 * is 58,858 bytes, or 30% -- at 131,073 items the saving is 2,011,104 bytes,
 * or 32%.  [The saving is always going to be < (M / (S + M)), which for 32
 * byte items is 33.33% and for 256 byte items is 5.88%.]
 *
 * Once a qmem_pool has been created, it is not destroyed until late in the
 * shutdown process... so pointers to the pool are stable and read-only (from
 * a pthread perspective).
 *
 *
 *
 *
 *
 *
 *
 * The Memory Pool Structures.
 */
typedef struct qmem_free_item  qmem_free_item_t ;
typedef struct qmem_free_item* qmem_free_item ;

struct qmem_free_item
{
  qmem_free_item   next ;
} ;

#if 0
typedef struct qmem_free_base  qmem_free_base_t ;

struct qmem_free_base
{
  qmem_free_item   next ;
  qmem_free_item   last ;
} ;
#endif

/* Each clutch has the following form, where the leading part is red tape for
 * garbage collection.
 *
 * The prefix is (on 64 bit machine) approx 56 bytes.  The minimum size
 * clutch is a page (typically 4096 bytes) and the minimum number of items per
 * clutch is 15.
 *
 */
typedef struct qmem_clutch  qmem_clutch_t ;
typedef struct qmem_clutch* qmem_clutch ;

struct qmem_clutch
{
  /* For garbage collection we need to be able to find which clutch a given
   * item belongs in... for that we use an avl tree.
   */
  avl_node_t       node[1] ;

  /* When a new clutch is created it is added to the new_clutches list, and
   * all its items are added to the free list, so:
   *
   *   next       -> next clutch on the new_clutches list
   *   free       -> next item to allocate (if any)
   *   free_count == number of items left to allocate
   *
   * Note that while on the new_clutches list, the item pointed to by the
   * free pointer does NOT point to the next free... the next free is
   * *implicitly* the one immediately following -- this avoids threading up
   * all the items when a new clutch is created.
   *
   * During garbage collection, before picking up current free items, must
   * check for new_clutches, and move same to the tree of known clutches.
   * At this moment all remaining free items are threaded up.
   *
   * The garbage collector co-opts all the free items and proceeds to move them
   * to the free list of their parent clutch.  All clutches with not empty
   * free list sit on the meta_free list, whence they can be removed and
   * pressed into service by the allocator.
   */
  qmem_clutch      next ;               /* on new_clutch or meta_free   */

  qmem_free_item   free ;
  uint             free_count ;

  uint             clutch_size ;        /* for tree search              */

  /* The body of the clutch -- this is purely notional, because the first item
   * is allocated some multiple of "item_align" from the head of the clutch.
   */
  byte             body[] ;
} ;

CONFIRM(sizeof(avl_node_t) == 32) ;
CONFIRM(offsetof(qmem_clutch_t, body) == 56) ;

CONFIRM(offsetof(qmem_clutch_t, node) == avl_node_offset) ;

typedef struct qmem_pool  qmem_pool_t ;

struct qmem_pool
{
  /* As they are created, memory pools are placed on a list of same, in
   * mtype and creation order.
   */
  qmem_pool    next ;

  /* The name is set when the pool is created, and never changed.
   */
  char         name[64] ;

  /* The parameters for items in the pool.
   *
   * These are set when the pool is created, and never changed.
   */
  mtype_t      mtype ;

  uint         item_size ;
  uint         clutch_offset ;
  uint         clutch_size ;
  uint         clutch_item_count ;

  /* The management of items and clutches thereof -- requires Spin-Lock
   *
   *   * free          -- pointer to currently free items
   *
   *                      For minimum fuss, allocating takes the first item on
   *                      the list and freeing just puts back at the head.
   *
   *   * allocated     -- count of allocated items
   *
   *   * assembled     -- count of assembled items (allocated or free).
   *
   *   * new_clutches  -- list of those created but not yet added to the tree.
   *
   *                      First on the list is *very* special, and contains
   *                      the most recently created items.  All these items
   *                      must be allocated before another new clutch is
   *                      created.
   *
   *   * meta_free     -- list of clutches with at least one free item found
   *                      by the garbage collector.
   *
   *   * collected     -- list of items being processed by the garbage
   *                      collector.
   */
  qmem_free_item free ;

  uint           allocated ;
  uint           assembled ;

  qmem_clutch    new_clutches ;
  qmem_clutch    meta_free ;

  qmem_free_item collected ;

  /* The garbage collector needs to be able to map an item to its clutch,
   * for which a tree is used.
   */
  avl_tree_t     tree[1] ;

  /* If this is a pool used by more than one pthread, then it must be set
   * "shared" when the pool is created (and the flag MUST NOT be changed !),
   * and then the slock and mutex will be initialised (if pthreads_enabled)
   * and used (if pthreads_active).
   *
   * Note that the 'shared' flag is overridden if is !pthreads_enabled.
   *
   * The spin-lock is used for allocation/freeing of items etc.
   *
   * The mutex is used when creating a clutch of items.
   */
  qpt_spin_t    slock ;
  qpt_mutex     mutex ;

  bool          shared ;
  bool          mallocing ;
} ;

/*==============================================================================
 * Memory Pool variables.
 */
static qmem_pool qmem_pool_list ;

static qpt_mutex qmem_pool_list_mutex ;         /* not recursive        */

/*==============================================================================
 * Lock functions -- for visibility
 *
 * NB: MUST release the spin lock before attempting to acquire the pool lock,
 *     but CAN acquire the spin lock inside the pool lock.
 */
inline static void
QMEM_POOL_LIST_LOCK(void)
{
  qpt_mutex_lock(qmem_pool_list_mutex) ;
} ;

inline static void
QMEM_POOL_LIST_UNLOCK(void)
{
  qpt_mutex_unlock(qmem_pool_list_mutex) ;
} ;

inline static void
QMEM_POOL_LOCK(qmem_pool pool)
{
  if (pool->shared)
    qpt_mutex_lock(pool->mutex) ;
} ;

inline static void
QMEM_POOL_UNLOCK(qmem_pool pool)
{
  if (pool->shared)
    qpt_mutex_unlock(pool->mutex) ;
} ;

inline static void
QMEM_SPIN_LOCK(qmem_pool pool)
{
  if (pool->shared)
    qpt_spin_lock(pool->slock) ;
} ;

inline static void
QMEM_SPIN_UNLOCK(qmem_pool pool)
{
  if (pool->shared)
    qpt_spin_unlock(pool->slock) ;
} ;

/*==============================================================================
 * The qlib start..finish stuff
 */
static qmem_pool qmp_destroy(qmem_pool pool, bool mem_stats) ;

/*------------------------------------------------------------------------------
 * Start up for qmem_pool.
 *
 * Not much to do here, other than set the qmem_pool_list empty
 */
extern void
qmp_start_up(void)
{
  qmem_pool_list       = NULL ;
  qmem_pool_list_mutex = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Second stage
 *
 * If any memory pools have been created before now, then now set up mutex and
 * spinlock.  Up to this point, can have created and used a memory pool, and
 * all locking operations will have been ignored.
 *
 * NB: this should be done after qpt_second_stage() but *BEFORE* any further
 *     use of any memory pool (ie between qpt_second_stage() and now).
 */
extern void
qmp_second_stage(void)
{
  qmem_pool pool ;

  qmem_pool_list_mutex = qpt_mutex_new(qpt_mutex_quagga, "qmem_pool_list") ;

  QMEM_POOL_LIST_LOCK() ;       /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  pool = qmem_pool_list ;
  while (pool != NULL)
    {
      pool->shared = pool->shared && qpthreads_enabled ;

      if ((pool->mutex == NULL) && (pool->shared))
        {
          pool->mutex = qpt_mutex_new(qpt_mutex_quagga, pool->name) ;
          qpt_spin_init(pool->slock) ;
        } ;
    } ;

  QMEM_POOL_LIST_UNLOCK() ;     /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Empty out all the pools.
 *
 * This is done so late in the day that nothing may still depend on the
 * contents of the pools.  If mem_stats is true and any pool is not actually
 * empty, then will throw information to stderr.
 */
extern void
qmp_finish(bool mem_stats)
{
  qmem_pool  pool ;

  qpt_mutex_destroy(qmem_pool_list_mutex) ;

  while ((pool = qmem_pool_list) != NULL)
    {
      qmem_pool_list = pool->next ;
      qmp_destroy(pool, mem_stats) ;
    } ;
} ;

/*==============================================================================
 * Creation, garbage collect and destruction of qmem_pools
 */
static void qmp_add_clutch(qmem_pool pool) ;
static void qmp_free_clutch(qmem_clutch clutch, qmem_pool pool) ;

/*------------------------------------------------------------------------------
 * Create a new qmem_pool.
 */
extern qmem_pool
qmp_create(const char* name, mtype_t mtype, uint item_size, uint item_align,
                                                   uint item_count, bool shared)
{
  qmem_pool pool, prev, next ;
  uint size, offset ;

  qassert(item_align != 0) ;

  pool = XCALLOC(mtype, sizeof(qmem_pool_t)) ;

  /* Zeroizing the pool sets:
   *
   *   * next                -- X         -- set below
   *
   *   * name                -- X         -- set below
   *
   *   * mtype               -- X         -- set below
   *   * item_size           -- X         -- set below
   *   * clutch_offset       -- X         -- set below
   *   * clutch_size         -- X         -- set below
   *   * clutch_item_count   -- X         -- set below
   *
   *   * free                -- NULL      -- nothing free, yet
   *   * allocated           -- 0         -- nothing allocated, yet
   *   * assembled           -- 0         -- nothing assembled, yet
   *
   *   * new_clutches        -- NULL      -- none, yet
   *   * meta_free           -- NULL      -- none, yet
   *   * collected           -- NULL      -- none, yet
   *
   *   * tree                -- X         -- initialised, below
   *
   *   * slock               -- X
   *   * mutex               -- X
   *
   *   * shared              -- X         -- set below
   *   * mallocing           -- false     -- not
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;

  strncpy_x(pool->name, name, sizeof(pool->name)) ;

  /* Adjust the item_size and item_count to enforce minima.
   */
  if (item_size < sizeof(qmem_free_item_t))
    {
      Need_alignof(qmem_free_item_t) ;

      item_size  = sizeof(qmem_free_item_t) ;
      item_align = alignof(qmem_free_item_t) ;
    } ;

  qassert((item_size % item_align) == 0) ;

  if (item_count < 15)
    item_count = 15 ;

  /* Calculate:
   *
   *   * offset       -- from the given item_align
   *
   *   * size         -- initially, expand up to some multiple of qlib_pagesize
   *                     based on the item_size and suggested item_count.
   *
   *   * item_count   -- work back from the size and offset to get a rounded up
   *                     number of items -- cannot be zero !
   *
   *   * size (again) -- finally, based on the now actual item_count.
   */
  offset     = uround_up(offsetof(qmem_clutch_t, body), item_align) ;
  size       = uround_up(offset + (item_size * item_count), qlib->pagesize) ;
  item_count = uround_up(size - offset, item_size) ;
  size       = offset + (item_count * item_size) ;

  pool->mtype             = mtype ;
  pool->item_size         = item_size ;
  pool->clutch_offset     = offset ;
  pool->clutch_item_count = item_count ;
  pool->clutch_size       = size ;

  assert(item_count != 0) ;

  /* If this is a shared pool, set up the spin-lock and mutex.
   *
   * NB: we allow for a pool to be created before qpthreads_enabled is set.
   *
   *     During second stage initialisation any spin-lock/mutex required will
   *     be created -- or the shared flag is cleared.
   */
  pool->shared = shared ;
  if (qpthreads_enabled && shared)
    {
      pool->mutex = qpt_mutex_new(qpt_mutex_quagga, pool->name) ;
      qpt_spin_init(pool->slock) ;
    } ;

  /* Add to list of known pools
   */
  QMEM_POOL_LIST_LOCK() ;       /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  prev = NULL ;
  next = qmem_pool_list ;
  while (next != NULL)
    {
      if (next->mtype > pool->mtype)
        break ;

      prev = next ;
      next = next->next ;
    } ;

  if (prev == NULL)
    {
      pool->next = qmem_pool_list ;
      qmem_pool_list = pool ;
    }
  else
    {
      pool->next = prev->next ;
      prev->next = pool ;
    } ;

  QMEM_POOL_LIST_UNLOCK() ;     /*->->->->->->->->->->->->->->->->->->->*/

  /* Done -- return the new qmem_pool
   */
  return pool ;
} ;

/*------------------------------------------------------------------------------
 * Destroy given pool -- once removed from list of pools.
 *
 * NB: assumed to be at shut down time !
 *
 * Returns:  NULL
 */
static qmem_pool
qmp_destroy(qmem_pool pool, bool mem_stats)
{
  qmem_clutch clutch ;
  avl_item    ream ;

  qassert(!qpthreads_active) ;

  if (pool->shared)
    {
      qpt_spin_destroy(pool->slock) ;
      pool->mutex = qpt_mutex_destroy(pool->mutex) ;

      pool->shared = false ;
    } ;

  if ((pool->allocated != 0) && mem_stats)
    {
      const char* prog_name ;

      prog_name = cmd_host_program_name() ;
      if (prog_name == NULL)
        prog_name = "*progname unknown*" ;

      fprintf (stderr, "%s: memstats: pool %-40s: %10lu\n",
                                prog_name, pool->name, (ulong)pool->allocated) ;
    } ;

  while ((clutch = pool->new_clutches) != NULL)
    {
      pool->new_clutches = clutch->next ;

      qmp_free_clutch(clutch, pool) ;
    } ;

  ream = avl_tree_fell(pool->tree) ;
  while ((clutch = avl_tree_ream(&ream)) != NULL)
    qmp_free_clutch(clutch, pool) ;

  XFREE(pool->mtype, pool) ;

  return NULL ;
} ;

/*==============================================================================
 * Allocation and freeing items
 */

/*------------------------------------------------------------------------------
 * Allocate item from the given pool.
 *
 * Returns:  address of item
 *
 * NB: if the caller wishes this to be zeroized, they must do that themselves.
 *
 *     Inter alia: the caller has a better idea how big the item is !
 */
extern void*
qmp_alloc(qmem_pool pool)
{
 qmem_free_item mem ;

  QMEM_SPIN_LOCK(pool) ;        /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  while (1)
    {
      qmem_clutch    clutch ;
      uint           free_count ;

      /* Hope to allocate directly from the current pool
       */
      mem = pool->free ;
      if (mem != NULL)
        {
          pool->free = mem->next ;
          break ;
        } ;

      /* Next best option, directly from a recently created clutch.
       *
       * Note that for new clutches, the items from the current free onwards
       * are *not* threaded up.  We finesse that here, to avoid the work
       * of threading (perhaps thousands) of items, which would just be
       * picked off one by one here in any case !
       */
      clutch = pool->new_clutches ;

      if ((clutch != NULL) && ((free_count = clutch->free_count) != 0))
        {
          mem = clutch->free ;

          clutch->free_count = free_count -= 1 ;
          if (free_count != 0)
            clutch->free = (qmem_free_item)(((byte*)mem) + pool->item_size) ;
          else
            clutch->free = NULL ;

          break ;
        } ;

      /* Next best option, from the meta-free list
       *
       * The meta-free list contains clutches which the garbage collector has
       * found to contain at least one free item.
       */
      clutch = pool->meta_free ;

      if (clutch != NULL)
        {
          /* For a clutch to be on the meta_free list, it MUST have at least
           * one free item !
           */
          qassert((clutch->free != NULL) && (clutch->free_count != 0)) ;

          mem = clutch->free ;

          clutch->free_count -= 1 ;
          clutch->free        = mem->next ;

          break ;
        } ;

      /* Penultimate option -- take back the collected stuff
       */
      mem = pool->collected ;

      if (mem != NULL)
        {
          pool->collected = NULL ;

          pool->free = mem->next ;
          break ;
        } ;

      /* Final option -- allocate an brand new clutch
       */
      qmp_add_clutch(pool) ;    /* NB: calls and returns with Spin Lock */
    } ;

  pool->allocated += 1 ;

  QMEM_SPIN_UNLOCK(pool) ;      /*->->->->->->->->->->->->->->->->->->->*/

  return (void*)mem ;
} ;

/*------------------------------------------------------------------------------
 * Free item (if any) back to the given pool.
 *
 * Returns:  NULL
 */
extern void*
qmp_free(qmem_pool pool, void* item)
{
  if (item != NULL)
    {
      QMEM_SPIN_LOCK(pool) ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

      ((qmem_free_item)item)->next = pool->free ;
      pool->free       = (qmem_free_item)item ;
      pool->allocated -= 1 ;

      QMEM_SPIN_UNLOCK(pool) ;  /*->->->->->->->->->->->->->->->->->->->*/

      item = NULL ;
    } ;

  return item ;
} ;

/*==============================================================================
 * Allocation and freeing of clutches
 */

/*------------------------------------------------------------------------------
 * Add a clutch of items to the given pool
 *
 * NB: requires the pool to be QMEM_SPIN_LOCKED  <<< LOCKED.
 *
 * Drops and re-acquires the Spin Lock -- do not wish to hold that while we
 * malloc.
 *
 * However... there is a tricky bit here.  If two pthreads arrive wanting
 * to allocate a new clutch, we must allow only one of them to do so.
 * We want to avoid allocating twice... AND the mechanics above assume that
 * only the first clutch on the new_clutches list can be in the newly allocated
 * state.
 *
 * SO: before doing a malloc() must acquire the pool mutex.  In the
 * (staggeringly) unlikely event that a second pthread arrives here while
 * an earlier pthread is busy allocating, it will wait on the pool mutex.
 * In the (absolutely) astonishingly unlikely event that the second
 * pthread gets to the mutex first, it will acquire and promptly free
 * the mutex, and (most likely) come round again and stop on the mutex
 * the second time.
 */
static void
qmp_add_clutch(qmem_pool pool)
{
  qmem_clutch    clutch ;
  byte*          ptr ;
  bool           alloc ;

  if (pool->mallocing)
    alloc = false ;
  else
    alloc = pool->mallocing = true ;

  QMEM_SPIN_UNLOCK(pool) ;      /*->->->->->->->->->->->->->->->->->->->*/
  QMEM_POOL_LOCK(pool) ;        /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (!alloc)
    clutch = NULL ;
  else
    {
      clutch = XMALLOC(pool->mtype, pool->clutch_size) ;

      memset(clutch, 0, pool->clutch_offset) ;

      ptr = ((byte*)clutch) + pool->clutch_offset ;

      clutch->free       = (qmem_free_item)ptr ;        /* first item   */
      clutch->free_count = pool->clutch_item_count ;
    } ;

  QMEM_POOL_UNLOCK(pool) ;      /*->->->->->->->->->->->->->->->->->->->*/
  QMEM_SPIN_LOCK(pool) ;        /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (clutch != NULL)
    {
      clutch->next = pool->new_clutches ;
      pool->new_clutches = clutch ;
      pool->assembled   += pool->clutch_item_count ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run the garbage collector
 *
 * The garbage collector can run in the background, so is presented as a
 * work-queue item.
 *
 * TODO ..... !
 */
extern wq_ret_code_t
qmp_garbage_collect(qmem_pool pool, qtime_mono_t yield_time)
{
  return wqrc_remove ;
} ;

/*------------------------------------------------------------------------------
 * Free the given clutch -- when already removed from any list(s) or the tree
 *
 * NB: must NOT be spin locked !
 */
static void
qmp_free_clutch(qmem_clutch clutch, qmem_pool pool)
{
  QMEM_SPIN_LOCK(pool) ;        /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  qassert(pool->assembled >= pool->clutch_item_count) ;
  pool->assembled -= pool->clutch_item_count ;

  QMEM_SPIN_UNLOCK(pool) ;      /*->->->->->->->->->->->->->->->->->->->*/

  XFREE(pool->mtype, clutch) ;
} ;
