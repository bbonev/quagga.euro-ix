#include "misc.h"
#include "qlib_init.h"
#include "command.h"

#include <string.h>

#include "svector.h"
#include "vector.h"

/* Small-Vector torture tests
 */

/* prototypes */
static void test_svl(void);

static uint assert_limit ;


#define test_assert(true, message) \
  do { if (!(true)) test_assert_fail(#true, message, __func__, __LINE__) ; \
  } while (0)

static void
test_assert_fail(const char* truth, const char* message, const char* func,
                                                                       int line)
{
  printf("*** %s %d: (%s) not true: %s\n", func, line, truth, message) ;

  if (assert_limit > 0)
    {
      --assert_limit ;
      assert(assert_limit > 0) ;
    } ;
} ;

/*==============================================================================
 * The tests.
 */
int
main(int argc, char **argv)
{
  qlib_init_first_stage(0);     /* Absolutely first     */
  host_init(argv[0]) ;

  printf("Starting 'svector' tests -- v0.01 23-Aug-2010\n") ;

  srand(22) ;                   /* Consistent testing required          */

  assert_limit = 25 ;

  test_svl() ;
  test_sdl() ;
  test_ddl() ;



  return 0;
}

/*==============================================================================
 * Construct a majic mark from two addresses
 */
static unsigned majic(void* a, void* b)
{
  uintptr_t z = (uintptr_t)a ^ (uintptr_t)b ^ (uintptr_t)&majic ;
  return z ;
} ;

/* aux list (vector) functions
 */
static vector aux_init(void) ;
static void aux_reset(vector aux) ;
static int aux_length(vector aux) ;
static void* aux_item(vector aux, int index) ;
static void* aux_next_item(vector aux, int index) ;
static void* aux_prev_item(vector aux, int index) ;
static void aux_insert(vector aux, int index, void* item) ;
static void aux_delete(vector aux, void* item) ;
static void aux_push_head(vector aux, void* item) ;
static void* aux_pop_head(vector aux) ;
static void aux_push_tail(vector aux, void* item) ;
static void* aux_pop_tail(vector aux) ;
static int aux_find(vector aux, void* item) ;

/*==============================================================================
 * Testing the Basic Small-Vector operations -- for:
 *
 *   svec_0t         -- no embedded items
 *   svec_1t         -- 1 embedded item   ) bit special for initial set up
 *   svec_2t         -- 2 embedded items  ) of extended body
 *   svec_3t         -- 3 embedded items  )
 *   svec_4t         -- 4 embedded items
 *   svec_11t        -- our own invention
 *
 * Initialisation/Destruction.
 *
 *   * svec_init(sv)          -- initialise from scratch
 *
 *                               No different from zeroizing !
 *
 *   * svec_reset(sv)         -- set empty, retaining any extended body.
 *
 *   * svec_clear(sv)         -- set empty, freeing any extended body
 *
 * The basic add/del/get operations.
 *
 *   * svec_add(sv, item)     -- add given item to the svec
 *
 *                               Returns: index of the item.
 *
 *   * svec_del(sv, i)        -- remove item at the given index from the svec.
 *
 *                               Returns: item removed.
 *
 *   * svec_get(sv, i)        -- get address of item at the given index.
 *
 *                               Returns: item
 *
 * NB: the svec_get() in particular is "light-weight" -- no checking is done
 *     on the index, the state of the svec or anything else.
 */
struct svecN(1) ;
struct svecN(2) ;
struct svecN(3) ;
struct svecN(11) ;

typedef struct svec1   svec1_t ;
typedef struct svec1*  svec1 ;
typedef struct svec2   svec2_t ;
typedef struct svec2*  svec2 ;
typedef struct svec3   svec3_t ;
typedef struct svec3*  svec3 ;
typedef struct svec11  svec11_t ;
typedef struct svec11* svec11 ;

typedef struct test_svec  test_svec_t ;
typedef struct test_svec* test_svec ;

struct test_svec
{
  uint          e ;
  union
    {
      svec_t    sv0[1] ;
      svec1_t   sv1 ;
      svec2_t   sv2 ;
      svec3_t   sv3[1] ;
      svec4_t   sv4 ;
      svec11_t  sv11 ;
    } u ;
} ;

static void test_svec_init(test_svec tsv) ;
static void test_svec_reset(test_svec tsv) ;
static void test_svec_clear(test_svec tsv) ;

static svec_index_t test_svec_add(test_svec tsv, void* item) ;
static svec_item test_svec_del(test_svec tsv, svec_index_t i) ;
static svec_item test_svec_get(test_svec tsv, svec_index_t i) ;








/*------------------------------------------------------------------------------
 * Run svec_init()
 */
static void
test_svec_init(test_svec tsv)
{
  switch (tsv->e)
    {
      case 0:
        svec_init(tsv->u.sv0) ;
        break ;

      case 1:
        svec_init(tsv->u.sv1) ;
        break ;

      case 2:
        svec_init(tsv->u.sv2) ;
        break ;

      case 3:
        svec_init(tsv->u.sv3) ;
        break ;

      case 4:
        svec_init(tsv->u.sv4) ;
        break ;

      case 11:
        svec_init(tsv->u.sv11) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run svec_reset()
 */
static void
test_svec_reset(test_svec tsv)
{
  switch (tsv->e)
    {
      case 0:
        svec_reset(tsv->u.sv0) ;
        break ;

      case 1:
        svec_reset(tsv->u.sv1) ;
        break ;

      case 2:
        svec_reset(tsv->u.sv2) ;
        break ;

      case 3:
        svec_reset(tsv->u.sv3) ;
        break ;

      case 4:
        svec_reset(tsv->u.sv4) ;
        break ;

      case 11:
        svec_reset(tsv->u.sv11) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run svec_clear()
 */
static void
test_svec_clear(test_svec tsv)
{
  switch (tsv->e)
    {
      case 0:
        svec_clear(tsv->u.sv0) ;
        break ;

      case 1:
        svec_clear(tsv->u.sv1) ;
        break ;

      case 2:
        svec_clear(tsv->u.sv2) ;
        break ;

      case 3:
        svec_clear(tsv->u.sv3) ;
        break ;

      case 4:
        svec_clear(tsv->u.sv4) ;
        break ;

      case 11:
        svec_clear(tsv->u.sv11) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run svec_add()
 */
static svec_index_t
test_svec_add(test_svec tsv, svec_item item)
{
  switch (tsv->e)
    {
      case 0:
        return svec_add(tsv->u.sv0, item) ;
        break ;

      case 1:
        return svec_add(tsv->u.sv1, item) ;
        break ;

      case 2:
        return svec_add(tsv->u.sv2, item) ;
        break ;

      case 3:
        return svec_add(tsv->u.sv3, item) ;
        break ;

      case 4:
        return svec_add(tsv->u.sv4, item) ;
        break ;

      case 11:
        return svec_add(tsv->u.sv11, item) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run svec_del()
 */
static svec_item
test_svec_del(test_svec tsv, svec_index_t i)
{
  switch (tsv->e)
    {
      case 0:
        return svec_del(tsv->u.sv0, i) ;
        break ;

      case 1:
        return svec_del(tsv->u.sv1, i) ;
        break ;

      case 2:
        return svec_del(tsv->u.sv2, i) ;
        break ;

      case 3:
        return svec_del(tsv->u.sv3, i) ;
        break ;

      case 4:
        return svec_del(tsv->u.sv4, i) ;
        break ;

      case 11:
        return svec_del(tsv->u.sv11, i) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run svec_get()
 */
static svec_item
test_svec_get(test_svec tsv, svec_index_t i)
{
  switch (tsv->e)
    {
      case 0:
        return svec_get(tsv->u.sv0, i) ;
        break ;

      case 1:
        return svec_get(tsv->u.sv1, i) ;
        break ;

      case 2:
        return svec_get(tsv->u.sv2, i) ;
        break ;

      case 3:
        return svec_get(tsv->u.sv3, i) ;
        break ;

      case 4:
        return svec_get(tsv->u.sv4, i) ;
        break ;

      case 11:
        return svec_get(tsv->u.sv11, i) ;
        break ;

      default:
        assert(false) ;
    } ;
} ;

/*==============================================================================
 * Small-Vector Linked Lists
 *
 *   * svl_init(base)            -- clear the given base (lvalue)
 *
 *   * svl_init_p(item_p)        -- clear the given pointer pair (lvalue)
 *
 *   * svl_head(base, sv)        -- get item which is head of given list
 *   * svl_tail(base, sv)        -- get item which is tail of the the given list
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_prepend(base, sv, i, it_t, lp)   -- place item on front of list
 *   * svl_push(base, sv, i, it_t, lp)
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     These (and other) macros take a *type* and a *field* as arguments, where
 *     the field is the svec_list_p_t pair, so that the offset of that field
 *     can be calculated by: offsetof(it_t, lp).
 *
 *     Suppose we have items of item_t:
 *
 *       typedef struct item item_t ;
 *       struct item
 *         {
 *           ....
 *           svec_list_p_t  list ;
 *           ....
 *         } ;
 *
 *     we can push item 'i' onto a given list by:
 *
 *       svl_push(base, sv, item_t, list) ;
 *
 *     And similarly for most of the other list operations.
 *
 *   * svl_append(base, sv, i, it_t, lp)    -- place item on tail of list
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *   * svl_in_before(ib, base, sv, i, it_t, lp) -- place item before given one
 *   * svl_in_after(ia, base, sv, i, it_t, lp)  -- place item after given one
 *
 *     If ib == SVEC_NULL, append to list.
 *     If ia == SVEC_NULL, prepend.
 *
 *     Consider a list in some ascending order.  A loop searching for the
 *     first item greater than some new value may run off the end of the list.
 *     Hence, for svl_in_before it makes sense to treat SVEC_NULL as append.
 *     For svl_in_after() the same logic applies, assuming working backwards
 *     along a sorted list.
 *
 *     If the list is empty, 'ib' and 'ia' can only be SVEC_NULL, and it
 *     matters not whether the operation is append or prepend !
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     It is also *vital* that items 'ia' and 'ib' exist are on the list !
 *
 *   * svl_del_head(base, sv, it_t, lp) -- remove and return head of list
 *   * svl_pop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_del_tail(base, sv, it_t, lp) -- remove and return tail of list
 *   * svl_crop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_del(base, sv, i, it_t, lp)   -- remove item from list
 *
 *     It is *vital* that item 'i' exists in the given sv, and is on the list.
 */

/* Testing runs two lists through struct ddt_item objects.
 */

enum list
  {
    a_list,
    b_list,             /* a_list..b_list is all main lists             */

    a_sub_list,
    b_sub_list,         /* a_sub_list..b_sub_list is all sub lists      */

    list_count          /* 0..list_count -1 is all lists                */
  } ;
typedef enum list list_t ;

enum list_bit
  {
    a_list_bit     = 1 << a_list,
    b_list_bit     = 1 << b_list,

    a_sub_list_bit = 1 << a_sub_list,
    b_sub_list_bit = 1 << b_sub_list,

    list_bits      = 1 << list_count,
  } ;
typedef enum list_bit list_bit_t ;

typedef struct ddt_item* ddt_item ;

struct ddt_list_pair dl_list_pair(ddt_item) ;  /* Example struct constructor */
struct ddt_base_pair dl_base_pair(ddt_item) ;

typedef struct dl_base_pair(ddt_item) ddt_base_pair_xt ;
                                            /* Example typedef constructor  */

typedef struct ddt_list_pair  ddt_list_pair_t ;
typedef struct ddt_list_pair* ddt_list_pair ;

typedef struct ddt_base_pair  ddt_base_pair_t ;
typedef struct ddt_base_pair* ddt_base_pair ;

struct ddt_item                 /* the test items               */
{
  ddt_list_pair_t a ;

  char  a_rubbish[21] ;

  uint  seen ;

  ddt_list_pair_t b ;

  char  b_rubbish[19] ;
} ;

/* Pointers to the actual bases, for use in
 * the verification code.
 */
struct ddt_test_list
{
  const char*   name ;

  ddt_base_pair base ;

  vector        aux ;
} ;

typedef struct ddt_test_list* ddt_test_list ;
typedef struct ddt_test_list  ddt_test_list_t ;

static ddt_test_list_t ddt_lists[list_count] ;


static inline ddt_list_pair
ddt_list(ddt_item item, list_t lt)
{
  switch (lt)
    {
      case a_list:
      case a_sub_list:
        return &(item->a) ;

      case b_list:
      case b_sub_list:
        return &(item->b) ;

      default:
        assert(false) ;
    } ;
} ;

static inline ddt_base_pair
ddt_base(list_t lt)
{
  switch (lt)
    {
      case a_list:
      case a_sub_list:
      case b_list:
      case b_sub_list:
        return ddt_lists[lt].base ;

      default:
        assert(false) ;
    } ;
} ;

static inline vector
ddt_aux(list_t lt)
{
  switch (lt)
    {
      case a_list:
      case a_sub_list:
      case b_list:
      case b_sub_list:
        return ddt_lists[lt].aux ;

      default:
        assert(false) ;
    } ;
} ;

static inline uint
ddt_list_bit(list_t lt)
{
  switch (lt)
    {
      case a_list:
      case a_sub_list:
        return 1 ;

      case b_list:
      case b_sub_list:
        return 2 ;

      default:
        assert(false) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Initialise a test list.
 */
static void
ddt_test_list_init(ddt_test_list tl, ddt_base_pair base, const char* name)
{
  tl->name   = name ;

  tl->base   = base ;

  base->head = NULL ;
  base->tail = NULL ;

  tl->aux    = aux_init() ;
} ;

/*------------------------------------------------------------------------------
 * The test list items -- keep track here also for use in verification.
 */
enum { ddt_max_items = 1000 } ;

static unsigned ddt_item_count = 0 ;
static unsigned ddt_item_alloc = 0 ;
static unsigned ddt_item_byte  = 0 ;
static ddt_item ddt_items[ddt_max_items] ;

static ddt_item
ddt_new_item(void)
{
  ddt_item item ;
  uint i, b ;

  assert(ddt_item_count <= ddt_item_alloc) ;

  if (ddt_item_count == ddt_item_alloc)
    {
      assert(ddt_item_alloc < ddt_max_items) ;
      ddt_items[ddt_item_alloc++] = malloc(sizeof(struct ddt_item)) ;
    } ;

  item = ddt_items[ddt_item_count++] ;

  b = ddt_item_byte + 0xA5 ;
  for (i = 0 ; i < sizeof(struct ddt_item) ; ++i)
    ((uchar*)item)[i] = (b += 0x55) ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Verification code.
 *
 * Blunt instrument to check that all known lists are valid.  Checks:
 *
 *   * bases are both NULL together, or both not NULL.
 *
 *   * first and last items on the list have suitable prev/next pointers.
 *
 *   * walk list to confirm, for each item:
 *
 *      -- prev pointer valid for each item
 *      -- item majic is correct (so not pointing somewhere invalid)
 *      -- item is supposed to be on the list
 *      -- item has not already been seen on list (list bent)
 *      -- ordinal, if not zero, is bigger than any previous non-zero ordinal
 *
 *   * last item visited on walk is what the tail points to
 *
 *   * for any items which are supposed to be on list, but were not found
 */
static void
ddt_verify_lists(void)
{
  uint i, l ;

  /* Wash the seen flags
   */
  for (i = 0 ; i < ddt_item_count ; ++i)
    ddt_items[i]->seen = 0 ;

  /* Walk the lists
   */
  for (l = 0 ; l < list_count ; ++l)
    {
      ddt_base_pair base ;

      base = ddt_lists[l].base ;
      if (base == NULL)
        continue ;

      if ((base->head == NULL) || (base->tail == NULL))
        test_assert(base->head == base->tail, "broken list bases") ;
      else
        {
          vector        aux ;
          ddt_list_pair list ;
          ddt_item this ;
          ddt_item prev ;
          uint s ;

          list = ddt_list(base->head, l) ;
          test_assert(list->prev == NULL, "broken list first item->prev") ;
          list = ddt_list(base->tail, l) ;
          test_assert(list->next == NULL, "broken list last item->next") ;

          this = base->head ;
          prev = NULL ;

          s = ddt_list_bit(l) ;         /* seen flag    */

          aux = ddt_lists[l].aux ;
          i = 0 ;
          while (this != NULL)
            {
              test_assert(i < vector_length(aux), "list longer than aux list") ;
              test_assert(aux_item(aux, i) == this,
                                              "list and aux list out of step") ;

              test_assert((this->seen & s) == 0, "list item seen already") ;
              this->seen |= s ;

              list = ddt_list(this, l) ;

              test_assert(list->prev == prev, "broken item->prev") ;

              prev = this ;
              this = list->next ;
              ++i ;
            } ;

          test_assert(i == vector_length(aux), "list shorter than aux list") ;
          test_assert(base->tail == prev, "broken tail pointer") ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Reset the test list handling
 *
 * Sets all ddt_lists empty.
 */
static void
ddt_reset_lists(void)
{
  int l ;

  for (l = 0 ; l < list_count ; ++l)
    {
      ddl_init(*(ddt_lists[l].base)) ;
      aux_reset(ddt_lists[l].aux) ;
    } ;

  ddt_item_count = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Set all lists empty, make main lists with 'n' and sub lists with 'm' items
 * each.
 *
 * Lists will have a random number of items in common.
 */
static void
ddt_test_make_lists(int n, int m)
{
  ddt_item      item ;
  vector        aux ;

  uint l, t ;

  ddt_reset_lists() ;

  uint req[list_count] ;

  /* Capture the requirements
   */
  t = 0 ;
  for (l = 0 ; l < list_count ; ++l)
    {
      uint ln ;

      switch (l)
        {
          case a_list:
          case b_list:
            ln = n ;
            break ;

          case a_sub_list:
          case b_sub_list:
            ln = m ;
            break ;

          default:
            assert(false) ;
        } ;

      t     += ln ;
      req[l] = ln ;
    } ;

  /* Have t = total number of items still required
   *
   * We ensure that the a_list and the a_sub_list are distinct, and that
   * the b_list and the b_sub_list are also distinct.
   */
  while (t != 0)
    {
      uint r ;

      r = rand() % list_bits ;

      if ((r & a_list_bit) || (m == 0))
        r &= ~a_sub_list_bit ;
      if ((r & b_list_bit) || (m == 0))
        r &= ~b_sub_list_bit ;

      item = NULL ;

      l = 0 ;
      while (r != 0)
        {
          if ((r & 1) && (req[l] != 0))
            {
              --req[l] ;
              --t ;

              if (item == NULL)
                item = ddt_new_item() ;

              aux = ddt_lists[l].aux ;
              aux_insert(aux, rand() % (vector_length(aux) + 1), item) ;
            } ;

          r >>= 1 ;
          l  += 1 ;
        }
    } ;

  /* Construct the lists
   */
  for (l = 0 ; l < list_count ; ++l)
    {
      ddt_base_pair base ;
      ddt_list_pair list ;
      uint i ;

      base = ddt_lists[l].base ;
      aux  = ddt_lists[l].aux ;

      base->head = NULL ;       /* Both NULL if list empty      */
      base->tail = NULL ;

      list = NULL ;
      for (i = 0 ; i < vector_length(aux) ; ++i)
        {
          ddt_list_pair prev ;

          prev = list ;

          item = aux_item(aux, i) ;
          list = ddt_list(item, l) ;

          if (prev == NULL)
            base->head = item ;
          else
            prev->next = item ;

          list->next = NULL ;
          list->prev = base->tail ;

          base->tail = item ;
        } ;
    } ;

  ddt_verify_lists() ;
} ;

/*------------------------------------------------------------------------------
 *   ddl_init(base)                 -- initialise base
 *   ddl_push(base, item, list)     -- insert at head of list
 *   ddl_append(base, item, list)   -- insert at tail of list
 *   ddl_in_after(after, base, item, list)   -- insert after
 *   ddl_in_before(before, base, item, list) -- insert before
 *   ddl_pop(&dst, base, next)      -- pop head of list, if any
 *   ddl_crop(&dst, base, next)     -- crop tail of list, if any
 *   ddl_del(base, item, list)      -- delete from list
 *   ddl_del_head(base, next)       -- delete head of list
 *   ddl_del_tail(base, next)       -- delete tail of list
 *   ddl_head(base)                 -- return head of list
 *   ddl_tail(base)                 -- return tail of list
 *   ddl_next(item, next)           -- step to next item, if any
 *   ddl_prev(item, next)           -- step to prev item, if any
 *
 *   ddl_slice(base, sub, list)     -- remove sublist from given list
 *   ddl_splice_after(after, base, sub, list)
 *                                  -- insert sublist after given item
 *   ddl_splice_before(before, base, sub, list)
 *                                  -- insert sublist before given item
 */

static struct ddt_parent
{
  char  zlxq[37] ;

  struct ddt_base_pair base ;

  char  qxlz[45] ;
} ddt_parent ;

static void
test_ddl(void)
{
  struct ddt_base_pair  a_base ;
  struct ddt_parent*    b ;
  ddt_base_pair_t       a_sub ;
  ddt_base_pair_t       b_sub ;

  int n ;

  int base_n = 23 ;
  int rand_n = 17 ;

  printf("=== Testing ddl -- Double Base, Double Link -- stuff\n") ;

  /* Initialise the test support
   */
  ddt_test_list_init(&ddt_lists[a_list], &a_base, "a-list") ;
  ddt_test_list_init(&ddt_lists[b_list], &ddt_parent.base, "b-list") ;

  ddt_test_list_init(&ddt_lists[a_sub_list], &a_sub, "a-sub-list") ;
  ddt_test_list_init(&ddt_lists[b_sub_list], &b_sub, "b-sub-list") ;

  ddt_item_count = 0 ;
  ddt_item_alloc = 0 ;

  /* Initialise the list bases                                          */
  b = &ddt_parent ;
  memset(b, 42, sizeof(struct ddt_parent)) ;

  ddl_init(a_base) ;
  ddl_init(b->base) ;

  ddt_verify_lists() ;          /* start as mean to go on               */

  /* ddl_push(base, item, list)     -- insert at head of list
   *
   * Cases: (a) empty list
   *        (b) list with one item
   *        (c) list with multiple items
   */
  printf("  ddl_push test") ;
  ddt_reset_lists() ;

  n = base_n + (rand() % rand_n) ;
  while (n > 0)
    {
      ddt_item item ;
      int r ;

      printf(".") ;

      item = ddt_new_item() ;
      r = (rand() % 3) + 1 ;

      if (r & 1)
        {
          ddl_push(a_base, item, a) ;
          test_assert(a_base.head == item, "ddl_push broken") ;
          aux_push_head(ddt_lists[a_list].aux, item) ;
        } ;
      ddt_verify_lists() ;

      if (r & 2)
        {
          ddl_push(b->base, item, b) ;
          test_assert(b->base.head == item, "ddl_push broken") ;
          aux_push_head(ddt_lists[b_list].aux, item) ;
        } ;
      ddt_verify_lists() ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_append(base, item, list)   -- insert at tail of list
   *
   * Cases: (a) empty list
   *        (b) list with one item
   *        (c) list with multiple items
   */
  printf("  ddl_append test") ;
  ddt_reset_lists() ;

  n = base_n + (rand() % rand_n) ;
  while (n > 0)
    {
      ddt_item item ;
      int r ;

      printf(".") ;

      item = ddt_new_item() ;
      r = (rand() % 3) + 1 ;

      if (r & 1)
        {
          ddl_append(a_base, item, a) ;
          test_assert(a_base.tail == item, "ddl_append broken") ;
          aux_push_tail(ddt_lists[a_list].aux, item) ;
        } ;
      ddt_verify_lists() ;

      if (r & 2)
        {
          ddl_append(b->base, item, b) ;
          test_assert(b->base.tail == item, "ddl_append broken") ;
          aux_push_tail(ddt_lists[b_list].aux, item) ;
        } ;
      ddt_verify_lists() ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_in_after(after, base, item, list)   -- insert after
   *
   * NB: after may NOT be NULL.
   *
   * Cases: (a) after NULL when list is empty
   *        (b) after NULL when list has 1 or more entries
   *        (c) after first and only (so is also last)
   *        (d) after first when more than one
   *        (e) after last when more than one
   *        (f) after something between
   */
  printf("  ddl_in_after test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      int w ;

      printf(".") ;

      for (w = 0 ; w <= n ; ++w)
        {
          ddt_item item ;
          ddt_item after ;
          vector aux ;

          ddt_test_make_lists(n, n) ;

          item  = ddt_new_item() ;

          aux = ddt_aux(a_list) ;
          after = aux_item(aux, w) ;

          ddl_in_after(after, a_base, item, a) ;

          if (after != NULL)
            aux_insert(aux, w+1, item) ;
          else
            aux_push_head(aux, item) ;

          ddt_verify_lists() ;

          item  = ddt_new_item() ;

          aux = ddt_aux(b_list) ;
          after = aux_item(aux, w) ;

          ddl_in_after(after, b->base, item, b) ;

          if (after != NULL)
            aux_insert(aux, w+1, item) ;
          else
            aux_push_head(aux, item) ;

          ddt_verify_lists() ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_in_before(before, base, item, list) -- insert before
   *
   * Cases: (a) before NULL when list empty
   *        (b) before NULL when list has 1 or more entries
   *        (c) before first and only (so is also last)
   *        (d) before first when more than one
   *        (e) before last when more than one
   *        (f) before something between
   */
  printf("  ddl_in_before test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      int     w ;

      printf(".") ;

      for (w = 0 ; w <= n ; ++w)
        {
          ddt_item item ;
          ddt_item before ;
          vector aux ;

          ddt_test_make_lists(n, n) ;

          item = ddt_new_item() ;

          aux  = ddt_aux(a_list) ;
          before = aux_item(aux, w) ;

          ddl_in_before(before, a_base, item, a) ;

          if (before != NULL)
            aux_insert(aux, w, item) ;
          else
            aux_push_tail(aux, item) ;

          ddt_verify_lists() ;

          item = ddt_new_item() ;

          aux  = ddt_aux(b_list) ;
          before = aux_item(aux, w) ;

          ddl_in_before(before, b->base, item, b) ;

          if (before != NULL)
            aux_insert(aux, w, item) ;
          else
            aux_push_tail(aux, item) ;

          ddt_verify_lists() ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_pop(&dst, base, next)      -- pop head of list, if any
   *
   * Cases: (a) list with more than one item
   *        (b) list with one item
   *        (c) empty list
   */
  printf("  ddl_pop test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      ddt_item item ;
      ddt_item temp ;
      ddt_item peek ;

      printf(".") ;

      ddt_test_make_lists(n, n) ;

      while (1)
        {
          peek = a_base.head ;
          temp = ddl_pop(&item, a_base, a) ;
          test_assert(temp == item, "ddl_pop broken") ;
          test_assert(peek == item, "ddl_pop broken") ;

          aux_pop_head(ddt_aux(a_list)) ;
          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      while (1)
        {
          peek = b->base.head ;
          temp = ddl_pop(&item, b->base, b) ;
          test_assert(temp == item, "ddl_pop broken") ;
          test_assert(peek == item, "ddl_pop broken") ;

          aux_pop_head(ddt_aux(b_list)) ;
          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_crop(&dst, base, next)     -- crop tail of list, if any
   *
   * Cases: (a) list with more than one item
   *        (b) list with one item
   *        (c) empty list
   */
  printf("  ddl_crop test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      ddt_item item ;
      ddt_item temp ;
      ddt_item peek ;

      printf(".") ;

      ddt_test_make_lists(n, n) ;

      while (1)
        {
          peek = a_base.tail ;
          temp = ddl_crop(&item, a_base, a) ;
          test_assert(temp == item, "ddl_crop broken") ;
          test_assert(peek == item, "ddl_crop broken") ;

          aux_pop_tail(ddt_aux(a_list)) ;
          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      while (1)
        {
          peek = b->base.tail ;
          temp = ddl_crop(&item, b->base, b) ;
          test_assert(temp == item, "ddl_crop broken") ;
          test_assert(peek == item, "ddl_crop broken") ;

          aux_pop_tail(ddt_aux(b_list)) ;
          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_del(base, item, list)      -- delete from list
   *
   * Cases: (a) first and only (so is also last)
   *        (b) first when more than one
   *        (c) last when more than one
   *        (d) everything between
   */
  printf("  ddl_del test") ;

  n = base_n + (rand() % rand_n) ;
  while (n > 0)
    {
      int  w ;

      printf(".") ;

      for (w = 0 ; w < n ; ++w)
        {
          ddt_item item ;
          vector   aux ;

          ddt_test_make_lists(n, n) ;

          aux  = ddt_aux(a_list) ;
          item = aux_item(aux, w) ;

          ddl_del(a_base, item, a) ;
          aux_delete(aux, item) ;
          ddt_verify_lists() ;

          aux  = ddt_aux(b_list) ;
          item = aux_item(aux, w) ;

          ddl_del(b->base, item, b) ;
          aux_delete(aux, item) ;
          ddt_verify_lists() ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_del_head(base, next)       -- delete head of list
   *
   * Cases: (a) list with more than one item
   *        (b) list with one item
   *        (c) empty list
   */
  printf("  ddl_del_head test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      ddt_item item ;
      ddt_item peek ;

      printf(".") ;

      ddt_test_make_lists(n, n) ;

      while (1)
        {
          item = a_base.head ;
          peek = (item != NULL) ? item->a.next : NULL ;

          ddl_del_head(a_base, a) ;

          test_assert(a_base.head == peek, "ddl_del_head broken") ;

          if (item != NULL)
            aux_delete(ddt_aux(a_list), item) ;

          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      while (1)
        {
          item = b->base.head ;
          peek = (item != NULL) ? item->b.next : NULL ;

          ddl_del_head(b->base, b) ;

          test_assert(b->base.head == peek, "ddl_del_head broken") ;

          if (item != NULL)
            aux_delete(ddt_aux(b_list), item) ;

          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_del_tail(base, next)       -- delete tail of list
   *
   * Cases: (a) list with more than one item
   *        (b) list with one item
   *        (c) empty list
   */
  printf("  ddl_del_tail test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      ddt_item item ;
      ddt_item peek ;

      printf(".") ;

      ddt_test_make_lists(n, n) ;

      while (1)
        {
          item = a_base.tail ;
          peek = (item != NULL) ? item->a.prev : NULL ;

          ddl_del_tail(a_base, a) ;

          test_assert(a_base.tail == peek, "ddl_del_tail broken") ;

          if (item != NULL)
            aux_delete(ddt_aux(a_list), item) ;

          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      while (1)
        {
          item = b->base.tail ;
          peek = (item != NULL) ? item->b.prev : NULL ;

          ddl_del_tail(b->base, b) ;

          test_assert(b->base.tail == peek, "ddl_del_tail broken") ;

          if (item != NULL)
            aux_delete(ddt_aux(b_list), item) ;

          ddt_verify_lists() ;

          if (item == NULL)
            break ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_head(base)                 -- return head of list
   * ddl_tail(base)                 -- return tail of list
   *
   * Cases: (a) list with more than one item
   *        (b) list with one item
   *        (c) empty list
   */
  printf("  ddl_head & ddl_tail test") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      printf(".") ;

      ddt_test_make_lists(n, n) ;

      test_assert(ddl_head(a_base)  == a_base.head,  "ddl_head broken") ;
      test_assert(ddl_tail(a_base)  == a_base.tail,  "ddl_head broken") ;
      test_assert(ddl_head(b->base) == b->base.head, "ddl_head broken") ;
      test_assert(ddl_tail(b->base) == b->base.tail, "ddl_head broken") ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_next(item, next)           -- step to next item, if any
   * ddl_prev(item, next)           -- step to prev item, if any
   *
   * Cases: (a) at first and only (so is also last)
   *        (b) at first when more than one
   *        (c) at last when more than one
   *        (d) at something between
   */
  printf("  ddl_next and ddl_prev test") ;

  n = base_n + (rand() % rand_n) ;
  while (n > 0)
    {
      int  w ;

      printf(".") ;

      for (w = 0 ; w < n ; ++w)
        {
          ddt_item item ;
          vector aux ;
          int i ;

          ddt_test_make_lists(n, n) ;

          aux  = ddt_aux(a_list) ;
          item = aux_item(aux, w) ;

          i = aux_find(aux, item) ;
          test_assert(i == w, "ddl_next/_prev list and aux list out of step") ;

          test_assert(ddl_next(item, a) == aux_next_item(aux, i),
                                                            "ddl_next broken") ;
          test_assert(ddl_prev(item, a) == aux_prev_item(aux, i),
                                                            "ddl_prev broken") ;

          aux  = ddt_aux(b_list) ;
          item = aux_item(aux, w) ;

          i = aux_find(aux, item) ;
          test_assert(i == w, "ddl_next/_prev list and aux list out of step") ;

          test_assert(ddl_next(item, b) == aux_next_item(aux, i),
                                                            "ddl_next broken") ;
          test_assert(ddl_prev(item, b) == aux_prev_item(aux, i),
                                                            "ddl_prev broken") ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_slice(base, sub, list)     -- remove sublist from given list
   *
   * Cases: (a) sub is empty
   *        (b) sub is the entire list -- list with 1 or more entries.
   *        (c) sub includes head of list, but 1 or more entries remain
   *        (d) sub includes tail of list, but 1 or more entries remain
   *        (e) sub is part of list, and 1 or more entries remain at either
   *            end.
   */
  printf("  ddl_slice") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      int s, e ;

      printf(".") ;

      for (s = 0 ; s <= n ; ++s)
        {
          for (e = s ; e <= n ; ++e)
            {
              vector aux ;

              ddt_test_make_lists(n, 0) ;

              if (s < e)
                {
                  vector aux_sub ;

                  aux = ddt_aux(a_list) ;

                  a_sub.head = aux_item(aux, s) ;
                  a_sub.tail = aux_item(aux, e - 1) ;

                  aux_sub = ddt_aux(a_sub_list) ;
                  assert(vector_length(aux_sub) == 0) ;

                  vector_move_extract(aux_sub, aux, s, e - s) ;
                } ;

              ddl_slice(a_base, a_sub, a) ;
              ddt_verify_lists() ;

              if (s < e)
                {
                  vector aux_sub ;

                  aux = ddt_aux(b_list) ;

                  b_sub.head = aux_item(aux, s) ;
                  b_sub.tail = aux_item(aux, e - 1) ;

                  aux_sub = ddt_aux(b_sub_list) ;
                  assert(vector_length(aux_sub) == 0) ;

                  vector_move_extract(aux_sub, aux, s, e - s) ;
                } ;

              ddl_slice(b->base, b_sub, b) ;
              ddt_verify_lists() ;
            } ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_splice_after(after, base, sub, list)
   *                                  -- insert sublist after given item
   * Cases: (a) sub is empty and list is empty
   *        (b) sub has 1 or more entries and list is empty (after = NULL).
   *        (c) sub includes head of list, but 1 or more entries remain
   *        (d) sub includes tail of list, but 1 or more entries remain
   *        (e) sub is part of list, and 1 or more entries remain at either
   *            end.
   */
  printf("  ddl_splice_after") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      printf(".") ;

      int m ;

      for (m = 0 ; m <= 5 ; ++m)
        {
          int w ;

          for (w = 0 ; w <= n ; ++w)
            {
              ddt_item after ;
              vector aux, s_aux ;

              ddt_test_make_lists(n, m) ;

              aux   = ddt_aux(a_list) ;
              after = aux_item(aux, w) ;

              ddl_splice_after(after, a_base, a_sub, a) ;

              s_aux = ddt_aux(a_sub_list) ;

              if (after != NULL)
                vector_move_replace(aux, w+1, 0, s_aux, 0, m) ;
              else
                vector_move_replace(aux, w,   0, s_aux, 0, m) ;

              ddl_init(a_sub) ;

              ddt_verify_lists() ;

              aux   = ddt_aux(b_list) ;
              after = aux_item(aux, w) ;

              ddl_splice_after(after, b->base, b_sub, b) ;

              s_aux = ddt_aux(b_sub_list) ;

              if (after != NULL)
                vector_move_replace(aux, w+1, 0, s_aux, 0, m) ;
              else
                vector_move_replace(aux, w,   0, s_aux, 0, m) ;

              ddl_init(b_sub) ;

              ddt_verify_lists() ;
            } ;
        } ;

      --n ;
    } ;
  printf("\n") ;

  /* ddl_splice_before(before, base, sub, list)
   *                                  -- insert sublist before given item
   *
   * Cases: (a) sub is empty and list is empty
   *        (b) sub has 1 or more entries and list is empty (before = NULL).
   *        (c) sub includes head of list, but 1 or more entries remain
   *        (d) sub includes tail of list, but 1 or more entries remain
   *        (e) sub is part of list, and 1 or more entries remain at either
   *            end.
   */
  printf("  ddl_splice_before") ;

  n = base_n + (rand() % rand_n) ;
  while (n >= 0)
    {
      printf(".") ;

      int m ;

      for (m = 0 ; m <= 5 ; ++m)
        {
          int w ;

          for (w = 0 ; w <= n ; ++w)
            {
              ddt_item before ;
              vector aux, s_aux ;

              ddt_test_make_lists(n, m) ;

              aux    = ddt_aux(a_list) ;
              before = aux_item(aux, w) ;

              ddl_splice_before(before, a_base, a_sub, a) ;

              s_aux = ddt_aux(a_sub_list) ;

              if (before != NULL)
                vector_move_replace(aux, w, 0, s_aux, 0, m) ;
              else
                vector_move_replace(aux, 0, 0, s_aux, 0, m) ;

              ddl_init(a_sub) ;

              ddt_verify_lists() ;

              aux    = ddt_aux(b_list) ;
              before = aux_item(aux, w) ;

              ddl_splice_before(before, b->base, b_sub, b) ;

              s_aux = ddt_aux(b_sub_list) ;

              if (before != NULL)
                vector_move_replace(aux, w, 0, s_aux, 0, m) ;
              else
                vector_move_replace(aux, 0, 0, s_aux, 0, m) ;

              ddl_init(b_sub) ;

              ddt_verify_lists() ;
            } ;
        } ;

      --n ;
    } ;
  printf("\n") ;

} ;

/*
 *  TODO
 *
 */

/*==============================================================================
 * Auxilliary list handling -- so that can test one list structure against
 * another.
 *
 * Implements list as vector of pointers.
 */

/*------------------------------------------------------------------------------
 * Create new, empty aux list (vector)
 */
static vector
aux_init(void)
{
  return vector_init_new(NULL, 50) ;
} ;

/*------------------------------------------------------------------------------
 * Empty the aux vector
 */
static void
aux_reset(vector aux)
{
  vector_set_length(aux, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Get number of items in the given aux list
 */
static int
aux_length(vector aux)
{
  return vector_length(aux) ;
} ;

/*------------------------------------------------------------------------------
 * Get item at the given index -- -ve counts from length
 *
 * Index must be -length..length
 */
static void*
aux_item(vector aux, int index)
{
  int length ;

  length = vector_length(aux) ;

  if (index < 0)
    index += length ;

  if ((index >= 0) && (index < length))
    return vector_get_item(aux, index) ;
  else
    return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get item after item at the given index -- -ve counts from length
 *
 * Index must be -length..length
 */
static void*
aux_next_item(vector aux, int index)
{
  int length ;

  length = vector_length(aux) ;

  if (index < 0)
    index += length ;

  if ((index >= 0) && (index < length))
    return vector_get_item(aux, index + 1) ;
  else
    return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get item before the item at the given index -- -ve counts from length
 *
 * Offset must be -length..length
 */
static void*
aux_prev_item(vector aux, int index)
{
  int length ;

  length = vector_length(aux) ;

  if (index < 0)
    index += length ;

  if ((index > 0) && (index <= length))
    return vector_get_item(aux, index - 1) ;
  else
    return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Insert item at given offset in the aux list.
 *
 * Item(s) at and beyond the given offset (if any) move along the list.
 *
 *   0 => at start
 *  -1 => at end
 *
 * Offset must be -1..length
 */
static void
aux_insert(vector aux, int index, void* item)
{
  if (index >= 0)
    assert((uint)index <= vector_length(aux)) ;
  else
    index = vector_length(aux) ;

  vector_insert_item(aux, index, item) ;
} ;

/*------------------------------------------------------------------------------
 * Find given item in the aux list and remove it.
 *
 * Shortens the list by 1 !
 */
static void
aux_delete(vector aux, void* item)
{
  int index ;

  index = aux_find(aux, item) ;

  if (index < 0)
    test_assert(index >= 0, "aux_delete: item not found !") ;
  else
    vector_delete_item(aux, index) ;
} ;

/*------------------------------------------------------------------------------
 * Push item onto front of list.
 */
static void
aux_push_head(vector aux, void* item)
{
  vector_unshift_item(aux, item) ;      /* opposite sense to vector !   */
} ;

/*------------------------------------------------------------------------------
 * Pop item from front of list -- returns NULL if list is empty.
 */
static void*
aux_pop_head(vector aux)
{
  return vector_shift_item(aux) ;       /* opposite sense to vector !   */
} ;

/*------------------------------------------------------------------------------
 * Append item to end of list.
 */
static void
aux_push_tail(vector aux, void* item)
{
  vector_push_item(aux, item) ;         /* opposite sense to vector !   */
} ;

/*------------------------------------------------------------------------------
 * Remove item from end of list -- returns NULL if list is empty.
 */
static void*
aux_pop_tail(vector aux)
{
  return vector_pop_item(aux) ;         /* opposite sense to vector !   */
} ;

/*------------------------------------------------------------------------------
 * Find index of item -- returns -1 if not found.
 */
static int
aux_find(vector aux, void* item)
{
  int i, l ;

  l = aux_length(aux) ;

  for (i = 0 ; i < l ; ++i)
    if (aux_item(aux, i) == item)
      return i ;

  return -1 ;
} ;
