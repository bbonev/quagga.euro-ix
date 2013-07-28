#include "misc.h"
#include <stdio.h>
#include "qlib_init.h"
#include "command.h"

#include "heap.h"

/*==============================================================================
 * Heap torture tests
 *
 */

/*------------------------------------------------------------------------------
 * Assertion and error handling
 */
static uint fail_count = 0 ;
static uint fail_limit = 0 ;

#define test_assert(assertion, message) \
  do { if (!(assertion)) \
         test_fail(__func__, __LINE__, #assertion, message) ; } while (0)

static void
test_fail(const char* func, uint line, const char* assertion,
                                       const char* message)
{
  ++fail_count ;

  fprintf(stderr, "***%4d: %s: %s() line %u assert(%s)\n",
                                   fail_count, message, func, line, assertion) ;

  if (fail_count == fail_limit)
    {
      fprintf(stderr, "*** hit failure limit\n") ;
      exit(1) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Test properties
 */

typedef char str[17] ;

struct heap_item_an     /* no back link, uint value             */
{
  char  gash1[21] ;

  uint  val ;

  char  gash2[17] ;
} ;

struct heap_item_bn     /* back link @ 0, uint value            */
{
  heap_backlink_t backlink ;

  char  gash1[21] ;

  uint  val ;

  char  gash2[17] ;
} ;

struct heap_item_cn     /* back link @ > 0, uint value          */
{
  char  gash1[9] ;

  heap_backlink_t backlink ;

  char  gash2[11] ;

  uint  val ;

  char  gash3[13] ;
} ;

struct heap_item_as     /* no back link, string value           */
{
  char  gash1[21] ;

  str   val ;

  char  gash2[17] ;
} ;

struct heap_item_bs     /* back link @ 0, string value          */
{
  heap_backlink_t backlink ;

  char  gash1[21] ;

  str   val ;

  char  gash2[17] ;
} ;

struct heap_item_cs     /* back link @ > 0, string value        */
{
  char  gash1[9] ;

  heap_backlink_t backlink ;

  char  gash2[11] ;

  str   val ;

  char  gash3[13] ;
} ;

typedef struct heap_item_an  heap_item_an_t ;
typedef struct heap_item_bn  heap_item_bn_t ;
typedef struct heap_item_cn  heap_item_cn_t ;
typedef struct heap_item_as  heap_item_as_t ;
typedef struct heap_item_bs  heap_item_bs_t ;
typedef struct heap_item_cs  heap_item_cs_t ;

typedef struct test_item  test_item_t ;
typedef struct test_item* test_item ;

struct test_item
{
  union
  {
    heap_item_an_t an ;
    heap_item_bn_t bn ;
    heap_item_cn_t cn ;
    heap_item_as_t as ;
    heap_item_bs_t bs ;
    heap_item_cs_t cs ;
  } it ;

  test_item     free ;

  test_item     self ;
  uint          index ;

  bool          in_heap ;
  bool          seen ;
} ;

typedef struct heap_item_an* heap_item_an ;
typedef struct heap_item_bn* heap_item_bn ;
typedef struct heap_item_cn* heap_item_cn ;
typedef struct heap_item_as* heap_item_as ;
typedef struct heap_item_bs* heap_item_bs ;
typedef struct heap_item_cs* heap_item_cs ;

typedef const struct heap_item_an* heap_item_an_c ;
typedef const struct heap_item_bn* heap_item_bn_c ;
typedef const struct heap_item_cn* heap_item_cn_c ;
typedef const struct heap_item_as* heap_item_as_c ;
typedef const struct heap_item_bs* heap_item_bs_c ;
typedef const struct heap_item_cs* heap_item_cs_c ;

static int uint_cmp(const uint* p_a, const uint* p_b) ;
static int str_cmp(const char* a, const char* b) ;

typedef int cmp(const void* a, const void* b) ;

static void uint_rnd(uint* p_v) ;
static void str_rnd(char* p_v) ;

typedef void rnd(const void* p_v) ;

static int heap_cmp_an(const heap_item_an_c* a, const heap_item_an_c* b) ;
static int heap_cmp_bn(const heap_item_bn_c* a, const heap_item_bn_c* b) ;
static int heap_cmp_cn(const heap_item_cn_c* a, const heap_item_cn_c* b) ;
static int heap_cmp_as(const heap_item_as_c* a, const heap_item_as_c* b) ;
static int heap_cmp_bs(const heap_item_bs_c* a, const heap_item_bs_c* b) ;
static int heap_cmp_cs(const heap_item_cs_c* a, const heap_item_cs_c* b) ;

static uint* val_an(heap_item_an item) ;
static uint* val_bn(heap_item_bn item) ;
static uint* val_cn(heap_item_cn item) ;
static char* val_as(heap_item_as item) ;
static char* val_bs(heap_item_bs item) ;
static char* val_cs(heap_item_cs item) ;

typedef void* p_val(void* item) ;

static heap_backlink_t* bl_bn(heap_item_bn item) ;
static heap_backlink_t* bl_cn(heap_item_cn item) ;
static heap_backlink_t* bl_bs(heap_item_bs item) ;
static heap_backlink_t* bl_cs(heap_item_cs item) ;

typedef struct heap_test  heap_test_t ;
typedef struct heap_test* heap_test ;

struct heap_test
{
  const char* name ;

  heap_cmp*      hcmp ;
  heap_backlink* bl ;

  p_val*      p_val ;
  cmp*        vcmp ;
  rnd*        rnd ;
} ;

/*------------------------------------------------------------------------------
 * The descriptions for all the tests
 */
static heap_test_t heap_tests[] =
{
    { .name            = "an: no backlink, uint value",

      .hcmp            = (heap_cmp*)heap_cmp_an,
      .bl              = NULL,

      .p_val           = (p_val*)val_an,
      .vcmp            = (cmp*)uint_cmp,
      .rnd             = (rnd*)uint_rnd,
    },

    { .name            = "bn: backlink == 0, uint value",

      .hcmp            = (heap_cmp*)heap_cmp_bn,
      .bl              = (heap_backlink*)bl_bn,

      .p_val           = (p_val*)val_bn,
      .vcmp            = (cmp*)uint_cmp,
      .rnd             = (rnd*)uint_rnd,
    },

    { .name            = "cn: backlink != 0, uint value",

      .hcmp            = (heap_cmp*)heap_cmp_cn,
      .bl              = (heap_backlink*)bl_cn,

      .p_val           = (p_val*)val_cn,
      .vcmp            = (cmp*)uint_cmp,
      .rnd             = (rnd*)uint_rnd,
    },

    { .name            = "as: no backlink, string value",

      .hcmp            = (heap_cmp*)heap_cmp_as,
      .bl              = NULL,

      .p_val           = (p_val*)val_as,
      .vcmp            = (cmp*)str_cmp,
      .rnd             = (rnd*)str_rnd,
    },

    { .name            = "bs: backlink == 0, string value",

      .hcmp            = (heap_cmp*)heap_cmp_bs,
      .bl              = (heap_backlink*)bl_bs,

      .p_val           = (p_val*)val_bs,
      .vcmp            = (cmp*)str_cmp,
      .rnd             = (rnd*)str_rnd,
    },

    { .name            = "cs: backlink != 0, string value",

      .hcmp            = (heap_cmp*)heap_cmp_cs,
      .bl              = (heap_backlink*)bl_cs,

      .p_val           = (p_val*)val_cs,
      .vcmp            = (cmp*)str_cmp,
      .rnd             = (rnd*)str_rnd,
    },

    { .name = NULL,     /* End marker */        },
};

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_heap_init(void) ;
static void test_heap(heap_test test, uint count) ;

static void init_test_items(void) ;
static void reset_test_items(void) ;
static void destroy_test_items(void) ;

static void verify_heap(heap_test test, heap h) ;

static void* get_test_item(heap_test test) ;
static void free_test_item(test_item item) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
  uint i ;

  qlib_init_first_stage(0);     /* Absolutely first     */
  host_init(argv[0]) ;

  fail_count  = 0 ;             /* make sure            */
  fail_limit  = 50 ;

  srand(314159265) ;            /* reproducible         */

  test_heap_init() ;

  init_test_items() ;

  i = 0 ;
  while (1)
    {
      heap_test test ;

      test = &(heap_tests[i]) ;

      if (test->name == NULL)
        break ;

      reset_test_items() ;
      test_heap(test, 50000) ;

      ++i ;
    } ;

  destroy_test_items() ;

  host_finish() ;
  qexit(0, true /* mem_stats */) ;
}

/*------------------------------------------------------------------------------
 * A few quick tests to check that heap creation and destruction works as
 * expected.
 */
static void
test_heap_init(void)
{
  heap   h ;
  void*  b ;
  uint   failures ;

  failures = fail_count ;

  fprintf(stdout, "test_heap_init") ;
  fflush(stdout) ;

  /* Start with simple creation of an empty heap
   */
  h = NULL ;
  h = heap_init_new(h, 0, (heap_cmp*)12345678, (heap_backlink*)87654321) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)12345678, "failed to init heap cmp") ;
  test_assert(h->bl  == (heap_backlink*)87654321, "failed to init heap bl") ;

  test_assert(h->v->p_items == NULL, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit == 0, "failed to init heap vector") ;

  /* Overwrite the heap object with rubbish, and then init_new() again
   */
  memset(h, 0xA5, sizeof(*h)) ;

  h = heap_init_new(h, 0, (heap_cmp*)12345678, (heap_backlink*)87654321) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)12345678, "failed to init heap cmp") ;
  test_assert(h->bl  == (heap_backlink*)87654321, "failed to init heap bl") ;

  test_assert(h->v->p_items == NULL, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit == 0, "failed to init heap vector") ;

  /* Discard what we have so far
   */
  h = heap_reset(h, free_it) ;
  test_assert(h == NULL, "failed to reset heap") ;

  /* Make a heap with at least one entry in the related vector
   */
  h = heap_init_new(h, 1, (heap_cmp*)23456789, (heap_backlink*)0) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)23456789, "failed to init heap cmp") ;
  test_assert(h->bl  == (heap_backlink*)0, "failed to init heap bl") ;

  test_assert(h->v->p_items != NULL, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit >= 1, "failed to init heap vector") ;

  /* Overwrite the heap object with rubbish, and then init_new() again
   * with at least one item in the heap.
   */
  b = h->v->p_items ;

  memset(h, 0xA5, sizeof(*h)) ;

  h = heap_init_new(h, 1, (heap_cmp*)34567890, (heap_backlink*)9876543) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)34567890, "failed to init heap cmp") ;
  test_assert(h->bl  == (heap_backlink*)9876543, "failed to init heap bl") ;

  test_assert(h->v->p_items != NULL, "failed to init heap vector") ;
  test_assert(h->v->p_items != b, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit >= 0, "failed to init heap vector") ;

  XFREE(MTYPE_VECTOR_BODY, b) ;

  /* Discard again
   */
  h = heap_reset(h, free_it) ;
  test_assert(h == NULL, "failed to reset heap") ;

  /* Re_init with a NULL is the same as create.
   */
  h = heap_re_init(h, 12, (heap_cmp*)45678901, (heap_backlink*)1987654) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)45678901, "failed to init heap cmp") ;
  test_assert(h->bl  == (heap_backlink*)1987654, "failed to init heap bl") ;

  test_assert(h->v->p_items != NULL, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit >= 12, "failed to init heap vector") ;

  /* Re_init keeps, but empties the vector.
   */
  h->v->end = 9 ;
  b = h->v->p_items ;

  h = heap_re_init(h, 12, (heap_cmp*)56789012, (heap_backlink*)12987654) ;

  test_assert(h != NULL, "failed to create heap") ;
  test_assert(h->cmp == (heap_cmp*)56789012, "failed to init heap cmp") ;
  test_assert(h->bl == (heap_backlink*)12987654, "failed to init heap bl") ;

  test_assert(h->v->p_items == b, "failed to init heap vector") ;
  test_assert(h->v->end == 0, "failed to init heap vector") ;
  test_assert(h->v->limit >= 12, "failed to init heap vector") ;

  /* Tidy up
   */
  h = heap_reset(h, free_it) ;
  test_assert(h == NULL, "failed to reset heap") ;

  if (failures == fail_count)
    fprintf(stdout, " -- OK\n") ;
  else
    fprintf(stdout, " *** %d faulures\n", fail_count - failures) ;

  fflush(stdout) ;
} ;

/*------------------------------------------------------------------------------
 * The main test functions
 */
static void test_heap_push_item(heap_test test, heap h) ;
static void test_heap_pop_item(heap_test test, heap h) ;
static void test_heap_pop_push_item(heap_test test, heap h) ;
static void test_heap_delete_item(heap_test test, heap h) ;
static void test_heap_update_top_item(heap_test test, heap h) ;
static void test_heap_update_item(heap_test test, heap h) ;
static void test_heap_pop_vector(heap_test test, heap h) ;

/*------------------------------------------------------------------------------
 * Bash a heap about the head.
 *
 * Will, more or less at random:
 *
 *    * heap_push_item() and heap_push_vector()
 *
 *    * heap_pop_item() and heap_top_item()
 *
 *    * heap_pop_push_item()
 *
 *    * heap_delete_item()
 *
 *    * heap_update_top_item()
 *
 *    * heap_update_item()
 *
 *    * heap_push_vector()
 *
 *    * heap_pop_vector()
 *
 * That is: exercise all the heap operations !
 *
 * When has cycled for long enough, reams out and discards the heap.
 */
static void
test_heap(heap_test test, uint count)
{
  heap      h ;
  test_item item ;
  uint      failures ;
  uint      mark_when ;
  uint      mark_count ;

  failures = fail_count ;

  fprintf(stdout, "test_heap: %s -- %u", test->name, count) ;
  fflush(stdout) ;

  h = heap_init_new(NULL, 0, test->hcmp, test->bl) ;

  verify_heap(test, h) ;

  test_heap_pop_item(test, h) ;         /* pop of empty heap !          */
  verify_heap(test, h) ;

  test_heap_pop_push_item(test, h) ;    /* pop_push of empty heap !     */
  verify_heap(test, h) ;

  mark_when  = count / 20 ;
  mark_count = 0 ;

  while (count-- > 0)
    {
      uint t ;

      ++mark_count ;

      if (mark_count == mark_when)
        {
          fprintf(stdout, ".") ;
          fflush(stdout) ;
          mark_count = 0 ;
        } ;

      switch (t = rand() % 14)
        {
          case 0:               /* 5/n chance of push           */
          case 1:               /* cf 2/n chance of pop and     */
          case 2:               /*    2/n chance of delete      */
          case 3:
          case 4:
            /* We want to keep a pretty big heap, so pump it up quite a bit
             * if we don't have 1000 items in the heap.
             */
            if (true && (h->v->end < 1000))
              {
                uint n, i ;
                vector a ;
                bool move ;

                if ((rand() % 6) == 0)
                  n = 0 ;
                else
                  n = (rand() % 100) + 100 ;

                a = vector_init_new(NULL, n) ;

                for (i = 0 ; i < n ; ++i)
                  vector_push_item(a, get_test_item(test)) ;

                move = (rand() % 2) ;
                heap_push_vector(h, a, move) ;

                if (move)
                  test_assert(vector_length(a) == 0, "did not move vector") ;
                else
                  test_assert(vector_length(a) == n, "did not retain vector") ;

                vector_reset(a, free_it) ;

                verify_heap(test, h) ;
              } ;

            test_heap_push_item(test, h) ;
            break ;

          case 5:               /* 3/n chance of pop            */
          case 6:
          case 7:
            /* Occasionally, we empty out the heap.
             */
            if ((rand() % 10) == 0)
              {
                while ((item = heap_top_item(h)) != NULL)
                  {
                    test_heap_pop_item(test, h) ;
                    verify_heap(test, h) ;
                  } ;
              } ;

            test_heap_pop_item(test, h) ;
            break ;

          case 8:               /* 1/n chance of pop_push       */
            test_heap_pop_push_item(test, h) ;
            break ;

          case 9:               /* 2/n chance of delete         */
          case 10:
            /* Occasionally, we empty out the heap.
             */
            if ((rand() % 10) == 0)
              {
                while ((item = heap_top_item(h)) != NULL)
                  {
                    test_heap_delete_item(test, h) ;
                    verify_heap(test, h) ;
                  } ;
              } ;

            test_heap_delete_item(test, h) ;
            break ;

          case 11:              /* 1/n chance of update top     */
            test_heap_update_top_item(test, h) ;
            break ;

          case 12:              /* 1/n chance of update         */
            test_heap_update_item(test, h) ;
            break ;

          case 13:              /* 1/n chance of pop            */
            test_heap_pop_vector(test, h) ;
            break ;

          default:
            assert(false) ;
        } ;

      verify_heap(test, h) ;
    } ;

  while ((item = heap_ream(h, keep_it)) != NULL)
    {
      test_assert(item->in_heap, "heap_ream() returned item not in heap !") ;
      free_test_item(item) ;
    } ;

  verify_heap(test, h) ;

  item = heap_ream(h, free_it) ;
  test_assert(item == NULL, "failed to ream") ;

  if (failures == fail_count)
    fprintf(stdout, " -- OK\n") ;
  else
    fprintf(stdout, " *** %d faulures\n", fail_count - failures) ;

  fflush(stdout) ;
} ;

/*------------------------------------------------------------------------------
 * Push new random item onto the heap
 */
static void
test_heap_push_item(heap_test test, heap h)
{
  test_item item ;

  item = get_test_item(test) ;          /* item marked as being in heap */

  heap_push_item(h, item) ;
} ;

/*------------------------------------------------------------------------------
 * Pop item off the heap -- if any -- also tests heap_top_item()
 */
static void
test_heap_pop_item(heap_test test, heap h)
{
  test_item expect ;
  test_item get ;

  expect = heap_top_item(h) ;

  if (expect != NULL)
    {
      test_assert(expect == expect->self, "invalid item") ;
      test_assert(expect->in_heap, "heap_top_item() not in heap !") ;
      test_assert(expect == h->v->p_items[0], "heap_top_item() is not top !") ;
    } ;

  get = heap_pop_item(h) ;

  test_assert(get == expect, "heap_pop_item() != heap_top_item() !") ;

  if (get != NULL)
    {
      test_assert(get->in_heap, "heap_pop_item() returned item not in heap !") ;
      free_test_item(get) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Pop and then push new random item
 */
static void
test_heap_pop_push_item(heap_test test, heap h)
{
  test_item expect ;
  test_item get ;
  test_item item ;

  expect = heap_top_item(h) ;

  if (expect != NULL)
    {
      test_assert(expect == expect->self, "invalid item") ;
      test_assert(expect->in_heap, "heap_top_item() not in heap !") ;
      test_assert(expect == h->v->p_items[0], "heap_top_item() is not top !") ;
    } ;

  item = get_test_item(test) ;          /* item marked as being in heap */

  get = heap_pop_push_item(h, item) ;

  test_assert(get == expect, "heap_pop_push_item() != heap_top_item() !") ;

  if (get != NULL)
    {
      test_assert(get->in_heap,
                          "heap_pop_push_item() returned item not in heap !") ;
      free_test_item(get) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * If heap is not empty, delete a random item
 *
 * Occasionally choose first or last item.
 */
static void
test_heap_delete_item(heap_test test, heap h)
{
  test_item item ;
  uint      i ;

  if (heap_top_item(h) == NULL)
    return ;

  switch (rand() % 6)
    {
      case 0:
        i = 0 ;
        break ;

      case 1:
        i = h->v->end - 1 ;
        break ;

      default:
        i = rand() % h->v->end ;
        break ;
    } ;

  item = h->v->p_items[i] ;
  test_assert(item == item->self, "invalid item") ;
  test_assert(item->in_heap, "item not in heap !") ;

  heap_delete_item(h, item) ;

  free_test_item(item) ;
} ;

/*------------------------------------------------------------------------------
 * If heap is not empty, change the top item
 *
 * Occasionally make no change at all to ensure test the "no move" case.
 */
static void
test_heap_update_top_item(heap_test test, heap h)
{
  test_item item ;

  item = heap_top_item(h) ;

  if (item == NULL)
    return ;

  test_assert(item == item->self, "invalid item") ;
  test_assert(item->in_heap, "item not in heap !") ;

  if ((rand() % 5) != 0)
    test->rnd(test->p_val(item)) ;

  heap_update_top_item(h) ;
} ;

/*------------------------------------------------------------------------------
 * If heap is not empty, change a random item
 *
 * Occasionally choose first or last item.
 *
 * Occasionally make no change at all to ensure test the "no move" case.
 */
static void
test_heap_update_item(heap_test test, heap h)
{
  test_item item ;
  uint      i ;

  if (heap_top_item(h) == NULL)
    return ;

  switch (rand() % 6)
    {
      case 0:
        i = 0 ;
        break ;

      case 1:
        i = h->v->end - 1 ;
        break ;

      default:
        i = rand() % h->v->end ;
        break ;
    } ;

  item = h->v->p_items[i] ;
  test_assert(item == item->self, "invalid item") ;
  test_assert(item->in_heap, "item not in heap !") ;

  if ((rand() % 5) != 0)
    test->rnd(test->p_val(item)) ;

  heap_update_item(h, item) ;
} ;

/*------------------------------------------------------------------------------
 * Pop entire contents of heap into vector.
 *
 * Occasionally empty the heap !
 *
 * Sometimes pop to existing vector, sometimes not.
 */
static void
test_heap_pop_vector(heap_test test, heap h)
{
  test_item item ;
  vector    p ;
  uint      i, n ;
  bool      move ;

  move = (rand() % 6) == 0 ;

  switch (rand() % 3)
    {
      case 0:
        p = NULL ;
        break ;

      case 1:
        p = vector_init_new(NULL, 0) ;
        break ;

      case 2:
        p = vector_init_new(NULL, (rand() % 25) + 25) ;
        break ;

      default:
        assert(false) ;
    } ;

  n = vector_length(h->v) ;

  p = heap_pop_vector(p, h, move) ;

  test_assert(n == vector_length(p), "popped vector not the same size") ;

  if (move)
    test_assert(vector_length(h->v) == 0, "popped 'move': heap not empty") ;
  else
    test_assert(vector_length(h->v) == n, "popped 'move': heap changed size") ;

  item = NULL ;
  for (i = 0 ; i < n ; ++i)
    {
      test_item prev ;

      prev = item ;

      item = vector_get_item(p, i) ;

      test_assert(item == item->self, "invalid item") ;
      test_assert(item->in_heap, "popped item not in heap") ;

      if (prev != NULL)
        {
          test_assert(test->vcmp(test->p_val(prev), test->p_val(item)) <= 0,
                                              "popped items are not in order") ;
          if (move)
            free_test_item(prev) ;
        } ;

      prev = item ;
    } ;

  if (move)
    {
      if (item != NULL)
        free_test_item(item) ;

      vector_re_init(p, (rand() % 3) * 10) ;

      p = heap_pop_vector(p, h, rand() & 1) ;

      test_assert(vector_length(p) == 0, "popped empty heap, not empty") ;
    } ;

  vector_reset(p, free_it) ;
} ;


/*==============================================================================
 * Handling of test items and the basic heap verification
 */
static char munge ;

static vector items ;

static test_item free_items ;

/*------------------------------------------------------------------------------
 * Initialise store of items for test
 */
static void
init_test_items(void)
{
  items = vector_init_new(NULL, 100) ;

  free_items = NULL ;

  munge = 77 ;
} ;

/*------------------------------------------------------------------------------
 * Place everything in the items vector on the free list
 */
static void
reset_test_items(void)
{
  uint i ;

  free_items = NULL ;

  for (i = 0 ; i < vector_length(items) ; ++i)
    {
      test_item item ;

      item = vector_get_item(items, i) ;

      assert(i == item->index) ;
      free_test_item(item) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Initialise store of items for test
 */
static void
destroy_test_items(void)
{
  test_item item ;

  while ((item = vector_ream(items, free_it)) != NULL)
    XFREE(MTYPE_TMP, item) ;

  items      = NULL ;
  free_items = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get a new item to be added to heap.
 *
 * Set a random value, set a gash backlink (if any), mark as in the heap.
 */
static void*
get_test_item(heap_test test)
{
  test_item item ;

  item = free_items ;

  if (item != NULL)
    {
      free_items = item->free ;
      item->free = NULL ;
    }
  else
    {
      item = XMALLOC(MTYPE_TMP, sizeof(*item)) ;

      do
        munge += 0xA5 ;
      while (munge == 0) ;

      memset(item, munge, sizeof(*item)) ;

      item->free    = NULL ;
      item->self    = item ;
      item->index   = vector_length(items) ;

      vector_push_item(items, item) ;
    } ;

  assert(item == vector_get_item(items, item->index)) ;
  assert(item == item->self) ;

  if (test->bl != NULL)
    *(test->bl(item)) = 0xA5A5A5A5 ;

  test->rnd(test->p_val(item)) ;

  item->in_heap = true ;
  item->seen    = false ;

  confirm(offsetof(test_item_t, it) == 0) ;

  return &(item->it) ;
} ;

/*------------------------------------------------------------------------------
 * Release item and put on the free list.
 *
 * NB: does not test the in_heap state -- but does clear it.
 */
static void
free_test_item(test_item item)
{
  assert(item != NULL) ;
  assert(item == item->self) ;
  assert(item == vector_get_item(items, item->index)) ;

  item->in_heap = false ;
  item->seen    = false ;

  item->free = free_items ;
  free_items = item ;
} ;

/*------------------------------------------------------------------------------
 * Verify the contents of the heap, checking that everything we think should
 * be in the heap, is in the heap.
 */
static void
verify_heap(heap_test test, heap h)
{
  vector v ;
  vector_index_t  i ;
  vector_length_t e ;
  test_item item ;

  /* Troll through and reset the seen flag
   */
  for (i = 0 ; i < vector_length(items) ; ++i)
    {
      item = vector_get_item(items, i) ;

      assert(i    == item->index) ;
      assert(item == item->self) ;

      item->seen = false ;
    } ;

  /* Now walk the heap to check what's there and that the heap discipline has
   * been maintained.
   */
  v = h->v ;
  e = vector_end(v) ;
  for (i = 0 ; i < e ; ++i)
    {
      item = vector_get_item(v, i) ;

      if (item == NULL)
        {
          test_assert(item != NULL, "NULL item in heap ??") ;
          continue ;
        }

      test_assert(item == item->self, "unknown item in heap ??") ;
      test_assert(item == vector_get_item(items, item->index),
                                          "broken index for item in heap ??") ;
      test_assert(!item->seen, "item seen twice in heap") ;
      test_assert(item->in_heap, "item not supposed to be in the heap") ;

      item->seen = true ;

      if (test->bl != NULL)
        test_assert(*(test->bl(item)) == i, "backlink broken") ;

      if (i != 0)
        {
          test_item parent ;

          parent = vector_get_item(v, (i - 1) / 2) ;

          test_assert(test->vcmp(test->p_val(parent), test->p_val(item)) <= 0,
                                                     "heap discipline broken") ;
        } ;
    } ;

  /* Make sure that if is supposed to be in the heap, we have seen it, and
   * vice versa.
   */
  for (i = 0 ; i < vector_length(items) ; ++i)
    {
      item = vector_get_item(items, i) ;

      if (item->in_heap)
        test_assert(item->seen, "item which should be in heap is not") ;
      else
        test_assert(!item->seen, "item which is in heap should not be") ;

      item->seen = false ;
    } ;
} ;

/*==============================================================================
 * The item mangling.
 */

/*------------------------------------------------------------------------------
 * Compare uint values
 */
static int
uint_cmp(const uint* p_a, const uint* p_b)
{
  if (*p_a < *p_b)
    return -1 ;
  if (*p_a > *p_b)
    return + 1 ;
  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Compare string values
 */
static int
str_cmp(const char* p_a, const char* p_b)
{
  return strcmp(p_a, p_b) ;
} ;

/*------------------------------------------------------------------------------
 * Random uint value
 */
static void
uint_rnd(uint* p_v)
{
  *p_v = rand() ;
} ;

/*------------------------------------------------------------------------------
 * Random string value
 */
static void
str_rnd(char* p_v)
{
  sprintf(p_v, "%x", rand()) ;
} ;

/*------------------------------------------------------------------------------
 * Heap Comparison functions
 */
static int
heap_cmp_an(const heap_item_an_c* a, const heap_item_an_c* b)
{
  return uint_cmp(&((*a)->val), &((*b)->val)) ;
} ;

static int
heap_cmp_bn(const heap_item_bn_c* a, const heap_item_bn_c* b)
{
  return uint_cmp(&((*a)->val), &((*b)->val)) ;
} ;

static int
heap_cmp_cn(const heap_item_cn_c* a, const heap_item_cn_c* b)
{
  return uint_cmp(&((*a)->val), &((*b)->val)) ;
} ;

static int
heap_cmp_as(const heap_item_as_c* a, const heap_item_as_c* b)
{
  return str_cmp((*a)->val, (*b)->val) ;
} ;

static int
heap_cmp_bs(const heap_item_bs_c* a, const heap_item_bs_c* b)
{
  return str_cmp((*a)->val, (*b)->val) ;
} ;

static int
heap_cmp_cs(const heap_item_cs_c* a, const heap_item_cs_c* b)
{
  return str_cmp((*a)->val, (*b)->val) ;
} ;

/*------------------------------------------------------------------------------
 * Return pointer to value
 */
static uint*
val_an(heap_item_an item)
{
  return &(item->val) ;
} ;

static uint*
val_bn(heap_item_bn item)
{
  return &(item->val) ;
} ;

static uint*
val_cn(heap_item_cn item)
{
  return &(item->val) ;
} ;

static char*
val_as(heap_item_as item)
{
  return item->val ;
} ;

static char*
val_bs(heap_item_bs item)
{
  return item->val ;
} ;

static char*
val_cs(heap_item_cs item)
{
  return item->val ;
} ;

/*------------------------------------------------------------------------------
 * Return address of backlink
 */
static heap_backlink_t*
bl_bn(heap_item_bn item)
{
  return &(item->backlink) ;
} ;

static heap_backlink_t*
bl_cn(heap_item_cn item)
{
  return &(item->backlink) ;
} ;

static heap_backlink_t*
bl_bs(heap_item_bs item)
{
  return &(item->backlink) ;
} ;

static heap_backlink_t*
bl_cs(heap_item_cs item)
{
  return &(item->backlink) ;
} ;




