/*==============================================================================
 * AVL Tree torture tests
 *
 */
#include "misc.h"

#include <stdio.h>

#include "avl.h"
#include "qlib_init.h"
#include "thread.h"
#include "command.h"

#define MCHECK_H

#ifdef MCHECK_H
#include <mcheck.h>
#endif

/*==============================================================================
 * lib/avl.c torture tests
 */
extern void next_test(void) ;

static uint test_count = 0 ;
static uint test_stop  = 0 ;

static uint fail_count = 0 ;
static uint fail_limit = 50 ;

static uint srand_seed = 314159265 ;

extern void
next_test(void)
{
  test_count++ ;

  if (test_count == test_stop)
    {
      fprintf(stderr, "\n+++ STOP at test %u...\n", test_count) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Assertion and error handling
 *
 * Returns: true <=> the assertion is true
 */
#define test_assert(assertion, ...) \
  ((assertion) ? true \
               : test_fail(__func__, __LINE__, #assertion, __VA_ARGS__))

static bool test_fail(const char* func, uint line, const char* assertion,
                               const char* format, ...) PRINTF_ATTRIBUTE(4, 5) ;

static bool
test_fail(const char* func, uint line, const char* assertion,
                                       const char* format, ...)
{
  va_list va;

  ++fail_count ;

  fprintf(stderr, "\n***%4d(%4d): %s() line %u assert(%s): ",
                                fail_count, test_count, func, line, assertion) ;
  va_start (va, format);
  vfprintf(stderr, format, va);
  va_end (va);

  if (fail_count == fail_limit)
    {
      fprintf(stderr, "\n*** hit failure limit\n") ;
      assert(false) ;
    } ;

  return false ;
} ;

/*==============================================================================
 * prototypes
 */

typedef enum
{
  forwards,
  backwards,
  random_order,
} order_t ;

static void test_avl_init(void) ;
static void test_avl_tree_new(void) ;
static void test_avl_tree_lookup(const uint len, const order_t how,
                                                 const uint seed) ;
static void test_avl_tree_delete(const uint len, const order_t how,
                                                 const uint seed) ;

static void scan_avl_tree(avl_tree tree, bool compare) ;
static void show_tree(avl_tree tree) ;
static void shuffle(uint list[], uint n, uint seed) ;

typedef enum avl_link
{
  avl_in_order,
  avl_in_reverse,
  avl_pre_order,
  avl_post_order,
  avl_level_order,
  avl_level_reverse,
} avl_link_t ;

static vector avl_tree_link(avl_tree tree, avl_link_t how, uint* p_height) ;

/*------------------------------------------------------------------------------
 * Run all tests
 */
int
main(int argc, char **argv)
{
  int i ;
  uint s ;

#ifdef MCHECK_H
  mcheck(NULL) ;
#endif

  qlib_init_first_stage(0);     /* Absolutely first     */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start AVL Tree testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  test_avl_init() ;

  test_avl_tree_new();

  test_avl_tree_lookup(75, forwards,     0) ;
  test_avl_tree_lookup(75, backwards,    0) ;
  test_avl_tree_lookup(75, random_order, 191229507) ;

  test_avl_tree_lookup(10000, forwards,     0) ;
  test_avl_tree_lookup(10000, backwards,    0) ;
  test_avl_tree_lookup(10000, random_order, 231690116) ;

  test_avl_tree_delete(75, forwards, 39219284) ;

  s = 39219283 ;
  for (i = 1 ; i <= 2000 ; ++i)
    {
      s *= 1234567 ;
      test_avl_tree_delete(10000, forwards, s) ;
    } ;

  return 0;
}

/*==============================================================================
 * Data structures and related functions
 */

/* The test avl_item is pretty simple.
 */
typedef struct test_item  test_item_t ;
typedef struct test_item* test_item ;

struct test_item
{
  avl_node_t avl ;

  uint  val ;

  uint  visit ;

  uint  pos ;

  char  name[] ;
} ;

struct test_create
{
  bool  added ;
  uint  count ;
};


CONFIRM(offsetof(test_item_t, avl) == 0) ;

typedef char test_name_t[24] ;

static uint item_count = 0 ;   /* Keep track of items created/freed   */
static uint item_max   = 0 ;   /* Keep track of items created/freed   */
static uint item_visit = 0 ;   /* current visit number                 */

enum { max_item_count = 100 * 1000 } ;

static test_item items[max_item_count] ;
static uint order[max_item_count] ;

static struct test_create items_created ;       /* see test_avl_new()   */

/*------------------------------------------------------------------------------
 * Initialise the test item handling
 *
 */
static void
test_avl_init(void)
{
  uint i ;

  for (i = 0 ; i < max_item_count ; ++i)
    {
      items[i] = NULL ;
      order[i]  = 0 ;
    } ;

  item_count = 0 ;
  item_max   = 0 ;
  item_visit = 0 ;

  items_created.count = 0 ; ;
  items_created.added = false ; ;
} ;

/*------------------------------------------------------------------------------
 * Set an ordering
 */
static char*
test_avl_set_order(uint len, order_t how, uint seed)
{
  uint i ;
  char* desc ;

  assert(len <= max_item_count) ;

  if (seed != 0)
    srand(seed) ;

  for (i = 0 ; i < len ; ++i)
    if (how == forwards)
      order[i] = i ;            /* forwards             */
    else
      order[i] = len - i - 1 ;  /* backwards or random  */

  if (how == random_order)
    shuffle(order, len, 0) ;

  desc = calloc(1, 60) ;
  switch (how)
    {
      case forwards:
        snprintf(desc, 60, "%d forwards", len) ;
        break ;

      case backwards:
        snprintf(desc, 60, "%d backards", len) ;
        break ;

      case random_order:
        snprintf(desc, 60, "%d random(%d)", len, seed) ;
        break ;
    } ;

  return desc ;
} ;

/*------------------------------------------------------------------------------
 * Shuffle array of uints
 */
static void
shuffle(uint list[], uint n, uint seed)
{
  if (seed != 0)
    srand(seed) ;

  while (n > 1)
    {
      uint v ;
      uint r ;

      r = rand() % n ;

      --n ;
            v = list[r] ;
      list[r] = list[n] ;
      list[n] = v ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set item name
 */
static const char*
test_avl_set_name(test_name_t name, uint val)
{
  snprintf(name, sizeof(test_name_t), "Name:%d", val) ;
  return name ;
} ;

/*------------------------------------------------------------------------------
 * Set new test item.
 *
 * Used when avl_insert_add signals that a new item has been added -- makes
 * sure that the item should not already exist, and replaces any existing
 * item.
 */
static void
test_avl_set_item(test_item item, uint val)
{
  test_name_t  name ;

  assert(val < max_item_count) ;

  assert(items[val] == NULL) ;
  assert(strcmp(test_avl_set_name(name, val), item->name) == 0) ;

  items[val] = item ;

  item->val = val ;
  item->visit = 0 ;

  if (val > item_max)
    item_max = val ;

  ++item_count ;
} ;

/*------------------------------------------------------------------------------
 * Unset test item.
 *
 * Used when avl_insert_add signals that a new item has been added -- makes
 * sure that the item should not already exist, and replaces any existing
 * item.
 */
static void
test_avl_unset_item(test_item item)
{
  if (item != NULL)
    {
      assert(item->val < max_item_count) ;
      assert(items[item->val] == item) ;

      items[item->val] = NULL ;
      free(item) ;

      --item_count ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Unset everything -- keep tidy between tests.
 */
static void
test_avl_unset_all(void)
{
  uint i ;

  for (i = 0 ; i <= item_max ; ++i)
    test_avl_unset_item(items[i]) ;

  assert(item_count == 0) ;

  item_max   = 0 ;
  item_visit = 0 ;
} ;

/*------------------------------------------------------------------------------
 * The comparison function -- avl_cmp_func
 */
static int
test_avl_cmp(avl_key_c name, avl_item item)
{
  return strcmp_mixed(name, ((const struct test_item*)item)->name) ;
} ;

/*------------------------------------------------------------------------------
 * The item create function -- avl_new_func
 *
 * Creates a skeleton item -- enough for insertion in the tree.
 *
 * Updates the item_count.
 */
static avl_item
test_avl_new(avl_key_c name, void* arg)
{
  struct test_item*   item ;
  struct test_create* created ;

  item = calloc(1, offsetof(test_item_t, name) + strlen(name) + 1) ;
  strcpy(item->name, name) ;

  created = arg ;
  created->added  = true ;
  created->count += 1 ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * The avl_tree parameters for our test tree
 */
static const avl_tree_params_t test_avl_tree_params =
    {
      .new    = test_avl_new,
      .cmp    = test_avl_cmp,
    };

/*------------------------------------------------------------------------------
 * Test that can construct and destroy a tree.
 *
 * Test that can search an empty tree, and add a single item and find it
 * again.
 *
 * Test the combinations of lookup/lookup_add, before and after the item
 * is added.
 */
static void
test_avl_tree_new(void)
{
  uint fail_count_was, test_count_was ;

  avl_tree tree = NULL;
  test_name_t name ;
  struct test_item* item ;
  struct test_item* item2 ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: construct and destroy a trivial tree") ;

  tree = avl_tree_init_new(NULL, &test_avl_tree_params) ;
  test_assert(tree != NULL, "tree == NULL");
  assert(items_created.count == 0) ;

  /* expect to not find                                 */
  item = avl_lookup(&tree->root, NULL, name, tree->params);
  test_assert(item == NULL, "item != NULL");

  /* add                                                */
  test_avl_set_name(name, 77) ;
  items_created.added = false ; ;
  item = avl_lookup_add(&tree->root, tree->root, name, tree->params,
                                                                &items_created);
  test_assert(item != NULL, "item == NULL");
  test_assert(items_created.added, "add == false") ;
  test_assert(items_created.count == 1, "items_created.count != 1") ;

  test_avl_set_item(item, 77) ;

  assert(item_count == 1) ;

  /* find                                               */
  item2 = avl_lookup(&tree->root, tree->root, name, tree->params);
  test_assert(item2 == item, "item2 != item") ;

  items_created.added = false ;
  item2 = avl_lookup_add(&tree->root, NULL, name, tree->params, &items_created);
  test_assert(item2 == item, "item2 != item") ;
  test_assert(!items_created.added, "add == true") ;
  test_assert(items_created.count == 1, "items_created.count != 1") ;

  /* delete                                             */
  item2 = avl_delete(&tree->root, tree->root, name, tree->params) ;
  test_assert(item2 == item, "item2 != item") ;

  test_avl_unset_item(item) ;
  assert(item_count == 0) ;
  items_created.count = 0 ;

  /* delete and don't expect to find                    */
  item2 = avl_delete(&tree->root, NULL, name, tree->params) ;
  test_assert(item2 == NULL, "found non-existent item") ;

  /* tidy up and finish                                 */
  test_avl_unset_all() ;

  tree = avl_tree_reset(tree, free_it) ;
  items_created.count = 0 ;
  test_assert(tree == NULL, "tree not freed") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

#if 0
static int
test_symbol_sort(const symbol* a, const symbol* b)
{
  return symbol_mixed_name_cmp(
                 ((struct test_item*)symbol_get_item(*a))->name,
                 ((struct test_item*)symbol_get_item(*b))->name ) ;
} ;
#endif








/*------------------------------------------------------------------------------
 * Test that can construct a large tree and find things again.
 *
 * Does no deletions.
 */
static void
test_avl_tree_lookup(const uint len, const order_t how, const uint seed)
{
  avl_tree tree ;
  test_name_t name ;
  vector linked ;
  uint i, height ;

  test_item item ;

  const bool trace = false ;

  char* desc ;

  /* Set up the test and construct empty tree.                          */

  desc = test_avl_set_order(len, how, seed) ;
  printf("%s %s\n", __func__, desc) ;
  free(desc) ;

  tree = avl_tree_init_new(NULL, &test_avl_tree_params) ;
  assert(items_created.count == 0) ;

  /* add                                                                */
  for (i = 0; i < len; ++i)
    {
      uint v ;

      v = order[i] ;

      items_created.added = false ; ;
      item = avl_lookup_add(&tree->root, NULL, test_avl_set_name(name, v),
                                                 tree->params, &items_created) ;
      test_assert(item != NULL, "add: item == NULL");
      test_assert(items_created.added, "add: not added") ;

      test_avl_set_item(item, v) ;

      if (trace)
        {
          if (i == 0)
            printf("\n") ;
          printf("Step %2d: insert %03d\n", i+1, v) ;
          show_tree(tree) ;
          printf("\n") ;
        } ;
    } ;

  assert(items_created.count == len) ;

  /* try walking the entire tree -- in order                            */
  ++item_visit ;               /* new walk     */
  linked = avl_tree_link(tree, avl_in_order, &height) ;
  for (i = 0 ; i < vector_length(linked) ; ++i)
    {
      item = vector_get_item(linked, i) ;

      test_assert(item->visit != item_visit, "item seen already") ;
      test_assert(item->val == i, "item != i") ;

      item->visit = item_visit ;
    } ;
  test_assert(i == len, "i != len");

  linked = vector_free(linked) ;

  assert(items_created.count == len) ;

  /* try walking the entire tree -- depth first: post_order
   */
  ++item_visit ;               /* new walk     */
  i = 0;
  linked = avl_tree_link(tree, avl_post_order, &height) ;
  for (i = 0 ; i < vector_length(linked) ; ++i)
    {
      test_item child ;

      item = vector_get_item(linked, i) ;

      test_assert(item->visit != item_visit, "item seen already") ;
      item->visit = item_visit ;

      child = (avl_item)((avl_node)item)->child[avl_left] ;
      if (child != NULL)
        test_assert(child->visit == item_visit, "left child not seen") ;

      child = (avl_item)((avl_node)item)->child[avl_right] ;
      if (child != NULL)
        test_assert(child->visit == item_visit, "right child not seen") ;
    } ;
  test_assert(i == len, "i != len");

  linked = vector_free(linked) ;

  assert(items_created.count == len) ;

  /* See what we got                                                    */
  scan_avl_tree(tree, true) ;

  /* Tidy up                                                            */
  test_avl_unset_all() ;

  tree = avl_tree_reset(tree, free_it) ;
  items_created.count = 0 ;
  test_assert(tree == NULL, "tree not freed") ;
} ;

/*------------------------------------------------------------------------------
 * Test that can construct a large tree, find things, delete things, insert
 * things and still find them... etc.
 */
static void
test_avl_tree_delete(const uint len, const order_t how, const uint seed)
{
  avl_tree tree ;
  test_name_t name ;
  uint i, q ;

  test_item item ;

  bool trace = false ;

  char* desc ;

  /* Set up the test and construct empty tree.                          */

  desc = test_avl_set_order(len, how, seed) ;
  printf("%s %s\n", __func__, desc) ;
  free(desc) ;

  tree = avl_tree_init_new(NULL, &test_avl_tree_params) ;
  assert(items_created.count == 0) ;

  /* Fill tree for the first time                                       */
  for (i = 0; i < len; ++i)
    {
      uint v ;

      v = order[i] ;

      items_created.added = false ; ;
      item = avl_lookup_add(&tree->root, NULL, test_avl_set_name(name, v),
                                                 tree->params, &items_created) ;
      test_assert(item != NULL, "add: item == NULL");
      test_assert(items_created.added, "add: not added") ;

      test_avl_set_item(item, v) ;

      if (trace)
        {
          if (i == 0)
            printf("\n") ;
          printf("Step %2d: insert %03d\n", i+1, v) ;
          show_tree(tree) ;
          printf("\n") ;
        } ;
    } ;

  assert(items_created.count == len) ;

  scan_avl_tree(tree, true) ;

  /* Now delete 25%, 50% 75% and add back in again.
   */
  for (q = 1 ; q < 4 ; ++q)
    {
      uint n = (len * q) / 4 ;
      uint c = len ;

      shuffle(order, len, 0) ;

      for (i = 0; i < n ; ++i)
        {
          uint v ;

          v = order[i] ;

          item = avl_delete(&tree->root, tree->root, test_avl_set_name(name, v),
                                                                tree->params) ;
          test_assert(item != NULL, "delete: item == NULL");
          items_created.count -= 1 ;

          test_avl_unset_item(item) ;

          --c ;

          if (trace)
            {
              if (i == 0)
                printf("\n") ;
              printf("Step %2d: delete %03d\n", i+1, v) ;
              show_tree(tree) ;
              printf("\n") ;
            } ;
        } ;

      scan_avl_tree(tree, true) ;

      shuffle(order, n, 0) ;

      for (i = 0; i < n ; ++i)
        {
          uint v ;

          v = order[i] ;

          items_created.added = false ; ;
          item = avl_lookup_add(&tree->root, tree->root,
                     test_avl_set_name(name, v), tree->params, &items_created) ;
          test_assert(item != NULL, "add: item == NULL");
          test_assert(items_created.added, "add: not added") ;

          test_avl_set_item(item, v) ;
          ++c ;

          if (trace)
            {
              if (i == 0)
                printf("\n") ;
              printf("Step %2d: insert %03d\n", i+1, v) ;
              show_tree(tree) ;
              printf("\n") ;
            } ;
        } ;
    } ;

  /* Now delete everything.
   */
  shuffle(order, len, 0) ;

  for (i = 0; i < len ; ++i)
    {
      uint v ;

      v = order[i] ;

      item = avl_delete(&tree->root, NULL, test_avl_set_name(name, v),
                                                            tree->params) ;
      test_assert(item != NULL, "delete: item == NULL");
      items_created.count -= 1 ;

      test_avl_unset_item(item) ;

      if (trace)
        {
          if (i == 0)
            printf("\n") ;
          printf("Step %2d: delete %03d\n", i+1, v) ;
          show_tree(tree) ;
          printf("\n") ;
        } ;
    } ;

  scan_avl_tree(tree, true) ;

  /* Tidy up                                                            */
  test_avl_unset_all() ;

  tree = avl_tree_reset(tree, free_it) ;
  items_created.count = 0 ;
  test_assert(tree == NULL, "tree not freed") ;
} ;

/*==============================================================================
 * Scanning AVL tree and showing properties.
 */
static void show_histogram(uint count[], uint max, uint n, uint t) ;
static char show_bal_char(int bal) ;

/*------------------------------------------------------------------------------
 * Scan AVL tree to...
 */
static void
scan_avl_tree(avl_tree tree, bool compare)
{
  uint   n = 24 ;               /* this is still nuts   */
  uint   depth[n + 2] ;
  uint   i ;
  uint   d ;
  uint   t ;
  uint   max_d ;
  uint   tpl ;
  uint   h ;
  uint   height ;
  vector linked ;
  test_item item ;

  /* Get number of nodes and height and report same.
   *
   * Under qdebug, getting the height also checks the node balance.
   */
  linked = avl_tree_link(tree, avl_post_order, &height) ;
  t = vector_length(linked) ;

  test_assert(t == items_created.count, "got %u items, expected %u", t,
                                                          items_created.count) ;
  printf("AVL Tree %'d entries:", t) ;

  /* Do a depth first walk to establish the depth of each and every node,
   * and report on the distribution etc. of node depths.
   */
  for (d = 0 ; d < (n + 2) ; ++d)
    depth[d] = 0 ;

  max_d = 0 ;
  tpl   = 0 ;

  for (i = 0 ; i < t ; ++i)
    {
      item = vector_get_item(linked, i) ;

      d = ((avl_node)item)->level + 1 ;

      if (d <= n)
        ++depth[d] ;
      else
        ++depth[n+1] ;

      if (d > max_d)
        max_d = d ;

      tpl += d ;
    } ;

  h = avl_get_height(tree->root) ;

  assert(i == t);
  test_assert(max_d == h, "max depth and heigh mismatch") ;

  printf(" max depth: %d  av. path length %3.1f\n", max_d,
                             tpl != 0 ? (double)tpl / (double)t : (double)tpl) ;

  test_assert(max_d <= n, "maximum depth is BROKEN\n") ;

  if (t != 0)
    show_histogram(depth, max_d, n, t) ;

  /* For comparison, show distribution of a perfect tree -- if required.
   */
  if (compare && (t != 0))
    {
      for (d = 0 ; d < (n + 2) ; ++d)
        depth[d] = 0 ;

      i     = t ;
      d     = 1 ;
      max_d = 1 ;
      tpl   = 0 ;
      while (i != 0)
        {
          if (i < d)
            d = i ;

          depth[max_d] = d ;
          tpl += max_d * d ;

          i -= d ;

          if (i != 0)
            {
              ++max_d ;
              d += d ;
            } ;
        } ;

      printf("Perfect balance max depth: %d  av. path length %3.1f\n", max_d,
                                                      (double)tpl / (double)t) ;

      show_histogram(depth, max_d, n, t) ;
    } ;

  /* If small enough -- show the entire tree
   */
  if ((t != 0) && (t < 100))
    show_tree(tree) ;
} ;

static void
show_histogram(uint count[], uint max, uint n, uint t)
{
  uint   i ;
  uint   m ;
  uint   c ;
  uint   h = 30 ;

  m = 0 ;
  for (i = 0 ; i < (n + 2) ; ++i)
    if (count[i] > m)
      m = count[i] ;

  c = 0 ;
  for (i = 1 ; i < (n + 2) ; ++i)
    {
      uint j ;
      uint s ;

      if (i > max)
        break ;

      if (i <= n)
        printf("   %2d: ", i) ;
      else
        printf("  >%2d: ", n) ;

      s = (count[i] * h) / m ;
      for (j = 0 ; j <= h ; ++j)
        if (j < s)
          printf("=") ;
        else
          printf(" ") ;

      j  = count[i] ;
      c += count[i] ;
      printf(" %6d %4.1f%%  %6d %5.1f%% :%2d\n",
                                            j, ((double)j * 100.0)/(double)t,
                                            c, ((double)c * 100.0)/(double)t,
                                                                           i) ;
    } ;
} ;

static void
show_tree(avl_tree tree)
{
  uint   level ;
  uint   i ;
  uint   pos ;
  vector linked ;
  char*  buf ;
  uint   bp ;
  uint   bl ;
  uint   height ;

  struct test_item* item ;

  /* Walk to establish the node widths  */

  linked = avl_tree_link(tree, avl_in_order, &height) ;
  for (i = 0 ; i < vector_length(linked) ; ++i)
    {
      item = vector_get_item(linked, i) ;
      item->pos  = i ;
    } ;
  linked = vector_free(linked) ;

  bl  = 200 ;
  buf = malloc(bl) ;

  pos = 0 ;
  level = UINT_MAX ;
  bp = 0 ;
  linked = avl_tree_link(tree, avl_level_order, &height) ;
  for (i = 0 ; i < vector_length(linked) ; ++i)
    {
      uint old_level ;
      uint tpos ;
      struct test_item* child ;

      item = vector_get_item(linked, i) ;

      tpos = item->pos * 2 + 1 ;

      old_level = level ;
      level = ((avl_node)item)->level ;

      if (level != old_level)
        {
          if (level == 0)
            {
              qassert((pos == 0) && (bp == 0)) ;
              printf("  :") ;
              while (pos < (tpos + 1))
                {
                  printf(" ") ;
                  ++pos ;
                } ;

              buf[bp++] = ((avl_node)item)->bal ;
            }
          else
            printf("\n  :") ;

          buf[bp] = '\0' ;
          printf("%s\n%2d:", buf, level) ;

          bp  = 0 ;
          pos = 0 ;
        } ;

      child = (avl_item)((avl_node)item)->child[avl_left] ;
      if (child != NULL)
        {
          uint cpos ;

          cpos = (child->pos * 2) + 2 ;
          qassert(cpos < tpos) ;

          if ((cpos + 2 + 1) > bl)
            {
              bl *= 2 ;
              buf = realloc(buf, bl) ;
            } ;

          qassert(bp <= cpos) ;
          while (bp < cpos)
            buf[bp++] = ' ' ;

          buf[bp++] = show_bal_char(((avl_node)child)->bal) ;
          buf[bp++] = '/' ;
          cpos += 2 ;

          if (cpos < tpos)
            {
              qassert(pos < tpos) ;
              while (pos < cpos)
                {
                  printf(" ") ;
                  ++pos ;
                } ;
              while (pos < tpos)
                {
                  printf("_") ;
                  ++pos ;
                } ;
            } ;
        } ;

      qassert(pos <= tpos) ;
      while (pos < tpos)
        {
          printf(" ") ;
          ++pos ;
        } ;

      printf("%03d", item->val) ;
      pos += 3 ;

      child = (avl_item)((avl_node)item)->child[avl_right] ;
      if (child != NULL)
        {
          uint cpos ;

          cpos = child->pos * 2 + 1 ;

          if ((cpos + 3 + 1) > bl)
            {
              bl *= 2 ;
              buf = realloc(buf, bl) ;
            } ;

          qassert(bp <= cpos) ;
          while (bp < cpos)
            buf[bp++] = ' ' ;

          buf[bp++] = '\\' ;
          buf[bp++] = show_bal_char(((avl_node)child)->bal) ;

          while (cpos > pos)
            {
              printf("_") ;
              ++pos ;
            } ;
        } ;
    } ;

  vector_free(linked) ;

  printf("\n") ;
} ;


static char
show_bal_char(int bal)
{
  switch(bal)
    {
      case -1:
        return '-' ;

      case  0:
        return '=' ;

      case +1:
        return '+' ;

      default:
        test_assert(false, "invalid balance") ;
        return '*' ;
    } ;
} ;

/*==============================================================================
 * Tree
 */
static void avl_link_in_order(vector order, avl_node node, uint level,
                                                               uint* p_height) ;
static void avl_link_in_reverse(vector order, avl_node node, uint level,
                                                               uint* p_height) ;
static void avl_link_pre_order(vector order, avl_node node, uint level,
                                                               uint* p_height) ;
static void avl_link_post_order(vector order, avl_node node, uint level,
                                                               uint* p_height) ;
static void avl_link_level_order(vector order, avl_node node,
                                                               uint* p_height) ;
static void avl_link_level_reverse(vector order, avl_node node,
                                                               uint* p_height) ;

/*------------------------------------------------------------------------------
 * Construct vector of items, in the required order.
 */
static vector
avl_tree_link(avl_tree tree, avl_link_t how, uint* p_height)
{
  vector order ;
  uint   height ;
  avl_node root ;

  if (p_height == NULL)
    p_height = &height ;
  *p_height = 0 ;

  order = vector_new(100) ;

  if (tree == NULL)
    root = NULL ;
  else
    root = (avl_node)tree->root ;

  switch (how)
    {
      case avl_in_order:
        avl_link_in_order(order, root, 0, p_height) ;
        break ;

      case avl_in_reverse:
        avl_link_in_reverse(order, root, 0, p_height) ;
        break ;

      case avl_pre_order:
        avl_link_pre_order(order, root, 0, p_height) ;
        break ;

      case avl_post_order:
        avl_link_post_order(order, root, 0, p_height) ;
        break ;

      case avl_level_order:
        avl_link_level_order(order, root, p_height) ;
        break ;

      case avl_level_reverse:
        avl_link_level_reverse(order, root, p_height) ;
        break ;

      default:
        assert(false) ;
    } ;

  return order ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list: in-order.
 *
 * In in-order each node follows its left but precedes its right children.
 */
static void
avl_link_in_order(vector order, avl_node node, uint level, uint* p_height)
{
  if (node != NULL)
    {
      avl_link_in_order(order, node->child[avl_left], level + 1, p_height) ;

      if (*p_height <= level)
        *p_height = level + 1 ;

      node->level = level ;
      vector_push_item(order, node) ;

      avl_link_in_order(order, node->child[avl_right], level + 1, p_height) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: in-order, reversed.
 *
 * In in-order each node follows its right but precedes its left children.
 */
static void
avl_link_in_reverse(vector order, avl_node node, uint level, uint* p_height)
{
  if (node != NULL)
    {
      avl_link_in_reverse(order, node->child[avl_right], level + 1, p_height) ;

      if (*p_height <= level)
        *p_height = level + 1 ;

      node->level = level ;
      vector_push_item(order, node) ;

      avl_link_in_reverse(order, node->child[avl_left], level + 1, p_height) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: pre-order.
 *
 * In pre-order each node precedes its left and then its right children.
 */
static void
avl_link_pre_order(vector order, avl_node node, uint level, uint* p_height)
{
  if (node != NULL)
    {
      if (*p_height <= level)
        *p_height = level + 1 ;

      node->level = level ;
      vector_push_item(order, node) ;

      avl_link_pre_order(order, node->child[avl_left],  level + 1, p_height) ;
      avl_link_pre_order(order, node->child[avl_right], level + 1, p_height) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: post-order.
 *
 * In post-order each node follows its left and then its right children.
 */
static void
avl_link_post_order(vector order, avl_node node, uint level, uint* p_height)
{
  if (node != NULL)
    {
      avl_link_post_order(order, node->child[avl_left],  level + 1, p_height) ;
      avl_link_post_order(order, node->child[avl_right], level + 1, p_height) ;

      if (*p_height <= level)
        *p_height = level + 1 ;

      node->level = level ;
      vector_push_item(order, node) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add tree to list, starting with level 0 (root), then level 1 and so on.
 *
 * In each level, the nodes are left to right across the tree.
 */
static void
avl_link_level_order(vector order, avl_node node, uint* p_height)
{
  vector queue ;
  uint   i, level, height ;

  if (node == NULL)
    return ;

  queue  = vector_new(100) ;
  i      = 0 ;
  level  = 0 ;
  height = 1 ;
  node->level = 0 ;

  do
    {
      avl_node child ;

      level = node->level ;     /* this level           */

      if (height <= level)
        height = level + 1 ;

      if (i >= 100)
        {
          vector_delete(queue, 0, i) ;
          i = 0 ;
        } ;

      vector_push_item(order, node) ;

      if ((child = node->child[avl_left]) != NULL)
        {
          child->level = level + 1 ;
          vector_push_item(queue, child) ;
        } ;

      if ((child = node->child[avl_right]) != NULL)
        {
          child->level = level + 1 ;
          vector_push_item(queue, child) ;
        } ;

      node = vector_get_item(queue, i++) ;
    }
  while (node != NULL) ;

  *p_height = height ;
} ;

/*------------------------------------------------------------------------------
 * Add tree to list, starting with deepest level, then up to level 0 (root).
 *
 * In each level, the nodes are left to right across the tree.
 */
static void
avl_link_level_reverse(vector order, avl_node node, uint* p_height)
{
  vector queue ;
  uint   i, level, height ;

  if (node == NULL)
    return ;

  queue  = vector_new(100) ;
  i      = 0 ;
  level  = 0 ;
  height = 1 ;
  node->level = 0 ;

  do
    {
      avl_node child ;

      level = node->level ;     /* this level           */

      if (height <= level)
        height = level + 1 ;

      if (i >= 100)
        {
          vector_delete(queue, 0, i) ;
          i = 0 ;
        } ;

      vector_push_item(order, node) ;

      if ((child = node->child[avl_right]) != NULL)
        {
          child->level = level + 1 ;
          vector_push_item(queue, child) ;
        } ;

      if ((child = node->child[avl_left]) != NULL)
        {
          child->level = level + 1 ;
          vector_push_item(queue, child) ;
        } ;

      node = vector_get_item(queue, i++) ;
    }
  while (node != NULL) ;

  *p_height = height ;

  vector_reverse(order) ;
} ;

