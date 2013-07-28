#include <misc.h>
#include <zebra.h>

#include "stdio.h"

#include "lib/qlib_init.h"
#include "lib/command.h"
#include "lib/list_util.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"

#define MCHECK_H

#ifdef MCHECK_H
#include <mcheck.h>
#endif

/*==============================================================================
 * bgpd/bgp_attr_store.c torture tests
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
 *
 */

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_mechanics(void) ;
static void test_attr_pair_set_as_path(void) ;
static void test_attr_pair_set_community(void) ;
static void test_attr_pair_set_ecommunity(void) ;
static void test_attr_pair_set_cluster(void) ;
static void test_attr_pair_set_transitive(void) ;
static void test_attr_pair_set_next_hop(void) ;
static void test_attr_pair_local_pref(void) ;
static void test_attr_pair_set_weight(void) ;
static void test_attr_pair_med(void) ;
static void test_attr_pair_origin(void) ;
static void test_attr_pair_set_atomic_aggregate(void) ;
static void test_attr_pair_originator_id(void) ;
static void test_attr_pair_set_aggregator(void) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
  uint count ;
#ifdef MCHECK_H
  mcheck(NULL) ;
#endif

  qlib_init_first_stage(0);     /* Absolutely first             */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start BGP attr_store testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  bgp_attr_start() ;            /* wind up the entire attribute store   */

  count = bgp_attr_count() ;
  test_assert(count == 0, "expected bgp_attr_count() == 0, got %u\n", count) ;

  test_mechanics() ;

  test_attr_pair_set_as_path() ;

  test_attr_pair_set_community() ;

  test_attr_pair_set_ecommunity() ;

  test_attr_pair_set_cluster() ;

  test_attr_pair_set_transitive() ;

  test_attr_pair_set_next_hop() ;

  test_attr_pair_local_pref() ;

  test_attr_pair_set_weight() ;

  test_attr_pair_med() ;

  test_attr_pair_origin() ;

  test_attr_pair_set_atomic_aggregate() ;

  test_attr_pair_originator_id() ;

  test_attr_pair_set_aggregator() ;

  count = bgp_attr_count() ;
  test_assert(count == 0, "expected bgp_attr_count() == 0, got %u\n", count) ;

  bgp_attr_finish() ;           /* close it down again                  */

  count = bgp_attr_count() ;
  test_assert(count == 0, "expected bgp_attr_count() == 0, got %u\n", count) ;

  fprintf(stderr, "Finished BGP attr_store testing") ;

  if (fail_count == 0)
    fprintf(stderr, " -- OK\n"
                    "...should now report NO remaining memory utilisation\n") ;
  else
    fprintf(stderr, " *** %u FAILURES\n", fail_count) ;

  host_finish() ;
  qexit(0, true /* mem_stats */) ;
}

/*==============================================================================
 * Test coverage:
 *
 *  * bgp_attr_start()                  -- see main()
 *  * bgp_attr_finish()                 -- see main()
 *  * bgp_attr_count()                  -- see main()
 *  * bgp_attr_show_all()               -- not tested here
 *
 *  * bgp_attr_lock()                   -- see test_mechanics()
 *  * bgp_attr_unlock()                 -- see test_mechanics()
 *
 *  * bgp_attr_pair_load_new()          -- see test_mechanics()
 *  * bgp_attr_pair_load()              -- see test_mechanics()
 *  * bgp_attr_pair_load_default()      -- see test_mechanics()
 *  * bgp_attr_pair_store()             -- see test_mechanics()
 *  * bgp_attr_pair_assign()            -- see test_mechanics()
 *  * bgp_attr_pair_unload()            -- see test_mechanics()
 *
 *  * bgp_attr_pair_set_as_path()       -- see test_attr_pair_set_as_path()
 *  * bgp_attr_pair_set_community()     -- see test_attr_pair_set_community()
 *  * bgp_attr_pair_set_ecommunity()    -- see test_attr_pair_set_ecommunity()
 *  * bgp_attr_pair_set_cluster()       -- see test_attr_pair_set_cluster()
 *  * bgp_attr_pair_set_transitive()    -- see
 *
 *  * bgp_attr_pair_set_next_hop()      -- see test_attr_pair_set_next_hop()
 *  * bgp_attr_pair_set_local_pref()    -- see test_attr_pair_local_pref()
 *  * bgp_attr_pair_clear_local_pref()  -- see test_attr_pair_local_pref()
 *  * bgp_attr_pair_set_weight()        -- see test_attr_pair_set_weight()
 *  * bgp_attr_pair_set_med()           -- see test_attr_pair_med()
 *  * bgp_attr_pair_clear_med()         -- see test_attr_pair_med()
 *  * bgp_attr_pair_set_origin()        -- see test_attr_pair_origin()
 *  * bgp_attr_pair_clear_origin()      -- see test_attr_pair_origin()
 *  * bgp_attr_pair_set_atomic_aggregate()
 *                                 -- see test_attr_pair_set_atomic_aggregate()
 *  * bgp_attr_pair_set_originator_id() -- see
 *  * bgp_attr_pair_set_aggregator()    -- see
 */

static void test_set_unlock(attr_set s, uint count, const char* name) ;


/*==============================================================================
 * Test of basic attribute pair load/store/assign/unload mechanics.
 *
 *  * bgp_attr_pair_load_new()
 *  * bgp_attr_pair_load()
 *  * bgp_attr_pair_load_default()
 *  * bgp_attr_pair_store()
 *  * bgp_attr_pair_assign()
 *  * bgp_attr_pair_unload()
 *
 *  * bgp_attr_lock()
 *  * bgp_attr_unlock()
 */
enum { test_sets = 200 } ;

attr_set  test_set[test_sets] ;

static void
test_mechanics(void)
{
  uint fail_count_was, test_count_was ;
  uint i, have ;
  attr_set    ts_a, ts_b, ts_e ;
  attr_pair_t tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: basic attribute pair mechanics") ;

  memset(test_set, 0, test_sets * sizeof(attr_set)) ;

  /* Simple stuff with the empty attr_set and default one
   */
  for (i = 0 ; i < 4 ; ++i)
    {
      uint count ;
      const char* how ;

      next_test() ;

      switch (i)
        {
          case 0:
          case 2:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
          case 3:
            bgp_attr_pair_load_default(tap, 2) ;
            break ;

          default:
            assert(false) ;
        } ;

      if (i & 2)
        {
          how   = "bgp_attr_pair_assign()" ;
          count = 4 ;
          ts_a = bgp_attr_pair_assign(tap) ;
        }
      else
        {
          how   = "bgp_attr_pair_store()" ;
          count = 2 ;
          ts_a = bgp_attr_pair_store(tap) ;
        } ;

      test_assert(vhash_is_set(ts_a),
            "expected attribute set to be stored after %s", how) ;
      test_assert(ts_a->vhash.ref_count == count,
                     "expected ref_count==%u, got=%u after %s",
                                           count, ts_a->vhash.ref_count, how) ;

      ts_b = bgp_attr_pair_assign(tap) ;
      count += 2 ;
      test_assert(ts_b == ts_a,
             "expected same stored attribute setfrom bgp_attr_pair_assign()") ;
      test_assert(ts_a->vhash.ref_count == count,
                "after bgp_attr_pair_assign() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      bgp_attr_pair_unload(tap) ;
      count -= 2 ;
      test_assert(ts_a->vhash.ref_count == count,
                "after bgp_attr_pair_unload() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      ts_b = bgp_attr_pair_load(tap, ts_a) ;
      count += 2 ;
      test_assert(ts_b == ts_a,
          "expected working value == stored value after bgp_attr_pair_load()") ;
      test_assert(ts_a->vhash.ref_count == count,
                "after bgp_attr_pair_load() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      ts_b = bgp_attr_pair_store(tap) ;
      test_assert(ts_b == ts_a,
                     "expected bgp_attr_pair_store() to return original "
                                                            "after no change") ;
      test_assert(ts_a->vhash.ref_count == count,
                  "after bgp_attr_pair_store() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      bgp_attr_pair_unload(tap) ;
      count -= 2 ;
      test_assert(ts_a->vhash.ref_count == count,
                "after bgp_attr_pair_unload() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      bgp_attr_lock(ts_a) ;
      count += 2 ;
      test_assert(ts_a->vhash.ref_count == count,
                    "after bgp_attr_lock() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;
      bgp_attr_unlock(ts_a) ;
      count -= 2 ;
      test_assert(ts_a->vhash.ref_count == count,
                    "after bgp_attr_unlock() expected ref_count==%u, got=%u",
                                                count, ts_a->vhash.ref_count) ;

      while (count > 0)
        {
          bgp_attr_unlock(ts_a) ;       /* undo implied lock in assign(s) */
          count -= 2 ;
        } ;
    } ;

  /* Create some trivially different attribute sets and store/lock/assign
   *
   * Sometimes we start from new, empty attribute pair, sometimes from the
   * stored, empty attribute set.
   *
   * Difference between the sets is weight/med/local_pref -- noting that the
   * same value is used for each of them.
   *
   * Tests that can store new and existing attribute sets.
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_assign(tap) ;

  test_assert(vhash_is_set(ts_e),
                       "expected empty attribute set to be stored "
                                               "after bgp_attr_pair_assign()") ;
  test_assert(ts_e->vhash.ref_count == 4,
                  "expected ref_count==4, got=%u "
                                        "after bgp_attr_pair_assign()",
                                                   ts_e->vhash.ref_count) ;

  for (i = 0 ; i < (test_sets * 20) ; ++i)
    {
      uint j, v ;

      next_test() ;

      j = rand() % test_sets ;

      if (rand() & 1)
        bgp_attr_pair_load_new(tap) ;
      else
        bgp_attr_pair_load(tap, ts_e) ;

      v = ((j / 3) + 1) * 57 ;
      switch (j % 3)
        {
          case 0:
            bgp_attr_pair_set_weight(tap, v) ;
            break ;

          case 1:
            bgp_attr_pair_set_med(tap, v) ;
            break ;

          case 2:
            bgp_attr_pair_set_local_pref(tap, v) ;
            break ;

          default:
            assert(false) ;
        } ;

      if (rand() & 7)
        {
          /* Most of the time we assign the result -- some of the time we
           * just discard it.
           */
          ts_a = bgp_attr_pair_assign(tap) ;

          test_assert(vhash_is_set(ts_a), "expected attribute set to be stored "
                                               "after bgp_attr_pair_assign()") ;

          if (test_set[j] == NULL)
            {
              test_assert(ts_a->vhash.ref_count == 4,
                              "expected ref_count==4, got=%u "
                                          "after first bgp_attr_pair_assign()",
                                                      ts_a->vhash.ref_count) ;
              test_set[j] = ts_a ;
            }
          else
            {
              test_assert(test_set[j] == ts_a,
                            "expected to get previously stored attribute set") ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;      /* book-end _load_new and _load */
    } ;

  /* Now, randomly unwind all the stored attributes.
   *
   */
  have = test_sets ;

  while (have > 0)
    {
      next_test() ;

      i = rand() % have ;

      ts_a = test_set[i] ;

      if (ts_a != NULL)
        {
          uint count ;

          count = ts_a->vhash.ref_count ;
          assert(count >= 2) ;
          count -= 2 ;

          bgp_attr_unlock(ts_a) ;

          if (count > 0)
            test_assert(ts_a->vhash.ref_count == count,
                            "expected ref_count==%u, got=%u "
                                                  "after bgp_attr_unlock()",
                                                count, ts_a->vhash.ref_count) ;
          else
            ts_a = NULL ;
        } ;

      if (ts_a == NULL)
        test_set[i] = test_set[--have] ;
    } ;

  /* Finally, unwind the empty attribute set.
   */
  test_set_unlock(ts_e, 4, "empty") ;
  test_set_unlock(ts_e, 2, "ts_a") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_as_path()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases:
 *
 *   1) starting from a new, empty set
 *
 *   2) starting from a stored, empty set
 *
 *   3) starting from a stored, set with as_path "A"
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set NULL as_path (same as setting the empty one).
 *
 *   c) set the empty as_path
 *
 *   d) set stored as_path "A"
 *
 *   e) set stored as_path "B"
 *
 *   f) set new as_path "C"
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_as_path(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set    ts_e, ts_a, ts_b, ts_c, ts_t ;
  as_path     asp_a, asp_b, asp_c, asp_t ;
  attr_pair_t tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_as_path()") ;

  /* Set up asp_a, asp_b and asp_c as stored as_path objects.
   */
  asp_a = as_path_from_str("2529") ;
  asp_t = as_path_store(asp_a) ;
  assert(asp_t == asp_a) ;

  asp_b = as_path_from_str("5417") ;
  asp_t = as_path_store(asp_b) ;
  assert(asp_t == asp_b) ;

  asp_c = as_path_from_str("666") ;
  asp_t = as_path_store(asp_c) ;
  assert(asp_t == asp_c) ;

  /* Set up ts_e, ts_a, ts_b, ts_c as stored attr_sets, empty and with asp_a,
   * asp_b, asp_c respectively
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_as_path(tap, asp_a) ;
  ts_a = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_a), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_a->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_a->vhash.ref_count) ;
  test_assert(ts_a->asp == asp_a,
                 "expected ts_a->asp to be asp_a after bgp_attr_pair_store()") ;
  test_assert(asp_a->vhash.ref_count == 4,
                 "expected asp_a ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       asp_a->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_as_path(tap, asp_b) ;
  ts_b = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_b), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_b->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_b->vhash.ref_count) ;
  test_assert(ts_b->asp == asp_b,
                 "expected ts_b->asp to be asp_b after bgp_attr_pair_store()") ;
  test_assert(asp_b->vhash.ref_count == 4,
                 "expected asp_b ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       asp_b->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_as_path(tap, asp_c) ;
  ts_c = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_c), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_c->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_c->vhash.ref_count) ;
  test_assert(ts_c->asp == asp_c,
                 "expected ts_c->asp to be asp_c after bgp_attr_pair_store()") ;
  test_assert(asp_c->vhash.ref_count == 4,
                 "expected asp_c ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       asp_c->vhash.ref_count) ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, empty value
   *                                           stored, with as_path "A"
   *
   *   * apply one 6 actions: do nothing
   *                          set NULL
   *                          set empty
   *                          set as_path "A" -- stored value
   *                          set as_path "B" -- stored value
   *                          set as_path "C" -- new as_path
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < (6 * 6 * 6 * 6 * 3 * 2) ; ++i)
    {
      uint d, j, p, q, dq, s ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 3 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_a) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      for (j = 0 ; j < 4 ; ++j)
        {
          q = s % 6 ;

          switch (q)
            {
              case 0:
                dq = 0 ;        /* null event                   */
                break ;

              case 1:
                bgp_attr_pair_set_as_path(tap, NULL) ;
                dq = 1 ;        /* expect ts_e to be debounced  */
                break ;

              case 2:
                bgp_attr_pair_set_as_path(tap, as_path_empty_asp) ;
                dq = 1 ;        /* expect ts_e to be debounced  */
                break ;

              case 3:
                bgp_attr_pair_set_as_path(tap, asp_a) ;
                dq = 2 ;        /* expect ts_a to be debounced  */
                break ;

              case 4:
                bgp_attr_pair_set_as_path(tap, asp_b) ;
                dq = 3 ;        /* must set value               */
                break ;

              case 5:
                asp_t = as_path_from_str("666") ;
                bgp_attr_pair_set_as_path(tap, asp_t) ;
                dq = 3 ;        /* must set value               */
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (dq != 0))
            {
              if (d != dq)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 6 ;

          if (s == 0)
            break ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
                switch(p)
                  {
                    case 0:
                    case 1:
                      test_assert(ts_t == ts_e,
                                      "expected ts_e for q==0, p==0 or p==1") ;
                      break ;

                    case 2:
                      test_assert(ts_t == ts_a,
                                      "expected ts_a for q==0, p==2") ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for q==1") ;
                break ;

              case 2:
                test_assert(ts_t == ts_e, "expected ts_e for q==2") ;
                break ;

              case 3:
                test_assert(ts_t == ts_a, "expected ts_a for q==3") ;
                break ;

              case 4:
                test_assert(ts_t == ts_b, "expected ts_b for q==4") ;
                break ;

              case 5:
                test_assert(ts_t == ts_c, "expected ts_c for q==5") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets and as_paths.
   */
  as_path_release(asp_a) ;
  as_path_release(asp_b) ;
  as_path_release(asp_c) ;

  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_a, 2, "ts_a") ;
  test_set_unlock(ts_b, 2, "ts_b") ;
  test_set_unlock(ts_c, 2, "ts_c") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_community()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases:
 *
 *   1) starting from a new, empty set
 *
 *   2) starting from a stored, empty set
 *
 *   3) starting from a stored, set with communities "A"
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set NULL communities
 *
 *   c) set stored communities "A"
 *
 *   d) set stored communities "B"
 *
 *   e) set new communities "C"
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_community(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_a, ts_b, ts_c, ts_t ;
  attr_community comm_a, comm_b, comm_c, comm_t ;
  attr_community_type_t act ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_community()") ;

  /* Set up comm_a, comm_b comm_c as stored attr_community objects.
   */
  comm_a = attr_community_from_str("2529:1", &act) ;
  comm_t = attr_community_store(comm_a) ;
  assert((comm_t != NULL) && (comm_t == comm_a)) ;

  comm_b = attr_community_from_str("5417:2", &act) ;
  comm_t = attr_community_store(comm_b) ;
  assert((comm_t != NULL) && (comm_t == comm_b)) ;

  comm_c = attr_community_from_str("666:3", &act) ;
  comm_t = attr_community_store(comm_c) ;
  assert((comm_t != NULL) && (comm_t == comm_c)) ;

  /* Set up ts_e, ts_a, ts_b, ts_c as stored attr_sets, empty and with comm_a,
   * comm_b, comm_c respectively
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_community(tap, comm_a) ;
  ts_a = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_a), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_a->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_a->vhash.ref_count) ;
  test_assert(ts_a->community == comm_a,
          "expected ts_a->community to be comm_a after bgp_attr_pair_store()") ;
  test_assert(comm_a->vhash.ref_count == 4,
                 "expected comm_a ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       comm_a->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_community(tap, comm_b) ;
  ts_b = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_b), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_b->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_b->vhash.ref_count) ;
  test_assert(ts_b->community == comm_b,
          "expected ts_b->community to be comm_b after bgp_attr_pair_store()") ;
  test_assert(comm_b->vhash.ref_count == 4,
                 "expected comm_b ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       comm_b->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_community(tap, comm_c) ;
  ts_c = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_c), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_c->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_c->vhash.ref_count) ;
  test_assert(ts_c->community == comm_c,
          "expected ts_c->community to be comm_c after bgp_attr_pair_store()") ;
  test_assert(comm_c->vhash.ref_count == 4,
                 "expected comm_c ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       comm_c->vhash.ref_count) ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, empty value
   *                                           stored, with community "A"
   *
   *   * apply one 5 actions: do nothing
   *                          set NULL
   *                          set community "A" -- stored value
   *                          set community "B" -- stored value
   *                          set community "C" -- new community
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < (5 * 5 * 5 * 5 * 3 * 2) ; ++i)
    {
      uint d, j, p, q, s ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 3 ;
      switch (p)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_a) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      for (j = 0 ; j < 4 ; ++j)
        {
          q = s % 5 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_community(tap, NULL) ;
                break ;

              case 2:
                bgp_attr_pair_set_community(tap, comm_a) ;
                break ;

              case 3:
                bgp_attr_pair_set_community(tap, comm_b) ;
                break ;

              case 4:
                comm_t = attr_community_from_str("666:3", &act) ;
                assert(comm_t != NULL) ;
                bgp_attr_pair_set_community(tap, comm_t) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 5 ;

          if (s == 0)
            break ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
                switch(p)
                  {
                    case 0:
                    case 1:
                      test_assert(ts_t == ts_e,
                                      "expected ts_e for q==0, p==0 or p==1") ;
                      break ;

                    case 2:
                      test_assert(ts_t == ts_a,
                                      "expected ts_a for q==0, p==2") ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for q==1") ;
                break ;

              case 2:
                test_assert(ts_t == ts_a, "expected ts_a for q==2") ;
                break ;

              case 3:
                test_assert(ts_t == ts_b, "expected ts_b for q==3") ;
                break ;

              case 4:
                test_assert(ts_t == ts_c, "expected ts_c for q==4") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets and communities.
   */
  attr_community_release(comm_a) ;
  attr_community_release(comm_b) ;
  attr_community_release(comm_c) ;

  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_a, 2, "ts_a") ;
  test_set_unlock(ts_b, 2, "ts_b") ;
  test_set_unlock(ts_c, 2, "ts_c") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_ecommunity()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases:
 *
 *   1) starting from a new, empty set
 *
 *   2) starting from a stored, empty set
 *
 *   3) starting from a stored, set with ecommunities "A"
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set NULL ecommunities
 *
 *   c) set stored ecommunities "A"
 *
 *   d) set stored ecommunities "B"
 *
 *   e) set new ecommunities "C"
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_ecommunity(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_a, ts_b, ts_c, ts_t ;
  attr_ecommunity ecomm_a, ecomm_b, ecomm_c, ecomm_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_ecommunity()") ;

  /* Set up ecomm_a, ecomm_b ecomm_c as stored attr_ecommunity objects.
   */
  ecomm_a = attr_ecommunity_from_str("RT:2529:1", true, 0) ;
  ecomm_t = attr_ecommunity_store(ecomm_a) ;
  assert((ecomm_t != NULL) && (ecomm_t == ecomm_a)) ;

  ecomm_b = attr_ecommunity_from_str("RT:5417:2", true, 0) ;
  ecomm_t = attr_ecommunity_store(ecomm_b) ;
  assert((ecomm_t != NULL) && (ecomm_t == ecomm_b)) ;

  ecomm_c = attr_ecommunity_from_str("RT:666:3", true, 0) ;
  ecomm_t = attr_ecommunity_store(ecomm_c) ;
  assert((ecomm_t != NULL) && (ecomm_t == ecomm_c)) ;

  /* Set up ts_e, ts_a, ts_b, ts_c as stored attr_sets, empty and with ecomm_a,
   * ecomm_b, ecomm_c respectively
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_ecommunity(tap, ecomm_a) ;
  ts_a = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_a), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_a->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_a->vhash.ref_count) ;
  test_assert(ts_a->ecommunity == ecomm_a,
          "expected ts_a->ecommunity to be ecomm_a after bgp_attr_pair_store()") ;
  test_assert(ecomm_a->vhash.ref_count == 4,
                 "expected ecomm_a ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       ecomm_a->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_ecommunity(tap, ecomm_b) ;
  ts_b = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_b), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_b->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_b->vhash.ref_count) ;
  test_assert(ts_b->ecommunity == ecomm_b,
          "expected ts_b->ecommunity to be ecomm_b after bgp_attr_pair_store()") ;
  test_assert(ecomm_b->vhash.ref_count == 4,
                 "expected ecomm_b ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       ecomm_b->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_ecommunity(tap, ecomm_c) ;
  ts_c = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_c), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_c->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_c->vhash.ref_count) ;
  test_assert(ts_c->ecommunity == ecomm_c,
          "expected ts_c->ecommunity to be ecomm_c after bgp_attr_pair_store()") ;
  test_assert(ecomm_c->vhash.ref_count == 4,
                 "expected ecomm_c ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       ecomm_c->vhash.ref_count) ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, empty value
   *                                           stored, with ecommunity "A"
   *
   *   * apply one 5 actions: do nothing
   *                          set NULL
   *                          set ecommunity "A" -- stored value
   *                          set ecommunity "B" -- stored value
   *                          set ecommunity "C" -- new ecommunity
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < (5 * 5 * 5 * 5 * 3 * 2) ; ++i)
    {
      uint d, j, p, q, s ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 3 ;
      switch (p)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_a) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      for (j = 0 ; j < 4 ; ++j)
        {
          q = s % 5 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_ecommunity(tap, NULL) ;
                break ;

              case 2:
                bgp_attr_pair_set_ecommunity(tap, ecomm_a) ;
                break ;

              case 3:
                bgp_attr_pair_set_ecommunity(tap, ecomm_b) ;
                break ;

              case 4:
                ecomm_t = attr_ecommunity_from_str("RT:666:3", true, 0) ;
                assert(ecomm_t != NULL) ;
                bgp_attr_pair_set_ecommunity(tap, ecomm_t) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 5 ;

          if (s == 0)
            break ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
                switch(p)
                  {
                    case 0:
                    case 1:
                      test_assert(ts_t == ts_e,
                                      "expected ts_e for q==0, p==0 or p==1") ;
                      break ;

                    case 2:
                      test_assert(ts_t == ts_a,
                                      "expected ts_a for q==0, p==2") ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for q==1") ;
                break ;

              case 2:
                test_assert(ts_t == ts_a, "expected ts_a for q==2") ;
                break ;

              case 3:
                test_assert(ts_t == ts_b, "expected ts_b for q==3") ;
                break ;

              case 4:
                test_assert(ts_t == ts_c, "expected ts_c for q==4") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets and ecommunities.
   */
  attr_ecommunity_release(ecomm_a) ;
  attr_ecommunity_release(ecomm_b) ;
  attr_ecommunity_release(ecomm_c) ;

  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_a, 2, "ts_a") ;
  test_set_unlock(ts_b, 2, "ts_b") ;
  test_set_unlock(ts_c, 2, "ts_c") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_cluster()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases:
 *
 *   1) starting from a new, empty set
 *
 *   2) starting from a stored, empty set
 *
 *   3) starting from a stored, set with cluster "A"
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set NULL cluster
 *
 *   c) set stored cluster "A"
 *
 *   d) set stored cluster "B"
 *
 *   e) set new cluster "C"
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_cluster(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_a, ts_b, ts_c, ts_t ;
  attr_cluster clust_a, clust_b, clust_c, clust_t ;
  attr_pair_t    tap[1] ;

  static const byte cluster_a[] = { 10, 0, 0, 0 } ;
  static const byte cluster_b[] = { 10, 0, 0, 1 } ;
  static const byte cluster_c[] = { 10, 0, 0, 2 } ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_cluster()") ;

  /* Set up clust_a, clust_b clust_c as stored attr_cluster objects.
   */
  clust_a = attr_cluster_set(cluster_a, 1) ;
  clust_t = attr_cluster_store(clust_a) ;
  assert((clust_t != NULL) && (clust_t == clust_a)) ;

  clust_b = attr_cluster_set(cluster_b, 1) ;
  clust_t = attr_cluster_store(clust_b) ;
  assert((clust_t != NULL) && (clust_t == clust_b)) ;

  clust_c = attr_cluster_set(cluster_c, 1) ;
  clust_t = attr_cluster_store(clust_c) ;
  assert((clust_t != NULL) && (clust_t == clust_c)) ;

  /* Set up ts_e, ts_a, ts_b, ts_c as stored attr_sets, empty and with clust_a,
   * clust_b, clust_c respectively
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_cluster(tap, clust_a) ;
  ts_a = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_a), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_a->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_a->vhash.ref_count) ;
  test_assert(ts_a->cluster == clust_a,
          "expected ts_a->cluster to be clust_a after bgp_attr_pair_store()") ;
  test_assert(clust_a->vhash.ref_count == 4,
                 "expected clust_a ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       clust_a->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_cluster(tap, clust_b) ;
  ts_b = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_b), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_b->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_b->vhash.ref_count) ;
  test_assert(ts_b->cluster == clust_b,
          "expected ts_b->cluster to be clust_b after bgp_attr_pair_store()") ;
  test_assert(clust_b->vhash.ref_count == 4,
                 "expected clust_b ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       clust_b->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_cluster(tap, clust_c) ;
  ts_c = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_c), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_c->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_c->vhash.ref_count) ;
  test_assert(ts_c->cluster == clust_c,
          "expected ts_c->cluster to be clust_c after bgp_attr_pair_store()") ;
  test_assert(clust_c->vhash.ref_count == 4,
                 "expected clust_c ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       clust_c->vhash.ref_count) ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, empty value
   *                                           stored, with cluster "A"
   *
   *   * apply one 5 actions: do nothing
   *                          set NULL
   *                          set cluster "A" -- stored value
   *                          set cluster "B" -- stored value
   *                          set cluster "C" -- new cluster
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < (5 * 5 * 5 * 5 * 3 * 2) ; ++i)
    {
      uint d, j, p, q, s ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 3 ;
      switch (p)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_a) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      for (j = 0 ; j < 4 ; ++j)
        {
          q = s % 5 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_cluster(tap, NULL) ;
                break ;

              case 2:
                bgp_attr_pair_set_cluster(tap, clust_a) ;
                break ;

              case 3:
                bgp_attr_pair_set_cluster(tap, clust_b) ;
                break ;

              case 4:
                clust_t = attr_cluster_set(cluster_c, 1) ;
                assert(clust_t != NULL) ;
                bgp_attr_pair_set_cluster(tap, clust_t) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 5 ;

          if (s == 0)
            break ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
                switch(p)
                  {
                    case 0:
                    case 1:
                      test_assert(ts_t == ts_e,
                                      "expected ts_e for q==0, p==0 or p==1") ;
                      break ;

                    case 2:
                      test_assert(ts_t == ts_a,
                                      "expected ts_a for q==0, p==2") ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for q==1") ;
                break ;

              case 2:
                test_assert(ts_t == ts_a, "expected ts_a for q==2") ;
                break ;

              case 3:
                test_assert(ts_t == ts_b, "expected ts_b for q==3") ;
                break ;

              case 4:
                test_assert(ts_t == ts_c, "expected ts_c for q==4") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets and clusters.
   */
  attr_cluster_release(clust_a) ;
  attr_cluster_release(clust_b) ;
  attr_cluster_release(clust_c) ;

  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_a, 2, "ts_a") ;
  test_set_unlock(ts_b, 2, "ts_b") ;
  test_set_unlock(ts_c, 2, "ts_c") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_transitive()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases:
 *
 *   1) starting from a new, empty set
 *
 *   2) starting from a stored, empty set
 *
 *   3) starting from a stored, set with transitive "A"
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set NULL transitive
 *
 *   c) set stored transitive "A"
 *
 *   d) set stored transitive "B"
 *
 *   e) set new transitive "C"
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_transitive(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_a, ts_b, ts_c, ts_t ;
  attr_unknown   unk_a, unk_b, unk_c, unk_t ;
  attr_pair_t    tap[1] ;

  static const byte transitive_a[] = { BGP_ATF_TRANSITIVE | BGP_ATF_OPTIONAL,
                                       99, 1, 'a' } ;
  static const byte transitive_b[] = { BGP_ATF_TRANSITIVE | BGP_ATF_OPTIONAL,
                                       99, 1, 'b' } ;
  static const byte transitive_c[] = { BGP_ATF_TRANSITIVE | BGP_ATF_OPTIONAL,
                                       99, 1, 'c' } ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_transitive()") ;

  /* Set up unk_a, unk_b unk_c as stored attr_transitive objects.
   */
  unk_a = attr_unknown_add(NULL, transitive_a) ;
  unk_t = attr_unknown_store(unk_a) ;
  assert((unk_t != NULL) && (unk_t == unk_a)) ;

  unk_b = attr_unknown_add(NULL, transitive_b) ;
  unk_t = attr_unknown_store(unk_b) ;
  assert((unk_t != NULL) && (unk_t == unk_b)) ;

  unk_c = attr_unknown_add(NULL, transitive_c) ;
  unk_t = attr_unknown_store(unk_c) ;
  assert((unk_t != NULL) && (unk_t == unk_c)) ;

  /* Set up ts_e, ts_a, ts_b, ts_c as stored attr_sets, empty and with unk_a,
   * unk_b, unk_c respectively
   */
  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_transitive(tap, unk_a) ;
  ts_a = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_a), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_a->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_a->vhash.ref_count) ;
  test_assert(ts_a->transitive == unk_a,
          "expected ts_a->transitive to be unk_a after bgp_attr_pair_store()") ;
  test_assert(unk_a->vhash.ref_count == 4,
                 "expected unk_a ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       unk_a->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_transitive(tap, unk_b) ;
  ts_b = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_b), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_b->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_b->vhash.ref_count) ;
  test_assert(ts_b->transitive == unk_b,
          "expected ts_b->transitive to be unk_b after bgp_attr_pair_store()") ;
  test_assert(unk_b->vhash.ref_count == 4,
                 "expected unk_b ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       unk_b->vhash.ref_count) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_transitive(tap, unk_c) ;
  ts_c = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_c), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_c->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_c->vhash.ref_count) ;
  test_assert(ts_c->transitive == unk_c,
          "expected ts_c->transitive to be unk_c after bgp_attr_pair_store()") ;
  test_assert(unk_c->vhash.ref_count == 4,
                 "expected unk_c ref_count==4, got %u "
                                               "after bgp_attr_pair_store()",
                                                       unk_c->vhash.ref_count) ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, empty value
   *                                           stored, with transitive "A"
   *
   *   * apply one 5 actions: do nothing
   *                          set NULL
   *                          set transitive "A" -- stored value
   *                          set transitive "B" -- stored value
   *                          set transitive "C" -- new transitive
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < (5 * 5 * 5 * 5 * 3 * 2) ; ++i)
    {
      uint d, j, p, q, s ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 3 ;
      switch (p)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_a) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      for (j = 0 ; j < 4 ; ++j)
        {
          q = s % 5 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_transitive(tap, NULL) ;
                break ;

              case 2:
                bgp_attr_pair_set_transitive(tap, unk_a) ;
                break ;

              case 3:
                bgp_attr_pair_set_transitive(tap, unk_b) ;
                break ;

              case 4:
                unk_t = attr_unknown_add(NULL, transitive_c) ;
                assert(unk_t != NULL) ;
                bgp_attr_pair_set_transitive(tap, unk_t) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 5 ;

          if (s == 0)
            break ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
                switch(p)
                  {
                    case 0:
                    case 1:
                      test_assert(ts_t == ts_e,
                                      "expected ts_e for q==0, p==0 or p==1") ;
                      break ;

                    case 2:
                      test_assert(ts_t == ts_a,
                                      "expected ts_a for q==0, p==2") ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for q==1") ;
                break ;

              case 2:
                test_assert(ts_t == ts_a, "expected ts_a for q==2") ;
                break ;

              case 3:
                test_assert(ts_t == ts_b, "expected ts_b for q==3") ;
                break ;

              case 4:
                test_assert(ts_t == ts_c, "expected ts_c for q==4") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets and unknown attributes.
   */
  attr_unknown_release(unk_a) ;
  attr_unknown_release(unk_b) ;
  attr_unknown_release(unk_c) ;

  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_a, 2, "ts_a") ;
  test_set_unlock(ts_b, 2, "ts_b") ;
  test_set_unlock(ts_c, 2, "ts_c") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_next_hop()
 *
 * Gentle testing of debouncing, setting NULL/empty, setting new and stored
 * values, etc.
 *
 * Cases, starting from:
 *
 *   1) a new, empty set
 *
 *   2) a stored, empty set
 *
 *   3) a stored set with ipv4 "A"
 *
 *   4) a stored set with ipv6 "A", global only
 *
 *   5) a stored set with ipv6 "A", link_local only
 *
 *   6) a stored set with ipv4 "A", global and link_local
 *
 * Do:
 *
 *   a) nothing
 *
 *   b) set nh_none
 *
 *   c) set ipv4 "A"
 *
 *   d) set ipv4 "B"
 *
 *   e) set ipv6 "A", global
 *
 *   f) set ipv6 "A", link_local
 *
 *   g) clear ipv6 link-local
 *
 *   h) set ipv6 "B", global
 *
 *   i) set ipv6 "B", link_local
 *
 * a number of times in all combinations:
 *
 * Then:
 *
 *   i) store the result
 *
 *      check that get the expected stored attribute set.
 *
 *  ii) do nothing
 *
 * and unload the attribute pair.
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_next_hop(void)
{
  enum
    {
      nun,
      ipv6_gn,
      ipv4_a,
      ipv4_b,
      ipv6_ga,
      ipv6_gb,
      ipv6_la,
      ipv6_lb,
      ipv6_ga_la,
      ipv6_gb_lb,
      ipv6_ga_lb,
      ipv6_gb_la,

      st_count
    } ;

  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set    ts_t ;
  attr_pair_t tap[1] ;
  attr_set    ts[st_count] = { NULL } ;

  static const char* ts_name[st_count] =
    {
      [nun]        = "nun",
      [ipv6_gn]    = "ipv6_gn",
      [ipv4_a]     = "ipv4_a",
      [ipv4_b]     = "ipv4_b",
      [ipv6_ga]    = "ipv6_ga",
      [ipv6_gb]    = "ipv6_gb",
      [ipv6_la]    = "ipv6_la",
      [ipv6_lb]    = "ipv6_lb",
      [ipv6_ga_la] = "ipv6_ga_la",
      [ipv6_gb_lb] = "ipv6_gb_lb",
      [ipv6_ga_lb] = "ipv6_ga_lb",
      [ipv6_gb_la] = "ipv6_gb_la",
    } ;

  static const attr_next_hop_t tnh[] =
    {
      [nun]        = { .type = nh_none },

      [ipv6_gn]    = { .type = nh_ipv6_1 },

      [ipv4_a]     = { .type = nh_ipv4,   .ip = { .v4 = 0x0A00000A } },
      [ipv4_b]     = { .type = nh_ipv4,   .ip = { .v4 = 0x0B00000B } },

      [ipv6_ga]    = { .type = nh_ipv6_1, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x01 } }
                                          } }
      },
      [ipv6_gb]    = { .type = nh_ipv6_1, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x02 } }
                                          } }
      },
      [ipv6_la]    = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [1] = { .b = { 0xFE, 0x81 } }
                                          } }
      },
      [ipv6_lb]    = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [1] = { .b = { 0xFE, 0x82 } }
                                          } }
      },
      [ipv6_ga_la] = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x01 } },
                                                [1] = { .b = { 0xFE, 0x81 } }
                                          } }
      },
      [ipv6_ga_lb] = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x01 } },
                                                [1] = { .b = { 0xFE, 0x82 } }
                                          } }
      },
      [ipv6_gb_la] = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x02 } },
                                                [1] = { .b = { 0xFE, 0x81 } }
                                           } }
      },
      [ipv6_gb_lb] = { .type = nh_ipv6_2, .ip = { .v6 = {
                                                [0] = { .b = { 0x20, 0x02 } },
                                                [1] = { .b = { 0xFE, 0x82 } }
                                          } }
      },
    } ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_next_hop()") ;

  /* Set up ts[nun] as an empty stored value.
   *
   * Note that we store and remember the set (as ts[nun]), so we do NOT unload (!)
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts[nun] = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts[nun]), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts[nun]->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts[nun]->vhash.ref_count) ;

  /* Set up ts[ipv6_gn] as an nh_ipv6_1, but with a zero value.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_gn].ip.v6[0]) ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_gn], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_gn] = bgp_attr_pair_store(tap) ;

  /* Test that setting nh_none and unsetting link_local are debounced for ts[nun].
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[nun]) ;
  assert((tap->stored == ts[nun]) && (tap->working == ts[nun])) ;

  ts_t = bgp_attr_pair_set_next_hop(tap, nh_none, NULL) ;
  test_assert(ts_t == ts[nun],
                          "expected setting nh_none to be debounced for ts[nun]") ;

  ts_t = bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, NULL) ;
  test_assert(ts_t == ts[nun],
                   "expected setting nh_ipv6_2/NULL to be debounced for ts[nun]") ;

  bgp_attr_pair_unload(tap) ;

  /* Set up ts[ipv4_a] and ts[ipv4_b] -- starting from new
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_a].ip.v4) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv4_a], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv4_a] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_b].ip.v4) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv4_b], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv4_b] = bgp_attr_pair_store(tap) ;

  /* Starting from ts[nun], set ipv4_a and check get what we expect
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[nun]) ;
  assert((tap->stored == ts[nun]) && (tap->working == ts[nun])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_a].ip.v4) ;
  test_assert(tap->stored == ts[nun], "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv4_a], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv4_a], "expected to get stored value ts[ipv4_a]") ;

  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv4_a], set ipv4_a and check debounced
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv4_a]) ;
  assert((tap->stored == ts[ipv4_a]) && (tap->working == ts[ipv4_a])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_a].ip.v4) ;
  test_assert(tap->stored == ts[ipv4_a],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->stored,
                                     "expected tp_a->working to be debounced") ;
  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv4_a], set ipv4_b and check changed
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv4_a]) ;
  assert((tap->stored == ts[ipv4_a]) && (tap->working == ts[ipv4_a])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_b].ip.v4) ;
  test_assert(tap->stored == ts[ipv4_a],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv4_b], "expected to get stored value ts[ipv4_b]") ;

  bgp_attr_pair_unload(tap) ;

  /* Set up ts[ipv6_ga] and ts[ipv6_gb] -- starting from new
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_ga].ip.v6[0]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_ga], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_ga] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_gb].ip.v6[0]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_gb], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_gb] = bgp_attr_pair_store(tap) ;

  /* Starting from ts[nun], set ts[ipv6_ga] and check get what we expect
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[nun]) ;
  assert((tap->stored == ts[nun]) && (tap->working == ts[nun])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_ga].ip.v6[0]) ;
  test_assert(tap->stored == ts[nun], "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_ga], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv6_ga], "expected to get stored value ts[ipv6_ga]") ;

  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv6_ga], set ipv6_ga and check debounced
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv6_ga]) ;
  assert((tap->stored == ts[ipv6_ga]) && (tap->working == ts[ipv6_ga])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_ga].ip.v6[0]) ;
  test_assert(tap->stored == ts[ipv6_ga],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->stored,
                                     "expected tp_a->working to be debounced") ;
  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv6_ga], set ipv6_gb and check changed
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv6_ga]) ;
  assert((tap->stored == ts[ipv6_ga]) && (tap->working == ts[ipv6_ga])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_gb].ip.v6[0]) ;
  test_assert(tap->stored == ts[ipv6_ga],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv6_gb], "expected to get stored value ts[ipv6_gb]") ;

  bgp_attr_pair_unload(tap) ;

  /* Set up ts[ipv6_la] and ts[ipv6_lb] -- starting from new
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_la].ip.v6[1]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_la], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_la] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_lb].ip.v6[1]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_lb], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_lb] = bgp_attr_pair_store(tap) ;

  /* Starting from ts[nun], set ts[ipv6_la] and check get what we expect
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[nun]) ;
  assert((tap->stored == ts[nun]) && (tap->working == ts[nun])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_la].ip.v6[1]) ;
  test_assert(tap->stored == ts[nun], "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_la], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv6_la],
                                  "expected to get stored value ts[ipv6_la]") ;
  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv6_la], set ipv6_la and check debounced
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv6_la]) ;
  assert((tap->stored == ts[ipv6_la]) && (tap->working == ts[ipv6_la])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_la].ip.v6[1]) ;
  test_assert(tap->stored == ts[ipv6_la],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->stored,
                                     "expected tp_a->working to be debounced") ;
  bgp_attr_pair_unload(tap) ;

  /* Starting from ts[ipv6_la], set ipv6_lb and check changed
   */
  next_test() ;

  bgp_attr_pair_load(tap, ts[ipv6_la]) ;
  assert((tap->stored == ts[ipv6_la]) && (tap->working == ts[ipv6_la])) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_lb].ip.v6[1]) ;
  test_assert(tap->stored == ts[ipv6_la],
                                     "did NOT expect tp_a->stored to changed") ;
  test_assert(tap->working == tap->scratch,
                          "expected tp_a->working to be set to tp_a->scratch") ;
  ts_t = bgp_attr_pair_store(tap) ;
  test_assert(ts_t == ts[ipv6_lb],
                                  "expected to get stored value ts[ipv6_lb]") ;
  bgp_attr_pair_unload(tap) ;

  /* Set up ts[ipv6_ga_la], ts[ipv6_ga_lb], ts[ipv6_gb_la] and ts[ipv6_gb_lb]
   *
   * For completeness, we set the two halves in different order for a & b.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_ga].ip.v6[0]) ;
  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_la].ip.v6[1]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_ga_la], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_ga_la] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_lb].ip.v6[1]) ;
  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_ga].ip.v6[0]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_ga_lb], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_ga_lb] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_la].ip.v6[1]) ;
  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_gb].ip.v6[0]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_gb_la], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_gb_la] = bgp_attr_pair_store(tap) ;

  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  assert((tap->stored == NULL) && (tap->working == tap->scratch)) ;

  bgp_attr_pair_set_next_hop(tap, nh_ipv6_1, &tnh[ipv6_gb].ip.v6[0]) ;
  bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, &tnh[ipv6_lb].ip.v6[1]) ;
  test_assert((tap->stored == NULL) && (tap->working == tap->scratch),
                     "did NOT expect tp_a->stored or tp_a->working to change") ;
  test_assert(memcmp(&tap->working->next_hop,
                     &tnh[ipv6_gb_lb], sizeof(attr_next_hop_t)) == 0,
                               "unexpected value for tp_a->working->next_hop") ;
  ts[ipv6_gb_lb] = bgp_attr_pair_store(tap) ;

  /* Ringing the changes
   */
  for (i = 0 ; i < (9 * 9 * 9 * 9 * 6 * 2) ; ++i)
    {
      uint  d, j, p, q, dq, s ;
      uint  st ;

      next_test() ;

      s = i / 2 ;

      d = p = s % 6 ;
      switch (p)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            st = nun ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts[nun]) ;
            st = nun ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts[ipv4_a]) ;
            st = ipv4_a ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts[ipv6_ga]) ;
            st = ipv6_ga ;
            break ;

          case 4:
            bgp_attr_pair_load(tap, ts[ipv6_la]) ;
            st = ipv6_la ;
            break ;

          case 5:
            bgp_attr_pair_load(tap, ts[ipv6_ga_la]) ;
            st = ipv6_ga_la ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 6) ;
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 9 ;

          switch (q)
            {
              case 0:
                dq = 0 ;        /* NULL event                   */
                break ;

              case 1:
                bgp_attr_pair_set_next_hop(tap, nh_none, NULL) ;
                st = nun ;
                dq = 1 ;        /* debounce if was nun          */
                break ;

              case 2:
                bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_a].ip.v4) ;
                st = ipv4_a ;
                dq = 2 ;        /* debounce if was ipv4_a       */
                break ;

              case 3:
                bgp_attr_pair_set_next_hop(tap, nh_ipv4, &tnh[ipv4_b].ip.v4) ;
                st = ipv4_b ;
                dq = 6 ;        /* will set value       */
                break ;

              case 4:           /* set 'ga'     */
                bgp_attr_pair_set_next_hop(tap, nh_ipv6_1,
                                                     &tnh[ipv6_ga].ip.v6[0]) ;
                if ((d == 3) || (d == 5))
                  dq = d ;      /* debounce if was ga or ga_la  */
                else
                  dq = 6 ;      /* set, otherwise               */

                switch (st)
                  {
                    case nun:
                    case ipv4_a:
                    case ipv4_b:
                    case ipv6_gn:
                    case ipv6_ga:
                    case ipv6_gb:
                      st = ipv6_ga ;
                      break ;

                    case ipv6_la:
                    case ipv6_ga_la:
                    case ipv6_gb_la:
                      st = ipv6_ga_la ;
                      break ;

                    case ipv6_lb:
                    case ipv6_ga_lb:
                    case ipv6_gb_lb:
                      st = ipv6_ga_lb ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 5:           /* set 'la'     */
                bgp_attr_pair_set_next_hop(tap, nh_ipv6_2,
                                                     &tnh[ipv6_la].ip.v6[1]) ;
                if ((d == 4) || (d == 5))
                  dq = d ;      /* debounce if was la or ga_la  */
                else
                  dq = 6 ;      /* set, otherwise               */

                switch (st)
                  {
                    case nun:
                    case ipv4_a:
                    case ipv4_b:
                    case ipv6_gn:
                    case ipv6_la:
                    case ipv6_lb:
                      st = ipv6_la ;
                      break ;

                    case ipv6_ga:
                    case ipv6_ga_la:
                    case ipv6_ga_lb:
                      st = ipv6_ga_la ;
                      break ;

                    case ipv6_gb:
                    case ipv6_gb_la:
                    case ipv6_gb_lb:
                      st = ipv6_gb_la ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 6:           /* clear 'lx'       */
                bgp_attr_pair_set_next_hop(tap, nh_ipv6_2, NULL) ;

                if ((d == 1) || (d == 3))
                  dq = d ;      /* debounce if was nun, or ga   */
                else
                  dq = 6 ;      /* set, otherwise               */

                switch (st)
                  {
                    case nun:
                    case ipv4_a:
                    case ipv4_b:
                      st = nun ;
                      break ;

                    case ipv6_gn:
                    case ipv6_ga:
                    case ipv6_gb:
                      break ;           /* no effect on state   */

                    case ipv6_la:
                    case ipv6_lb:
                      st = ipv6_gn ;
                      break ;

                    case ipv6_ga_la:
                    case ipv6_ga_lb:
                      st = ipv6_ga ;
                      break ;

                    case ipv6_gb_la:
                    case ipv6_gb_lb:
                      st = ipv6_gb ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 7:           /* set 'gb'             */
                bgp_attr_pair_set_next_hop(tap, nh_ipv6_1,
                                                       &tnh[ipv6_gb].ip.v6[0]) ;
                dq = 6 ;        /* will set value       */

                switch (st)
                  {
                    case nun:
                    case ipv4_a:
                    case ipv4_b:
                    case ipv6_gn:
                    case ipv6_ga:
                    case ipv6_gb:
                      st = ipv6_gb ;
                      break ;

                    case ipv6_la:
                    case ipv6_ga_la:
                    case ipv6_gb_la:
                      st = ipv6_gb_la ;
                      break ;

                    case ipv6_lb:
                    case ipv6_ga_lb:
                    case ipv6_gb_lb:
                      st = ipv6_gb_lb ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              case 8:           /* set 'lb'             */
                bgp_attr_pair_set_next_hop(tap, nh_ipv6_2,
                                                       &tnh[ipv6_lb].ip.v6[1]) ;
                dq = 6 ;        /* will set value       */

                switch (st)
                  {
                    case nun:
                    case ipv4_a:
                    case ipv4_b:
                    case ipv6_gn:
                    case ipv6_la:
                    case ipv6_lb:
                      st = ipv6_lb ;
                      break ;

                    case ipv6_ga:
                    case ipv6_ga_la:
                    case ipv6_ga_lb:
                      st = ipv6_ga_lb ;
                      break ;

                    case ipv6_gb:
                    case ipv6_gb_la:
                    case ipv6_gb_lb:
                      st = ipv6_gb_lb ;
                      break ;

                    default:
                      assert(false) ;
                  } ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (dq != 0))
            {
              if (d != dq)
                {
                  test_assert(tap->working == tap->scratch,
                              "expecting working value to have been changed: "
                              "d=%u, dq=%u, i=%u", d, dq, i) ;
                  d = 0 ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                                   "expecting change to have been debounced:"
                                   "d=%u, dq=%u, i=%u", d, dq, i) ;
                } ;
            } ;

          s = s / 9 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          test_assert(ts_t == ts[st],
                        "did NOT get the expected stored result for %s",
                                                                  ts_name[st]) ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets
   */
  for (i = 0 ; i < st_count ; ++i)
    {
      assert(ts[i] != NULL) ;
      test_set_unlock(ts[i], 2, ts_name[i]) ;
    } ;

  /* Finish up in th usual way -- reporting local error totals.
   */
  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_local_pref()/_clear_local_pref()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_local_pref(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_0, ts_1, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_local_pref()/_clear_local_pref()");

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert((ts_e->local_pref == 0) && !(ts_e->have & atb_local_pref),
                                             "expected to find NO local_pref") ;

  /* Set up ts_0.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_local_pref(tap, 0) ;
  ts_0 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_0), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_0->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_0->vhash.ref_count) ;
  test_assert(ts_0->have & atb_local_pref,
                                          "expected to have local_pref set") ;
  test_assert(ts_0->local_pref == 0,
                   "expected to have local_pref==0, got=%u", ts_0->local_pref) ;

  /* Set up ts_1.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_local_pref(tap, 1) ;
  ts_1 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_1), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_1->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_1->vhash.ref_count) ;
  test_assert(ts_1->have & atb_local_pref,
                                          "expected to have local_pref set") ;
  test_assert(ts_1->local_pref == 1,
                   "expected to have local_pref==1, got=%u", ts_1->local_pref) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states: new, empty attr_pair
   *                                           stored, with no local_pref
   *                                           stored, with local_pref == 0
   *                                           stored, with local_pref == 1
   *
   *   * apply one 4 actions: do nothing
   *                          clear local_pref
   *                          set local_pref == 0
   *                          set local_pref == 1
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_0) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_1) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_clear_local_pref(tap) ;
                break ;

              case 2:
                bgp_attr_pair_set_local_pref(tap, 0) ;
                break ;

              case 3:
                bgp_attr_pair_set_local_pref(tap, 1) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_0, "expected ts_0 for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_1, "expected ts_1 for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_0, 2, "ts_0") ;
  test_set_unlock(ts_1, 2, "ts_1") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_weight()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_weight(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_1, ts_x, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_weight()");

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert(ts_e->weight == 0, "expected weight=0, got=%u", ts_e->weight) ;

  /* Set up ts_1 == 1.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_weight(tap, 1) ;
  ts_1 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_1), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_1->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_1->vhash.ref_count) ;
  test_assert(ts_1->weight == 1,
                   "expected to have weight==1, got=%u", ts_1->weight) ;

  /* Set up ts_x = 666.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_weight(tap, 666) ;
  ts_x = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_x), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_x->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_x->vhash.ref_count) ;
  test_assert(ts_x->weight == 666,
                   "expected to have weight==666, got=%u", ts_x->weight) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states: new, empty attr_pair
   *                                           stored, with weight == 0
   *                                           stored, with weight == 1
   *                                           stored, with weight == 666
   *
   *   * apply one 4 actions: do nothing
   *                          set weight == 0
   *                          set weight == 1
   *                          set weight == 666
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_1) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_x) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_weight(tap, 0) ;
                break ;

              case 2:
                bgp_attr_pair_set_weight(tap, 1) ;
                break ;

              case 3:
                bgp_attr_pair_set_weight(tap, 666) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_1, "expected ts_1 for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_x, "expected ts_x for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_1, 2, "ts_1") ;
  test_set_unlock(ts_x, 2, "ts_x") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_med()/_clear_med()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_med(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_0, ts_1, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_med()/_clear_med()");

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert((ts_e->med == 0) && !(ts_e->have & atb_med),
                                             "expected to find NO med") ;

  /* Set up ts_0.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_med(tap, 0) ;
  ts_0 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_0), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_0->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_0->vhash.ref_count) ;
  test_assert(ts_0->have & atb_med, "expected to have med set") ;
  test_assert(ts_0->med == 0, "expected to have med==0, got=%u", ts_0->med) ;

  /* Set up ts_1.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_med(tap, 1) ;
  ts_1 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_1), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_1->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_1->vhash.ref_count) ;
  test_assert(ts_1->have & atb_med, "expected to have med set") ;
  test_assert(ts_1->med == 1, "expected to have med==1, got=%u", ts_1->med) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states: new, empty attr_pair
   *                                           stored, with no med
   *                                           stored, with med == 0
   *                                           stored, with med == 1
   *
   *   * apply one 4 actions: do nothing
   *                          clear med
   *                          set med == 0
   *                          set med == 1
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_0) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_1) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_clear_med(tap) ;
                break ;

              case 2:
                bgp_attr_pair_set_med(tap, 0) ;
                break ;

              case 3:
                bgp_attr_pair_set_med(tap, 1) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_0, "expected ts_0 for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_1, "expected ts_1 for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_0, 2, "ts_0") ;
  test_set_unlock(ts_1, 2, "ts_1") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_origin()/_clear_origin()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_origin(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_min, ts_max, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_origin()/_clear_origin()");

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert(ts_e->origin == BGP_ATT_ORG_UNSET,
                       "expected to have origin==%u, got=%u",
                                              BGP_ATT_ORG_UNSET, ts_e->origin) ;

  /* Set up ts_min == 0.
   */
  next_test() ;

  confirm(BGP_ATT_ORG_MIN == 0) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_origin(tap, BGP_ATT_ORG_MIN) ;
  ts_min = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_min), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_min->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                     ts_min->vhash.ref_count) ;
  test_assert(ts_min->origin == BGP_ATT_ORG_MIN,
                       "expected to have origin==%u, got=%u",
                                              BGP_ATT_ORG_MIN, ts_min->origin) ;

  /* Set up ts_max = 666 -- squashes to BGP_ATT_ORG_MAX
   */
  next_test() ;

  confirm(BGP_ATT_ORG_MAX < 666) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_origin(tap, 666) ;
  ts_max = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_max), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_max->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                     ts_max->vhash.ref_count) ;
  test_assert(ts_max->origin == BGP_ATT_ORG_MAX,
                       "expected to have origin==%u, got=%u",
                                              BGP_ATT_ORG_MAX, ts_max->origin) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states: new, empty attr_pair
   *                                           stored, with origin unset
   *                                           stored, with origin == min
   *                                           stored, with origin == max
   *
   *   * apply one 4 actions: do nothing
   *                          clear origin
   *                          set origin == min
   *                          set origin == max
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_min) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_max) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_clear_origin(tap) ;
                break ;

              case 2:
                bgp_attr_pair_set_origin(tap, BGP_ATT_ORG_MIN) ;
                break ;

              case 3:
                bgp_attr_pair_set_origin(tap, BGP_ATT_ORG_MAX) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_min, "expected ts_min for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_max, "expected ts_max for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_min, 2, "ts_min") ;
  test_set_unlock(ts_max, 2, "ts_max") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_atomic_aggregate()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_atomic_aggregate(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_0, ts_1, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_atomic_aggregate()");

  /* Set up ts_0 == false
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_0 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_0), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_0->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_0->vhash.ref_count) ;
  test_assert(!(ts_0->have & atb_atomic_aggregate),
                                            "expected atomic_aggregate=false") ;

  /* Set up ts_1 == true.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_atomic_aggregate(tap, true) ;
  ts_1 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_1), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_1->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_1->vhash.ref_count) ;
  test_assert(ts_1->have & atb_atomic_aggregate,
                                             "expected atomic_aggregate=true") ;

  /* Run test where:
   *
   *   * start with one of 3 attr_pair states: new, empty attr_pair
   *                                           stored, atomic_aggregate = false
   *                                           stored, atomic_aggregate = true
   *
   *   * apply one 3 actions: do nothing
   *                          set false
   *                          set true
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((3 * 3 * 3 * 3) * 3 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 3 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_0) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_1) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 3) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 3 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_atomic_aggregate(tap, false) ;
                break ;

              case 2:
                bgp_attr_pair_set_atomic_aggregate(tap, true) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 3 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_0, "expected ts_0 for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_1, "expected ts_1 for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_0, 2, "ts_0") ;
  test_set_unlock(ts_1, 2, "ts_1") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of bgp_attr_pair_set_originator_id()/_clear_originator_id()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_originator_id(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_0, ts_x, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_originator_id()/"
                                                    "_clear_originator_id()") ;

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert((ts_e->originator_id == 0) && !(ts_e->have & atb_originator_id),
                                          "expected to find NO originator_id") ;

  /* Set up ts_0 == 0.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_originator_id(tap, BGP_ATT_ORG_MIN) ;
  ts_0 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_0), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_0->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_0->vhash.ref_count) ;
  test_assert(ts_0->have & atb_originator_id,
                                         "expected to have originator_id set") ;
  test_assert(ts_0->originator_id == 0,
                       "expected to have originator_id==%u, got=%u",
                                                       0, ts_0->originator_id) ;

  /* Set up ts_x = 0x0A00000A
   */
  next_test() ;

  confirm(BGP_ATT_ORG_MAX < 666) ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_originator_id(tap, 0x0A00000A) ;
  ts_x = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_x), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_x->have & atb_originator_id,
                                         "expected to have originator_id set") ;
  test_assert(ts_x->originator_id == 0x0A00000A,
                       "expected to have originator_id==%u, got=%u",
                                              0x0A00000A, ts_x->originator_id) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states:
   *
   *      new, empty attr_pair
   *      stored, with originator_id unset
   *      stored, with originator_id == 0
   *      stored, with originator_id == 0x0A00000A
   *
   *   * apply one 4 actions: do nothing
   *                          clear originator_id
   *                          set originator_id == 0
   *                          set originator_id == 0x0A00000A
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_0) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_x) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_clear_originator_id(tap) ;
                break ;

              case 2:
                bgp_attr_pair_set_originator_id(tap, 0) ;
                break ;

              case 3:
                bgp_attr_pair_set_originator_id(tap, 0x0A00000A) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_0, "expected ts_0 for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_x, "expected ts_x for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_0, 2, "ts_0") ;
  test_set_unlock(ts_x, 2, "ts_x") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;



extern attr_set bgp_attr_pair_set_aggregator(attr_pair pair, as_t as,
                                                                 in_addr_t ip) ;

/*==============================================================================
 * Test of bgp_attr_pair_set_aggregator()
 *
 * If all goes well the test will not leak memory !
 */
static void
test_attr_pair_set_aggregator(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_set       ts_e, ts_1, ts_x, ts_t ;
  attr_pair_t    tap[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: bgp_attr_pair_set_aggregator()");

  /* Set up ts_e.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  ts_e = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_e), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_e->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_e->vhash.ref_count) ;
  test_assert(ts_e->aggregator_as == 0,
                             "expected aggregator_as=%u, got=%u",
                                                       0, ts_e->aggregator_as) ;
  test_assert(ts_e->aggregator_ip == 0,
                             "expected aggregator_ip=%u, got=%u",
                                                       0, ts_e->aggregator_ip) ;

  /* Set up ts_1 == 1 & 0x0A00000A.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_aggregator(tap, 1, 0x0A00000A) ;
  ts_1 = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_1), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_1->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_1->vhash.ref_count) ;
  test_assert(ts_1->aggregator_as == 1,
                             "expected aggregator_as=%u, got=%u",
                                                       1, ts_1->aggregator_as) ;
  test_assert(ts_1->aggregator_ip == 0x0A00000A,
                             "expected aggregator_ip=%u, got=%u",
                                              0x0A00000A, ts_1->aggregator_ip) ;

  /* Set up ts_x = 666 & 0x66000066.
   */
  next_test() ;

  bgp_attr_pair_load_new(tap) ;
  bgp_attr_pair_set_aggregator(tap, 666, 0x66000066) ;
  ts_x = bgp_attr_pair_store(tap) ;

  test_assert(vhash_is_set(ts_x), "expected stored attr_set after "
                                                     "bgp_attr_pair_store()") ;
  test_assert(ts_x->vhash.ref_count == 2,
              "expected refcount==2, but got %u after bgp_attr_pair_store()",
                                                       ts_x->vhash.ref_count) ;
  test_assert(ts_x->aggregator_as == 666,
                             "expected aggregator_as=%u, got=%u",
                                                     666, ts_x->aggregator_as) ;
  test_assert(ts_x->aggregator_ip == 0x66000066,
                             "expected aggregator_ip=%u, got=%u",
                                              0x66000066, ts_x->aggregator_ip) ;

  /* Run test where:
   *
   *   * start with one of 4 attr_pair states:
   *
   *       new, empty attr_pair
   *       stored, with aggregator unset (0, 0)
   *       stored, with aggregator ==   1, 0x0A00000A
   *       stored, with aggregator == 666, 0x66000066
   *
   *   * apply one 4 actions: do nothing
   *                          unset aggregator (0, 0)
   *                          set aggregator ==   1, 0x0A00000A
   *                          set aggregator == 666, 0x66000066
   *
   *     4 times, in all combinations
   *
   *   * final 2 actions: store and check get expected stored value
   *                      do nothing
   *
   *   * unload
   */
  for (i = 0 ; i < ((4 * 4 * 4 * 4) * 4 * 2) ; ++i)
    {
      uint d, j, q, s ;

      next_test() ;

      s = i / 2 ;

      d = s % 4 ;
      switch (d)
        {
          case 0:
            bgp_attr_pair_load_new(tap) ;
            break ;

          case 1:
            bgp_attr_pair_load(tap, ts_e) ;
            break ;

          case 2:
            bgp_attr_pair_load(tap, ts_1) ;
            break ;

          case 3:
            bgp_attr_pair_load(tap, ts_x) ;
            break ;

          default:
            assert(false) ;
        } ;

      s = (s / 4) ;
      q = d ;                   /* for s == 0   */
      for (j = 0 ; (j < 4) && (s != 0) ; ++j)
        {
          q = s % 4 ;

          switch (q)
            {
              case 0:
                break ;

              case 1:
                bgp_attr_pair_set_aggregator(tap, 0, rand()) ;
                break ;

              case 2:
                bgp_attr_pair_set_aggregator(tap, 1, 0x0A00000A) ;
                break ;

              case 3:
                bgp_attr_pair_set_aggregator(tap, 666, 0x66000066) ;
                break ;

              default:
                assert(false) ;
            } ;

          if ((d != 0) && (q != 0))
            {
              if (d != q)
                {
                  d = 0 ;
                  test_assert(tap->working == tap->scratch,
                               "expecting working value to have been changed") ;
                }
              else
                {
                  test_assert(tap->working == tap->stored,
                               "expecting change to have been debounced") ;
                } ;
            } ;

          s = s / 4 ;
        } ;

      if (i & 1)
        {
          ts_t = bgp_attr_pair_store(tap) ;

          switch (q)
            {
              case 0:
              case 1:
                test_assert(ts_t == ts_e, "expected ts_e for i=%u", i) ;
                break ;

              case 2:
                test_assert(ts_t == ts_1, "expected ts_1 for i=%u", i) ;
                break ;

              case 3:
                test_assert(ts_t == ts_x, "expected ts_x for i=%u", i) ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      bgp_attr_pair_unload(tap) ;
    } ;

  /* Finally, tear down the stored attribute sets.
   */
  test_set_unlock(ts_e, 2, "empty") ;
  test_set_unlock(ts_1, 2, "ts_1") ;
  test_set_unlock(ts_x, 2, "ts_x") ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test Utilities
 */

/*------------------------------------------------------------------------------
 * Unlock given attribute set, expecting the given count before doing so.
 *
 * If expected count is > 2, check that the count is as expected afterwards.
 */
static void
test_set_unlock(attr_set s, uint count, const char* name)
{
  test_assert(s->vhash.ref_count == count,
              "expected ref_count=%u, got=%u for %s attribute set",
                                             count, s->vhash.ref_count, name) ;
  bgp_attr_unlock(s) ;

  if (count > 2)
    {
      test_assert(s->vhash.ref_count == (count - 2),
                 "expected ref_count=%u after bgp_attr_unlock(), "
                            "got=%u for %s attribute set",
                                        (count - 2), s->vhash.ref_count, name) ;
    } ;
} ;
