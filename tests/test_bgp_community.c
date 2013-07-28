#include <misc.h>
#include <zebra.h>

#include "stdio.h"

#include "qlib_init.h"
#include "command.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"

/*==============================================================================
 * bgpd/bgp_community.c torture tests
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
enum { comm_max = 100 } ;      /* maximum length we test to !  */

typedef struct comm_list  comm_list_t ;
typedef struct comm_list* comm_list ;

struct comm_list
{
  uint  list_count ;
  community_t list[comm_max] ;          /* Original with duplicates etc. */

  uint  sorted_count ;
  community_t sorted[comm_max] ;        /* Sorted and dedupped           */
} ;

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_comm_simple(void) ;
static void test_comm_store(void) ;
static void test_comm_release(void) ;
static void test_comm_from_str(void) ;
static void test_comm_str(void) ;
static void test_comm_composite(void) ;
static void test_comm_add_list(void) ;
static void test_comm_clear(void) ;
static void test_comm_replace_list(void) ;
static void test_comm_del_list(void) ;
static void test_comm_out_prepare(void) ;
static void test_comm_text_vector(void) ;

static comm_list make_comm_list(uint count) ;
static comm_list perturb_comm_list(comm_list orginal) ;
static community_t drop_comm_list(comm_list cl) ;
static comm_list split_comm_list(comm_list cl, uint old, uint both) ;
static comm_list copy_comm_list(comm_list original) ;
static bool delete_comm_list(comm_list cl, comm_list cld) ;
static void show_delta(const community_t* got, const community_t* exp,
                                                                   uint count) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
  qlib_init_first_stage(0);     /* Absolutely first             */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start BGP Community Attribute testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  bgp_attr_start() ;            /* wind up the entire attribute store   */

  test_comm_simple() ;

  test_comm_store() ;

  test_comm_from_str() ;

  test_comm_str() ;

  test_comm_composite() ;

  test_comm_add_list() ;

  test_comm_clear() ;

  test_comm_replace_list() ;

  test_comm_del_list() ;

  test_comm_out_prepare() ;

  test_comm_text_vector() ;

  test_comm_release() ;         /* last -- releases stored[]            */

  bgp_attr_finish() ;           /* close it down again                  */

  fprintf(stderr, "Finished BGP Community Attribute testing") ;

  if (fail_count == 0)
    fprintf(stderr, " -- OK\n"
                    "...should now report NO remaining memory utilisation\n") ;
  else
    fprintf(stderr, " *** %u FAILURES\n", fail_count) ;

  host_finish() ;
  qexit(0, true /* mem_stats */) ;
}

/*------------------------------------------------------------------------------
 * Test Tables
 */

/*==============================================================================
 * Test coverage:
 *
 *  * attr_community_start()         -- main()
 *  * attr_community_finish()        -- main()
 *
 *  * attr_community_store()         -- test_comm_simple(), test_comm_store()
 *                                                            & test_comm_str()
 *  * attr_community_free()          -- test_comm_simple()
 *                                                       & test_comm_from_str()
 *  * attr_community_lock()          -- test_comm_store()
 *  * attr_community_release()       -- test_comm_store() & test_comm_str()
 *
 *  * attr_community_set()           -- test_comm_simple() etc.
 *
 *  * attr_community_out_prepare()   -- test_comm_out_prepare()
 *
 *  * attr_community_add_list()      -- test_comm_add_list()
 *  * attr_community_replace_list()  -- test_comm_replace_list()
 *  * attr_community_del_value()     -- test_comm_composite()
 *  * attr_community_del_list()      -- test_comm_del_list()
 *  * attr_community_drop_value()    -- used in attr_community_del_value()
 *
 *  * attr_community_clear()         -- test_comm_clear()
 *
 *  * attr_community_known()         -- test_comm_from_str()
 *
 *  * attr_community_match()         -- test_comm_composite()
 *  * attr_community_equal()         -- test_comm_composite()
 *
 *  * attr_community_from_str()      -- test_comm_from_str()
 *  * attr_community_str()           -- test_comm_str() & test_comm_from_str()
 *
 *  * attr_community_text_vector()   -- test_comm_text_vector()
 *
 *  * attr_community_print_all_vty() -- not tested
 */
enum { stored_count = 401 } ;

static attr_community stored[stored_count] ;
static comm_list      originals[stored_count] ;

/*==============================================================================
 * Test of simple attr_community stuff.
 *
 * For community list lengths from 0 to 100 (100 gives a >400 byte attribute),
 * four times:
 *
 *   * construct a random community list
 *
 *   * set the list and check contains required stuff
 *
 *   * free the attr_community -- so do attr_community_free().
 *
 *   * set the list again, store and check contents
 *
 *     checks that can store NULL and empty not-NULL and get the same thing.
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_comm_simple(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community construction and storage") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_community comm ;
      uint count ;
      bool ok ;

      next_test() ;

      if (i == 0)
        count = 0 ;
      else
        count = ((i - 1) % 100) + 1 ;

      /* Create an original community list, and then create an attr_community.
       *
       * Check that the result is exactly as expected.
       */
      originals[i] = make_comm_list(count) ;

      comm = attr_community_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      if (count == 0)
        {
          test_assert(comm == NULL,
                     "expected comm == NULL for an empty community list") ;
        }
      else
        {
          test_assert(comm != NULL,
                      "expected comm != NULL for a community list length=%u",
                                                                       count) ;
        } ;

      if (comm != NULL)
        {
          uint s_count = originals[i]->sorted_count ;

          ok = test_assert(comm->list.len == s_count,
                 "expected %u sorted/dedupped communities, got %u",
                                                      s_count, comm->list.len) ;

          if (ok && (s_count != 0))
            {
              ok = test_assert(memcmp(comm->list.body.v,
                                      originals[i]->sorted, s_count * 4) == 0,
                                          "community list is not as expected") ;
              if (!ok)
                show_delta((const community_t*)comm->list.body.v,
                                                originals[i]->sorted, s_count) ;
            } ;
        } ;

      /* Free and then recreate -- so have called free !
       */
      attr_community_free(comm) ;

      assert(count == originals[i]->list_count) ;
      comm = attr_community_set((byte*)(originals[i]->list), count) ;

      /* Now store the community list.
       *
       * At this point, for count == 0 we have a NULL community list -- stick
       * in test for storing non-NULL but empty one, too.
       */
      if (count == 0)
        {
          assert(comm == NULL) ;

          stored[0] = attr_community_store(NULL) ;

          test_assert(stored[0] == NULL,
              "expect NULL when storing a NULL attr_community") ;

          comm = attr_community_new(community_list_embedded_size) ;
          test_assert(comm->list.body.v == comm->embedded_list,
                                     "expected community list to be embedded") ;

          stored[0] = attr_community_store(comm) ;
          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_community") ;

          comm = attr_community_new(community_list_embedded_size + 1) ;
          test_assert(comm->list.body.v != comm->embedded_list,
                               "did NOT expect community list to be embedded") ;

          stored[0] = attr_community_store(comm) ;
          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_community") ;
        }
      else
        {
          attr_community s_comm ;
          uint s_count ;

          assert(comm != NULL) ;

          stored[i] = s_comm = attr_community_store(comm) ;
          s_count = originals[i]->sorted_count ;

          test_assert(s_comm == comm,
                                "expect to store the original attr_community") ;

          test_assert(s_comm->stored,
                                  "expect to stored community to be 'stored'") ;

          test_assert(s_comm->vhash.ref_count == 2,
                "expected reference count == 2 after attr_community_store(), "
                                           "got=%u", s_comm->vhash.ref_count) ;

          ok = test_assert(s_comm->list.len == s_count,
                             "expected community length %u, got %u", s_count,
                                                            s_comm->list.len) ;

          if (s_count <= community_list_embedded_size)
            test_assert(s_comm->list.body.v == s_comm->embedded_list,
                    "expect count of %u to be held in embedded body", s_count) ;

          if (ok && (s_count != 0))
            {
              ok = test_assert(memcmp(s_comm->list.body.v,
                                    originals[i]->sorted, s_count * 4) == 0,
                                   "stored community list is not as expected") ;
              if (!ok)
                show_delta((const community_t*)s_comm->list.body.v,
                                                originals[i]->sorted, s_count) ;
            } ;
        } ;

    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_community_store().
 *
 *   * create new copy of each original, then release
 *
 *     tests release of not-stored value and release of NULL
 *
 *   * create another new copy of each original, and store it.
 *
 *     should find existing stored value and increment its count.
 *
 *   * do attr_community_lock() -- ref count should be increased
 *
 *   * do attr_community_release(), twice -- ref count should be reduced
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_comm_store(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_store") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_community comm, s_comm ;

      next_test() ;

      /* Create an attr_community, starting from NULL
       *
       * Release it again -- to test release of not-stored and NULL.
       */
      comm = attr_community_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      if (comm != NULL)
        test_assert(comm->list.len == originals[i]->sorted_count,
                             "expected community length %u, got %u",
                             originals[i]->sorted_count, comm->list.len) ;
      else
        test_assert(originals[i]->sorted_count == 0,
                 "did NOT expect NULL community, since length=%u",
                                                   originals[i]->sorted_count) ;

      attr_community_release(comm) ;

      /* Create an attr_community, starting from NULL
       *
       * Store it and check we get the previously stored value.
       */
      comm = attr_community_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      s_comm = attr_community_store(comm) ;

      test_assert(s_comm == stored[i],
                           "expected to find previously stored attr_community") ;

      if (s_comm == NULL)
        continue ;

      test_assert(s_comm->stored,
                                "expect to stored community to be 'stored'") ;

      test_assert(s_comm->vhash.ref_count == 4,
            "expected reference count == 4 after second attr_community_store(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      /* Lock and check result
       */
      attr_community_lock(s_comm) ;

      test_assert(s_comm->vhash.ref_count == 6,
            "expected reference count == 6 after attr_community_lock(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      /* Release twice and check result
       */
      attr_community_release(s_comm) ;
      attr_community_release(s_comm) ;

      test_assert(s_comm->vhash.ref_count == 2,
            "expected reference count == 2 after attr_community_release(), "
                                       "got=%u", s_comm->vhash.ref_count) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_community_out_release().
 *
 * For all stored attr_community:
 *
 *   * check that the reference count is as expected.
 *
 *   * release
 *
 * Leaves the stored array empty.
 */
static void
test_comm_release(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_out_release()") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_community s_comm ;

      next_test() ;

      s_comm = stored[i] ;

      if (s_comm != NULL)
        test_assert(s_comm->vhash.ref_count == 2,
           "expected reference count == 2 before last attr_community_release(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      stored[i] = attr_community_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_community_from_str() & attr_community_known().
 *
 */
typedef struct comm_str_test  comm_str_test_t ;
typedef const struct comm_str_test* comm_str_test ;

struct comm_str_test
{
  const char*  str ;

  attr_community_type_t act ;

  bool         known ;
  attr_community_state_t state ;

  uint         count ;
  community_t  list[6] ;
};

static const comm_str_test_t  com_str_tests[] =
  {
      /* Empty string -- check for whitespace
       */
      { .str      = "",
        .act      = act_empty,
        .known    = true,
        .state    = 0,
      },
      { .str      = " \n \t \r ",
        .act      = act_empty,
        .known    = true,
        .state    = 0,
      },

      /* Simple numerics and edge cases -- invalids
       */
      { .str      = "0",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0 },
        .known    = true,
        .state    = 0,
      },
      { .str      = "  0:0  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0 },
        .known    = true,
        .state    = 0,
      },
      { .str      = " 2529:1\t165740544  \r\n",
        .act      = act_simple,
        .count    = 2,
        .list     = { 165740544, 165740545 },
        .known    = true,
        .state    = 0,
      },
      { .str      = "2529:0001 000000000000000002529:0000000",
        .act      = act_simple,
        .count    = 2,
        .list     = { 165740544, 165740545 },
        .known    = true,
        .state    = 0,
      },
      { .str      = "  0:65535  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0x0000FFFF  },
        .known    = true,
        .state    = 0,
      },
      { .str      = "  0:65536  ",
        .act      = act_invalid,
      },
      { .str      = "  65535:0  ",
        .act      = act_simple,
        .count    = 1,
        .known    = true,
        .state    = 0,
        .list     = { 0xFFFF0000 },
      },
      { .str      = "  65535:65535  ",
        .act      = act_simple,
        .count    = 1,
        .known    = true,
        .state    = 0,
        .list     = { 0xFFFFFFFF },
      },
      { .str      = "  65535:65536  ",
        .act      = act_invalid,
      },
      { .str      = "  65536:0  ",
        .act      = act_invalid,
      },
      { .str      = "  65536:65535  ",
        .act      = act_invalid,
      },
      { .str      = "  65536:65536  ",
        .act      = act_invalid,
      },
      { .str      = "  4294967295  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0xFFFFFFFF },
      },
      { .str      = "  4294967296  ",
        .act      = act_invalid,
      },
      { .str      = "  0x0:0xFFFF  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0x0000FFFF  },
      },
      { .str      = "  0:0x10000  ",
        .act      = act_invalid,
      },
      { .str      = "  0xFFFF:0  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0xFFFF0000 },
        .known    = true,
        .state    = 0,
      },
      { .str      = "  0xFFFF:0xFFFF  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0xFFFFFFFF },
        .known    = true,
        .state    = 0,
      },
      { .str      = "  0xFFFF:0x10000  ",
        .act      = act_invalid,
      },
      { .str      = "  0x10000:0  ",
        .act      = act_invalid,
      },
      { .str      = "  0x10000:0xFFFF  ",
        .act      = act_invalid,
      },
      { .str      = "  0x10000:0x10000  ",
        .act      = act_invalid,
      },
      { .str      = "  0xFFFF_FFFF  ",
        .act      = act_simple,
        .count    = 1,
        .list     = { 0xFFFFFFFF },
      },
      { .str      = "  0x1_0000_0000  ",
        .act      = act_invalid,
      },
      { .str      = "  999999999999999999999999999999999999999999999999  ",
        .act      = act_invalid,
      },
      { .str      = "  999999999999999999999999999999999999999999999999:0  ",
        .act      = act_invalid,
      },
      { .str      = "  0:999999999999999999999999999999999999999999999999  ",
        .act      = act_invalid,
      },
      { .str      = "  123?4  ",
        .act      = act_invalid,
      },
      { .str      = "  123?4:0000  ",
        .act      = act_invalid,
      },
      { .str      = "  1234:0000?  ",
        .act      = act_invalid,
      },
      { .str      = "  1234:0000 ?  ",
        .act      = act_invalid,
      },

      /* The well-knowns
       */
      { .str      = "no-export",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_EXPORT },
        .known    = true,
        .state    = cms_no_export,
      },
      { .str      = "no-advertise",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_ADVERTISE },
        .known    = true,
        .state    = cms_no_advertise,
      },
      { .str      = "local-AS",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_LOCAL_AS },
        .known    = true,
        .state    = cms_local_as,
      },
      { .str      = "nO-e",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_EXPORT },
        .known    = true,
        .state    = cms_no_export,
      },
      { .str      = "No-a",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_ADVERTISE },
        .known    = true,
        .state    = cms_no_advertise,
      },
      { .str      = "local-as",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_LOCAL_AS },
        .known    = true,
        .state    = cms_local_as,
      },
      { .str      = "L",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_LOCAL_AS },
        .known    = true,
        .state    = cms_local_as,
      },
      { .str      = "nO-eXp",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_EXPORT },
        .known    = true,
        .state    = cms_no_export,
      },
      { .str      = "No-aDverT",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_NO_ADVERTISE },
        .known    = true,
        .state    = cms_no_advertise,
      },
      { .str      = "loCa",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_LOCAL_AS },
        .known    = true,
        .state    = cms_local_as,
      },
      { .str      = "no-adv 3 nO-eXp 2 loCa 2 no-export 1 No-aDverT local-as",
        .count    = 6,
        .list     = { 1,
                      2,
                      3,
                      BGP_ATT_COM_NO_EXPORT,
                      BGP_ATT_COM_NO_ADVERTISE,
                      BGP_ATT_COM_LOCAL_AS
                    },
        .known    = true,
        .state    = cms_no_export | cms_no_advertise | cms_local_as,
      },
      { .str      = "loCa",
        .act      = act_simple,
        .count    = 1,
        .list     = { BGP_ATT_COM_LOCAL_AS },
        .known    = true,
        .state    = cms_local_as,
      },
      { .str      = "no-",
        .act      = act_invalid,
      },
      { .str      = "no",
        .act      = act_invalid,
      },
      { .str      = "no-export?",
        .act      = act_invalid,
      },
      { .str      = "no-advertize",
        .act      = act_invalid,
      },
      { .str      = "local-AS!",
        .act      = act_invalid,
      },

      /* additive
       */
      { .str      = "additive",
        .act      = act_invalid,
      },
      { .str      = "ad",
        .act      = act_invalid,
      },

      { .str      = "1 additive",
        .act      = act_additive,
        .count    = 1,
        .list     = { 1 },
      },
      { .str      = "no-e 1 ad",
        .act      = act_additive,
        .count    = 2,
        .list     = { 1, BGP_ATT_COM_NO_EXPORT },
      },
      { .str      = "2 no-a add",
        .act      = act_additive,
        .count    = 2,
        .list     = { 2, BGP_ATT_COM_NO_ADVERTISE },
      },
      { .str      = "0x000000003 local-AS 3 0:3 addit",
        .act      = act_additive,
        .count    = 2,
        .list     = { 3, BGP_ATT_COM_LOCAL_AS },
      },
      { .str      = "add 1",
        .act      = act_invalid,
      },
      { .str      = "add no-export",
        .act      = act_invalid,
      },
      { .str      = "add none",
        .act      = act_invalid,
      },
      { .str      = "internet additive",
        .act      = act_invalid,
      },
      { .str      = "any additive",
        .act      = act_invalid,
      },

      /* none
       */
      { .str      = "none",
        .act      = act_none,
      },
      { .str      = "non",
        .act      = act_none,
      },
      { .str      = "no",
        .act      = act_invalid,
      },
      { .str      = "0 non",
        .act      = act_invalid,
      },
      { .str      = "non 0",
        .act      = act_invalid,
      },
      { .str      = "no-export non",
        .act      = act_invalid,
      },
      { .str      = "non no-advertise",
        .act      = act_invalid,
      },
      { .str      = "local-as non no-advertise",
        .act      = act_invalid,
      },

      /* any
       */
      { .str      = "any",
        .act      = act_any,
      },
      { .str      = "an",
        .act      = act_any,
      },
      { .str      = "a",
        .act      = act_invalid,
      },
      { .str      = "0 any",
        .act      = act_invalid,
      },
      { .str      = "an 0",
        .act      = act_invalid,
      },
      { .str      = "no-export an",
        .act      = act_invalid,
      },
      { .str      = "any no-advertise",
        .act      = act_invalid,
      },
      { .str      = "local-as any no-advertise",
        .act      = act_invalid,
      },

      /* internet
       */
      { .str      = "internet",
        .act      = act_internet,
      },
      { .str      = "I",
        .act      = act_internet,
      },
      { .str      = "0 i",
        .act      = act_invalid,
      },
      { .str      = "in 0",
        .act      = act_invalid,
      },
      { .str      = "no-export Int",
        .act      = act_invalid,
      },
      { .str      = "inter no-advertise",
        .act      = act_invalid,
      },
      { .str      = "local-as intern no-advertise",
        .act      = act_invalid,
      },

      /* Additional tests for attr_community_known()
       */
      { .str      = "no-e no-a 0xFFFF_FF00",
        .count    = 3,
        .list     = { 0xFFFFFF00,
                      BGP_ATT_COM_NO_EXPORT,
                      BGP_ATT_COM_NO_ADVERTISE,
                    },
        .known    = true,
        .state    = cms_no_export | cms_no_advertise,
      },
      { .str      = "no-e local 0xFFFF_FF04",
        .count    = 3,
        .list     = { BGP_ATT_COM_NO_EXPORT,
                      BGP_ATT_COM_LOCAL_AS,
                      0xFFFFFF04,
                    },
        .known    = true,
        .state    = cms_no_export | cms_local_as,
      },
      { .str      = "0xFFFF_FF04 no-a local 0xFFFF_FF00 0xFFFF_FFFF",
        .count    = 5,
        .list     = { 0xFFFFFF00,
                      BGP_ATT_COM_NO_ADVERTISE,
                      BGP_ATT_COM_LOCAL_AS,
                      0xFFFFFF04,
                      0xFFFFFFFF,
                    },
        .known    = true,
        .state    = cms_no_advertise | cms_local_as,
      },

      /* End
       */
      { .str      = NULL }
  };

/*------------------------------------------------------------------------------
 * Test of attr_community_from_str() & attr_community_known().
 *
 * Run the strings from the table above and check get what we expect.
 */
static void
test_comm_from_str(void)
{
  uint fail_count_was, test_count_was ;
  comm_str_test n_test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_from_str()") ;

  n_test = com_str_tests ;

  while (n_test->str != NULL)
    {
      comm_str_test test ;
      attr_community comm ;
      attr_community_type_t    act ;
      bool ok ;

      next_test() ;
      test   = n_test ;
      n_test = test + 1 ;

      comm = attr_community_from_str (test->str, &act) ;

      test_assert(test->act == act,
                                  "expected act=%u, but got=%u\n"
                                  "   for: '%s'", test->act, act, test->str) ;

      switch (act)
        {
          case act_simple:      /* nothing special, not empty           */
            test_assert(comm != NULL,
                              "expect NON-NULL comm with act_simple\n"
                              "   for: '%s'",test->str) ;
            break ;

          case act_additive:    /* 'additive'                           */
            test_assert(comm != NULL,
                              "expect NON-NULL comm with act_additive\n"
                              "   for: '%s'",test->str) ;
            break ;

          case act_none:        /* 'none'                               */
          case act_any:         /* 'any'                                */
          case act_internet:    /* 'internet'                           */
          case act_empty:       /* completely empty string              */
          case act_invalid:     /* invalid string                       */
            test_assert(comm == NULL,
                              "expect NULL comm with act=%u\n"
                              "   for: '%s'", act, test->str) ;
            break ;

          default:
            assert(false) ;
        } ;

      if (comm != NULL)
        {
          test_assert(test->count == comm->list.len,
              "expected %u communities, but got %u\n"
              "   for: '%s'", test->count, comm->list.len, test->str) ;

          if ((test->count != 0) && (test->count == comm->list.len))
            {
              ok = test_assert(memcmp(comm->list.body.v, test->list,
                                                       test->count * 4) == 0,
                         "community list is not as expected\n"
                         "   for: '%s'", test->str) ;
              if (!ok)
                show_delta((const community_t*)comm->list.body.v,
                                                      test->list, test->count) ;
            } ;
        } ;

      if (test->known)
        {
          attr_community_state_t state ;

          if (comm != NULL)
            {
              test_assert(!(comm->state & cms_known),
                  "do NOT expect cms_known after attr_community_from_str()") ;

              comm->state |= (rand() & (cms_no_export | cms_no_advertise
                                                      | cms_local_as)) ;
            } ;

          state = attr_community_known(comm) ;

          test_assert(state == test->state,
              "expected state=0x%02x after attr_community_known(), got=%02x\n"
              "   for: '%s'", test->state, state, test->str) ;
        } ;

      attr_community_free(comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_community_str().
 *
 * Generate attr_community objects at a number of random lengths, create
 * string, create attr_community from the string, check that the result is
 * the same by storing.
 */
static void
test_comm_str(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_str()") ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint count ;
      comm_list      cl ;
      attr_community comm ;
      attr_community s_comm ;
      const char*    str ;
      attr_community_type_t    act ;
      bool ok ;

      next_test() ;

      count = rand() % ((tc % 100) + 1) ;

      cl = make_comm_list(count) ;

      comm = attr_community_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_community_store(comm) ;

      if (comm == NULL)
        {
          test_assert(s_comm == NULL,
              "expected NULL attr_community after attr_community_store(NULL)") ;
        }
      else
        {
          test_assert(s_comm->stored,
                            "expected attr_community to be 'stored' "
                                               "after attr_community_store()") ;
        } ;

      str = attr_community_str(s_comm) ;

      if (s_comm == NULL)
        test_assert(*str == '\0',
            "expected empty string from attr_community_str(NULL)") ;
      else
        test_assert(s_comm->state & cms_string,
               "expected to find string state set after attr_community_str()") ;

      comm = attr_community_from_str(str, &act) ;

      switch (act)
        {
          case act_simple:      /* nothing special, not empty           */
            ok = test_assert(comm != NULL,
                              "expect NON-NULL comm with act_simple\n"
                              "   for: '%s'", str) ;
            break ;

          case act_empty:       /* completely empty string              */
            ok = test_assert(comm == NULL,
                              "expect NULL comm with act_empty\n"
                              "   for: '%s'", str) ;
            break ;

          case act_additive:
          case act_none:
          case act_any:
          case act_internet:
          case act_invalid:     /* invalid string                       */
            test_assert(false, "did NOT expect act=%u\n"
                               "   for: '%s'", act, str) ;
            ok = false ;
            break ;

          default:
            assert(false) ;
        } ;

      if (ok)
        {
          comm = attr_community_store(comm) ;

          test_assert(comm == s_comm,
              "did not get expected stored attr_community after "
              "attr_community_str() and attr_community_from_str()") ;
        } ;

      attr_community_release(comm) ;
      attr_community_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Composite test for:
 *
 *  * attr_community_del_value()
 *  * attr_community_match()
 *  * attr_community_equal()
 *
 * For a variety of random lengths of community attribute:
 *
 *  * check that attr_community is equal to itself and matches itself.
 *
 *  * store the test community.
 *
 *  * modify one entry in the original community and check that it does not
 *    equal and does not match the test community.
 *
 *    The equal check stops very quickly if the attr_community lengths differ,
 *    so this check ensures that the scan through the body of the attr_community
 *    does the job !
 *
 *  * for each community value in the original list (in the original random
 *    order, and with the original repeats):
 *
 *      - delete the value from the working attr_community
 *
 *        check that the value has been deleted cleanly.
 *
 *      - check that the test community if matched by the working one.
 *
 *      - check that the test community is not equal to the working one
 *
 *      - check that the working community is not matched by the test one.
 *
 * This should test the three functions against each other.
 */
static void
test_comm_composite(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  attr_community comm ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: composite attr_community_match/_equal/_del_value") ;

  /* Check that empty and NULL are the same for attr_community_match() and
   * for attr_community_equal).
   */
  comm = attr_community_new(0) ;

  next_test() ;

  test_assert(attr_community_match(NULL, NULL),
                      "expect a NULL attr_community to match a NULL one") ;
  test_assert(attr_community_match(comm, NULL),
                      "expect an empty attr_community to match a NULL one") ;
  test_assert(attr_community_match(NULL, comm),
                      "expect a NULL attr_community to match an empty one") ;
  test_assert(attr_community_match(comm, comm),
                      "expect an empty attr_community to match an empty one") ;

  test_assert(attr_community_equal(NULL, NULL),
                      "expect a NULL attr_community to equal a NULL one") ;
  test_assert(attr_community_equal(comm, NULL),
                      "expect an empty attr_community to equal a NULL one") ;
  test_assert(attr_community_equal(NULL, comm),
                      "expect a NULL attr_community to equal an empty one") ;
  test_assert(attr_community_equal(comm, comm),
                      "expect an empty attr_community to equal an empty one") ;

  attr_community_free(comm) ;

  /* Run main test for a number of community list lengths
   */
  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint count ;
      comm_list      cl, pcl ;
      attr_community s_comm, t_comm ;
      bool ok ;

      next_test() ;

      count = rand() % ((tc % 100) + 1) ;
      cl = make_comm_list(count) ;

      comm = attr_community_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_community_store(comm) ;
      comm = attr_community_set((byte*)cl->list, cl->list_count) ;

      /* So we have a stored s_comm built from cl, and a second copy comm,
       * also built from cl -- and those should both match and be equal to
       * each other.
       *
       * NB: for empty community list expect both to be NULL
       */
      test_assert(attr_community_match(s_comm, comm),
                                   "expect an attr_community to match itself") ;
      test_assert(attr_community_match(comm, s_comm),
                                   "expect an attr_community to match itself") ;

      test_assert(attr_community_equal(s_comm, comm),
                                   "expect an attr_community to equal itself") ;
      test_assert(attr_community_equal(comm, s_comm),
                                   "expect an attr_community to equal itself") ;

      /* If the community list is not empty, create a new list which is the
       * same as the one we have, except for one entry.
       *
       * Note that if the comm_list is empty we should have NULL comm and
       * s_comm, and that perturb_comm_list creates a comm_list with one entry.
       * So we test match and equal of an empty list with a non-empty one.
       *
       * The result should not match or be matched by the stored community, and
       * will not be equal to it, either.
       */
      pcl = perturb_comm_list(cl) ;
      if (cl->list_count != 0)
        assert( (cl->list_count   == pcl->list_count) &&
                (cl->sorted_count == pcl->sorted_count) ) ;
      else
        assert( (pcl->list_count == 1) && (pcl->sorted_count == 1) ) ;

      t_comm = attr_community_set((byte*)pcl->list, pcl->list_count) ;

      if (s_comm != NULL)
        assert(t_comm->list.len == s_comm->list.len) ;
      else
        assert(t_comm->list.len == 1) ;

      test_assert(!attr_community_match(s_comm, t_comm),
                "do NOT expect an attr_community to match perturbed copy") ;
      if (s_comm != NULL)
        test_assert(!attr_community_match(t_comm, s_comm),
                "do NOT expect a perturbed copy to match attr_community") ;
      else
        test_assert(attr_community_match(t_comm, s_comm),
                "expect an empty attr_community to match anything") ;

      test_assert(!attr_community_equal(s_comm, t_comm),
                "do NOT expect an attr_community to equal perturbed copy") ;

      attr_community_free(t_comm) ;

      /* Dropping one entry at a time:
       *
       *   * make sure that each drop changes the working attr_community as
       *     expected.
       *
       *   * that the new working community matches the stored community
       *
       *   * that the new working community is not matched by the stored
       *     community
       *
       *   * that the new working community does not equal the stored community
       */
      while (cl->list_count > 0)
        {
          community_t drop ;

          /* Update cl by dropping one community value.
           *
           * Drop that value from the working community and check result
           */
          drop = drop_comm_list(cl) ;

          comm = attr_community_del_value(comm, drop) ;

          ok = test_assert(comm->list.len == cl->sorted_count,
               "expected length=%u, got=%u after r attr_community_del_value()",
                                            cl->sorted_count, comm->list.len) ;
          if (ok && (cl->sorted_count != 0))
            {
              ok = test_assert(memcmp(comm->list.body.v, cl->sorted,
                                                    cl->sorted_count * 4) == 0,
               "did not get expected result after attr_community_del_value()") ;
              if (!ok)
                show_delta((const community_t*)comm->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
            } ;

          /* Check that:
           *
           *   * working community matches stored one
           *
           *   * stored community does not match the working one
           *
           *   * working and stored communities are not equal
           */
          test_assert(!attr_community_equal(comm, s_comm),
               "do NOT expect stored attr_community to match working") ;

          test_assert(attr_community_match(s_comm, comm),
               "expect working to match stored attr_community") ;

          test_assert(!attr_community_equal(comm, s_comm),
               "do NOT expect working and stored attr_community to be equal") ;
          test_assert(!attr_community_equal(s_comm, comm),
               "do NOT expect working and stored attr_community to be equal") ;
       } ;

      attr_community_release(comm) ;
      attr_community_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_add_list()
 *
 * For a variety of random lengths of community attribute:
 *
 *   * create a stored and a not stored copy of the list.
 *
 *   * check that adding NULL or empty list makes no difference.
 *
 *   * check that adding to NULL creates a new copy
 *
 *   * check that adding the not-stored to the stored, creates a new
 *     copy.
 *
 *   * check that adding stored to the not-stored has no effect
 *
 *   * split the list in various ways and check that when part of list to
 *     stored and not-stored other part, get the original.
 *
 *     When splitting the list:  x / 10   goes to list to be added to
 *                               y / 10   goes to both lists
 *                               x / 10   goes to list to add
 *
 *     so tries all combinations of partial and no overlap in the lists being
 *     added together, and adding nothing and adding to nothing.
 */
static void
test_comm_add_list(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  attr_community comm, e_comm ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_add_list") ;

  e_comm = attr_community_new(0) ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint count ;
      comm_list      cl ;
      attr_community s_comm, t_comm ;
      uint o ;
      bool ok ;

      next_test() ;

      count = tc % 101 ;
      cl = make_comm_list(count) ;

      /* Create a stored s_comm built from cl, and a second copy comm,
       * also built from count -- and those should both be equal to each other.
       */
      comm = attr_community_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_community_store(comm) ;
      comm = attr_community_set((byte*)cl->list, cl->list_count) ;

      test_assert(attr_community_equal(comm, s_comm),
                                         "expect comm and s_comm to be equal") ;

      /* Adding NULL or empty makes no difference.
       */
      t_comm = attr_community_add_list(comm, NULL) ;
      test_assert(t_comm == comm,
                            "expect adding NULL to comm to return comm") ;
      test_assert(attr_community_equal(comm, s_comm),
                   "do NOT expect adding NULL to make any difference to comm") ;

      t_comm = attr_community_add_list(s_comm, NULL) ;
      test_assert(t_comm == s_comm,
                            "expect adding NULL to s_comm to return s_comm") ;
      test_assert(attr_community_equal(comm, s_comm),
                 "do NOT expect adding NULL to make any difference to s_comm") ;

      t_comm = attr_community_add_list(comm, e_comm) ;
      test_assert(t_comm == comm,
                            "expect adding empty to comm to return comm") ;
      test_assert(attr_community_equal(comm, s_comm),
                   "do NOT expect adding empty to make any difference to comm") ;

      t_comm = attr_community_add_list(s_comm, e_comm) ;
      test_assert(t_comm == s_comm,
                            "expect adding empty to s_comm to return s_comm") ;
      test_assert(attr_community_equal(comm, s_comm),
               "do NOT expect adding empty to make any difference to s_comm") ;

      /* Adding to NULL should return a new attr_community equal to that added.
       */
      t_comm = attr_community_add_list(NULL, comm) ;

      if (comm != NULL)
        test_assert(t_comm != comm,
                "expect adding not-NULL to NULL to create new attr_community") ;
      else
        test_assert(t_comm == comm,
                            "expect adding NULL to NULL to return NULL") ;
      test_assert(attr_community_equal(t_comm, comm),
                              "expect adding to NULL to copy original comm") ;

      attr_community_free(t_comm) ;

      t_comm = attr_community_add_list(NULL, s_comm) ;

      if (s_comm != NULL)
        test_assert(t_comm != s_comm,
                "expect adding not-NULL to NULL to create new attr_community") ;
      else
        test_assert(t_comm == s_comm,
                            "expect adding NULL to NULL to return NULL") ;
      test_assert(attr_community_equal(t_comm, s_comm),
                              "expect adding to NULL to copy original s_comm") ;

      attr_community_free(t_comm) ;

      /* A number of times, split the original comm_list, to create two
       * attr_community values, which contain some part of the original, and
       * have some degree of overlap, such that when added together should be
       * the give the original again.
       *
       * ~ o / 10 of list remains in original list
       * ~ b / 10 of list is reproduced in both lists.
       *
       */
      for (o = 0 ; o <= 10 ; ++o)
        {
          uint b ;

          for (b = 0 ; b <= (10 - o) ; ++b)
            {
              comm_list cla, clb ;
              attr_community comm_a, comm_b, comm_sa ;

              next_test() ;

              cla = copy_comm_list(cl) ;
              clb = split_comm_list(cla, o, b) ;

              comm_a = attr_community_set((byte*)cla->list, cla->list_count) ;
              comm_sa = attr_community_store(comm_a) ;
              comm_a = attr_community_set((byte*)cla->list, cla->list_count) ;
              comm_b = attr_community_set((byte*)clb->list, clb->list_count) ;

              if (cla->list_count == 0)
                assert(comm_a == NULL) ;
              else
                assert( (comm_a->list.len == cla->sorted_count) &&
                        (memcmp(comm_a->list.body.v, cla->sorted,
                                                cla->sorted_count * 4) == 0) ) ;

              if (clb->list_count == 0)
                assert(comm_b == NULL) ;
              else
                assert( (comm_b->list.len == clb->sorted_count) &&
                        (memcmp(comm_b->list.body.v, clb->sorted,
                                                clb->sorted_count * 4) == 0) ) ;

              comm_a = attr_community_add_list(comm_a, comm_b) ;

              if (cl->list_count == 0)
                test_assert(comm_a == NULL,
                    "expect attr_community_add_list() to give NULL when "
                                                         "original was empty") ;
              else
                {
                  ok = test_assert(comm_a->list.len == cl->sorted_count,
                      "expected original length=%u after "
                          "attr_community_add_list(), got %u",
                                          cl->sorted_count, comm_a->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(comm_a->list.body.v, cl->sorted,
                                                cl->sorted_count * 4) == 0,
                          "expected original contents after "
                                                 "attr_community_add_list()") ;
                      if (!ok)
                        show_delta((const community_t*)comm_a->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
                    } ;
                } ;

              attr_community_free(comm_a) ;

              comm_a = attr_community_add_list(comm_sa, comm_b) ;

              if (cl->list_count == 0)
                test_assert(comm_a == NULL,
                    "expect attr_community_add_list() to give NULL when "
                                                         "original was empty") ;
              else
                {
                  if (clb->list_count != 0)
                    test_assert(comm_sa != comm_a,
                      "expect a new attr_community after "
                                            "attr_community_add_list(stored)") ;
                  else
                    test_assert(comm_sa == comm_a,
                      "expect same new attr_community after "
                                "attr_community_add_list(stored, NULL/empty)") ;

                  ok = test_assert(comm_a->list.len == cl->sorted_count,
                      "expected original length=%u after "
                          "attr_community_add_list(), got %u",
                                          cl->sorted_count, comm_a->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(comm_a->list.body.v, cl->sorted,
                                                cl->sorted_count * 4) == 0,
                          "expected original contents after "
                                                 "attr_community_add_list()") ;
                      if (!ok)
                        show_delta((const community_t*)comm_a->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
                    } ;
                } ;

              attr_community_release(comm_sa) ;
              if (comm_a != comm_sa)
                attr_community_free(comm_a) ;
              attr_community_free(comm_b) ;

              free(cla) ;
              free(clb) ;
            } ;
        } ;

      attr_community_release(comm) ;
      attr_community_release(s_comm) ;
    } ;

  attr_community_free(e_comm) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_clear()
 *
 * Clearing is pretty straightforward:
 *
 *   * clearing NULL       -- result is NULL
 *   * clearing empty      -- result is unchanged original
 *   * clearing stored     -- result is a new copy of the not-stored
 *   * clearing not-stored -- result is NULL
 */
static void
test_comm_clear(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_clear") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      comm_list      cl ;
      attr_community comm, s_comm, t_comm ;

      next_test() ;

      /* Check for trivial case of clearing NULL
       */
      if (count == 0)
        {
          comm = attr_community_clear(NULL) ;
          test_assert(comm == NULL,
              "expect attr_community_clear(NULL) == NULL") ;
        } ;

      /* Check for case of empty of various lengths.
       */
      comm   = attr_community_new(count) ;

      t_comm = attr_community_clear(comm) ;
      test_assert(t_comm == comm,
          "expect attr_community_clear(empty) == empty") ;
      test_assert(attr_community_equal(comm, NULL),
          "expect attr_community_clear() to give an empty attr_community") ;

      attr_community_free(comm) ;

      /* Make comm and s_comm (same) to count length.
       */
      cl = make_comm_list(count) ;
      comm  = attr_community_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_community_store(comm) ;
      comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      /* Emptying yields NULL for stored
       */
      t_comm = attr_community_clear(s_comm) ;
      test_assert(t_comm == NULL,
          "expect attr_community_clear(stored) == NULL") ;

      /* Emptying yields empty for not-stored
       */
      t_comm = attr_community_clear(comm) ;
      test_assert(t_comm == comm,
          "expect attr_community_clear(not-stored) == self") ;
      test_assert(attr_community_equal(comm, NULL),
          "expect attr_community_clear() to give an empty attr_community") ;

      /* Tidy up
       */
      attr_community_release(comm) ;
      attr_community_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_replace_list()
 *
 * Replacing is pretty straightforward -- but there are a number of cases:
 *
 *   * NULL replacing NULL         )
 *   * NULL replacing stored       ) Result is NULL
 *   * empty replacing NULL        )
 *   * empty replacing stored      )
 *
 *   * NULL replacing empty        )
 *   * NULL replacing not-stored   ) Result is empty original,
 *   * empty replacing empty       )
 *   * empty replacing not-stored  )
 *
 *   * stored replacing NULL       )
 *   * stored replacing stored     ) result is the (new) stored value,
 *   * stored replacing empty      ) the original is untouched
 *   * stored replacing not-stored )
 *
 *   * not-stored replacing NULL       -- result is a new copy of the not-stored
 *   * not-stored replacing empty      -- result is updated original
 *   * not-stored replacing stored     -- result is a new copy of the not-stored
 *   * not-stored replacing not-stored -- result is updated original
 */
static void
test_comm_replace_list(void)
{
  uint fail_count_was, test_count_was ;
  attr_community ea_comm, eb_comm ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_replace_list") ;

  /* Test NULL and empty combinations:
   */
  ea_comm = attr_community_new(0) ;
  eb_comm = attr_community_new(0) ;

  for (count = 1 ; count < (community_list_embedded_size * 2) ; ++count)
    {
      comm_list      cl ;
      attr_community comm, s_comm, n_comm ;

      cl = make_comm_list(count) ;
      next_test() ;

      comm   = attr_community_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_community_store(comm) ;
      n_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      comm = attr_community_replace_list(NULL, NULL) ;
      test_assert(comm == NULL,
               "expect attr_community_replace_list(NULL, NULL) == NULL") ;

      comm = attr_community_replace_list(s_comm, NULL) ;
      test_assert(comm == NULL,
               "expect attr_community_replace_list(stored, NULL) == NULL") ;

      comm = attr_community_replace_list(NULL, eb_comm) ;
      test_assert(comm == NULL,
               "expect attr_community_replace_list(NULL, empty) == NULL") ;

      comm = attr_community_replace_list(s_comm, eb_comm) ;
      test_assert(comm == NULL,
               "expect attr_community_replace_list(stored, empty) == NULL") ;

      comm = attr_community_replace_list(ea_comm, NULL) ;
      test_assert(comm == ea_comm,
           "expect attr_community_replace_list(empty, NULL) == empty") ;
      test_assert(attr_community_equal(ea_comm, NULL),
           "expect attr_community_replace_list(empty, NULL) to be empty") ;

      comm = attr_community_replace_list(n_comm, NULL) ;
      test_assert(comm == n_comm,
           "expect attr_community_replace_list(not-stored, NULL) == not-stored") ;
      test_assert(attr_community_equal(n_comm, NULL),
           "expect attr_community_replace_list(not-stored, NULL) to be empty") ;

      attr_community_free(n_comm) ;
      n_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      comm = attr_community_replace_list(ea_comm, eb_comm) ;
      test_assert(comm == ea_comm,
           "expect attr_community_replace_list(empty, empty) == NULL") ;
      test_assert(attr_community_equal(ea_comm, NULL),
           "expect attr_community_replace_list(empty, empty) to be empty") ;

      comm = attr_community_replace_list(n_comm, eb_comm) ;
      test_assert(comm == n_comm,
           "expect attr_community_replace_list(not-stored, empty) == not-stored") ;
      test_assert(attr_community_equal(n_comm, NULL),
           "expect attr_community_replace_list(not-stored, empty) to be empty") ;

      attr_community_free(n_comm) ;
      attr_community_release(s_comm) ;
    } ;

  /* Test replacing by a not-empty stored or not-stored.
   */
  for (count = 1 ; count < 100 ; ++count)
    {
      comm_list      cl ;
      attr_community comm, a_comm, b_comm, sa_comm, sb_comm;

      next_test() ;

      /* Make a_comm and sa_comm (same) to count length.
       *
       * Make b_comm and sb_comm (same) to random length.
       */
      cl = make_comm_list(count) ;
      a_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;
      sa_comm = attr_community_store(a_comm) ;
      a_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      cl = make_comm_list((rand() % 100) + 1) ;
      b_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;
      sb_comm = attr_community_store(b_comm) ;
      b_comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      /* Replacing by stored yields the stored -- without changing the
       * original.
       */
      comm = attr_community_replace_list(NULL, sb_comm) ;
      test_assert(comm == sb_comm,
          "expect attr_community_replace_list(NULL, stored) == stored") ;

      comm = attr_community_replace_list(ea_comm, sb_comm) ;
      test_assert(comm == sb_comm,
          "expect attr_community_replace_list(NULL, stored) == stored") ;

      comm = attr_community_replace_list(sa_comm, sb_comm) ;
      test_assert(comm == sb_comm,
          "expect attr_community_replace_list(stored, stored_n) == stored_n") ;

      comm = attr_community_replace_list(a_comm, sb_comm) ;
      test_assert(comm == sb_comm,
          "expect attr_community_replace_list(not-stored, stored) == stored") ;

      /* Replacing by not-stored yields copy of the not-stored or updates the
       * original.
       */
      comm = attr_community_replace_list(NULL, b_comm) ;
      test_assert((comm != b_comm) && (comm != NULL),
          "expect attr_community_replace_list(NULL, not-stored) == new") ;
      test_assert(attr_community_equal(comm, b_comm),
                                        "expect new list == replacement list") ;
      attr_community_free(comm) ;

      comm = attr_community_replace_list(ea_comm, b_comm) ;
      test_assert(comm == ea_comm,
          "expect attr_community_replace_list(empty, not-stored) == updated") ;
      test_assert(attr_community_equal(comm, b_comm),
                                        "expect new list == replacement list") ;

      attr_community_clear(ea_comm) ;

      comm = attr_community_replace_list(sa_comm, b_comm) ;
      test_assert((comm != sa_comm) && (comm != b_comm) && (comm != NULL),
          "expect attr_community_replace_list(stored, not-stored) == new") ;
      test_assert(attr_community_equal(comm, b_comm),
                                        "expect new list == replacement list") ;
      attr_community_free(comm) ;

      comm = attr_community_replace_list(a_comm, b_comm) ;
      test_assert(comm == a_comm,
          "expect attr_community_replace_list(not-stored, not-stored) == "
                                                                    "updated") ;
      test_assert(attr_community_equal(comm, b_comm),
                                        "expect new list == replacement list") ;

      attr_community_release(a_comm) ;
      attr_community_release(b_comm) ;
      attr_community_release(sa_comm) ;
      attr_community_release(sb_comm) ;
    } ;

  attr_community_free(ea_comm) ;
  attr_community_free(eb_comm) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_del_list()
 *
 * For a variety of random lengths of community attribute, start with a random
 * comm_list and:
 *
 *   * split the list in various ways:
 *
 *     When splitting the list:  x / 10   goes to list to be deleted from
 *                               y / 10   goes to both lists
 *                               x / 10   goes to list to delete
 *
 *     so tries all combinations of partial and no overlap in the lists being
 *     added together, and adding nothing and adding to nothing.
 *
 *  * construct stored and not-stored versions of the list to be deleted from.
 *
 *    If the list is empty, let the not-stored version be not-NULL, empty.
 *
 *  * construct stored and not-stored list to be deleted
 *
 *    If the list is empty, let the not-stored version be not-NULL, empty.
 *
 *  * do attr_community_del_list() on stored and not-stored.
 *
 *    Alternate deleting stored from not-stored
 *
 *  * construct what we expect to get -- delete_comm_list() and check the
 *    retsults.
 */
static void
test_comm_del_list(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  bool ok ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_del_list") ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint count ;
      comm_list cl ;
      uint o ;

      next_test() ;

      count = tc % 101 ;
      cl = make_comm_list(count) ;

      /* We run an odd number of lengths: 0..100, so every other time we will
       * have tc odd when length == 0.
       */

      /* A number of times, split the original comm_list, to create two
       * attr_community values, which contain some part of the original, and
       * have some degree of overlap, such that when added together should be
       * the give the original again.
       *
       * ~ o / 10 of list remains in original list
       * ~ b / 10 of list is reproduced in both lists.
       */
      for (o = 0 ; o <= 10 ; ++o)
        {
          uint b ;

          for (b = 0 ; b <= (10 - o) ; ++b)
            {
              comm_list cla, cld ;
              attr_community comm_a, comm_sa, comm_d, comm_sd,
                                              comm_t, comm_st ;
              bool changed ;

              next_test() ;

              cla = copy_comm_list(cl) ;                /* delete from  */
              cld = split_comm_list(cla, o, b) ;        /* delete       */

              comm_a  = attr_community_set((byte*)cla->list, cla->list_count) ;
              comm_sa = attr_community_store(comm_a) ;
              comm_a  = attr_community_set((byte*)cla->list, cla->list_count) ;

              if (cla->list_count != 0)
                {
                  assert((comm_a != NULL) && (comm_sa != NULL)) ;
                }
              else
                {
                  assert((comm_a == NULL) && (comm_sa == NULL)) ;
                  comm_a = attr_community_new(rand() %
                                           (community_list_embedded_size * 2)) ;
                } ;

              comm_d  = attr_community_set((byte*)cld->list, cld->list_count) ;
              comm_sd = attr_community_store(comm_d) ;
              comm_d  = attr_community_set((byte*)cld->list, cld->list_count) ;

              if (cld->list_count != 0)
                {
                  assert((comm_d != NULL) && (comm_sd != NULL)) ;
                }
              else
                {
                  assert((comm_d == NULL) && (comm_sd == NULL)) ;
                  comm_d = attr_community_new(rand() %
                                           (community_list_embedded_size * 2)) ;
                } ;

              if (tc & 1)
                {
                  comm_t  = attr_community_del_list(comm_a,  comm_d) ;
                  comm_st = attr_community_del_list(comm_sa, comm_sd) ;
                }
              else
                {
                  comm_t  = attr_community_del_list(comm_a,  comm_sd) ;
                  comm_st = attr_community_del_list(comm_sa, comm_d) ;
                } ;

              changed = delete_comm_list(cla, cld) ;

              test_assert(comm_t == comm_a,
                  "expect self after "
                                   "attr_community_del_list(not-stored, ...)") ;
              if (comm_sa != NULL)
                {
                  if (changed)
                    test_assert(comm_st != comm_sa,
                      "expect new value after "
                                   "attr_community_del_list(stored, ...)") ;
                  else
                    test_assert(comm_st == comm_sa,
                      "expect same value after "
                                "attr_community_del_list(stored, NULL/empty)") ;
                }
              else
                test_assert(comm_st == NULL,
                  "expect NULL after "
                                   "attr_community_del_list(NULL, ...)") ;

              test_assert(attr_community_equal(comm_t, comm_st),
                               "expected stored and not-stored results equal") ;

              if (comm_t == NULL)
                {
                  test_assert(cla->sorted_count == 0,
                      "expected %u entries remaining, got NULL",
                                                            cla->sorted_count) ;
                }
              else
                {
                  ok = test_assert(cla->sorted_count == comm_t->list.len,
                      "expected %u entries remaining, got=%u",
                                          cla->sorted_count, comm_t->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(cla->sorted, comm_t->list.body.c,
                                                   cla->sorted_count * 4) == 0,
                                                "did not get expected result") ;
                      if (!ok)
                        show_delta((const community_t*)comm_t->list.body.v,
                                               cla->sorted, cla->sorted_count) ;
                    } ;
                } ;

              if (comm_st == NULL)
                {
                  test_assert(cla->sorted_count == 0,
                      "expected %u entries remaining, got NULL",
                                                            cla->sorted_count) ;
                }
              else
                {
                  ok = test_assert(cla->sorted_count == comm_st->list.len,
                      "expected %u entries remaining, got=%u",
                                         cla->sorted_count, comm_st->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(cla->sorted, comm_st->list.body.c,
                                                   cla->sorted_count * 4) == 0,
                                                "did not get expected result") ;
                      if (!ok)
                        show_delta((const community_t*)comm_st->list.body.v,
                                               cla->sorted, cla->sorted_count) ;
                    } ;
                } ;

              attr_community_release(comm_sa) ;
              attr_community_release(comm_sd) ;
              attr_community_free(comm_a) ;
              if (comm_st != comm_sa)
                attr_community_free(comm_st) ;
              attr_community_free(comm_d) ;

              free(cla) ;
              free(cld) ;
            } ;
        } ;

      free(cl) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_out_prepare()
 *
 * Pretty straightforward -- test for a range of lengths including zero
 * (not forgetting to test for NULL and empty)
 */
static void
test_comm_out_prepare(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_out_prepare") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      comm_list      cl ;
      attr_community comm ;
      uint     length ;
      byte*    p_attr ;
      bool ok ;

      next_test() ;

      /* Check for case of empty of various lengths.
       */
      comm   = attr_community_new(count) ;

      p_attr = attr_community_out_prepare(comm, &length) ;
      test_assert(p_attr == NULL,
          "expect attr_community_out_prepare(empty, ...) == NULL") ;
      test_assert(length == 0,
          "expect attr_community_out_prepare(empty, ...) to give length==0, "
          "got=%u", length) ;

      attr_community_free(comm) ;

      /* Make comm to count length.
       */
      cl = make_comm_list(count) ;
      comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      p_attr = attr_community_out_prepare(comm, &length) ;
      if (count == 0)
        {
          assert(comm == NULL) ;

          test_assert(p_attr == NULL,
              "expect attr_community_out_prepare(NULL, ...) == NULL") ;
          test_assert(length == 0,
              "expect attr_community_out_prepare(NULL, ...) to give length==0, "
              "got=%u", length) ;
        }
      else
        {
          uint t_length, b_length, a_length ;
          byte e_flags ;
          byte* ap ;

          assert(comm != NULL) ;

          b_length = cl->sorted_count * 4 ;
          t_length = 2 + (b_length > 255 ? 2 : 1) + b_length ;

          ok = test_assert(p_attr != NULL,
              "expect attr_community_out_prepare() != NULL") ;
          if (ok)
            ok = test_assert(length == t_length,
              "expect attr_community_out_prepare() to give length=%u, "
              "got=%u", t_length, length) ;

          e_flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE
                                   | ((b_length > 255) ? BGP_ATF_EXTENDED : 0) ;
          if (ok)
            ok = test_assert(p_attr[0] == e_flags, "expected flags=%u, got=%u",
                                                           e_flags, p_attr[0]) ;
          if (ok)
            ok = test_assert(p_attr[1] == BGP_ATT_COMMUNITIES,
                   "expected type=%u, got=%u", BGP_ATT_COMMUNITIES, p_attr[1]) ;

          if (ok)
            {
              if (e_flags & BGP_ATF_EXTENDED)
                {
                  a_length = load_ns(&p_attr[2]) ;
                  ap = p_attr + 4 ;
                }
              else
                {
                  a_length = p_attr[2] ;
                  ap = p_attr + 3 ;
                } ;

              ok = test_assert(a_length == b_length,
                  "expect attr_community_out_prepare() to give attribute body "
                    "length=%u, got=%u", b_length, a_length) ;

              if (ok)
                {
                  community_t*  v ;
                  uint i ;

                  v = cl->sorted ;
                  for (i = 0 ; i < cl->sorted_count ; ++i)
                    {
                      if (v[i] != load_nl(ap))
                        break ;

                      ap += 4 ;
                    } ;

                  test_assert(i >= cl->sorted_count,
                                          "body of attribute not as expected") ;
                } ;
            } ;
        } ;

      /* Tidy up
       */
      attr_community_release(comm) ;
      free(cl) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_community_text_vector()
 *
 * Pretty straightforward -- test for a range of lengths including zero
 * (not forgetting to test for NULL and empty)
 */
static void
test_comm_text_vector(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_community_text_vector") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      comm_list      cl ;
      attr_community comm ;
      vector text_v, text_vx ;
      bool ok ;

      next_test() ;

      /* Check for case of empty of various lengths.
       */
      comm   = attr_community_new(count) ;

      text_v = attr_community_text_vector(comm) ;
      test_assert((text_v == NULL) || (vector_length(text_v) == 0),
          "expect attr_community_text_vector(empty) == NULL or empty") ;

      text_vx = attr_community_text_vector(comm) ;
      test_assert((text_v == text_vx),
          "expect attr_community_text_vector() to return same vector "
                                                         "second time around") ;
      attr_community_free(comm) ;

      /* Make comm to count length.
       */
      cl = make_comm_list(count) ;
      comm  = attr_community_set((byte*)cl->list, cl->list_count) ;

      text_v = attr_community_text_vector(comm) ;

      if (count == 0)
        {
          assert(comm == NULL) ;

          test_assert(text_v == NULL,
              "expect attr_community_text_vector(empty) == NULL") ;
        }
      else
        {
          ok = test_assert(vector_length(text_v) == cl->sorted_count,
                          "expect text_vector length=%u, got=%u",
                                     cl->sorted_count, vector_length(text_v)) ;
          if (ok)
            {
              community_t* v ;
              uint iv ;
              attr_community comm_v ;

              v = cl->sorted ;
              comm_v = NULL ;
              for (iv = 0 ; iv < cl->sorted_count ; ++iv)
                {
                  attr_community_type_t act ;
                  community_t cv ;

                  comm_v = attr_community_from_str (vector_get_item(text_v, iv),
                                                                         &act) ;
                  if ((comm_v == NULL) || (act != act_simple)
                                       || (comm_v->list.len != 1))
                    break ;

                  cv = *((community_t*)comm_v->list.body.v) ;

                  if (cv != v[iv])
                    break ;

                  comm_v = attr_community_free(comm_v) ;
                } ;

              test_assert(iv >= cl->sorted_count,
                  "did not expect text vector entry '%s'",
                                           (char*)vector_get_item(text_v, iv)) ;
              attr_community_free(comm_v) ;
            } ;
        } ;

      text_vx = attr_community_text_vector(comm) ;
      test_assert((text_v == text_vx),
          "expect attr_community_text_vector() to return same vector "
                                                         "second time around") ;
      /* Tidy up
       */
      attr_community_release(comm) ;
      free(cl) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test support functions
 */
static comm_list sort_comm_list(comm_list cl) ;

/*------------------------------------------------------------------------------
 * Make a random community list of given length
 *
 * Includes ~25% repeated values.
 *
 * Some ~25% of lists will contain one or more of the no-advertise etc specials.
 *
 *  Fills in:
 *
 *    cl->list_count     -- original count of community values
 *    cl->list           -- the original community values in whatever order,
 *                          with repeats, etc
 *
 *    cl->sorted_count   -- count of community values after sort/dedup
 *    cl->sorted         -- the community values after sort/dedup
 */
static comm_list
make_comm_list(uint count)
{
  comm_list cl ;
  community_t* v ;
  uint i ;

  static const community_t specials[3] =
                   { 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03 } ;

  assert(count <= comm_max) ;

  cl = malloc(sizeof(comm_list_t)) ;

  memset(cl, 0, sizeof(comm_list_t)) ;

  cl->list_count = count ;
  v = cl->list ;

  /* Fill with random values -- the cl->list is in Network Order, but that
   * doesn't matter much here !
   */
  for (i = 0 ; i < count ; ++i)
    v[i] = rand() * 5 ;

  /* 25% of the time, insert one or more of the "specials"
   */
  if ((count != 0) && ((rand() % 4) == 0))
    {
      uint q ;
      uint n ;

      if (count < 3)
        n = (rand() % count) + 1 ;
      else
        n = (rand() % 3)     + 1 ;

      q = rand() % 3 ;
      while (n--)
        {
          v[rand() % count] = htonl(specials[q]) ;
          confirm(sizeof(community_t) == 4) ;
          q = (q + 1) % 3 ;
        }
    } ;

  /* Now introduce some repeats
   */
  for (i = 0 ; i < count ; ++i)
    {
      if ((rand() % 4) == 0)
        v[i] = v[rand() % count] ;
    } ;

  /* Fill in the sorted part and return result.
   */
  return sort_comm_list(cl) ;
} ;

/*------------------------------------------------------------------------------
 * Perturb given comm_list, creating a copy of the original.
 *
 * If the original is empty, create new comm_list with one entry.
 *
 * Changes one entry in the comm_list, so that the result is exactly the same
 * length as the original, but one value (possibly repeated) is different.
 */
static comm_list
perturb_comm_list(comm_list original)
{
  comm_list cl ;
  uint i ;
  community_t* v ;
  community_t from, to, delta ;

  if (original->list_count == 0)
    return make_comm_list(1) ;

  /* Make a nice new copy of the original, and chose something to change, at
   * random.
   */
  cl = copy_comm_list(original) ;

  v = cl->list ;
  from = v[rand() % cl->list_count] ;

  /* Choose a bit to change, at random, then check that this does not change
   * value to another existing one !
   *
   * If it does, then we change the next bit down... and if we shift the delta
   * down to zero, simply increment the 'to' value.  Must eventually find
   * a new value to set to !
   *
   * Note that the cl->list is in Network Order -- but that's not important
   * right now.
   */
  delta = (community_t)1 << (rand() % 32) ;
  to = from ;
  i = 0 ;
  while (i < cl->list_count)
    {
      if (delta == 0)
        to += 1 ;
      else
        {
          to ^= delta ;
          delta >>= 1 ;
        } ;

      for (i = 0 ; i < cl->list_count ; ++i)
        if (v[i] == to)
          break ;
    } ;

  /* Change the chosen value
   */
  for (i = 0 ; i < cl->list_count ; ++i)
    if (v[i] == from)
      v[i] = to ;

  /* Fill in the sorted part and return result.
   */
  return sort_comm_list(cl) ;
} ;

/*------------------------------------------------------------------------------
 * Drop item from given comm_list.
 *
 * Does nothing at all if is empty.
 *
 * Returns:  community value dropped
 */
static community_t
drop_comm_list(comm_list cl)
{
  community_t drop ;
  uint i, j ;
  community_t* v ;

  if (cl->list_count == 0)
    return 0 ;

  /* Choose value to drop and then drop it
   */
  v = cl->list ;
  drop = v[rand() % cl->list_count] ;

  j = 0 ;
  for (i = 0 ; i < cl->list_count ; ++i)
    if (v[i] != drop)
      v[j++] = v[i] ;

  cl->list_count = j ;

  /* Fill in the sorted part and return result.
   */
  sort_comm_list(cl) ;

  /* Return what we dropped -- in Host Order
   */
  return ntohl(drop) ;
} ;

/*------------------------------------------------------------------------------
 * Take given comm_list and move/copy a random proportion of the sorted and
 * dedupped items to a new list.
 *
 * One or both lists may be empty.
 *
 *   ~ old  / 10 items will stay in the old list
 *
 *   ~ both / 10 items will go in both lists
 *
 *   ~ rest of   items will go in the new list
 *
 * Returns:  the other part of the list.
 *
 * NB: because the split is done on the sorted/dedupped list, the "both"
 *     proportion governs the overlap between the two lists (repeats in the
 *     original have no bearing on the matter).
 */
static comm_list
split_comm_list(comm_list cl, uint old, uint both)
{
  comm_list clx ;
  uint i, n, nx ;

  assert((old + both) <= 10) ;

  clx = copy_comm_list(cl) ;

  if (cl->list_count == 0)
    return clx ;

  n = nx = 0 ;
  for (i = 0 ; i < cl->sorted_count ; ++i)
    {
      community_t cv ;
      uint r ;

      cv = htonl(cl->sorted[i]) ;
      r  = rand() % 10 ;

      if (r < both)
        {
          cl->list[n++]   = cv ;
          clx->list[nx++] = cv ;
        }
      else if ((r - both) < old)
        {
          cl->list[n++] = cv ;
        }
      else
        {
          clx->list[nx++] = cv ;
        } ;
    } ;

  cl->list_count  = n ;
  clx->list_count = nx ;

  /* Fill in the sorted part and return result.
   */
  sort_comm_list(cl) ;
  sort_comm_list(clx) ;

  return clx ;
} ;

/*------------------------------------------------------------------------------
 * Delete entries from given list which exist in the other given list.
 */
static bool
delete_comm_list(comm_list cl, comm_list cld)
{
  uint i, n ;
  bool changed ;

  changed = false ;

  if (cl->list_count == 0)
    return changed ;

  if (cld->list_count == 0)
    return changed ;

  n = 0 ;
  for (i = 0 ; i < cl->sorted_count ; ++i)
    {
      uint j ;

      for (j = 0 ; j < cld->sorted_count ; ++j)
        if (cl->sorted[i] == cld->sorted[j])
          break ;

      if (j >= cld->sorted_count)
        cl->list[n++] = htonl(cl->sorted[i]) ;
      else
        changed = true ;
    } ;

  cl->list_count  = n ;

  /* Fill in the sorted part and return result.
   */
  sort_comm_list(cl) ;

  return changed ;
} ;

/*------------------------------------------------------------------------------
 * Sort and de-dup the given comm_list
 */
static comm_list
sort_comm_list(comm_list cl)
{
  uint i, n ;
  community_t* v ;

  /* Copy to the sorted version in host order, then sort and dedup.
   */
  n = cl->list_count ;
  v = cl->sorted ;

  for (i = 0 ; i < n ; ++i)
    v[i] = ntohl(cl->list[i]) ;
  confirm(sizeof(community_t) == 4) ;

  for (i = 0 ; (n > 1) && (i < (n - 1)) ; ++i)
    {
      uint j ;

      for (j = i+1 ; j < n ; ++j)
        {
          while (v[j] == v[i])
            {
              n -= 1 ;

              if (j == n)
                break ;

              v[j] = v[n] ;
            } ;

          if (v[j] < v[i])
            {
              community_t t ;

              t    = v[j] ;
              v[j] = v[i] ;
              v[i] = t ;
            } ;
        } ;
    } ;

  cl->sorted_count = n ;

  return cl ;
} ;

/*------------------------------------------------------------------------------
 * Make copy of the given comm_list
 */
static comm_list
copy_comm_list(comm_list original)
{
  comm_list cl ;

  cl = malloc(sizeof(comm_list_t)) ;
  memcpy(cl, original, sizeof(comm_list_t)) ;

  return cl ;
} ;

/*------------------------------------------------------------------------------
 * Show difference between the community list we got, and the community list
 * we expected.
 */
static void
show_delta(const community_t* got, const community_t* exp, uint count)
{
  uint off, i ;

  off = 0 ;
  while (1)
    {
      if (got[off] != exp[off])
        break ;

      ++off ;
      if (off < count)
        continue ;

      test_assert(off < count, "found no difference in show_delta()") ;
      return ;
    } ;

  if (off > 2)
    off -= 2 ;
  else
    off = 0 ;

  fprintf(stderr, "\n  e%3d:", off) ;
  for (i = off ; (i < (off + 5)) && (i < count) ; ++i)
    fprintf(stderr, " %08x", exp[i]) ;

  fprintf(stderr, "  ... total length = %u (entries)", count) ;

  fprintf(stderr, "\n  g%3d:", off) ;
  for (i = off ; (i < (off + 5)) && (i < count) ; ++i)
    fprintf(stderr, " %08x", got[i]) ;
} ;

