#include <misc.h>
#include <zebra.h>

#include "stdio.h"

#include "qlib_init.h"
#include "command.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"

/*==============================================================================
 * bgpd/bgp_ecommunity.c torture tests
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
enum { ecomm_max = 100 } ;      /* maximum length we test to !  */

typedef struct ecomm_list  ecomm_list_t ;
typedef struct ecomm_list* ecomm_list ;

struct ecomm_list
{
  uint  list_count ;
  ecommunity_t list[ecomm_max] ;        /* Original with duplicates etc. */

  uint  sorted_count ;
  ecommunity_t sorted[ecomm_max] ;      /* Sorted and dedupped           */
} ;

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_ecomm_simple(void) ;
static void test_ecomm_store(void) ;
static void test_ecomm_release(void) ;
static void test_ecomm_from_str(void) ;
static void test_ecomm_str(void) ;
static void test_ecomm_composite(void) ;
static void test_ecomm_add_list(void) ;
static void test_ecomm_clear(void) ;
static void test_ecomm_replace_list(void) ;
static void test_ecomm_del_list(void) ;
static void test_ecomm_out_prepare(void) ;
#if 0
static void test_ecomm_text_vector(void) ;
#endif

static ecomm_list make_ecomm_list(uint count) ;
static ecomm_list perturb_ecomm_list(ecomm_list orginal) ;
static ecommunity_t drop_ecomm_list(ecomm_list cl) ;
static ecomm_list split_ecomm_list(ecomm_list cl, uint old, uint both) ;
static ecomm_list copy_ecomm_list(ecomm_list original) ;
static bool delete_ecomm_list(ecomm_list cl, ecomm_list cld) ;
static void show_delta(const ecommunity_t* got, const ecommunity_t* exp,
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

  test_ecomm_simple() ;

  test_ecomm_store() ;

  test_ecomm_from_str() ;

  test_ecomm_str() ;

  test_ecomm_composite() ;

  test_ecomm_add_list() ;

  test_ecomm_clear() ;

  test_ecomm_replace_list() ;

  test_ecomm_del_list() ;

  test_ecomm_out_prepare() ;

#if 0
  test_ecomm_text_vector() ;
#endif

  test_ecomm_release() ;         /* last -- releases stored[]            */

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
 *  * attr_ecommunity_start()        -- main()
 *  * attr_ecommunity_finish()       -- main()
 *
 *  * attr_ecommunity_store()        -- test_ecomm_simple(), test_ecomm_store()
 *                                                           & test_ecomm_str()
 *  * attr_ecommunity_free()         -- test_ecomm_simple()
 *                                                      & test_ecomm_from_str()
 *  * attr_ecommunity_lock()         -- test_ecomm_store()
 *  * attr_ecommunity_release()      -- test_ecomm_store() & test_ecomm_str()
 *
 *  * attr_ecommunity_set()          -- test_ecomm_simple() etc.
 *
 *  * attr_ecommunity_out_prepare()  -- test_ecomm_out_prepare()
 *
 *  * attr_ecommunity_add_list()     -- test_ecomm_add_list()
 *  * attr_ecommunity_replace_list() -- test_ecomm_replace_list()
 *  * attr_ecommunity_del_value()    -- test_ecomm_composite()
 *  * attr_ecommunity_del_list()     -- test_ecomm_del_list()
 *  * attr_ecommunity_drop_value()   -- used in attr_ecommunity_del_value()
 *
 *  * attr_ecommunity_clear()        -- test_ecomm_clear()
 *
 *  * attr_ecommunity_known()        -- test_ecomm_from_str()
 *
 *  * attr_ecommunity_match()        -- test_ecomm_composite()
 *  * attr_ecommunity_equal()        -- test_ecomm_composite()
 *
 *  * attr_ecommunity_from_str()     -- test_ecomm_from_str()
 *  * attr_ecommunity_str()          -- test_ecomm_str() & test_ecomm_from_str()
 *
 *  * attr_ecommunity_print_all_vty() -- not tested
 */
enum { stored_count = 401 } ;

static attr_ecommunity stored[stored_count] ;
static ecomm_list      originals[stored_count] ;

/*==============================================================================
 * Test of simple attr_ecommunity stuff.
 *
 * For ecommunity list lengths from 0 to 100 (100 gives a >400 byte attribute),
 * four times:
 *
 *   * construct a random ecommunity list
 *
 *   * set the list and check contains required stuff
 *
 *   * free the attr_ecommunity -- so do attr_ecommunity_free().
 *
 *   * set the list again, store and check contents
 *
 *     checks that can store NULL and empty not-NULL and get the same thing.
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_ecomm_simple(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity construction and storage") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_ecommunity ecomm ;
      uint count ;
      bool ok ;

      next_test() ;

      if (i == 0)
        count = 0 ;
      else
        count = ((i - 1) % 100) + 1 ;

      /* Create an original ecommunity list, and then create an attr_ecommunity.
       *
       * Check that the result is exactly as expected.
       */
      originals[i] = make_ecomm_list(count) ;

      ecomm = attr_ecommunity_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      if (count == 0)
        {
          test_assert(ecomm == NULL,
                     "expected ecomm == NULL for an empty ecommunity list") ;
        }
      else
        {
          test_assert(ecomm != NULL,
                      "expected ecomm != NULL for a ecommunity list length=%u",
                                                                       count) ;
        } ;

      if (ecomm != NULL)
        {
          uint s_count = originals[i]->sorted_count ;

          ok = test_assert(ecomm->list.len == s_count,
                 "expected %u sorted/dedupped communities, got %u",
                                                      s_count, ecomm->list.len) ;

          if (ok && (s_count != 0))
            {
              ok = test_assert(memcmp(ecomm->list.body.v,
                                      originals[i]->sorted, s_count * 8) == 0,
                                          "ecommunity list is not as expected") ;
              if (!ok)
                show_delta((const ecommunity_t*)ecomm->list.body.v,
                                                originals[i]->sorted, s_count) ;
            } ;
        } ;

      /* Free and then recreate -- so have called free !
       */
      attr_ecommunity_free(ecomm) ;

      assert(count == originals[i]->list_count) ;
      ecomm = attr_ecommunity_set((byte*)(originals[i]->list), count) ;

      /* Now store the ecommunity list.
       *
       * At this point, for count == 0 we have a NULL ecommunity list -- stick
       * in test for storing non-NULL but empty one, too.
       */
      if (count == 0)
        {
          assert(ecomm == NULL) ;

          stored[0] = attr_ecommunity_store(NULL) ;

          test_assert(stored[0] == NULL,
              "expect NULL when storing a NULL attr_ecommunity") ;

          ecomm = attr_ecommunity_new(ecommunity_list_embedded_size) ;
          test_assert(ecomm->list.body.v == ecomm->embedded_list,
                                     "expected ecommunity list to be embedded") ;

          stored[0] = attr_ecommunity_store(ecomm) ;
          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_ecommunity") ;

          ecomm = attr_ecommunity_new(ecommunity_list_embedded_size + 1) ;
          test_assert(ecomm->list.body.v != ecomm->embedded_list,
                               "did NOT expect ecommunity list to be embedded") ;

          stored[0] = attr_ecommunity_store(ecomm) ;
          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_ecommunity") ;
        }
      else
        {
          attr_ecommunity s_comm ;
          uint s_count ;

          assert(ecomm != NULL) ;

          stored[i] = s_comm = attr_ecommunity_store(ecomm) ;
          s_count = originals[i]->sorted_count ;

          test_assert(s_comm == ecomm,
                                "expect to store the original attr_ecommunity") ;

          test_assert(s_comm->stored,
                                  "expect to stored ecommunity to be 'stored'") ;

          test_assert(s_comm->vhash.ref_count == 2,
                "expected reference count == 2 after attr_ecommunity_store(), "
                                           "got=%u", s_comm->vhash.ref_count) ;

          ok = test_assert(s_comm->list.len == s_count,
                             "expected ecommunity length %u, got %u", s_count,
                                                            s_comm->list.len) ;

          if (s_count <= ecommunity_list_embedded_size)
            test_assert(s_comm->list.body.v == s_comm->embedded_list,
                    "expect count of %u to be held in embedded body", s_count) ;

          if (ok && (s_count != 0))
            {
              ok = test_assert(memcmp(s_comm->list.body.v,
                                    originals[i]->sorted, s_count * 8) == 0,
                                   "stored ecommunity list is not as expected") ;
              if (!ok)
                show_delta((const ecommunity_t*)s_comm->list.body.v,
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
 * Test of attr_ecommunity_store().
 *
 *   * create new copy of each original, then release
 *
 *     tests release of not-stored value and release of NULL
 *
 *   * create another new copy of each original, and store it.
 *
 *     should find existing stored value and increment its count.
 *
 *   * do attr_ecommunity_lock() -- ref count should be increased
 *
 *   * do attr_ecommunity_release(), twice -- ref count should be reduced
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_ecomm_store(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_store") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_ecommunity ecomm, s_comm ;

      next_test() ;

      /* Create an attr_ecommunity, starting from NULL
       *
       * Release it again -- to test release of not-stored and NULL.
       */
      ecomm = attr_ecommunity_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      if (ecomm != NULL)
        test_assert(ecomm->list.len == originals[i]->sorted_count,
                             "expected ecommunity length %u, got %u",
                             originals[i]->sorted_count, ecomm->list.len) ;
      else
        test_assert(originals[i]->sorted_count == 0,
                 "did NOT expect NULL ecommunity, since length=%u",
                                                   originals[i]->sorted_count) ;

      attr_ecommunity_release(ecomm) ;

      /* Create an attr_ecommunity, starting from NULL
       *
       * Store it and check we get the previously stored value.
       */
      ecomm = attr_ecommunity_set((byte*)(originals[i]->list),
                                                     originals[i]->list_count) ;

      s_comm = attr_ecommunity_store(ecomm) ;

      test_assert(s_comm == stored[i],
                         "expected to find previously stored attr_ecommunity") ;

      if (s_comm == NULL)
        continue ;

      test_assert(s_comm->stored,
                                "expect to stored ecommunity to be 'stored'") ;

      test_assert(s_comm->vhash.ref_count == 4,
          "expected reference count == 4 after second attr_ecommunity_store(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      /* Lock and check result
       */
      attr_ecommunity_lock(s_comm) ;

      test_assert(s_comm->vhash.ref_count == 6,
            "expected reference count == 6 after attr_ecommunity_lock(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      /* Release twice and check result
       */
      attr_ecommunity_release(s_comm) ;
      attr_ecommunity_release(s_comm) ;

      test_assert(s_comm->vhash.ref_count == 2,
            "expected reference count == 2 after attr_ecommunity_release(), "
                                       "got=%u", s_comm->vhash.ref_count) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_ecommunity_out_release().
 *
 * For all stored attr_ecommunity:
 *
 *   * check that the reference count is as expected.
 *
 *   * release
 *
 * Leaves the stored array empty.
 */
static void
test_ecomm_release(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_out_release()") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_ecommunity s_comm ;

      next_test() ;

      s_comm = stored[i] ;

      if (s_comm != NULL)
        test_assert(s_comm->vhash.ref_count == 2,
           "expected reference count == 2 before last attr_ecommunity_release(), "
                                       "got=%u", s_comm->vhash.ref_count) ;

      stored[i] = attr_ecommunity_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_ecommunity_from_str() & attr_ecommunity_known().
 *
 */
typedef struct ecomm_str_test  ecomm_str_test_t ;
typedef const struct ecomm_str_test* ecomm_str_test ;

struct ecomm_str_test
{
  const char*  str ;

  bool         prefix ;
  uint         sub_type ;

  uint         count ;
  ecommunity_t  list[6] ;
};

static const ecomm_str_test_t  com_str_tests[] =
  {
      /* Empty string is rejected -- check for whitespace
       */
      { .str      = "",
        .prefix   = true,
        .sub_type = 0,
        .count    = 0,
      },
      { .str      = " \n \t \r ",
        .prefix   = true,
        .sub_type = 0,
        .count    = 0,
      },

      /* Single values -- multiples are tested later, this is just to check
       *                  the token reader
       */
      { .str      = "rt 1:1",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0002000100000001 },
      },
      { .str      = "rT:1:4294967295\t \r\n",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x00020001FFFFFFFF },
      },
      { .str      = "rt\t65535:0x12345678",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0002FFFF12345678 },
      },
      { .str      = "\t \r\n soo \t 1:1",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0003000100000001 },
      },
      { .str      = "SOO:1:4294967295",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x00030001FFFFFFFF },
      },
      { .str      = "SoO\t65535:0x12345678",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0003FFFF12345678 },
      },
      { .str      = "\t \r\n65535:0x12345678\t \r\n",
        .prefix   = false,
        .sub_type = 9,
        .count    = 1,
        .list     = { 0x0009FFFF12345678 },
      },

      { .str      = "rt 10.1.2.3:4",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x01020A0102030004 },
      },
      { .str      = "rT:127.3.2.1:65535",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x01027F030201FFFF },
      },
      { .str      = "rt\t64.65.66.67:0x1234",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0102404142431234 },
      },
      { .str      = "soo \t 10.1.2.3:4",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x01030A0102030004 },
      },
      { .str      = "SOO:127.3.2.1:65535",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x01037F030201FFFF },
      },
      { .str      = "SoO\t64.65.66.67:0x1234",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0103404142431234 },
      },
      { .str      = "\t \r\n64.65.66.67:0x1234",
        .prefix   = false,
        .sub_type = 11,
        .count    = 1,
        .list     = { 0x010B404142431234 },
      },

      { .str      = "rt 65536:1",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0202000100000001 },
      },
      { .str      = "rT:4294967295:2",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0202FFFFFFFF0002 },
      },
      { .str      = "rt\t65538:0x1234",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0202000100021234 },
      },
      { .str      = "soo \t 65536:1",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0203000100000001 },
      },
      { .str      = "SOO:4294967295:2",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0203FFFFFFFF0002 },
      },
      { .str      = "SoO\t65538:0x1234",
        .prefix   = true,
        .sub_type = 0,
        .count    = 1,
        .list     = { 0x0203000100021234 },
      },
      { .str      = "65538:0x1234\t \r\n",
        .prefix   = false,
        .sub_type = 14,
        .count    = 1,
        .list     = { 0x020E000100021234 },
      },
#if 0
      /* Edge cases -- invalids
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
#endif

      /* End
       */
      { .str      = NULL }
  };

/*------------------------------------------------------------------------------
 * Test of attr_ecommunity_from_str() & attr_ecommunity_known().
 *
 * Run the strings from the table above and check get what we expect.
 */
static void
test_ecomm_from_str(void)
{
  uint fail_count_was, test_count_was ;
  ecomm_str_test n_test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_from_str()") ;

  n_test = com_str_tests ;

  while (n_test->str != NULL)
    {
      ecomm_str_test test ;
      attr_ecommunity ecomm ;
      bool ok ;

      next_test() ;
      test   = n_test ;
      n_test = test + 1 ;

      ecomm = attr_ecommunity_from_str (test->str, test->prefix,
                                                              test->sub_type) ;
      if (test->count != 0)
        {
          ok = test_assert(ecomm != NULL,
                          "expected %u ecommunities, got=NULL\n"
                          "   for: '%s'", test->count, test->str) ;
          if (ok)
            ok = test_assert(ecomm->list.len == test->count,
                "expected %u ecommunities, got=%u\n"
                "   for: '%s'", test->count, ecomm->list.len, test->str) ;
          if (ok)
            {
              ok = test_assert(memcmp(ecomm->list.body.v, test->list,
                                                       test->count * 8) == 0,
                         "ecommunity list is not as expected\n"
                         "   for: '%s'", test->str) ;
              if (!ok)
                show_delta((const ecommunity_t*)ecomm->list.body.v,
                                                      test->list, test->count) ;
            } ;
        }
      else
        {
          ok = test_assert(ecomm == NULL,
                          "expected NULL ecommunities, got=%u\n"
                          "   for: '%s'", ecomm->list.len, test->str) ;
        } ;

      attr_ecommunity_free(ecomm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_ecommunity_str().
 *
 * Generate attr_ecommunity objects at a number of random lengths, create
 * string, create attr_ecommunity from the string, check that the result is
 * the same by storing.
 */
static void
test_ecomm_str(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_str()") ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint            count ;
      ecomm_list      cl ;
      attr_ecommunity ecomm ;
      attr_ecommunity ecomm_s ;
      const char*    str ;
      bool ok ;

      next_test() ;

      count = rand() % ((tc % 100) + 1) ;
      cl = make_ecomm_list(count) ;

      ecomm = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      ecomm_s = attr_ecommunity_store(ecomm) ;

      if (ecomm == NULL)
        {
          test_assert(ecomm_s == NULL,
            "expected NULL attr_ecommunity after attr_ecommunity_store(NULL)") ;
        }
      else
        {
          test_assert(ecomm_s->stored,
                            "expected attr_ecommunity to be 'stored' "
                                             "after attr_ecommunity_store()") ;
        } ;

      str = attr_ecommunity_str(ecomm_s) ;

      if (ecomm_s == NULL)
        test_assert(*str == '\0',
            "expected empty string from attr_ecommunity_str(NULL)") ;
      else
        test_assert(ecomm_s->state & ecms_string,
             "expected to find string state set after attr_ecommunity_str()") ;

      ecomm = attr_ecommunity_from_str(str, true /* with-prefix */, 0) ;

      if (*str == '\0')
        {
          ok = test_assert(ecomm == NULL,
                            "expected NULL ecomm\n"
                            "   for: '%s'", str) ;
        }
      else
        {
          ok = test_assert(ecomm != NULL,
                            "expected a not-NULL ecomm\n"
                            "   for: '%s'", str) ;
        } ;

      if (ok)
        {
          ecomm = attr_ecommunity_store(ecomm) ;

          test_assert(ecomm == ecomm_s,
              "did not get expected stored attr_ecommunity after "
              "attr_ecommunity_str() and attr_ecommunity_from_str()") ;
        } ;

      attr_ecommunity_release(ecomm) ;
      attr_ecommunity_release(ecomm_s) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Composite test for:
 *
 *  * attr_ecommunity_del_value()
 *  * attr_ecommunity_match()
 *  * attr_ecommunity_equal()
 *
 * For a variety of random lengths of ecommunity attribute:
 *
 *  * check that attr_ecommunity is equal to itself and matches itself.
 *
 *  * store the test ecommunity.
 *
 *  * modify one entry in the original ecommunity and check that it does not
 *    equal and does not match the test ecommunity.
 *
 *    The equal check stops very quickly if the attr_ecommunity lengths differ,
 *    so this check ensures that the scan through the body of the
 *    attr_ecommunity does the job !
 *
 *  * for each ecommunity value in the original list (in the original random
 *    order, and with the original repeats):
 *
 *      - delete the value from the working attr_ecommunity
 *
 *        check that the value has been deleted cleanly.
 *
 *      - check that the test ecommunity if matched by the working one.
 *
 *      - check that the test ecommunity is not equal to the working one
 *
 *      - check that the working ecommunity is not matched by the test one.
 *
 * This should test the three functions against each other.
 */
static void
test_ecomm_composite(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  attr_ecommunity ecomm ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: composite attr_ecommunity_match/_equal/_del_value") ;

  /* Check that empty and NULL are the same for attr_ecommunity_match() and
   * for attr_ecommunity_equal).
   */
  ecomm = attr_ecommunity_new(0) ;

  next_test() ;

  test_assert(attr_ecommunity_match(NULL, NULL),
                      "expect a NULL attr_ecommunity to match a NULL one") ;
  test_assert(attr_ecommunity_match(ecomm, NULL),
                      "expect an empty attr_ecommunity to match a NULL one") ;
  test_assert(attr_ecommunity_match(NULL, ecomm),
                      "expect a NULL attr_ecommunity to match an empty one") ;
  test_assert(attr_ecommunity_match(ecomm, ecomm),
                      "expect an empty attr_ecommunity to match an empty one") ;

  test_assert(attr_ecommunity_equal(NULL, NULL),
                      "expect a NULL attr_ecommunity to equal a NULL one") ;
  test_assert(attr_ecommunity_equal(ecomm, NULL),
                      "expect an empty attr_ecommunity to equal a NULL one") ;
  test_assert(attr_ecommunity_equal(NULL, ecomm),
                      "expect a NULL attr_ecommunity to equal an empty one") ;
  test_assert(attr_ecommunity_equal(ecomm, ecomm),
                      "expect an empty attr_ecommunity to equal an empty one") ;

  attr_ecommunity_free(ecomm) ;

  /* Run main test for a number of ecommunity list lengths
   */
  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint            count ;
      ecomm_list      cl, pcl ;
      attr_ecommunity s_comm, t_comm ;
      bool ok ;

      next_test() ;

      count = rand() % ((tc % 100) + 1) ;
      cl = make_ecomm_list(count) ;

      ecomm = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_ecommunity_store(ecomm) ;
      ecomm = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      /* So we have a stored s_comm built from cl, and a second copy ecomm,
       * also built from cl -- and those should both match and be equal to
       * each other.
       *
       * NB: for empty ecommunity list expect both to be NULL
       */
      test_assert(attr_ecommunity_match(s_comm, ecomm),
                                 "expect an attr_ecommunity to match itself") ;
      test_assert(attr_ecommunity_match(ecomm, s_comm),
                                 "expect an attr_ecommunity to match itself") ;

      test_assert(attr_ecommunity_equal(s_comm, ecomm),
                                 "expect an attr_ecommunity to equal itself") ;
      test_assert(attr_ecommunity_equal(ecomm, s_comm),
                                 "expect an attr_ecommunity to equal itself") ;

      /* If the ecommunity list is not empty, create a new list which is the
       * same as the one we have, except for one entry.
       *
       * Note that if the ecomm_list is empty we should have NULL ecomm and
       * s_comm, and that perturb_ecomm_list creates a ecomm_list with one entry.
       * So we test match and equal of an empty list with a non-empty one.
       *
       * The result should not match or be matched by the stored ecommunity,
       * and will not be equal to it, either.
       */
      pcl = perturb_ecomm_list(cl) ;
      if (cl->list_count != 0)
        assert( (cl->list_count   == pcl->list_count) &&
                (cl->sorted_count == pcl->sorted_count) ) ;
      else
        assert( (pcl->list_count == 1) && (pcl->sorted_count == 1) ) ;

      t_comm = attr_ecommunity_set((byte*)pcl->list, pcl->list_count) ;

      if (s_comm != NULL)
        assert(t_comm->list.len == s_comm->list.len) ;
      else
        assert(t_comm->list.len == 1) ;

      test_assert(!attr_ecommunity_match(s_comm, t_comm),
                "do NOT expect an attr_ecommunity to match perturbed copy") ;
      if (s_comm != NULL)
        test_assert(!attr_ecommunity_match(t_comm, s_comm),
                "do NOT expect a perturbed copy to match attr_ecommunity") ;
      else
        test_assert(attr_ecommunity_match(t_comm, s_comm),
                "expect an empty attr_ecommunity to match anything") ;

      test_assert(!attr_ecommunity_equal(s_comm, t_comm),
                "do NOT expect an attr_ecommunity to equal perturbed copy") ;

      attr_ecommunity_free(t_comm) ;

      /* Dropping one entry at a time:
       *
       *   * make sure that each drop changes the working attr_ecommunity as
       *     expected.
       *
       *   * that the new working ecommunity matches the stored ecommunity
       *
       *   * that the new working ecommunity is not matched by the stored
       *     ecommunity
       *
       *   * that the new working ecommunity does not equal the stored
       *     ecommunity
       */
      while (cl->list_count > 0)
        {
          ecommunity_t drop ;

          /* Update cl by dropping one ecommunity value.
           *
           * Drop that value from the working ecommunity and check result
           */
          drop = drop_ecomm_list(cl) ;

          ecomm = attr_ecommunity_del_value(ecomm, drop) ;

          ok = test_assert(ecomm->list.len == cl->sorted_count,
               "expected length=%u, got=%u after r attr_ecommunity_del_value()",
                                            cl->sorted_count, ecomm->list.len) ;
          if (ok && (cl->sorted_count != 0))
            {
              ok = test_assert(memcmp(ecomm->list.body.v, cl->sorted,
                                                    cl->sorted_count * 8) == 0,
               "did not get expected result after attr_ecommunity_del_value()") ;
              if (!ok)
                show_delta((const ecommunity_t*)ecomm->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
            } ;

          /* Check that:
           *
           *   * working ecommunity matches stored one
           *
           *   * stored ecommunity does not match the working one
           *
           *   * working and stored communities are not equal
           */
          test_assert(!attr_ecommunity_equal(ecomm, s_comm),
               "do NOT expect stored attr_ecommunity to match working") ;

          test_assert(attr_ecommunity_match(s_comm, ecomm),
               "expect working to match stored attr_ecommunity") ;

          test_assert(!attr_ecommunity_equal(ecomm, s_comm),
               "do NOT expect working and stored attr_ecommunity to be equal") ;
          test_assert(!attr_ecommunity_equal(s_comm, ecomm),
               "do NOT expect working and stored attr_ecommunity to be equal") ;
       } ;

      attr_ecommunity_release(ecomm) ;
      attr_ecommunity_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_ecommunity_add_list()
 *
 * For a variety of random lengths of ecommunity attribute:
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
test_ecomm_add_list(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  attr_ecommunity ecomm, e_comm ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_add_list") ;

  e_comm = attr_ecommunity_new(0) ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint            count ;
      ecomm_list      cl ;
      attr_ecommunity s_comm, t_comm ;
      uint o ;
      bool ok ;

      next_test() ;

      count = tc % 101 ;
      cl = make_ecomm_list(count) ;

      /* Create a stored s_comm built from cl, and a second copy ecomm,
       * also built from cl -- and those should both be equal to each other.
       */
      ecomm = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_ecommunity_store(ecomm) ;
      ecomm = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      test_assert(attr_ecommunity_equal(ecomm, s_comm),
                                         "expect ecomm and s_comm to be equal") ;

      /* Adding NULL or empty makes no difference.
       */
      t_comm = attr_ecommunity_add_list(ecomm, NULL) ;
      test_assert(t_comm == ecomm,
                            "expect adding NULL to ecomm to return ecomm") ;
      test_assert(attr_ecommunity_equal(ecomm, s_comm),
                   "do NOT expect adding NULL to make any difference to ecomm") ;

      t_comm = attr_ecommunity_add_list(s_comm, NULL) ;
      test_assert(t_comm == s_comm,
                            "expect adding NULL to s_comm to return s_comm") ;
      test_assert(attr_ecommunity_equal(ecomm, s_comm),
                 "do NOT expect adding NULL to make any difference to s_comm") ;

      t_comm = attr_ecommunity_add_list(ecomm, e_comm) ;
      test_assert(t_comm == ecomm,
                            "expect adding empty to ecomm to return ecomm") ;
      test_assert(attr_ecommunity_equal(ecomm, s_comm),
                   "do NOT expect adding empty to make any difference to ecomm") ;

      t_comm = attr_ecommunity_add_list(s_comm, e_comm) ;
      test_assert(t_comm == s_comm,
                            "expect adding empty to s_comm to return s_comm") ;
      test_assert(attr_ecommunity_equal(ecomm, s_comm),
               "do NOT expect adding empty to make any difference to s_comm") ;

      /* Adding to NULL should return a new attr_ecommunity equal to that added.
       */
      t_comm = attr_ecommunity_add_list(NULL, ecomm) ;

      if (ecomm != NULL)
        test_assert(t_comm != ecomm,
                "expect adding not-NULL to NULL to create new attr_ecommunity") ;
      else
        test_assert(t_comm == ecomm,
                            "expect adding NULL to NULL to return NULL") ;
      test_assert(attr_ecommunity_equal(t_comm, ecomm),
                              "expect adding to NULL to copy original ecomm") ;

      attr_ecommunity_free(t_comm) ;

      t_comm = attr_ecommunity_add_list(NULL, s_comm) ;

      if (s_comm != NULL)
        test_assert(t_comm != s_comm,
                "expect adding not-NULL to NULL to create new attr_ecommunity") ;
      else
        test_assert(t_comm == s_comm,
                            "expect adding NULL to NULL to return NULL") ;
      test_assert(attr_ecommunity_equal(t_comm, s_comm),
                              "expect adding to NULL to copy original s_comm") ;

      attr_ecommunity_free(t_comm) ;

      /* A number of times, split the original ecomm_list, to create two
       * attr_ecommunity values, which contain some part of the original, and
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
              ecomm_list cla, clb ;
              attr_ecommunity ecomm_a, ecomm_b, ecomm_sa ;

              next_test() ;

              cla = copy_ecomm_list(cl) ;
              clb = split_ecomm_list(cla, o, b) ;

              ecomm_a = attr_ecommunity_set((byte*)cla->list, cla->list_count) ;
              ecomm_sa = attr_ecommunity_store(ecomm_a) ;
              ecomm_a = attr_ecommunity_set((byte*)cla->list, cla->list_count) ;
              ecomm_b = attr_ecommunity_set((byte*)clb->list, clb->list_count) ;

              if (cla->list_count == 0)
                assert(ecomm_a == NULL) ;
              else
                assert( (ecomm_a->list.len == cla->sorted_count) &&
                        (memcmp(ecomm_a->list.body.v, cla->sorted,
                                                cla->sorted_count * 8) == 0) ) ;

              if (clb->list_count == 0)
                assert(ecomm_b == NULL) ;
              else
                assert( (ecomm_b->list.len == clb->sorted_count) &&
                        (memcmp(ecomm_b->list.body.v, clb->sorted,
                                                clb->sorted_count * 8) == 0) ) ;

              ecomm_a = attr_ecommunity_add_list(ecomm_a, ecomm_b) ;

              if (cl->list_count == 0)
                test_assert(ecomm_a == NULL,
                    "expect attr_ecommunity_add_list() to give NULL when "
                                                         "original was empty") ;
              else
                {
                  ok = test_assert(ecomm_a->list.len == cl->sorted_count,
                      "expected original length=%u after "
                          "attr_ecommunity_add_list(), got %u",
                                          cl->sorted_count, ecomm_a->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(ecomm_a->list.body.v, cl->sorted,
                                                cl->sorted_count * 8) == 0,
                          "expected original contents after "
                                                 "attr_ecommunity_add_list()") ;
                      if (!ok)
                        show_delta((const ecommunity_t*)ecomm_a->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
                    } ;
                } ;

              attr_ecommunity_free(ecomm_a) ;

              ecomm_a = attr_ecommunity_add_list(ecomm_sa, ecomm_b) ;

              if (cl->list_count == 0)
                test_assert(ecomm_a == NULL,
                    "expect attr_ecommunity_add_list() to give NULL when "
                                                         "original was empty") ;
              else
                {
                  if (clb->list_count != 0)
                    test_assert(ecomm_sa != ecomm_a,
                      "expect a new attr_ecommunity after "
                                            "attr_ecommunity_add_list(stored)") ;
                  else
                    test_assert(ecomm_sa == ecomm_a,
                      "expect same new attr_ecommunity after "
                                "attr_ecommunity_add_list(stored, NULL/empty)") ;

                  ok = test_assert(ecomm_a->list.len == cl->sorted_count,
                      "expected original length=%u after "
                          "attr_ecommunity_add_list(), got %u",
                                          cl->sorted_count, ecomm_a->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(ecomm_a->list.body.v, cl->sorted,
                                                cl->sorted_count * 8) == 0,
                          "expected original contents after "
                                                 "attr_ecommunity_add_list()") ;
                      if (!ok)
                        show_delta((const ecommunity_t*)ecomm_a->list.body.v,
                                                 cl->sorted, cl->sorted_count) ;
                    } ;
                } ;

              attr_ecommunity_release(ecomm_sa) ;
              if (ecomm_a != ecomm_sa)
                attr_ecommunity_free(ecomm_a) ;
              attr_ecommunity_free(ecomm_b) ;

              free(cla) ;
              free(clb) ;
            } ;
        } ;

      attr_ecommunity_release(ecomm) ;
      attr_ecommunity_release(s_comm) ;
    } ;

  attr_ecommunity_free(e_comm) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_ecommunity_clear()
 *
 * Clearing is pretty straightforward:
 *
 *   * clearing NULL       -- result is NULL
 *   * clearing empty      -- result is unchanged original
 *   * clearing stored     -- result is a new copy of the not-stored
 *   * clearing not-stored -- result is NULL
 */
static void
test_ecomm_clear(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_clear") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      ecomm_list      cl ;
      attr_ecommunity ecomm, s_comm, t_comm ;

      next_test() ;

      /* Check for trivial case of clearing NULL
       */
      if (count == 0)
        {
          ecomm = attr_ecommunity_clear(NULL) ;
          test_assert(ecomm == NULL,
              "expect attr_ecommunity_clear(NULL) == NULL") ;
        } ;

      /* Check for case of empty of various lengths.
       */
      ecomm   = attr_ecommunity_new(count) ;

      t_comm = attr_ecommunity_clear(ecomm) ;
      test_assert(t_comm == ecomm,
          "expect attr_ecommunity_clear(empty) == empty") ;
      test_assert(attr_ecommunity_equal(ecomm, NULL),
          "expect attr_ecommunity_clear() to give an empty attr_ecommunity") ;

      attr_ecommunity_free(ecomm) ;

      /* Make ecomm and s_comm (same) to count length.
       */
      cl = make_ecomm_list(count) ;
      ecomm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_ecommunity_store(ecomm) ;
      ecomm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      /* Emptying yields NULL for stored
       */
      t_comm = attr_ecommunity_clear(s_comm) ;
      test_assert(t_comm == NULL,
          "expect attr_ecommunity_clear(stored) == NULL") ;

      /* Emptying yields empty for not-stored
       */
      t_comm = attr_ecommunity_clear(ecomm) ;
      test_assert(t_comm == ecomm,
          "expect attr_ecommunity_clear(not-stored) == self") ;
      test_assert(attr_ecommunity_equal(ecomm, NULL),
          "expect attr_ecommunity_clear() to give an empty attr_ecommunity") ;

      /* Tidy up
       */
      attr_ecommunity_release(ecomm) ;
      attr_ecommunity_release(s_comm) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_ecommunity_replace_list()
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
test_ecomm_replace_list(void)
{
  uint fail_count_was, test_count_was ;
  attr_ecommunity ea_comm, eb_comm ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_replace_list") ;

  /* Test NULL and empty combinations:
   */
  ea_comm = attr_ecommunity_new(0) ;
  eb_comm = attr_ecommunity_new(0) ;

  for (count = 1 ; count < (ecommunity_list_embedded_size * 2) ; ++count)
    {
      ecomm_list      cl ;
      attr_ecommunity ecomm, s_comm, n_comm ;

      cl = make_ecomm_list(count) ;
      next_test() ;

      ecomm   = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      s_comm = attr_ecommunity_store(ecomm) ;
      n_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      ecomm = attr_ecommunity_replace_list(NULL, NULL) ;
      test_assert(ecomm == NULL,
               "expect attr_ecommunity_replace_list(NULL, NULL) == NULL") ;

      ecomm = attr_ecommunity_replace_list(s_comm, NULL) ;
      test_assert(ecomm == NULL,
               "expect attr_ecommunity_replace_list(stored, NULL) == NULL") ;

      ecomm = attr_ecommunity_replace_list(NULL, eb_comm) ;
      test_assert(ecomm == NULL,
               "expect attr_ecommunity_replace_list(NULL, empty) == NULL") ;

      ecomm = attr_ecommunity_replace_list(s_comm, eb_comm) ;
      test_assert(ecomm == NULL,
               "expect attr_ecommunity_replace_list(stored, empty) == NULL") ;

      ecomm = attr_ecommunity_replace_list(ea_comm, NULL) ;
      test_assert(ecomm == ea_comm,
           "expect attr_ecommunity_replace_list(empty, NULL) == empty") ;
      test_assert(attr_ecommunity_equal(ea_comm, NULL),
           "expect attr_ecommunity_replace_list(empty, NULL) to be empty") ;

      ecomm = attr_ecommunity_replace_list(n_comm, NULL) ;
      test_assert(ecomm == n_comm,
           "expect attr_ecommunity_replace_list(not-stored, NULL) == not-stored") ;
      test_assert(attr_ecommunity_equal(n_comm, NULL),
           "expect attr_ecommunity_replace_list(not-stored, NULL) to be empty") ;

      attr_ecommunity_free(n_comm) ;
      n_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      ecomm = attr_ecommunity_replace_list(ea_comm, eb_comm) ;
      test_assert(ecomm == ea_comm,
           "expect attr_ecommunity_replace_list(empty, empty) == NULL") ;
      test_assert(attr_ecommunity_equal(ea_comm, NULL),
           "expect attr_ecommunity_replace_list(empty, empty) to be empty") ;

      ecomm = attr_ecommunity_replace_list(n_comm, eb_comm) ;
      test_assert(ecomm == n_comm,
           "expect attr_ecommunity_replace_list(not-stored, empty) == not-stored") ;
      test_assert(attr_ecommunity_equal(n_comm, NULL),
           "expect attr_ecommunity_replace_list(not-stored, empty) to be empty") ;

      attr_ecommunity_free(n_comm) ;
      attr_ecommunity_release(s_comm) ;
    } ;

  /* Test replacing by a not-empty stored or not-stored.
   */
  for (count = 1 ; count < 100 ; ++count)
    {
      ecomm_list      cl ;
      attr_ecommunity ecomm, a_comm, b_comm, sa_comm, sb_comm;

      next_test() ;

      /* Make a_comm and sa_comm (same) to count length.
       *
       * Make b_comm and sb_comm (same) to random length.
       */
      cl = make_ecomm_list(count) ;
      a_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      sa_comm = attr_ecommunity_store(a_comm) ;
      a_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      cl = make_ecomm_list((rand() % 100) + 1) ;
      b_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;
      sb_comm = attr_ecommunity_store(b_comm) ;
      b_comm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      /* Replacing by stored yields the stored -- without changing the
       * original.
       */
      ecomm = attr_ecommunity_replace_list(NULL, sb_comm) ;
      test_assert(ecomm == sb_comm,
          "expect attr_ecommunity_replace_list(NULL, stored) == stored") ;

      ecomm = attr_ecommunity_replace_list(ea_comm, sb_comm) ;
      test_assert(ecomm == sb_comm,
          "expect attr_ecommunity_replace_list(NULL, stored) == stored") ;

      ecomm = attr_ecommunity_replace_list(sa_comm, sb_comm) ;
      test_assert(ecomm == sb_comm,
          "expect attr_ecommunity_replace_list(stored, stored_n) == stored_n") ;

      ecomm = attr_ecommunity_replace_list(a_comm, sb_comm) ;
      test_assert(ecomm == sb_comm,
          "expect attr_ecommunity_replace_list(not-stored, stored) == stored") ;

      /* Replacing by not-stored yields copy of the not-stored or updates the
       * original.
       */
      ecomm = attr_ecommunity_replace_list(NULL, b_comm) ;
      test_assert((ecomm != b_comm) && (ecomm != NULL),
          "expect attr_ecommunity_replace_list(NULL, not-stored) == new") ;
      test_assert(attr_ecommunity_equal(ecomm, b_comm),
                                        "expect new list == replacement list") ;
      attr_ecommunity_free(ecomm) ;

      ecomm = attr_ecommunity_replace_list(ea_comm, b_comm) ;
      test_assert(ecomm == ea_comm,
          "expect attr_ecommunity_replace_list(empty, not-stored) == updated") ;
      test_assert(attr_ecommunity_equal(ecomm, b_comm),
                                        "expect new list == replacement list") ;

      attr_ecommunity_clear(ea_comm) ;

      ecomm = attr_ecommunity_replace_list(sa_comm, b_comm) ;
      test_assert((ecomm != sa_comm) && (ecomm != b_comm) && (ecomm != NULL),
          "expect attr_ecommunity_replace_list(stored, not-stored) == new") ;
      test_assert(attr_ecommunity_equal(ecomm, b_comm),
                                        "expect new list == replacement list") ;
      attr_ecommunity_free(ecomm) ;

      ecomm = attr_ecommunity_replace_list(a_comm, b_comm) ;
      test_assert(ecomm == a_comm,
          "expect attr_ecommunity_replace_list(not-stored, not-stored) == "
                                                                    "updated") ;
      test_assert(attr_ecommunity_equal(ecomm, b_comm),
                                        "expect new list == replacement list") ;

      attr_ecommunity_release(a_comm) ;
      attr_ecommunity_release(b_comm) ;
      attr_ecommunity_release(sa_comm) ;
      attr_ecommunity_release(sb_comm) ;
    } ;

  attr_ecommunity_free(ea_comm) ;
  attr_ecommunity_free(eb_comm) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test for: attr_ecommunity_del_list()
 *
 * For a variety of random lengths of ecommunity attribute, start with a random
 * ecomm_list and:
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
 *  * do attr_ecommunity_del_list() on stored and not-stored.
 *
 *    Alternate deleting stored from not-stored
 *
 *  * construct what we expect to get -- delete_ecomm_list() and check the
 *    retsults.
 */
static void
test_ecomm_del_list(void)
{
  uint fail_count_was, test_count_was ;
  uint tc ;
  bool ok ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_del_list") ;

  for (tc = 0 ; tc < 1000 ; ++tc)
    {
      uint       count, o ;
      ecomm_list cl ;

      next_test() ;

      count = tc % 101 ;
      cl = make_ecomm_list(count) ;

      /* We run an odd number of lengths: 0..100, so every other time we will
       * have tc odd when length == 0.
       */

      /* A number of times, split the original ecomm_list, to create two
       * attr_ecommunity values, which contain some part of the original, and
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
              ecomm_list cla, cld ;
              attr_ecommunity ecomm_a, ecomm_sa, ecomm_d, ecomm_sd,
                                              ecomm_t, ecomm_st ;
              bool changed ;

              next_test() ;

              cla = copy_ecomm_list(cl) ;                /* delete from  */
              cld = split_ecomm_list(cla, o, b) ;        /* delete       */

              ecomm_a  = attr_ecommunity_set((byte*)cla->list, cla->list_count) ;
              ecomm_sa = attr_ecommunity_store(ecomm_a) ;
              ecomm_a  = attr_ecommunity_set((byte*)cla->list, cla->list_count) ;

              if (cla->list_count != 0)
                {
                  assert((ecomm_a != NULL) && (ecomm_sa != NULL)) ;
                }
              else
                {
                  assert((ecomm_a == NULL) && (ecomm_sa == NULL)) ;
                  ecomm_a = attr_ecommunity_new(rand() %
                                           (ecommunity_list_embedded_size * 2)) ;
                } ;

              ecomm_d  = attr_ecommunity_set((byte*)cld->list, cld->list_count) ;
              ecomm_sd = attr_ecommunity_store(ecomm_d) ;
              ecomm_d  = attr_ecommunity_set((byte*)cld->list, cld->list_count) ;

              if (cld->list_count != 0)
                {
                  assert((ecomm_d != NULL) && (ecomm_sd != NULL)) ;
                }
              else
                {
                  assert((ecomm_d == NULL) && (ecomm_sd == NULL)) ;
                  ecomm_d = attr_ecommunity_new(rand() %
                                           (ecommunity_list_embedded_size * 2)) ;
                } ;

              if (tc & 1)
                {
                  ecomm_t  = attr_ecommunity_del_list(ecomm_a,  ecomm_d) ;
                  ecomm_st = attr_ecommunity_del_list(ecomm_sa, ecomm_sd) ;
                }
              else
                {
                  ecomm_t  = attr_ecommunity_del_list(ecomm_a,  ecomm_sd) ;
                  ecomm_st = attr_ecommunity_del_list(ecomm_sa, ecomm_d) ;
                } ;

              changed = delete_ecomm_list(cla, cld) ;

              test_assert(ecomm_t == ecomm_a,
                  "expect self after "
                                   "attr_ecommunity_del_list(not-stored, ...)") ;
              if (ecomm_sa != NULL)
                {
                  if (changed)
                    test_assert(ecomm_st != ecomm_sa,
                      "expect new value after "
                                   "attr_ecommunity_del_list(stored, ...)") ;
                  else
                    test_assert(ecomm_st == ecomm_sa,
                      "expect same value after "
                                "attr_ecommunity_del_list(stored, NULL/empty)") ;
                }
              else
                test_assert(ecomm_st == NULL,
                  "expect NULL after "
                                   "attr_ecommunity_del_list(NULL, ...)") ;

              test_assert(attr_ecommunity_equal(ecomm_t, ecomm_st),
                               "expected stored and not-stored results equal") ;

              if (ecomm_t == NULL)
                {
                  test_assert(cla->sorted_count == 0,
                      "expected %u entries remaining, got NULL",
                                                            cla->sorted_count) ;
                }
              else
                {
                  ok = test_assert(cla->sorted_count == ecomm_t->list.len,
                      "expected %u entries remaining, got=%u",
                                          cla->sorted_count, ecomm_t->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(cla->sorted, ecomm_t->list.body.c,
                                                   cla->sorted_count * 8) == 0,
                                                "did not get expected result") ;
                      if (!ok)
                        show_delta((const ecommunity_t*)ecomm_t->list.body.v,
                                               cla->sorted, cla->sorted_count) ;
                    } ;
                } ;

              if (ecomm_st == NULL)
                {
                  test_assert(cla->sorted_count == 0,
                      "expected %u entries remaining, got NULL",
                                                            cla->sorted_count) ;
                }
              else
                {
                  ok = test_assert(cla->sorted_count == ecomm_st->list.len,
                      "expected %u entries remaining, got=%u",
                                         cla->sorted_count, ecomm_st->list.len) ;
                  if (ok)
                    {
                      ok = test_assert(memcmp(cla->sorted, ecomm_st->list.body.c,
                                                   cla->sorted_count * 8) == 0,
                                                "did not get expected result") ;
                      if (!ok)
                        show_delta((const ecommunity_t*)ecomm_st->list.body.v,
                                               cla->sorted, cla->sorted_count) ;
                    } ;
                } ;

              attr_ecommunity_release(ecomm_sa) ;
              attr_ecommunity_release(ecomm_sd) ;
              attr_ecommunity_free(ecomm_a) ;
              if (ecomm_st != ecomm_sa)
                attr_ecommunity_free(ecomm_st) ;
              attr_ecommunity_free(ecomm_d) ;

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
 * Test for: attr_ecommunity_out_prepare()
 *
 * Pretty straightforward -- test for a range of lengths including zero
 * (not forgetting to test for NULL and empty)
 */
static void
test_ecomm_out_prepare(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_out_prepare") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      ecomm_list      cl ;
      attr_ecommunity ecomm ;
      uint     length ;
      byte*    p_attr ;
      bool ok ;

      next_test() ;

      /* Check for case of empty of various lengths.
       */
      ecomm   = attr_ecommunity_new(count) ;

      p_attr = attr_ecommunity_out_prepare(ecomm, false /* not just trans */,
                                                                     &length) ;
      test_assert(p_attr == NULL,
        "expect attr_ecommunity_out_prepare(empty, ...) == NULL") ;
      test_assert(length == 0,
        "expect attr_ecommunity_out_prepare(empty, ...) to give length==0, "
        "got=%u", length) ;

      attr_ecommunity_free(ecomm) ;

      /* Make ecomm to count length.
       */
      cl = make_ecomm_list(count) ;
      ecomm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      p_attr = attr_ecommunity_out_prepare(ecomm, false /* not just trans */,
                                                                     &length) ;
      if (count == 0)
        {
          assert(ecomm == NULL) ;

          test_assert(p_attr == NULL,
            "expect attr_ecommunity_out_prepare(NULL, ...) == NULL") ;
          test_assert(length == 0,
            "expect attr_ecommunity_out_prepare(NULL, ...) to give length==0, "
            "got=%u", length) ;
        }
      else
        {
          uint t_length, b_length, a_length ;
          byte e_flags ;
          byte* ap ;

          assert(ecomm != NULL) ;

          b_length = cl->sorted_count * 8 ;
          t_length = 2 + (b_length > 255 ? 2 : 1) + b_length ;

          ok = test_assert(p_attr != NULL,
              "expect attr_ecommunity_out_prepare() != NULL") ;
          if (ok)
            ok = test_assert(length == t_length,
              "expect attr_ecommunity_out_prepare() to give length=%u, "
              "got=%u", t_length, length) ;

          e_flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE
                                   | ((b_length > 255) ? BGP_ATF_EXTENDED : 0) ;
          if (ok)
            ok = test_assert(p_attr[0] == e_flags, "expected flags=%u, got=%u",
                                                           e_flags, p_attr[0]) ;
          if (ok)
            ok = test_assert(p_attr[1] == BGP_ATT_ECOMMUNITIES,
                  "expected type=%u, got=%u", BGP_ATT_ECOMMUNITIES, p_attr[1]) ;

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
                  "expect attr_ecommunity_out_prepare() to give attribute body "
                    "length=%u, got=%u", b_length, a_length) ;

              if (ok)
                {
                  ecommunity_t*  v ;
                  uint i ;

                  v = cl->sorted ;
                  for (i = 0 ; i < cl->sorted_count ; ++i)
                    {
                      if (v[i] != load_nq(ap))
                        break ;

                      ap += 8 ;
                    } ;

                  test_assert(i >= cl->sorted_count,
                                          "body of attribute not as expected") ;
                } ;
            } ;
        } ;

      /* Tidy up
       */
      attr_ecommunity_release(ecomm) ;
      free(cl) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

#if 0
/*==============================================================================
 * Test for: attr_ecommunity_text_vector()
 *
 * Pretty straightforward -- test for a range of lengths including zero
 * (not forgetting to test for NULL and empty)
 */
static void
test_ecomm_text_vector(void)
{
  uint fail_count_was, test_count_was ;
  uint count ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_ecommunity_text_vector") ;

  /* Test clearing NULL, empty and stored of a few lengths and not-stored ditto.
   */
  for (count = 0 ; count < 100 ; ++count)
    {
      ecomm_list      cl ;
      attr_ecommunity ecomm ;
      vector text_v, text_vx ;
      bool ok ;

      next_test() ;

      /* Check for case of empty of various lengths.
       */
      ecomm   = attr_ecommunity_new(count) ;

      text_v = attr_ecommunity_text_vector(ecomm) ;
      test_assert((text_v == NULL) || (vector_length(text_v) == 0),
          "expect attr_ecommunity_text_vector(empty) == NULL or empty") ;

      text_vx = attr_ecommunity_text_vector(ecomm) ;
      test_assert((text_v == text_vx),
          "expect attr_ecommunity_text_vector() to return same vector "
                                                         "second time around") ;
      attr_ecommunity_free(ecomm) ;

      /* Make ecomm to count length.
       */
      cl = make_ecomm_list(count) ;
      ecomm  = attr_ecommunity_set((byte*)cl->list, cl->list_count) ;

      text_v = attr_ecommunity_text_vector(ecomm) ;

      if (count == 0)
        {
          assert(ecomm == NULL) ;

          test_assert(text_v == NULL,
              "expect attr_ecommunity_text_vector(empty) == NULL") ;
        }
      else
        {
          ok = test_assert(vector_length(text_v) == cl->sorted_count,
                          "expect text_vector length=%u, got=%u",
                                     cl->sorted_count, vector_length(text_v)) ;
          if (ok)
            {
              ecommunity_t* v ;
              uint iv ;
              attr_ecommunity ecomm_v ;

              v = cl->sorted ;
              ecomm_v = NULL ;
              for (iv = 0 ; iv < cl->sorted_count ; ++iv)
                {
                  attr_ecommunity_type_t act ;
                  ecommunity_t cv ;

                  ecomm_v = attr_ecommunity_from_str (vector_get_item(text_v, iv),
                                                                         &act) ;
                  if ((ecomm_v == NULL) || (act != act_simple)
                                       || (ecomm_v->list.len != 1))
                    break ;

                  cv = *((ecommunity_t*)ecomm_v->list.body.v) ;

                  if (cv != v[iv])
                    break ;

                  ecomm_v = attr_ecommunity_free(ecomm_v) ;
                } ;

              test_assert(iv >= cl->sorted_count,
                  "did not expect text vector entry '%s'",
                                           (char*)vector_get_item(text_v, iv)) ;
              attr_ecommunity_free(ecomm_v) ;
            } ;
        } ;

      text_vx = attr_ecommunity_text_vector(ecomm) ;
      test_assert((text_v == text_vx),
          "expect attr_ecommunity_text_vector() to return same vector "
                                                         "second time around") ;
      /* Tidy up
       */
      attr_ecommunity_release(ecomm) ;
      free(cl) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

#endif

/*==============================================================================
 * Test support functions
 */
static ecomm_list sort_ecomm_list(ecomm_list cl) ;

/*------------------------------------------------------------------------------
 * Make a random ecommunity list of given length
 *
 * Includes ~25% repeated values.
 *
 *  Fills in:
 *
 *    cl->list_count     -- original count of ecommunity values
 *    cl->list           -- the original ecommunity values in whatever order,
 *                          with repeats, etc
 *
 *    cl->sorted_count   -- count of ecommunity values after sort/dedup
 *    cl->sorted         -- the ecommunity values after sort/dedup
 */
static ecomm_list
make_ecomm_list(uint count)
{
  ecomm_list cl ;
  ecommunity_t* v ;
  uint i ;

  assert(count <= ecomm_max) ;

  cl = malloc(sizeof(ecomm_list_t)) ;
  memset(cl, 0, sizeof(ecomm_list_t)) ;

  cl->list_count = count ;
  v = cl->list ;

  /* Fill with random values -- the cl->list is in Network Order, but that
   * doesn't matter much here !
   */
  for (i = 0 ; i < count ; ++i)
    {
      ecommunity_t  ecv ;

      ecv = ((ecommunity_t)rand() << 24) ^ rand() ;

      ecv &= 0x0000FFFFFFFFFFFF ;

      ecv |= ((ecommunity_t)(rand() % 3))       << 56 ;
      ecv |= ((ecommunity_t)((rand() % 2) + 2)) << 48 ;

      v[i] = htonq(ecv) ;
      confirm(sizeof(ecommunity_t) == 8) ;
    }

  /* Now introduce some repeats
   */
  for (i = 0 ; i < count ; ++i)
    {
      if ((rand() % 4) == 0)
        v[i] = v[rand() % count] ;
    } ;

  /* Fill in the sorted part and return result.
   */
  return sort_ecomm_list(cl) ;
} ;

/*------------------------------------------------------------------------------
 * Perturb given ecomm_list, creating a copy of the original.
 *
 * If the original is empty, create new ecomm_list with one entry.
 *
 * Changes one entry in the ecomm_list, so that the result is exactly the same
 * length as the original, but one value (possibly repeated) is different.
 */
static ecomm_list
perturb_ecomm_list(ecomm_list original)
{
  ecomm_list cl ;
  uint i ;
  ecommunity_t* v ;
  ecommunity_t from, to, delta ;

  if (original->list_count == 0)
    return make_ecomm_list(1) ;

  /* Make a nice new copy of the original, and chose something to change, at
   * random.
   */
  cl = copy_ecomm_list(original) ;

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
  delta = (ecommunity_t)1 << (rand() % 32) ;
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
  return sort_ecomm_list(cl) ;
} ;

/*------------------------------------------------------------------------------
 * Drop item from given ecomm_list.
 *
 * Does nothing at all if is empty.
 *
 * Returns:  ecommunity value dropped
 */
static ecommunity_t
drop_ecomm_list(ecomm_list cl)
{
  ecommunity_t drop ;
  uint i, j ;
  ecommunity_t* v ;

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
  sort_ecomm_list(cl) ;

  /* Return what we dropped -- in Host Order
   */
  return ntohq(drop) ;
} ;

/*------------------------------------------------------------------------------
 * Take given ecomm_list and move/copy a random proportion of the sorted and
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
static ecomm_list
split_ecomm_list(ecomm_list cl, uint old, uint both)
{
  ecomm_list clx ;
  uint i, n, nx ;

  assert((old + both) <= 10) ;

  clx = copy_ecomm_list(cl) ;

  if (cl->list_count == 0)
    return clx ;

  n = nx = 0 ;
  for (i = 0 ; i < cl->sorted_count ; ++i)
    {
      ecommunity_t cv ;
      uint r ;

      cv = htonq(cl->sorted[i]) ;
      confirm(sizeof(ecommunity_t) == 8) ;
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
  sort_ecomm_list(cl) ;
  sort_ecomm_list(clx) ;

  return clx ;
} ;

/*------------------------------------------------------------------------------
 * Delete entries from given list which exist in the other given list.
 */
static bool
delete_ecomm_list(ecomm_list cl, ecomm_list cld)
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
        cl->list[n++] = htonq(cl->sorted[i]) ;
      else
        changed = true ;
    } ;

  cl->list_count  = n ;

  /* Fill in the sorted part and return result.
   */
  sort_ecomm_list(cl) ;

  return changed ;
} ;

/*------------------------------------------------------------------------------
 * Sort and de-dup the given ecomm_list
 */
static ecomm_list
sort_ecomm_list(ecomm_list cl)
{
  uint i, n ;
  ecommunity_t* v ;

  /* Copy to the sorted version in host order, then sort and dedup.
   */
  n = cl->list_count ;
  v = cl->sorted ;

  for (i = 0 ; i < n ; ++i)
    v[i] = ntohq(cl->list[i]) ;
  confirm(sizeof(ecommunity_t) == 8) ;

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
              ecommunity_t t ;

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
 * Make copy of the given ecomm_list
 */
static ecomm_list
copy_ecomm_list(ecomm_list original)
{
  ecomm_list cl ;

  cl = malloc(sizeof(ecomm_list_t)) ;
  memcpy(cl, original, sizeof(ecomm_list_t)) ;

  return cl ;
} ;

/*------------------------------------------------------------------------------
 * Show difference between the ecommunity list we got, and the ecommunity list
 * we expected.
 */
static void
show_delta(const ecommunity_t* got, const ecommunity_t* exp, uint count)
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
    fprintf(stderr, " %016lx", exp[i]) ;

  fprintf(stderr, "  ... total length = %u (entries)", count) ;

  fprintf(stderr, "\n  g%3d:", off) ;
  for (i = off ; (i < (off + 5)) && (i < count) ; ++i)
    fprintf(stderr, " %016lx", got[i]) ;
} ;

