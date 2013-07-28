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
 * bgpd/as_path.c torture tests
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
enum { as_path_max = 2000 } ;           /* maximum length we test to !  */

typedef struct as_test_seg  as_test_seg_t ;
typedef struct as_test_seg* as_test_seg ;

struct as_test_seg
{
  struct dl_list_pair(as_test_seg)   list ;

  as_seg_t      seg ;

  uint          len ;
  uint          size ;
  as_t*         body ;
} ;

typedef struct dl_base_pair(as_test_seg) path_list_t ;
typedef path_list_t* path_list ;

typedef struct as_test_path  as_test_path_t ;
typedef struct as_test_path* as_test_path ;

struct as_test_path
{
  /* The 'path' is the primary value for the as_test_path -- this may be set
   * from an as_path or in other ways for constructing tests.
   */
  path_list_t   path ;

  /* The 'parse' is constructed from the 'path', in either AS4 or AS2 form,
   * for testing of as_path_parse()
   */
  byte*         parse ;
  uint          parse_len ;

  /* The 'comp' and related stuff is constructed from the path, for comparison
   * with what as_path_post_process() creates.
   */
  asp_item_t*   comp ;
  uint          comp_len ;
  uint          comp_size ;

  as_path_properties_t  p ;

  /* The 'enc' and related stuff is constructed from the path, for comparison
   * with what as_path_out_prepare() creates.
   */
  byte*         enc ;
  uint          enc_len ;

  /* The 'extract' is a as_test_seg (BGP_AS_SET), containing the ASN in the
   * current 'path'.
   */
  as_test_seg   extract ;
};

/*------------------------------------------------------------------------------
 * Is given segment value valid ?
 */
inline static bool
seg_is_valid(as_seg_t seg)
{
  switch (seg)
    {
      case BGP_AS_SEQUENCE:
      case BGP_AS_SET:
      case BGP_AS_CONFED_SEQUENCE:
      case BGP_AS_CONFED_SET:
        return true ;

      default:
        return false ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Knobs for make_test_path()
 */
typedef enum
{
  all_asn,              /* 1..0xFFFF_FFFF       */
  as2_only,             /* 1..0xFFFF            */
  private_only,         /* 64512..65534         */
} test_asn_t;

typedef enum
{
  all_sorts,
  random_segs,
  no_confeds,
} test_sort_t ;

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_as_path_post_process(void) ;
static void test_as_path_parse(void) ;
static void test_as_path_out_prepare(void) ;
static void test_as_path_from_str(void) ;
static void test_as_path_str(void) ;
static void test_as_path_properties(void) ;
static void test_as_path_ap_pre_pend_path(void) ;
static void test_as_path_prepend(void) ;
static void test_as_path_confed_stuff(void) ;
static void test_as_path_reconcile_as4(void) ;
static void test_as_path_aggregate(void) ;
static void test_asn_set(void) ;
static void test_as_path_store(void) ;
static void test_as_path_exclude_asns(void) ;

static void show_delta(const asp_item_t* got, const asp_item_t* exp,
                                                                   uint count) ;
static void show_delta_properties(const as_path_properties_t* got,
                                  const as_path_properties_t* exp) ;

static void make_test_path(as_test_path astp, uint count, bool small_rep,
                                            test_asn_t which, test_sort_t how) ;
static as_path make_post_process_test(uint count) ;
static void make_parse_test(as_test_path astp, bool as4) ;
static void show_test_path(void) ;
static void make_not_private_test(as_test_path astp) ;
static void test_path_prepend(as_test_path astp, as_seg_t seg, uint count) ;
static void test_as_path_private_as_check(void) ;

static const char* post_process(as_test_path astp, as_path asp) ;
static as_test_path astp_new(void) ;
static void astp_reset(as_test_path astp) ;
static as_test_path astp_free(as_test_path astp) ;
static void astp_sort_dedup(as_test_path astp) ;
static void astp_compress(as_test_path astp, bool sort_dedup, bool as4) ;
static void astp_properties(as_test_path astp, bool as4) ;
static bool astp_confed_ok(as_test_path astp) ;
static bool astp_encode(as_test_path astp, bool as4, bool as4_parse,
                                                              as_path_out out) ;
static void astp_trans(as_test_path astp) ;
static void astp_extract(as_test_path astp) ;
static as_t astp_present(as_test_path astp) ;
static uint astp_present_count(as_test_path astp, as_t asn) ;
static as_t astp_not_present(as_test_path astp) ;
static as_t astp_highest_asn(as_test_path astp) ;
static uint astp_confed_delete(as_test_path astp) ;
static uint astp_confed_sweep(as_test_path astp) ;
static void astp_reconcile_as4(as_test_path astp_2, as_test_path astp_4) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
#ifdef MCHECK_H
  mcheck(NULL) ;
#endif

  qlib_init_first_stage(0);     /* Absolutely first             */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start BGP AS_PATH testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  bgp_attr_start() ;            /* wind up the entire attribute store   */

  test_as_path_post_process() ;

  test_as_path_parse() ;

  test_as_path_out_prepare() ;

  test_as_path_from_str() ;

  test_as_path_str() ;

  test_as_path_properties() ;

  test_as_path_private_as_check() ;

  test_as_path_ap_pre_pend_path() ;

  test_as_path_prepend() ;

  test_as_path_confed_stuff() ;

  test_as_path_reconcile_as4() ;

  test_as_path_aggregate() ;

  test_asn_set() ;

  test_as_path_store() ;

  test_as_path_exclude_asns() ;

  bgp_attr_finish() ;           /* close it down again                  */

  fprintf(stderr, "Finished BGP AS_PATH testing") ;

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
 *  * as_path_start()              -- see main()
 *  * as_path_finish()             -- see main()
 *
 *  * as_path as_path_new()        -- see test_as_path_post_process()
 *  * as_path_store()              -- see test_as_path_parse()
 *                                                        & test_as_path_store()
 *  * as_path_free()               -- ditto
 *  * as_path_lock()               -- ditto
 *  * as_path as_path_release()    -- ditto
 *
 *  * as_path_parse()              -- see test_as_path_parse()
 *  * as_path_out_prepare()        -- see test_as_path_out_prepare()
 *
 *  * as_path_post_process()       -- see test_as_path_post_process()
 *
 *  * as_path_count()
 *
 *  * as_path_simple_path_length() -- see test_as_path_properties()
 *  * as_path_confed_path_length() -- see test_as_path_properties()
 *  * as_path_total_path_length()  -- see test_as_path_properties()
 *  * as_path_is_empty()           -- see test_as_path_properties()
 *  * as_path_confed_ok()          -- see test_as_path_properties()
 *  * as_path_first_simple_asn()   -- see test_as_path_properties()
 *  * as_path_first_confed_asn()   -- see test_as_path_properties()
 *  * as_path_left_most_asn()      -- see test_as_path_properties()
 *  * as_path_loop_check()         -- see test_as_path_properties()
 *  * as_path_highest()            -- see test_as_path_properties()
 *  * as_path_size()               -- see test_as_path_properties()
 *
 *  * as_path_private_as_check()   -- see test_as_path_private_as_check()
 *
 *  * as_path_prepend_path()       -- see test_as_path_ap_pre_pend_path()
 *  * as_path_add_seq()            -- see test_as_path_prepend()
 *  * as_path_add_confed_seq()     -- see test_as_path_prepend()
 *  * as_path_append_path()        -- see test_as_path_ap_pre_pend_path()
 *
 *  * as_path_confed_delete()      -- see test_as_path_confed_stuff()
 *  * as_path_confed_sweep()       -- see test_as_path_confed_stuff()
 *  * as_path_reconcile_as4()      -- see test_as_path_reconcile_as4()
 *  * as_path_aggregate()          -- see test_as_path_aggregate()
 *  * as_path_exclude_asns()       -- see test_as_path_exclude_asns()
 *
 *  * as_path_from_str()           -- see test_as_path_from_str() and
 *                                                            test_as_path_str()
 *  * as_path_str()                -- see test_as_path_str()
 *
 *  * as_path_print_all_vty()
 *
 *  * asn_set_free()               -- see test_asn_set()
 *  * asn_set_add()                -- ditto
 *  * asn_set_contains()           -- ditto
 *  * asn_set_from_str()           -- ditto
 */

/*==============================================================================
 * Test of as_path_post_process().
 *
 * Generates a large number of pretty random many nonsensical as_path path
 * objects, and checks that the post-processing deals with all corner cases.
 */
static void
test_as_path_post_process(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path astp ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_post_process() low level") ;

  astp= astp_new() ;

  for (i = 0 ; i < 20000 ; ++i)
    {
      as_path asp ;
      bool ok ;
      const char* ret ;

      next_test() ;

      asp = make_post_process_test((i % 57) + 1) ;

      ret = post_process(astp, asp) ;
      assert(ret == NULL) ;

      as_path_post_process_tx(asp) ;

      ok = test_assert(astp->comp_len == asp->path.len,
                       "expected post-processed length %u, but got %u",
                                            astp->comp_len, asp->path.len) ;
      if (ok && (astp->comp_len != 0))
        {
          ok = test_assert(memcmp(asp->path.body.v, astp->comp,
                                 astp->comp_len * sizeof(asp_item_t)) == 0,
                                 "post-processed as_path not as expected") ;
          if (!ok)
            show_delta(asp->path.body.v, astp->comp, astp->comp_len) ;
        } ;

      if (ok)
        ok = test_assert(memcmp(&astp->p, &asp->p,
                                         sizeof(as_path_properties_t)) == 0,
                   "properties of post-processed as_path not as expected") ;
      if (!ok)
        show_delta_properties(&asp->p, &astp->p) ;

      if (!ok)
        show_test_path() ;

      as_path_free(asp) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_parse().
 *
 * Zero length attribute test:
 *
 *   * checks that produces empty AS_PATH for zero length attribute
 *
 *   * checks that stores zero length path as the well known as_path_empty_asp
 *
 *   * checks the reference count on the well known as_path_empty_asp, after
 *     storing and then after releasing.
 *
 * Invalid attribute tests, for a small number of attributes with various
 * lengths (including zero) and for as2/as4 at random:
 *
 *   * checks that attribute parses
 *
 *   * unless length was zero, checks that fails if length is reduced by 1
 *
 *   * checks that fails if length is increased by 1 -- even with a valid
 *     orphan segment seg byte.
 *
 *   * checks that fails a segment length of zero
 *
 *   * check that fails a segment containing a zero ASN
 *
 *   * check that does not fail if ASN is set not zero
 *
 *   * check that fails all invalid segment types
 *
 * Main test, for a large number of trials:
 *
 *   * generates moderately plausible, non-zero length, AS_PATH attributes:
 *
 *      - some with small repeats
 *
 *      - some with only AS2 ASN
 *
 *      - in AS2/AS4 form at random
 *
 *   * checks that parses
 *
 *   * checks that stores
 *
 *   * checks that stored as_path and its properties are all as expected
 *
 *   * parses a second time, and checks that stores to the same stored value
 *
 *   * checks that the stored value has plausible reference counts etc.
 *
 *   * checks that releasing reduces the reference count as expected
 *
 * Should end up with no allocated/stored stuff.
 */
static void
test_as_path_parse(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path astp ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_parse()") ;

  astp = astp_new() ;

  /* Start with the invalid parse object tests.
   *
   * Slips in test for zero length parse.
   */
  for (i = 0 ; i < 400 ; ++i)
    {
      uint count, s ;
      as_path asp ;
      bool ok, as4 ;
      byte* end ;

      next_test() ;

      count = i % 43 ;
      make_test_path(astp, count, true /* small_rep */, all_asn, all_sorts) ;

      as4 = (rand() & 0x10000) ;
      make_parse_test(astp, as4) ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
      test_assert(asp != NULL, "expect initial parse to be valid") ;

      if (count == 0)
        {
          as_path asp_s ;

          assert(astp->parse_len == 0) ;

          ok = test_assert(asp->path.len == 0,
                                 "expect empty attribute to yield empty path") ;

          if (ok)
            {
              asp_s = as_path_store(asp) ;
              asp = NULL ;

              ok = test_assert(asp_s == as_path_empty_asp,
                      "expect empty path top store as the as_path_empty_asp") ;
            } ;

          if (ok)
            ok = test_assert(asp_s->stored,
                              "expected the stored asp to be marked 'stored'") ;
          if (ok)
            ok = test_assert(asp_s->state & asps_processed,
                           "expected the stored asp to be marked 'processed'") ;
          if (ok)
            ok = test_assert(asp_s->vhash.ref_count == 3,
             "expected the stored empty asp to have reference count==3, got %u",
                                                       asp_s->vhash.ref_count) ;
          if (ok)
            as_path_release(asp_s) ;

          if (ok)
            ok = test_assert(asp_s->vhash.ref_count == 1,
             "expected the stored empty asp to have reference count==1, got %u",
                                                       asp_s->vhash.ref_count) ;
        } ;

      as_path_free(asp) ;

      if (astp->parse_len != 0)
        {
          astp->parse_len -= 1 ;
          asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
          test_assert(asp == NULL,
                       "expect attribute which is 1 byte short to be invalid") ;

          astp->parse_len += 1 ;
        } ;

      end = astp->parse + astp->parse_len ;

      end[0] = BGP_AS_SEQUENCE ;        /* valid segment....            */
      end[1] = 0 ;
      astp->parse_len += 1 ;            /* .... but incomplete          */

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
      test_assert(asp == NULL,
                   "expect attribute which is incomplete to be invalid") ;

      astp->parse_len += 1 ;            /* Complete, but zero length.   */

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
      test_assert(asp == NULL, "expect zero length segment to be invalid") ;

      if (as4)
        astp->parse_len += 4 ;          /* one ASN                      */
      else
        astp->parse_len += 2 ;

      end[1] = 1 ;                      /* valid length                 */
      store_nl(&end[2], 0) ;            /* invalid ASN == 0             */

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
      test_assert(asp == NULL, "expect zero ASN to be invalid") ;

      store_nl(&end[2], 0x00010001) ;
      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
      test_assert(asp != NULL, "expect non-zero ASN to be valid") ;

      as_path_free(asp) ;

      for (s = 0 ; s < 256 ; s++)
        {
          end[0] = s ;
          asp = as_path_parse(astp->parse, astp->parse_len, as4) ;
          if (seg_is_valid(s))
            test_assert(asp != NULL, "expect segment type == %u to be valid",
                                                                            s) ;
          else
            test_assert(asp == NULL, "expect segment type == %u to be invalid",
                                                                            s) ;
          as_path_free(asp) ;
        } ;
    } ;

  /* Expect all sorts of paths to be valid and to be decoded correctly
   *
   * NB: all paths tested here are at least 1 ASN
   */
  for (i = 0 ; i < 20000 ; ++i)
    {
      uint count ;
      as_path asp, asp_s, asp_t ;
      bool ok, as4 ;

      next_test() ;

      count = (i % 97) + 1 ;
      make_test_path(astp, count, (rand() & 0x30000) /* small_rep */,
                                  (rand() & 0x70000) ? all_asn
                                                     : as2_only, all_sorts) ;

      as4 = (rand() & 0x10000) ;
      make_parse_test(astp, as4) ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;
      if (!ok)
        continue ;

      asp_s = as_path_store(asp) ;

      ok = test_assert(asp_s == asp, "expected the asp to be stored") ;
      if (ok)
        ok = test_assert(asp_s->stored,
                              "expected the stored asp to be marked 'stored'") ;
      if (ok)
        ok = test_assert(asp_s->state & asps_processed,
                           "expected the stored asp to be marked 'processed'") ;
      if (ok)
        ok = test_assert(asp_s->vhash.ref_count == 2,
                "expected the stored asp to have reference count==2, got %u",
                                                       asp_s->vhash.ref_count) ;
      if (!ok)
        continue ;

      astp_compress(astp, true /* sort/dedup sets */, as4) ;

      ok = test_assert(astp->comp_len == asp->path.len,
                       "expected post-processed length %u, but got %u",
                                            astp->comp_len, asp->path.len) ;
      if (ok && (astp->comp_len != 0))
        {
          ok = test_assert(memcmp(asp->path.body.v, astp->comp,
                                 astp->comp_len * sizeof(asp_item_t)) == 0,
                                 "post-processed as_path not as expected") ;
          if (!ok)
            show_delta(asp->path.body.v, astp->comp, astp->comp_len) ;
        } ;

      if (ok)
        {
          astp_properties(astp, as4) ;

          ok = test_assert(memcmp(&astp->p, &asp->p,
                                         sizeof(as_path_properties_t)) == 0,
                   "properties of post-processed as_path not as expected") ;
          if (!ok)
            show_delta_properties(&asp->p, &astp->p) ;
        } ;

      if (!ok)
        show_test_path() ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4) ;

      test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      asp_t = as_path_store(asp) ;

      ok = test_assert(asp_t != asp, "did NOT expect to store the asp") ;
      if (ok)
        ok = test_assert(asp_t == asp_s, "expected to get the stored asp") ;
      if (ok)
        ok = test_assert(asp_s->stored,
                              "expected the stored asp to be marked 'stored'") ;
      if (ok)
        ok = test_assert(asp_s->state & asps_processed,
                           "expected the stored asp to be marked 'processed'") ;
      if (ok)
        ok = test_assert(asp_s->vhash.ref_count == 4,
                "expected the stored asp to have reference count==4, got %u",
                                                       asp_s->vhash.ref_count) ;

      as_path_release(asp_t) ;

      if (ok)
        ok = test_assert(asp_s->vhash.ref_count == 2,
                "expected the stored asp to have reference count==2, got %u",
                                                       asp_s->vhash.ref_count) ;
      as_path_release(asp_s) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;


/*==============================================================================
 * Test of as_path_out_prepare().
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path in as2 or as4 form
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * parse same
 *
 *   * generate as2 and as4 encoded versions, prepending:
 *
 *       nothing
 *
 *       0, 1 or 2 BGP_AS_SEQUENCE (which strips any leading Confed stuff)
 *
 *       0, 1 or 2 BGP_AS_CONFED_SEQUENCE
 *
 *     for 14 "sub-tests" for each generated path
 *
 *   * make sure we test against special cases of leading BGP_AS_SEQUENCE
 *     and BGP_AS_CONFED segments with 253..255 entries -- which are the
 *     edge cases for pre-pending
 */
static void
test_as_path_out_prepare(void)
{
  uint fail_count_was, test_count_was ;
  uint i, special_case, special_len ;
  as_test_path  astp ;
  as_seg_t special_seg ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_out_prepare()") ;

  astp = astp_new() ;

  /* Expect all sorts of paths to be valid and to be encoded correctly
   */
  special_case = 0 ;
  special_seg  = BGP_AS_SEG_NULL ;
  special_len  = 0 ;

  for (i = 0 ; i < 2000 ; ++i)
    {
      uint count, j ;
      as_path  asp ;
      bool as4_parse, as4_out, ok, is_special ;

      /* Make sure we cover the empty path case.
       */
      if (i == 0)
        count = 0 ;             /* want to run empty case, once */
      else
        count = (i % 41) + 1 ;

      make_test_path(astp, count, (rand() & 0x30000) /* small_rep */,
                                  (rand() & 0x70000) ? all_asn
                                                     : as2_only, all_sorts) ;

      /* Need to make sure we cover the following special cases of initial
       * segment:
       *
       *   * BGP_AS_SEQUENCE         -- segment length 253..255
       *
       *   * BGP_AS_CONFED_SEQUENCE  -- segment length ditto.
       *
       * So, there are 6 special cases here.  Doesn't matter whether is
       * parsed as as4 or not.
       *
       * This covers the special cases when prepending 1 or 2 ASN.
       */
      is_special = false ;
      if ((special_case < 6) && (count == 9))
        {
          is_special = true ;

          special_len = 255 ;

          switch (special_case)
            {
              case 0:
                --special_len ;
                fall_through ;
              case 1:
                --special_len ;
                fall_through ;
              case 2:
                special_seg = BGP_AS_SEQUENCE ;
                break ;

              case 3:
                --special_len ;
                fall_through ;
              case 4:
                --special_len ;
                fall_through ;
              case 5:
                special_seg = BGP_AS_CONFED_SEQUENCE ;
                break ;

              default:
                assert(false) ;
            } ;

          test_path_prepend(astp, special_seg,
                                           ((rand() % 3) * 255) + special_len) ;
          special_case += 1 ;
        } ;

      as4_parse = (rand() & 0x10000) ;
      make_parse_test(astp, as4_parse) ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4_parse) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      if (!ok)
        continue ;

      as4_out = rand() & 0x1000 ;

      for (j = 0 ; j < 14 ; ++j)
        {
          as_path_out_t out[1] ;
          bool as4_req_get, as4_req_exp ;
          uint plen, k ;

          next_test() ;

          memset(out, 0, sizeof(as_path_out_t)) ;   /* No prepend   */

          switch (j)
            {
              case 0:
              case 1:
                out->seg = BGP_AS_SEG_NULL ;
                break ;

              case 2:
              case 3:
                out->seg = BGP_AS_SEQUENCE ;
                break ;

              case 4:
              case 5:
                out->seg = BGP_AS_CONFED_SEQUENCE ;
                break ;

              case 6:
              case 7:
                out->seg = BGP_AS_SEQUENCE ;
                out->prepend_count = 1 ;
                break ;

              case 8:
              case 9:
                out->seg = BGP_AS_CONFED_SEQUENCE ;
                out->prepend_count = 1 ;
                break ;

              case 10:
              case 11:
                out->seg = BGP_AS_SEQUENCE ;
                out->prepend_count = 2 ;
                break ;

              case 12:
              case 13:
                out->seg = BGP_AS_CONFED_SEQUENCE ;
                out->prepend_count = 2 ;
                break ;

              default:
                assert(false) ;
            } ;

          for (k = 0 ; k < out->prepend_count ; ++k)
            {
              if (rand() % 4)
                out->prepend_asn[k] = (rand() % 65535) + 1 ;
              else
                out->prepend_asn[k] = (rand() % 1065535) + 1 ;
            } ;

          as4_req_get = as_path_out_prepare(out, asp, as4_out) ;

          as4_req_exp = astp_encode(astp, as4_out, as4_parse, out) ;

          if (is_special && (j == 0))
            {
              assert(astp->enc[0] == special_seg) ;
              assert(astp->enc[1] == special_len) ;
            } ;

          if (astp->enc_len > 255)
            plen = 4 ;
          else
            plen = 3 ;

          ok = test_assert( (out->len[0] + out->len[1])
                                                      == (plen + astp->enc_len),
                            "expected len[0]+len[1]=%u+%u, got=%u+%u",
                                plen, astp->enc_len, out->len[0], out->len[1]) ;
          if (ok)
            {
              uint alen, xlen ;
              const byte* attr ;
              bool body_match ;

              if (plen == 4)
                {
                  attr = (const byte*)"\x50\x02" ;
                  alen = load_ns(out->part[0] + 2) ;
                }
              else
                {
                  attr = (const byte*)"\x40\x02" ;
                  alen = *(out->part[0] + 2) ;
                } ;

              if (!test_assert((memcmp(out->part[0], attr, 2) == 0)
                                                     && (alen == astp->enc_len),
                           "did not get expected AS_PATH attribute red tape"))
                ok = false ;

              xlen = out->len[0] - plen ;

              if (xlen == 0)
                body_match = true ;
              else
                body_match = (memcmp(astp->enc, out->part[0] + plen, xlen)
                                                                        == 0) ;

              if (body_match)
                body_match = (memcmp(astp->enc + xlen, out->part[1],
                                                   astp->enc_len - xlen) == 0) ;

              if (!test_assert(body_match,
                                "did not get expected AS_PATH attribute body"))
                ok = false ;

              if (!ok)
                {
                  const byte* p ;
                  uint l ;

                  p = out->part[0] ;
                  fprintf(stderr, "\n    got: 0x%02x 0x%02x %u (%u)",
                                                       p[0], p[1], alen, plen) ;
                  fprintf(stderr, "\n    got %s:", as4_out ? "as4" : "as2") ;

                  for (l = plen ; l < out->len[0] ; ++l)
                    fprintf(stderr, " %02x", p[l]) ;

                  p = out->part[1] ;
                  for (l = 0 ; l < out->len[1] ; ++l)
                    fprintf(stderr, " %02x", p[l]) ;

                  p = attr ;
                  fprintf(stderr, "\n    exp: 0x%02x 0x%02x %u (%u)",
                                              p[0], p[1], astp->enc_len, plen) ;

                  p = astp->enc ;
                  fprintf(stderr, "\n    exp %s:", as4_out ? "as4" : "as2") ;
                  for (l = 0 ; l < astp->enc_len ; ++l)
                    fprintf(stderr, " %02x", p[l]) ;
                } ;
            } ;

          if (ok)
            {
              if (as4_req_exp)
                ok = test_assert(as4_req_get,
                                      "expected AS4_PATH requirement") ;
              else
                ok = test_assert(!as4_req_get,
                                      "did NOT expect AS4_PATH requirement") ;
            } ;

          if (!ok)
            {
              fprintf(stderr, "\n   seg=%u, prepend_count=%u, "
                     "as4_parse=%u, as4_out=%u, as4_req_get=%u, as4_req_exp=%u",
                        out->seg, out->prepend_count,
                                 as4_parse, as4_out, as4_req_get, as4_req_exp) ;
              show_test_path() ;
            } ;

          if (j == 0)
            {
              asp = as_path_store(asp) ;

              if (count == 0)
                ok = test_assert(asp == as_path_empty_asp,
                                       "expected the empty path after store") ;
              else
                ok = test_assert(asp != as_path_empty_asp,
                                  "did NOT expect the empty path after store") ;
            } ;

          as4_out = !as4_out ;
        } ;

      as_path_release(asp) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_from_str().
 *
 * A few straightforward tests for basic string handling, particularly where
 * string is invalid.
 */
typedef struct asp_str_test  asp_str_test_t ;
typedef const struct asp_str_test* asp_str_test ;

struct asp_str_test
{
  const char*  str ;

  bool         good ;

  uint         len ;
  asp_item_t   body[10] ;
};

static const asp_str_test_t  asp_str_tests[] =
  {
      /* Empty string -- check for whitespace
       */
      { .str      = "",
        .good     = true,
        .len      = 0,
      },
      { .str      = " \n \t \r ",
        .good     = true,
        .len      = 0,
      },

      /* Simple numerics and edge cases -- invalids
       */
      { .str      = "0",
        .good     = false,
      },
      { .str      = "  0.0  ",
        .good     = false,
      },
      { .str      = "  1  ",
        .good     = true,
        .len      = 1,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "\t4294967295",
        .good     = true,
        .len      = 1,
        .body     = { { .asn   = 0xFFFFFFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "\t4294967296",
        .good     = false,
      },
      { .str      = "\t0.1 0.65535 \t  1.0 \r\n 1.65535 \t 65535.65535",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0xFFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0x10000,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0x1FFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0xFFFFFFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "0.65536",
        .good     = false,
      },
      { .str      = "65536.0",
        .good     = false,
      },
      { .str      = "65536.65536",
        .good     = false,
      },
      { .str      = "123456789012345678901234567890",
        .good     = false,
      },
      { .str      = "\t0.0x1 0x0.0xFFFF \t  0x00001.0 \r\n "
                                               "0x1.0xFFFF \t 0xFFFF.0xFFFF",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0xFFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0x10000,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0x1FFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 0xFFFFFFFF,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "0.0x10000",
        .good     = false,
      },
      { .str      = "0x10000.0",
        .good     = false,
      },
      { .str      = "0x10000.0x10000",
        .good     = false,
      },
      { .str      = "0x123456789012345678901234567890",
        .good     = false,
      },

      /* Broken characters in simple sequence
       */
      { .str      = "1 2 3,4",
        .good     = false,
      },
      { .str      = "1 2,3,4",
        .good     = false,
      },
      { .str      = "1:2 3 4",
        .good     = false,
      },
      { .str      = "ab5 !",
        .good     = false,
      },
      { .str      = "55blah!",
        .good     = false,
      },

      /* Trivial sets and broken ones -- checks that sets are sorted etc.
       */
      { .str      = "{1}",
        .good     = true,
        .len      = 1,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                    },
      },
      { .str      = "{1,2,3,4}",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                    },
      },
      { .str      = "{4,3,2,1,1,2,3,4,4,1}",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                    },
      },
      { .str      = "1 {2} 3 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "1 {2 , 3} 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "1 { 2 , 3 4 } 5",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 5,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = " 1 { 2 3 4 } 5",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 5,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = " 1 { 2 3 } {4 } 5",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SET | qAS_SET_START
                      },
                      { .asn   = 5,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = " 1 {,2  3,  4  } 5",
        .good     = false,
      },
      { .str      = " 1 {2 , 3  4,} 5",
        .good     = false,
      },
      { .str      = " 1 2} 3",
        .good     = false,
      },
      { .str      = " 1 {2,3,4",
        .good     = false,
      },
      { .str      = " 1 {2,(3),4} 5",
        .good     = false,
      },

      /* Trivial Confed sequences and broken ones
       */
      { .str      = "(1)",
        .good     = true,
        .len      = 1,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                    },
      },
      { .str      = "(1 2 3 4)",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                    },
      },
      { .str      = "1 (2) 3 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "1 ( 2 \t 3 ) 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "1 (2   3 4 ) 5",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 5,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = " 1 ( 2,3 4 ) 5",
        .good     = false,
      },
      { .str      = " 1 (,2 3 4) 5",
        .good     = false,
      },
      { .str      = " 1 (2 3 4,) 5",
        .good     = false,
      },
      { .str      = " 1 2) 3",
        .good     = false,
      },
      { .str      = " 1 (2 3 4",
        .good     = false,
      },
      { .str      = " 1 (2 (3) 4) 5",
        .good     = false,
      },

      /* Trivial Confed sets and broken ones
       */
      { .str      = "[1]",
        .good     = true,
        .len      = 1,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                    },
      },
      { .str      = "[1,2,3,4]",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                    },
      },
      { .str      = "[1,2,3,4,4,3,2,1,2,3]",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                    },
      },
      { .str      = "(1) [2] 3 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "(1) [2 , 3] 4",
        .good     = true,
        .len      = 4,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = "(1 1 1 1) [ 4 2  3 ,4 ] 5 5 5",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 4,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 5,
                        .count = 3,
                        .qseg  = qAS_SEQUENCE
                      },
                    },
      },
      { .str      = " (1) [ 2 3 2 4 ] (5)",
        .good     = true,
        .len      = 5,
        .body     = { { .asn   = 1,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                      { .asn   = 2,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET | qAS_SET_START
                      },
                      { .asn   = 3,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 4,
                        .count = 1,
                        .qseg  = qAS_CONFED_SET
                      },
                      { .asn   = 5,
                        .count = 1,
                        .qseg  = qAS_CONFED_SEQUENCE
                      },
                    },
      },
      { .str      = " 1 [,2,3,4] 5",
        .good     = false,
      },
      { .str      = " 1 [2,3,4,] 5",
        .good     = false,
      },
      { .str      = " 1 2] 3",
        .good     = false,
      },
      { .str      = " 1 [2,3,4",
        .good     = false,
      },
      { .str      = " 1 [2,(3),4] 5",
        .good     = false,
      },

      /* End
       */
      { .str      = NULL }
  };

/*------------------------------------------------------------------------------
 * Test of as_path_from_str()
 *
 * Run the strings from the table above and check get what we expect.
 */
static void
test_as_path_from_str(void)
{
  uint fail_count_was, test_count_was ;
  asp_str_test n_test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_from_str()") ;

  n_test = asp_str_tests ;

  while (n_test->str != NULL)
    {
      asp_str_test test ;
      as_path asp ;
      bool ok ;

      next_test() ;
      test   = n_test ;
      n_test = test + 1 ;

      asp = as_path_from_str (test->str) ;

      if (asp == NULL)
        {
          test_assert(!test->good,
                         "did not expect failure\n"
                         "   for: '%s'", test->str) ;
        }
      else
        {
          ok = test_assert(test->good,
                                 "expected failure but got as_path length %u\n"
                                 "   for: '%s'", asp->path.len, test->str) ;
          if (ok)
            {
              asp = as_path_store(asp) ;        /* canonical, please    */

              ok = test_assert(test->len == asp->path.len,
                    "expected path length %u, got=%u\n"
                    "   for: '%s'", test->len, asp->path.len, test->str) ;
              if (ok)
                ok = test_assert(memcmp(test->body, asp->path.body.v,
                                           test->len * sizeof(asp_item_t)) == 0,
                                "did not get the expected path\n"
                                "   for: '%s'", test->str) ;
            } ;

          if (!ok)
            {
              const asp_item_t* p ;
              uint i ;

              p = asp->path.body.v ;
              fprintf(stderr, "\n     got %2u:", asp->path.len) ;
              for (i = 0 ; i < asp->path.len ; ++i)
                fprintf(stderr, " %x/0x%08x*%2d", p[i].qseg, p[i].asn,
                                                             p[i].count) ;

              p = test->body ;
              fprintf(stderr, "\n     exp %2u:", test->len) ;
              for (i = 0 ; i < test->len ; ++i)
                fprintf(stderr, " %x/0x%08x*%2d", p[i].qseg, p[i].asn,
                                                             p[i].count) ;
            } ;

          as_path_release(asp) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_str()
 */
const char* const test_str_table[] =
  {
    "",
    "1",
    "1 2 3 4",
    "{1,2,3,4}",
    "(1 2 3 4)",
    "[1,2,3,4]",
    "1 2 (3 4) {5,6} [7,8] 9",
     NULL,
  };

/*------------------------------------------------------------------------------
 * Test of as_path_str()
 *
 * Run a small number of round-trip tests, from the table above.
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path in as4 form
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * parse same and confirm is as expected
 *
 *   * generate string and store same
 *
 *     or store same and generate string
 *
 *   * convert string to a new string
 *
 *   * store the new string
 *
 *   * confirm that get the original as_path
 */
static void
test_as_path_str(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp ;
  const char* const* p_str ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_str()") ;

  astp = astp_new() ;

  p_str = test_str_table ;
  while (*p_str != NULL)
    {
      as_path  asp ;
      const char* str_in ;

      str_in = *p_str++ ;

      asp = as_path_from_str(str_in) ;

      if (test_assert(asp != NULL, "expect to convert string '%s'", str_in))
        {
          const char* str_out ;

          str_out = as_path_str(asp) ;

          test_assert(strcmp(str_in, str_out) == 0,
                     "expect round trip in==out: '%s'=='%s'", str_in, str_out) ;
          as_path_free(asp) ;
        } ;
    } ;

  /* Expect all sorts of paths to be valid and to be encoded correctly
   */
  for (i = 0 ; i < 20000 ; ++i)
    {
      uint count ;
      as_path  asp, asp_s ;
      bool ok, as4_original ;
      const char* str, * str2 ;

      next_test() ;

      /* Make sure we cover the empty path case.
       */
      if (i == 0)
        count = 0 ;             /* want to run empty case, once */
      else
        count = (i % 41) + 1 ;

      make_test_path(astp, count, (rand() & 0x70000) /* small_rep */,
                                  (rand() & 0x70000) ? all_asn
                                                     : as2_only, all_sorts) ;

      as4_original = rand() & 0x10000 ;
      make_parse_test(astp, as4_original) ;
      astp_compress(astp, true /* sort/dedup sets */, as4_original) ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4_original) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      if (!ok)
        continue ;

      /* Half the time we get the string and store, the other half we store
       * and then get the string.
       *
       * Either was, we expect to get the same thing when we ask for
       * as_path_str a second time, and then to get the same thing every time.
       */
      if (rand() & 0x10000)
        {
          as_path_str(asp) ;
          asp_s = as_path_store(asp) ;
        }
      else
        {
          asp_s = as_path_store(asp) ;
          as_path_str(asp_s) ;
        } ;

      if (count == 0)
        ok = test_assert(asp_s == as_path_empty_asp,
                          "expected stored empty asp to be as_path_empty_asp") ;
      else
        ok = test_assert(asp_s == asp, "expected to store the new asp") ;

      if (ok)
        ok = test_assert(asp_s->stored, "expected stored asp the be stored") ;

      str  = as_path_str(asp_s) ;
      str2 = as_path_str(asp_s) ;

      if (ok)
        ok = test_assert(strcmp(str, str2) == 0,
             "expected as_path_str() to return the same thing a second time"
             "\n  one: '%s'"
             "\n  two; '%s'", str, str2) ;

      if (ok)
        {
          str = as_path_str(asp_s) ;

          ok = test_assert(str == as_path_str(asp_s),
                          "expected as_path_str() to return the cached value") ;
          if (ok)
            test_assert((asp_s->str->size - asp_s->str->len) <= 4,
                                  "expect stored asp->str to be minimum size") ;
        } ;

      /* Quick check that the parsed/stored value is what we expected it to
       * be -- really do not expect this to fail, but need this to be true
       * for the next step.
       */
      if (ok)
        ok = test_assert(astp->comp_len == asp_s->path.len,
                       "expected parsed/post-processed length %u, but got %u",
                                            astp->comp_len, asp_s->path.len) ;
      if (ok && (astp->comp_len != 0))
        ok = test_assert(memcmp(asp_s->path.body.v, astp->comp,
                                 astp->comp_len * sizeof(asp_item_t)) == 0,
                              "parsed/post-processed as_path not as expected") ;
      if (!ok)
        continue ;

      /* Create a new asp from the string form of the stored asp_s.
       */
      asp = as_path_from_str(str = as_path_str(asp_s)) ;

      ok = test_assert(asp != NULL, "expected to parse the string '%s'", str) ;

      if (ok)
        {
          ok = test_assert(astp->comp_len == asp->path.len,
                                   "expected from_str length %u, but got %u",
                                                astp->comp_len, asp->path.len) ;
          if (ok && (astp->comp_len != 0))
            ok = test_assert(memcmp(asp->path.body.v, astp->comp,
                                     astp->comp_len * sizeof(asp_item_t)) == 0,
                                           "from_str as_path not as expected") ;

          str2 = as_path_str(asp) ;

          test_assert(strcmp(str2, str) == 0,
                                  "expected to get the same string back"
                                  "\n   got: '%s'"
                                  "\n   exp: '%s'", str2, str) ;

          asp = as_path_store(asp) ;
          test_assert(asp == asp_s, "expected to get the stored as_path") ;
       } ;

      if (asp != NULL)
        as_path_release(asp) ;
      as_path_release(asp_s) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path properties
 *
 *  * as_path_simple_path_length()
 *  * as_path_confed_path_length()
 *  * as_path_total_path_length()
 *  * as_path_is_empty()
 *  * as_path_confed_ok()
 *  * as_path_first_simple_asn()
 *  * as_path_first_confed_asn()
 *  * as_path_left_most_asn()
 *
 *  * as_path_loop_check()
 *  * as_path_highest()
 *  * as_path_size()
 *
 * For a smattering of paths, test for manually set up results.
 *
 * Then run a number of tests across randomly generated paths.
 */
static bool check_properties(as_path asp, const as_path_properties_t* exp,
                                                               bool confed_ok) ;

typedef struct asp_prop_test  asp_prop_test_t ;
typedef const struct asp_prop_test* asp_prop_test ;

struct asp_prop_test
{
  const char*  str ;            /* From which to generate as_path       */

  as_path_properties_t p ;      /* expected properties                  */

  bool  confed_ok ;
};

static const asp_prop_test_t  prop_test_table[] =
  {
      { .str = "",

        .p   = { .simple_sequence = true
               },

        .confed_ok = true
      },

      { .str = "2529",

        .p   = { .simple_sequence = true,
                 .total_length    = 1,
                 .left_most_asn   = 2529,

                 .simple  = { .length     = 1,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 0,
                              .last       = 1,
                              .first_asn  = 2529,
                            },
               },

        .confed_ok = true
      },

      { .str = "2529 5417",

        .p   = { .simple_sequence = true,
                 .total_length    = 2,
                 .left_most_asn   = 2529,

                 .simple  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 0,
                              .last       = 2,
                              .first_asn  = 2529,
                            },
               },
        .confed_ok = true
      },

      { .str = "{1000,2000} 2529 5417",

        .p   = { .simple_sequence = false,
                 .total_length    = 3,
                 .left_most_asn   = BGP_ASN_NULL,

                 .simple  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_SET,
                              .first      = 0,
                              .last       = 4,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = true
      },

      { .str = "(65530 65525) 2529 5417",

        .p   = { .simple_sequence = false,
                 .total_length    = 4,
                 .left_most_asn   = 65530,

                 .simple  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 2,
                              .last       = 4,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_CONFED_SEQUENCE,
                              .first      = 0,
                              .last       = 2,
                              .first_asn  = 65530,
                            },
               },
        .confed_ok = true
      },

      { .str = "2529 5417 (65530 65525)",

        .p   = { .simple_sequence = false,
                 .total_length    = 4,
                 .left_most_asn   = 2529,

                 .simple  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 0,
                              .last       = 2,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_CONFED_SEQUENCE,
                              .first      = 2,
                              .last       = 4,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = false
      },

      { .str = "[65530 65525] 2529 5417 (65530 65525)",

        .p   = { .simple_sequence = false,
                 .total_length    = 5,
                 .left_most_asn   = BGP_ASN_NULL,

                 .simple  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 2,
                              .last       = 4,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_CONFED_SET,
                              .first      = 0,
                              .last       = 6,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = false
      },

      { .str = "[65530 65525] 2529 5417 (65530 65525)",

        .p   = { .simple_sequence = false,
                 .total_length    = 5,
                 .left_most_asn   = BGP_ASN_NULL,

                 .simple  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 2,
                              .last       = 4,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_CONFED_SET,
                              .first      = 0,
                              .last       = 6,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = false
      },

      { .str = "(65530 65525) 2529 5417 {1000,2000}",

        .p   = { .simple_sequence = false,
                 .total_length    = 5,
                 .left_most_asn   = 65530,

                 .simple  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 2,
                              .last       = 6,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 2,
                              .seq_count  = 1,
                              .set_count  = 0,
                              .first_seg  = BGP_AS_CONFED_SEQUENCE,
                              .first      = 0,
                              .last       = 2,
                              .first_asn  = 65530,
                            },
               },
        .confed_ok = true
      },

      { .str = "[65545] (65530 65525) 2529 5417 {1000,2000}",

        .p   = { .simple_sequence = false,
                 .total_length    = 6,
                 .left_most_asn   = BGP_ASN_NULL,

                 .simple  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_SEQUENCE,
                              .first      = 3,
                              .last       = 7,
                              .first_asn  = 2529,
                            },

                 .confed  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_CONFED_SET,
                              .first      = 0,
                              .last       = 3,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = true
      },

      { .str = "[65545] (65530 65525) {1000,2000} 2529 5417",

        .p   = { .simple_sequence = false,
                 .total_length    = 6,
                 .left_most_asn   = BGP_ASN_NULL,

                 .simple  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_SET,
                              .first      = 3,
                              .last       = 7,
                              .first_asn  = BGP_ASN_NULL,
                            },

                 .confed  = { .length     = 3,
                              .seq_count  = 1,
                              .set_count  = 1,
                              .first_seg  = BGP_AS_CONFED_SET,
                              .first      = 0,
                              .last       = 3,
                              .first_asn  = BGP_ASN_NULL,
                            },
               },
        .confed_ok = true
      },

      { .str = NULL }
  } ;

/*------------------------------------------------------------------------------
 * Test of most of the "properties" functions.
 *
 * Run a small number of tests to check properties, from the table above.
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path in as4/as2 form
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * parse same and confirm is as expected
 *
 *   * check the properties -- see check_properties(), below
 *
 *   * check:  as_path_loop_check()
 *             as_path_highest()
 *             as_path_size()
 */
static void
test_as_path_properties(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp ;
  asp_prop_test p_test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path properties") ;

  astp = astp_new() ;

  p_test = prop_test_table ;
  while (p_test->str != NULL)
    {
      as_path  asp ;

      next_test() ;

      asp = as_path_from_str(p_test->str) ;

      if (test_assert(asp != NULL, "expect to convert string '%s'",
                                                                   p_test->str))
        {
          check_properties(asp, &p_test->p, p_test->confed_ok) ;
          as_path_free(asp) ;
        } ;

      ++p_test ;
    } ;

  /* Expect all sorts of paths to return the correct properties.
   */
  for (i = 0 ; i < 20000 ; ++i)
    {
      uint count, n, t ;
      as_path  asp ;
      bool ok, as4_original ;
      as_t asn ;
      as_path_out_t out[1] ;

      next_test() ;

      /* Make sure we cover the empty path case.
       *
       * Generate the test case and check that all looks kosher.
       */
      if (i == 0)
        count = 0 ;             /* want to run empty case, once */
      else
        count = (i % 41) + 1 ;

      make_test_path(astp, count, (rand() & 0x70000) /* small_rep */,
                                  (rand() & 0x70000) ? all_asn
                                                     : as2_only, all_sorts) ;

      as4_original = rand() & 0x10000 ;
      make_parse_test(astp, as4_original) ;
      if (!as4_original)
        astp_trans(astp) ;
      astp_sort_dedup(astp) ;
      astp_compress(astp, false /* already sorted/dedup sets */,
                          true  /* ASN already 'trans' */) ;
      astp_properties(astp, true /* ASN already 'trans' */) ;

      asp = as_path_parse(astp->parse, astp->parse_len, as4_original) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      if (!ok)
        continue ;

      asp = as_path_store(asp) ;

      ok = test_assert(astp->comp_len == asp->path.len,
                       "expected post-processed length %u, but got %u",
                                            astp->comp_len, asp->path.len) ;
      if (ok && (astp->comp_len != 0))
        {
          ok = test_assert(memcmp(asp->path.body.v, astp->comp,
                                 astp->comp_len * sizeof(asp_item_t)) == 0,
                                 "post-processed as_path not as expected") ;
          if (!ok)
            show_delta(asp->path.body.v, astp->comp, astp->comp_len) ;
        } ;

      if (!ok)
        continue ;

      /* Check the general properties
       */
      ok = check_properties(asp, &astp->p, astp_confed_ok(astp)) ;

      /* Check that the following work:
       *
       *  * as_path_loop_check()
       *  * as_path_highest()
       *  * as_path_size()
       */
      astp_extract(astp) ;              /* ready for tests      */

      asn = astp_present(astp) ;
      n   = astp_present_count(astp, asn) ;
      if (n != 0)
        t = rand() % (n * 2) ;
      else
        {
          assert(asn == 0) ;
          t = 0 ;
        } ;

      if (t < n)
        {
          if (!test_assert(!as_path_loop_check(asp, asn, t),
              "did NOT expect as_path_loop_check(asn=%u, t=%u) to return true",
                                                                       asn, t))
            ok = false ;
        }
      else
        {
          if (!test_assert(as_path_loop_check(asp, asn, t),
                 "expected as_path_loop_check(asn=%u, t=%u) to return true",
                                                                       asn, t))
            ok = false ;
        } ;

      asn = astp_not_present(astp) ;

      ok = ok & test_assert(as_path_loop_check(asp, asn, 0),
              "expected as_path_loop_check(asn=%u, 0) to return true", asn) ;

      asn = astp_highest_asn(astp) ;

      ok = ok & test_assert(as_path_highest(asp) == asn,
                           "expected %u to be the highest asn, got=%u", asn,
                                                       as_path_highest(asp)) ;

      memset(out, 0, sizeof(as_path_out_t)) ;   /* No prepend   */
      astp_encode(astp, true /* as4 */, as4_original, out) ;

      ok = ok & test_assert(as_path_size(asp) == astp->enc_len,
                      "expected as_path_size()=%u, got=%u",
                                             astp->enc_len, as_path_size(asp)) ;
      if (!ok)
        fprintf(stderr, "\n    for '%s'", as_path_str(asp)) ;

      as_path_release(asp) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*------------------------------------------------------------------------------
 * Check the properties of the given as_path against the expected properties,
 * and check that the related functions return the expected value:
 *
 *  * as_path_simple_path_length()
 *  * as_path_confed_path_length()
 *  * as_path_total_path_length()
 *  * as_path_is_empty()
 *  * as_path_confed_ok()
 *  * as_path_first_simple_asn()
 *  * as_path_first_confed_asn()
 *  * as_path_left_most_asn()
 */
static bool
check_properties(as_path asp, const as_path_properties_t* exp, bool confed_ok)
{
  const char* str ;
  bool ok ;

  str = as_path_str(asp) ;              /* ensures post processed       */

  ok = test_assert(memcmp(&asp->p, exp, sizeof(as_path_properties_t)) == 0,
                                       "did not get the expected properties") ;
  if (!ok)
    show_delta_properties(&asp->p, exp) ;
  else
    {
      ok = ok &
            test_assert(as_path_simple_path_length(asp) == exp->simple.length,
                   "expected as_path_simple_path_length()=%u, got=%u",
                          exp->simple.length, as_path_simple_path_length(asp)) ;

      ok = ok &
            test_assert(as_path_confed_path_length(asp) == exp->confed.length,
                   "expected as_path_confed_path_length()=%u, got=%u",
                          exp->confed.length, as_path_confed_path_length(asp)) ;

      ok = ok &
            test_assert(as_path_total_path_length(asp) == exp->total_length,
                   "expected as_path_total_path_length()=%u, got=%u",
                          exp->total_length, as_path_total_path_length(asp)) ;

      if (*str == '\0')
        ok = ok & test_assert(as_path_is_empty(asp),
                                          "expected the as_path to be empty") ;
      else
        ok = ok & test_assert(!as_path_is_empty(asp),
                                     "did NOT expect the as_path to be empty") ;

      if (confed_ok)
        ok = ok & test_assert(as_path_confed_ok(asp),
                                     "expected the as_path to be 'confed_ok'") ;
      else
        ok = ok & test_assert(!as_path_confed_ok(asp),
                               "did NOT expect the as_path to be 'confed_ok'") ;

      ok = ok &
            test_assert(as_path_first_simple_asn(asp) == exp->simple.first_asn,
                   "expected as_path_first_simple_asn()=%u, got=%u",
                         exp->simple.first_asn, as_path_first_simple_asn(asp)) ;

      ok = ok &
            test_assert(as_path_first_confed_asn(asp) == exp->confed.first_asn,
                   "expected as_path_first_confed_asn()=%u, got=%u",
                         exp->confed.first_asn, as_path_first_confed_asn(asp)) ;

      ok = ok & test_assert(as_path_left_most_asn(asp) == exp->left_most_asn,
                   "expected as_path_left_most_asn()=%u, got=%u",
                         exp->left_most_asn, as_path_left_most_asn(asp)) ;
    } ;

  if (!ok)
    fprintf(stderr, "\n    for '%s'", str) ;

  return ok ;
} ;

/*==============================================================================
 * Test of as_path_private_as_check()
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path in as4, with private ASN only and parse same
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * about half the time, store the path -- so test both states.
 *
 *   * check as_path_private_as_check()
 *
 *   * change one ASN in the path and check as_path_private_as_check() again
 */
static void
test_as_path_private_as_check(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_private_as_check()") ;

  astp = astp_new() ;

  /* Expect all sorts of paths to return the correct properties.
   */
  for (i = 0 ; i < 2000 ; ++i)
    {
      uint count ;
      as_path  asp ;
      bool ok ;

      next_test() ;

      /* We generate the empty case a number of times -- will test both stored
       * and not stored empty.
       */
      count = (i % 43) ;

      make_test_path(astp, count, (rand() & 0x7000) /* small_rep */,
                                                     private_only, all_sorts) ;
      make_parse_test(astp, true /* as4 */) ;

      asp = as_path_parse(astp->parse, astp->parse_len, true /* as4 */) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      if (!ok)
        continue ;

      if (i & 1)
        asp = as_path_store(asp) ;

      if (count == 0)
        ok = test_assert(!as_path_private_as_check(asp),
                         "expected as_path_private_as_check()==false for '%s'",
                                                            as_path_str(asp)) ;
      else
        ok = test_assert(as_path_private_as_check(asp),
                         "expected as_path_private_as_check()==true for '%s'",
                                                            as_path_str(asp)) ;

      as_path_release(asp) ;

      if (!ok || (count == 0))
        continue ;

      make_not_private_test(astp) ;
      make_parse_test(astp, true /* as4 */) ;

      asp = as_path_parse(astp->parse, astp->parse_len, true /* as4 */) ;

      ok = test_assert(asp != NULL, "did not expect as_path_parse() to fail") ;

      if (!ok)
        continue ;

      if (!(i & 1))
        asp = as_path_store(asp) ;

      test_assert(!as_path_private_as_check(asp),
                         "expected as_path_private_as_check()==false for '%s'",
                                                            as_path_str(asp)) ;

      as_path_release(asp) ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_prepend_path()/_append_path()
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path (as4) and parse same
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * half the time, store the path -- so test both states.
 *
 *     So we cover the possible cases for the path to be appended/prepended to:
 *
 *       * not-stored, empty
 *
 *       * not-stored, not empty
 *
 *       * stored, empty
 *
 *       * stored, not empty
 *
 *   * generate paths to append/prepend:
 *
 *       * NULL
 *
 *       * not-stored, empty
 *
 *       * not-stored, not empty
 *
 *       * stored, empty
 *
 *       * stored, not empty
 *
 *     append/prepend and make sure we get what we expect.
 *
 * Note that AS4-ness has no bearing on as_path_prefix(), so we do everything
 * in the internal AS4 state.
 */
static void
test_as_path_ap_pre_pend_path(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp_a, astp_b ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_prepend_path()/_append_path()") ;

  astp_a = astp_new() ;
  astp_b = astp_new() ;

  /* Expect all sorts of paths to return the correct properties.
   */
  for (i = 0 ; i < 8000 ; ++i)
    {
      uint j, count_a, count_b, parse_all_len ;
      as_path  asp_a, asp_b ;
      byte* parse_all ;
      bool ok, append ;
      const char* action ;

      if (rand() & 0x100)
        {
          append = true ;
          action = "as_path_append_path()" ;
        }
      else
        {
          append = false ;
          action = "as_path_prepend_path()" ;
        } ;

      /* We generate the empty case a number of times -- will test both stored
       * and not stored empty.
       */
      count_a = (i % 43) ;

      make_test_path(astp_a, count_a, (rand() & 0x7000) /* small_rep */,
                                      (rand() & 0x70000) ? all_asn
                                                         : as2_only, all_sorts);
      make_parse_test(astp_a, true /* as4 */) ;

      count_b = (i % 17) + 1 ;          /* Do empty separately  */

      make_test_path(astp_b, count_b, true /* small_rep */,
                                      (rand() & 0x70000) ? all_asn
                                                         : as2_only, all_sorts);
      make_parse_test(astp_b, true /* as4 */) ;

      parse_all_len = astp_b->parse_len + astp_a->parse_len ;
      assert(parse_all_len != 0) ;

      if (astp_a->parse_len == 0)
        parse_all = astp_b->parse ;
      else
        {
          parse_all = malloc(parse_all_len) ;

          if (append)
            {
              memcpy(parse_all + 0,                 astp_a->parse,
                                                    astp_a->parse_len) ;
              memcpy(parse_all + astp_a->parse_len, astp_b->parse,
                                                    astp_b->parse_len) ;
            }
          else
            {
              memcpy(parse_all + 0,                 astp_b->parse,
                                                    astp_b->parse_len) ;
              memcpy(parse_all + astp_b->parse_len, astp_a->parse,
                                                    astp_a->parse_len) ;
            } ;
        } ;

      for (j = 0 ; j < 5 ; ++j)
        {
          as_path asp_t, asp_x ;
          const char* str_t, * str_x ;

          next_test() ;

          asp_a = as_path_parse(astp_a->parse, astp_a->parse_len,
                                                               true /* as4 */) ;

          ok = test_assert(asp_a != NULL,
                           "did not expect as_path_parse() to fail for asp_a") ;

          if (!ok)
            continue ;

          /* j = 0 -> asp_b = NULL
           *   = 1 -> asp_b empty, stored
           *   = 2 -> asp_b empty, not-stored
           *   = 3 -> asp_b not-empty, stored
           *   = 4 -> asp_b not-empty, not-stored
           */
          if (j == 0)
            asp_b = NULL ;
          else
            {
              if (j <= 2)
                asp_b = as_path_parse(NULL, 0, true /* as4 */) ;
              else
                asp_b = as_path_parse(astp_b->parse,
                                      astp_b->parse_len, true /* as4 */) ;

              ok = test_assert(asp_b != NULL,
                           "did not expect as_path_parse() to fail for asp_b") ;

              if (!ok)
                continue ;
            } ;

          if (i & 1)
            asp_a = as_path_store(asp_a) ;

          if (j & 1)
            asp_b = as_path_store(asp_b) ;

          if (append)
            asp_t = as_path_append_path(asp_a, asp_b) ;
          else
            asp_t = as_path_prepend_path(asp_a, asp_b) ;

          if      (asp_t == asp_a)
            {
              if (asp_a->stored)
                test_assert((asp_b == NULL) || (asp_b->path.len == 0),
                      "%s should not return original, "
                      "stored asp_a unless asp_b is NULL or empty", action) ;
            }
          else if (asp_t == asp_b)
            {
              test_assert(asp_a->path.len == 0,
                  "%s should not return asp_b unless asp_a is empty", action) ;

              test_assert(asp_b->stored,
                  "%s should not return asp_b unless asp_b is stored", action) ;
            }
          else
            {
              test_assert(asp_a->stored,
                  "%s should not return new as_path unless asp_a is stored",
                                                                       action) ;
            } ;

          if (j <= 2)
            asp_x = as_path_parse(astp_a->parse, astp_a->parse_len,
                                                               true /* as4 */) ;
          else
            asp_x = as_path_parse(parse_all, parse_all_len,    true /* as4 */) ;

          str_t = as_path_str(asp_t) ;
          str_x = as_path_str(asp_x) ;

          test_assert(strcmp(str_t, str_x) == 0,
              "expecting '%s' from %s"
              "\n   got '%s'", str_x, action, str_t) ;

          as_path_release(asp_a) ;
          if (asp_b != NULL)
            as_path_release(asp_b) ;
          if ((asp_t != asp_a) && (asp_t != asp_b))
            as_path_release(asp_t) ;
          as_path_release(asp_x) ;
        } ;

      if (astp_a->parse_len != 0)
        free(parse_all) ;
    } ;

  astp_free(astp_a) ;
  astp_free(astp_b) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_prepend()
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path (as4) and parse same
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * half the time, store the path -- so test both states.
 *
 *     So we cover the possible cases for the path to be prepended to:
 *
 *       * not-stored, empty
 *
 *       * not-stored, not empty
 *
 *       * stored, empty
 *
 *       * stored, not empty
 *
 *   * choose segment type, ASN and count at random (though ASN is drawn from
 *     the same limited pool).
 *
 *     test as_path_prepend() against as_path_prepend_path().
 *
 * Note that AS4-ness has no bearing on these functions, so we do everything
 * in the internal AS4 state.
 */
typedef struct add_seq_test  add_seq_test_t ;
typedef struct add_seq_test* add_seq_test ;

struct add_seq_test
{
  as_seg_t   seg ;
  uint       count ;
  as_t       asn ;
};

static void make_seq_test(as_test_path astp, add_seq_test test,
                                                             test_asn_t which) ;

static void
test_as_path_prepend(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp_a, astp_b ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_prepend()") ;

  astp_a = astp_new() ;
  astp_b = astp_new() ;

  /* Expect all sorts of paths to return the correct properties.
   */
  for (i = 0 ; i < 10000 ; ++i)
    {
      uint count_a, count_t ;
      as_path  asp_a, asp_b, asp_t, asp_x ;
      add_seq_test_t test[1] ;
      bool ok ;
      const char* str_t, * str_x ;

      next_test() ;

      make_seq_test(astp_b, test, (rand() & 0x70000) != 0 ? all_asn
                                                          : as2_only) ;
      make_parse_test(astp_b, true /* as4 */) ;

      asp_b = as_path_parse(astp_b->parse,
                            astp_b->parse_len, true /* as4 */) ;

      ok = test_assert(asp_b != NULL,
                 "did not expect as_path_parse() to fail for asp_b") ;
      if (!ok)
        continue ;

      /* We generate the empty case a number of times -- will test both stored
       * and not stored empty.
       */
      count_a = (i % 43) ;

      make_test_path(astp_a, count_a, (rand() & 0x7000) /* small_rep */,
                                      (rand() & 0x70000) ? all_asn
                                                         : as2_only, all_sorts);
      make_parse_test(astp_a, true /* as4 */) ;

      asp_a = as_path_parse(astp_a->parse, astp_a->parse_len, true /* as4 */) ;

      ok = test_assert(asp_a != NULL,
                           "did not expect as_path_parse() to fail for asp_a") ;

      if (ok)
        {
          asp_x = as_path_parse(astp_a->parse, astp_a->parse_len,
                                                               true /* as4 */) ;
          ok = test_assert(asp_a != NULL,
                           "did not expect as_path_parse() to fail for asp_x") ;
        } ;

      if (!ok)
        continue ;

      if (i & 1)
        asp_a = as_path_store(asp_a) ;

      asp_x = as_path_prepend_path(asp_x, asp_b) ;

      count_t = test->count ;
      assert(count_t != 0) ;

      if ((count_t == 1) || (test->seg == BGP_AS_SET)
                         || (test->seg == BGP_AS_CONFED_SET))
        count_t = rand() % 2 ;

      asp_t = as_path_prepend_tx(asp_a, test->seg, test->asn, count_t) ;

      if (asp_t == asp_a)
        {
          if (asp_a->stored)
            test_assert(!asp_a->stored,
                 "as_path_prepend() should not return original, stored asp_a") ;
        } ;

      str_t = as_path_str(asp_t) ;
      str_x = as_path_str(asp_x) ;

      test_assert(strcmp(str_t, str_x) == 0,
              "expecting '%s' from as_path_prepend()"
              "\n   got '%s'", str_x, str_t) ;

      as_path_release(asp_a) ;
      as_path_release(asp_b) ;
      if (asp_t != asp_a)
        as_path_release(asp_t) ;
      as_path_release(asp_x) ;
    } ;

  astp_free(astp_a) ;
  astp_free(astp_b) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_confed_delete() and as_path_confed_sweep()
 *
 * For a variety of path lengths, including zero:
 *
 *   * generate a test path (as4) and parse same
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * half the time, store the path -- so test both states.
 *
 *   * do as_path_confed_delete() or as_path_confed_sweep() and
 *     check on the result.
 *
 * Note that AS4-ness has no bearing on these functions, so we do everything
 * in the internal AS4 state.
 */
static void
test_as_path_confed_stuff(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  as_test_path  astp ;
  uint count_sweep, count_delete, count_null, count_total ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_confed_delete()/_sweep()") ;

  astp = astp_new() ;

  count_sweep  = 0 ;
  count_delete = 0 ;
  count_null   = 0 ;

  /* Expect all sorts of paths to return the correct properties.
   */
  for (i = 0 ; i < 40000 ; ++i)
    {
      uint count ;
      as_path  asp_a, asp_t, asp_x ;
      bool ok, had_effect ;
      const char* str_t, * str_x, * action ;
      char* str_a ;

      next_test() ;

      /* We generate the empty case a number of times -- will test both stored
       * and not stored empty.
       */
      count = (i % 43) ;

      make_test_path(astp, count, (rand() & 0x7000) /* small_rep */,
                                  (rand() & 0x70000) ? all_asn
                                                     : as2_only, random_segs) ;

      make_parse_test(astp, true /* as4 */) ;

      asp_a = as_path_parse(astp->parse, astp->parse_len, true /* as4 */) ;

      ok = test_assert(asp_a != NULL,
                           "did not expect as_path_parse() to fail for asp_a") ;

      if (!ok)
        continue ;

      if (i & 1)
        asp_a = as_path_store(asp_a) ;

      str_a = strdup(as_path_str(asp_a)) ;

      /* Sweep or Delete, at random.
       */
      if (rand() & 0x10000)
        {
          had_effect = (astp_confed_sweep(astp) > 0) ;

          if (had_effect)
            count_sweep  += 1 ;
          else
            count_null   += 1 ;

          asp_t  =  as_path_confed_sweep(asp_a) ;
          action = "as_path_confed_sweep()" ;
        }
      else
        {
          had_effect = (astp_confed_delete(astp) > 0) ;

          if (had_effect)
            count_delete += 1 ;
          else
            count_null   += 1 ;

          asp_t  =  as_path_confed_delete(asp_a) ;
          action = "as_path_confed_delete()" ;
        } ;

      make_parse_test(astp, true /* as4 */) ;
      asp_x = as_path_parse(astp->parse, astp->parse_len, true /* as4 */) ;
      ok = test_assert(asp_a != NULL,
                           "did not expect as_path_parse() to fail for asp_x") ;

      if (!ok)
        continue ;

      if (asp_t == asp_a)
        {
          test_assert(!asp_a->stored || !had_effect,
                 "did NOT expect %s to return original, stored asp_a", action) ;
        }
      else
        {
          test_assert(asp_a->stored && had_effect,
                               "expected %s to return original asp_a", action) ;
        }

      str_t = as_path_str(asp_t) ;
      str_x = as_path_str(asp_x) ;

      test_assert(strcmp(str_t, str_x) == 0,
              "expecting '%s' from %s"
              "\n   got '%s'"
              "\n   for '%s'", str_x, action, str_t, str_a) ;

      as_path_release(asp_a) ;
      if (asp_t != asp_a)
        as_path_release(asp_t) ;
      as_path_release(asp_x) ;

      free(str_a) ;
    } ;

  astp_free(astp) ;

  count_total = count_null + count_delete + count_sweep ;
  assert(count_total == (test_count - test_count_was)) ;

  count_delete = (count_delete * 100) / count_total ;
  count_sweep  = (count_sweep  * 100) / count_total ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests (%d%% delete, %d%% sweep) -- OK\n",
                                      count_total, count_delete, count_sweep) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;


/*==============================================================================
 * Test of as_path_reconcile_as4
 *
 * Test a few hand-made cases to ensure the simple stuff is working as
 * expected.
 *
 * Test for the OK cases: for a variety of path lengths, including zero:
 *
 *   * generate a test path (as4, but no confeds) and parse same as as4 path
 *
 *     see make_test_path() for the changes which are rung.
 *
 *   * encode as as2 and decode to as2 version of original.
 *
 *   * encode as as4 and decode seed the expected result.
 *
 *   * generate a short prepend (as2, with confeds) and parse same
 *
 *     The prepend includes zero length prepend... which covers the case of
 *     the as2 and as4 being the same length (counting sets as 1).
 *
 *   * prepend to both working as2 and expected result
 *
 *   * 50% of time store the original as4
 *
 *   * 50% of time store the working as2
 *
 *   * as_path_reconcile_as4() the working as2 and the original as4
 *
 *     result should be the same as the expected
 */
typedef struct asp_reconcile_test  asp_reconcile_test_t ;
typedef const struct asp_reconcile_test* asp_reconcile_test ;

struct asp_reconcile_test
{
  const char* as2_str ;
  const char* as4_str ;
  const char* result ;
} ;

static const asp_reconcile_test_t  reconcile_test_table[] =
  {
    { .as2_str  = "",
      .as4_str  = "",
      .result   = "",
    },

    { .as2_str  = "2529",
      .as4_str  = "",
      .result   = "2529",
    },

    { .as2_str  = "23456",
      .as4_str  = "100666",
      .result   = "100666",
    },

    { .as2_str  = "2529 23456",
      .as4_str  = "100666",
      .result   = "2529 100666",
    },

    { .as2_str  = "2529 23456 {1,23456}",
      .as4_str  = "100666 {1,200000,400000}",
      .result   = "2529 100666 {1,200000,400000}",
    },

    { .as2_str  = "(100 200) 2529 2529 23456 {1,23456}",
      .as4_str  = "100666 {1,200000,400000}",
      .result   = "(100 200) 2529 2529 100666 {1,200000,400000}",
    },

    /* This covers the case of cutting the as2 path in the middle of a repeat
     * and illustrates that the RFC prescribed process can look a little odd.
     *
     * This is an edge case where a repeat count is removed.
     */
    { .as2_str  = "(100 200) 2529 2529 23456 {1,23456}",
      .as4_str  = "5417 100666 {1,200000,400000}",
      .result   = "(100 200) 2529 5417 100666 {1,200000,400000}",
    },

    /* And a second example.
     *
     * This is an edge case where a repeat count is reduced.
     */
    { .as2_str  = "(100 200) 2529 2529 2529 2529 23456 {1,23456}",
      .as4_str  = "5417 5417 100666 {1,200000,400000}",
      .result   = "(100 200) 2529 2529 5417 5417 100666 {1,200000,400000}",
    },

    /* Examples where the AS4_PATH is longer !!
     *
     * First where the resulting set is empty !
     */
    { .as2_str  = "2529 5417 2529",
      .as4_str  = "2529 2529 5417 5417",
      .result   = "2529 5417 2529",
    },

    /* Second where the resulting set is not empty !
     */
    { .as2_str  = "2529 5417",
      .as4_str  = "2529 100000 2529 2 5417 {91,76} 5417 200000",
      .result   = "2529 5417 {2,76,91,100000,200000}",
    },

    { .as2_str  = NULL }
  } ;

static void
test_as_path_reconcile_as4(void)
{
 uint fail_count_was, test_count_was ;
 uint i ;
 as_test_path  astp, astp_4 ;
 asp_reconcile_test test ;

 fail_count_was = fail_count ;
 test_count_was = test_count ;

 fprintf(stderr, "  test: as_path_reconcile_as4()") ;

 astp   = astp_new() ;
 astp_4 = astp_new() ;

 /* The specific (spot) tests
  */
 test = reconcile_test_table ;
 while (test->as2_str != NULL)
   {
     as_path  asp_as2, asp_as4 ;
     bool ok ;

     next_test() ;

     asp_as2 = as_path_from_str(test->as2_str) ;

     ok = test_assert(asp_as2 != NULL,
                         "expected to convert string asp_as2='%s' to as_path",
                                                                test->as2_str) ;

     asp_as4 = as_path_from_str(test->as4_str) ;

     ok = ok &
          test_assert(asp_as4 != NULL,
                         "expected to convert string asp_as4='%s' to as_path",
                                                                test->as4_str) ;
     if (ok)
       {
         as_path  asp_t ;
         const char* str_t ;

         asp_t = as_path_reconcile_as4(asp_as2, asp_as4) ;

         str_t = as_path_str(asp_t) ;

         test_assert(strcmp(test->result, str_t) == 0,
             "expected '%s' but got '%s', when reconciling '%s' with '%s'",
                            test->result, str_t, test->as2_str, test->as4_str) ;

         if ((asp_t != asp_as2) && (asp_t != asp_as4))
           as_path_free(asp_t) ;
       }

     as_path_free(asp_as2) ;
     as_path_free(asp_as4) ;

     ++test ;
   } ;

 /* Test all sorts of OK paths.
  */
 for (i = 0 ; i < 20000 ; ++i)
   {
     uint count ;
     as_path  asp_as4, asp_as2, asp_x, asp_p, asp_t ;
     char* str_as2 ;
     const char* str_as4, * str_x, * str_t ;
     bool ok ;

     next_test() ;

     /* We generate the empty case a number of times -- will test both stored
      * and not stored empty.
      */
     count = (i % 43) ;

     make_test_path(astp, count, true /* small_rep */, all_asn, no_confeds) ;

     make_parse_test(astp, true /* as4 */) ;
     asp_as4 = as_path_parse(astp->parse, astp->parse_len, true  /* as4 */) ;

     make_parse_test(astp, true /* as4 */) ;
     asp_x = as_path_parse(astp->parse, astp->parse_len, true  /* as4 */) ;

     make_parse_test(astp, false /* as2 */) ;
     asp_as2 = as_path_parse(astp->parse, astp->parse_len, false /* as2 */) ;

     ok = test_assert((asp_as4 != NULL) && (asp_x != NULL) && (asp_as2 != NULL),
       "did not expect as_path_parse() to fail for asp_as4, asp_x or asp_as2") ;

     if (!ok)
       continue ;

     /* Make thing to prepend and prepend to asp_as2
      *
      * Then sweep confeds to the front, and prepend to asp_x
      *
      * This generates the test asp_as2 to be reconciled with the original
      * asp_as4, to generate what is in asp_x.
      */
     make_test_path(astp, (i % 5), true /* small_rep */, as2_only, all_sorts) ;

     make_parse_test(astp, false /* as2 */) ;
     asp_p = as_path_parse(astp->parse, astp->parse_len, false /* as2 */) ;

     ok = test_assert(asp_p != NULL,
       "did not expect as_path_parse() to fail for asp_p") ;

     asp_t = as_path_prepend_path(asp_as2, asp_p) ;
     assert(asp_t == asp_as2) ;
     as_path_free(asp_p) ;

     astp_confed_sweep(astp) ;

     make_parse_test(astp, false /* as2 */) ;
     asp_p = as_path_parse(astp->parse, astp->parse_len, false /* as2 */) ;

     ok = test_assert(asp_p != NULL,
       "did not expect as_path_parse() to fail for asp_p") ;

     asp_t = as_path_prepend_path(asp_x, asp_p) ;
     assert(asp_t == asp_x) ;
     as_path_free(asp_p) ;

     str_x = as_path_str(asp_x) ;

     /* So now store the asp_as4 and asp_as2 at random.
      *
      * Then do the as_path_reconcile_as4() and check the result.
      */
     if (i & 1)
       asp_as2 = as_path_store(asp_as2) ;

     if (i & 2)
       asp_as4 = as_path_store(asp_as4) ;

     str_as4 = as_path_str(asp_as4) ;
     str_as2 = strdup(as_path_str(asp_as2)) ;

     asp_t = as_path_reconcile_as4(asp_as2, asp_as4) ;

     if      (asp_t == asp_as4)
       {
         test_assert(asp_as4->stored
                      && (asp_as2->p.confed.length == 0)
                      && (asp_as4->p.confed.length == 0)
                      && (asp_as2->p.simple.length == asp_as4->p.simple.length),
                "did NOT expect as_path_reconcile_as4() to return original, "
                                                             "stored asp_as4") ;
       }
     else if (asp_t == asp_as2)
       {
         test_assert(!asp_as2->stored || (asp_as4->path.len == 0),
                "did NOT expect as_path_reconcile_as4() to return original, "
                                                            "stored asp_as2") ;
       }
     else
       {
         test_assert(asp_as2->stored,
                "did NOT expect as_path_reconcile_as4() to return "
                                                              "a new as_path") ;
       } ;

     str_t = as_path_str(asp_t) ;

     test_assert(strcmp(str_t, str_x) == 0,
             "expecting '%s'"
             "\n   got '%s'"
             "\n   reconciling as2 '%s'"
             "\n          with as4 '%s'", str_x, str_t, str_as2, str_as4) ;

     as_path_release(asp_as2) ;
     if ((asp_t != asp_as2) && (asp_t != asp_as4))
       as_path_release(asp_t) ;
     as_path_release(asp_as4) ;
     as_path_release(asp_x) ;

     free(str_as2) ;
   } ;

 /* Now need to test the odd cases -- where the AS4_PATH is longer than the
  * AS2 one, and where the AS4_PATH has nothing much in common with the
  * AS2 one.
  *
  * The specific tests covered the edge case where a longer AS4 path is reduced
  * to nothing because the AS2 contains all the ASN is the AS4 path.  So, here
  * we can hack about with randomly created paths -- though the limited number
  * of ASN in those paths will mean that where the AS4 path is merged as a
  * set, it may well have ASN in common with the AS2 path.
  */
 for (i = 0 ; i < 10000 ; ++i)
   {
     uint count ;
     as_path  asp_as4, asp_as2, asp_x, asp_t ;
     char* str_as2 ;
     const char* str_as4, * str_x, * str_t ;

     bool ok ;

     next_test() ;

     /* We generate the empty case a number of times -- will test both stored
      * and not stored empty.
      */
     count = (i % 43) ;

     make_test_path(astp, count, true /* small_rep */, all_asn, all_sorts) ;
     astp_trans(astp) ;
     make_parse_test(astp, false  /* as2 */) ;
     asp_as2 = as_path_parse(astp->parse, astp->parse_len, false  /* as2 */) ;

     if      (count >= 2)
       count += (rand() % 5) - 2 ;
     else if (count == 1)
       count += (rand() % 4) - 1 ;
     else
       count += (rand() % 3) ;

     make_test_path(astp_4, count, true /* small_rep */, all_asn, all_sorts) ;
     make_parse_test(astp_4, true /* as4 */) ;
     asp_as4 = as_path_parse(astp_4->parse, astp_4->parse_len, true  /* as4 */);

     ok = test_assert((asp_as2 != NULL) && (asp_as4 != NULL),
       "did not expect as_path_parse() to fail for asp_as2 or asp_as4") ;

     if (!ok)
       continue ;

     /* Work out what we now expect to get
      */
     astp_reconcile_as4(astp, astp_4) ;

     make_parse_test(astp, true /* as4 */) ;
     asp_x = as_path_parse(astp->parse, astp->parse_len, true  /* as4 */) ;

     ok = test_assert(asp_x != NULL,
                          "did not expect as_path_parse() to fail for asp_x") ;
     if (!ok)
       continue ;

     /* So now store the asp_as4 and asp_as2 at random.
      *
      * Then do the as_path_reconcile_as4() and check the result.
      */
     if (i & 1)
       asp_as2 = as_path_store(asp_as2) ;

     if (i & 2)
       asp_as4 = as_path_store(asp_as4) ;

     str_as4 = as_path_str(asp_as4) ;
     str_as2 = strdup(as_path_str(asp_as2)) ;

     asp_t = as_path_reconcile_as4(asp_as2, asp_as4) ;

     if      (asp_t == asp_as4)
       {
         test_assert(asp_as4->stored
                      && (asp_as2->p.confed.length == 0)
                      && (asp_as4->p.confed.length == 0)
                      && (asp_as2->p.simple.length == asp_as4->p.simple.length),
                "did NOT expect as_path_reconcile_as4() to return original, "
                                                             "stored asp_as4") ;
       }
     else if (asp_t == asp_as2)
       {
         test_assert(!asp_as2->stored || (asp_as4->path.len == 0),
                "did NOT expect as_path_reconcile_as4() to return original, "
                                                            "stored asp_as2") ;
       }
     else
       {
         test_assert(asp_as2->stored,
                "did NOT expect as_path_reconcile_as4() to return "
                                                              "a new as_path") ;
       } ;

     str_t = as_path_str(asp_t) ;
     str_x = as_path_str(asp_x) ;

     test_assert(strcmp(str_t, str_x) == 0,
             "expecting '%s'"
             "\n   got '%s'"
             "\n   reconciling as2 '%s'"
             "\n          with as4 '%s'", str_x, str_t, str_as2, str_as4) ;

     as_path_release(asp_as2) ;
     if ((asp_t != asp_as2) && (asp_t != asp_as4))
       as_path_release(asp_t) ;
     as_path_release(asp_as4) ;
     as_path_release(asp_x) ;

     free(str_as2) ;
   } ;

 astp_free(astp) ;
 astp_free(astp_4) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests  -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_aggregate
 *
  */
typedef struct asp_aggregate_test  asp_aggregate_test_t ;
typedef const struct asp_aggregate_test* asp_aggregate_test ;

struct asp_aggregate_test
{
  const char* asp_a_str ;
  const char* asp_b_str ;
  const char* result ;
} ;

static const asp_aggregate_test_t  aggregate_test_table[] =
  {
    /* The simplest of simple stuff.
     */
    { .asp_a_str = "",
      .asp_b_str = "",
      .result    = "",
    },

    { .asp_a_str = "2529",
      .asp_b_str = "2529",
      .result    = "2529",
    },

    { .asp_a_str = "2529 5417",
      .asp_b_str = "2529 5417",
      .result    = "2529 5417",
    },

    { .asp_a_str = "2529",
      .asp_b_str = "2529 5417",
      .result    = "2529 {5417}",
    },

    { .asp_a_str = "",
      .asp_b_str = "2529 5417",
      .result    = "{2529,5417}",
    },

    { .asp_a_str = "2529 5417 90",
      .asp_b_str = "2529 5417 91",
      .result    = "2529 5417 {90,91}",
    },

    { .asp_a_str = "2529 5417 90",
      .asp_b_str = "2529 5417 91 92 93",
      .result    = "2529 5417 {90,91,92,93}",
    },

    { .asp_a_str = "2529 5417 90 1 2",
      .asp_b_str = "2529 5417 91 92 93 1 2",
      .result    = "2529 5417 {90,91,92,93} 1 2",
    },

    /* Similarly as Confed.
     */
    { .asp_a_str = "(2529)",
      .asp_b_str = "(2529)",
      .result    = "(2529)",
    },

    { .asp_a_str = "(2529 5417)",
      .asp_b_str = "(2529 5417)",
      .result    = "(2529 5417)",
    },

    { .asp_a_str = "(2529)",
      .asp_b_str = "(2529 5417)",
      .result    = "(2529) [5417]",
    },

    { .asp_a_str = "",
      .asp_b_str = "(2529 5417)",
      .result    = "[2529,5417]",
    },

    { .asp_a_str = "(2529 5417 90)",
      .asp_b_str = "(2529 5417 91)",
      .result    = "(2529 5417) [90,91]",
    },

    { .asp_a_str = "(2529 5417 90)",
      .asp_b_str = "(2529 5417 91 92 93)",
      .result    = "(2529 5417) [90,91,92,93]",
    },

    { .asp_a_str = "(2529 5417 90 1 2)",
      .asp_b_str = "(2529 5417 91 92 93 1 2)",
      .result    = "(2529 5417) [90,91,92,93] (1 2)",
    },

    { .asp_a_str = "(2529 5417 90)",
      .asp_b_str = "(2529 5417) [90,92]",
      .result    = "(2529 5417) [90,92]",
    },

    /* Sets in the middle, merging with each other etc. but resync on
     * middle and trailing sequence.
     *
     * Noting that "matching" sets force a set-start after themselves.
     */
    { .asp_a_str = "2529 5417 {90} 99 2 1",
      .asp_b_str = "2529 5417 {91,92} 2 1",
      .result    = "2529 5417 {90,91,92,99} 2 1",
    },

    { .asp_a_str = "2529 5417 {90} 99 2 1",
      .asp_b_str = "2529 5417 {91,92} 98 2 1",
      .result    = "2529 5417 {90,91,92} {98,99} 2 1",
    },

    { .asp_a_str = "2529 5417 {90} {97} 99 2 1",
      .asp_b_str = "2529 5417 {91,92} 2 1",
      .result    = "2529 5417 {90,91,92,97,99} 2 1",
    },

    { .asp_a_str = "2529 5417 99 {90} 2 1",
      .asp_b_str = "2529 5417 {91,92} 2 1",
      .result    = "2529 5417 {90,91,92,99} 2 1",
    },

    { .asp_a_str = "2529 5417 {90} {95} 99 2 1",
      .asp_b_str = "2529 5417 {91,92} 97 2 1",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1",
    },

    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1",
      .asp_b_str = "2529 5417 {91,92} 97 2 1",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1",
    },

    /* Merging of trailing sets and other stuff.
     */
    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1 {100}",
      .asp_b_str = "2529 5417 {91,92} 97 2 1 {101} 102",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1 {100,101,102}",
    },

    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1 {100}",
      .asp_b_str = "2529 5417 {91,92} 97 2 1 {101} {102}",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1 {100,101,102}",
    },

    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1 {100}",
      .asp_b_str = "2529 5417 {91,92} 97 2 1 {101} 102 {103}",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1 {100,101,102,103}",
    },

    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1 {100} {104}",
      .asp_b_str = "2529 5417 {91,92} 97 2 1 {101} 102 {103}",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1 {100,101}"
                                                               " {102,103,104}",
    },

    { .asp_a_str = "2529 5417 {90} 95 {99} 2 1 {100} {104}",
      .asp_b_str = "2529 5417 {91,92} 97 2 1 {101} {102} {103}",
      .result    = "2529 5417 {90,91,92} {95,97,99} 2 1 {100,101}"
                                                              " {102,103,104}",
    },

    /* Leading Confed and trailing simple -- treated separately when knocking
     * out repeated ASN.
     */
    { .asp_a_str = "(2529 5417 2)     7 {222} 8 9 {11}",
      .asp_b_str = "(2529 5417) [1,2] 7 {222} 8 9 10 {12}",
      .result    = "(2529 5417) [1,2] 7 {222} 8 9 {10,11,12}",
    },

    { .asp_a_str = "(2529 5417 2)     7 {222} 8 9 {11} 77",
      .asp_b_str = "(2529 5417) [1,2] 7 {222} 8 9 10 {12}",
      .result    = "(2529 5417) [1,2] 7 {222} 8 9 {10,11,12,77}",
    },

    { .asp_a_str = "(2529 5417 2)     7 {222} 8 9 {11} 77",
      .asp_b_str = "(2529 5417) [1,2] 7 {222} 8 9 10 {12} 88",
      .result    = "(2529 5417) [1,2] 7 {222} 8 9 {10,11,12,77,88}",
    },

    { .asp_a_str = "(2529 5417 2)     7 2 1 {111,222} 8 9 1",
      .asp_b_str = "(2529 5417) [1,2] 7 2 1 {222,333} 8 9 2",
      .result    = "(2529 5417) [1,2] 7 2 1 {111,222,333} 8 9",
    },

    { .asp_a_str = "(2529 5417) 8",
      .asp_b_str = "8 9",
      .result    = "[2529,5417] 8 {9}",
    },

    { .asp_a_str = "8 2529 5417 6 5 4 33 2 1",
      .asp_b_str = "8 7 6 5 4 99 2 1",
      .result    = "8 {7,2529,5417} 6 5 4 {33,99} 2 1",
    },

    { .asp_a_str = "8 2529 5417 6 5 4 {33} 2 1",
      .asp_b_str = "8 7 6 5 4 {99} 2 1",
      .result    = "8 {7,2529,5417} 6 5 4 {33,99} 2 1",
    },

    { .asp_a_str = "8 2529 5417 6 5 4 {33} 22 {98,99} 2 1",
      .asp_b_str = "8 7 6 5 4 {99} 77 66 2 1",
      .result    = "8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1",
    },

    { .asp_a_str = "(8 2529 5417 6 5 4) [33] (22) [98,99] (2 1)",
      .asp_b_str = "(8 7 6 5 4) [99] (77 66 2 1)",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)",
    },

    { .asp_a_str = "(8 2529 5417 6 5 4) [33] (22) [98,99] (2 1)"
                   " 8 2529 5417 6 5 4 {33} 22 {98,99} 2 1",
      .asp_b_str = "(8 7 6 5 4) [99] (77 66 2 1)"
                   " 8 7 6 5 4 {99} 77 66 2 1",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)"
                   " 8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1"
    },

    { .asp_a_str = "(8 2529 5417 6 5 4) [33] (22) [98,99] (2 1)"
                   " 8 2529 5417 6 5 4 {33} 22 {98,99} 2 1",
      .asp_b_str = "(8 7 6 5 4) [99] (77 66 2 1)"
                   " 8 7 6 5 4 {99} 77 66 2 1",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)"
                   " 8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1"
    },

    /* Knocking ASN out of sets for preference, but also out of sequences.
     */
    { .asp_a_str = "{90,95,99} 1 2 95 95 95 3 4 {95} 5 6 95 7",
      .asp_b_str = "1 2 95 3 4 5 6 95 7",
      .result    = "{90,99} 1 2 95 95 95 3 4 5 6 7"
    },

    /* Mish-mash of confed and simple stuff
     */
    { .asp_a_str = "8 2529 5417 6 5 4 {33} 22 {98,99} 2 1"
                   " (8 2529 5417 6 5 4) [33] (22) [98,99] (2 1)",
      .asp_b_str = "(8 7 6 5 4) [99] (77 66 2 1)"
                   " 8 7 6 5 4 {99} 77 66 2 1",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)"
                   " 8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1"
    },

    { .asp_a_str = "8 2529 5417 6 5 4 (8 2529 5417 6 5 4) [33] (22)"
                   " {33} 22 {98,99} 2 1 [98,99] (2 1)",
      .asp_b_str = "(8 7 6 5 4) [99] (77 66 2 1) 8 7 6 5 4 {99} 77 66 2 1",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)"
                   " 8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1"
    },

    { .asp_a_str = "8 2529 5417 6 5 4 (8 2529 5417 6 5 4) [33] (22)"
                   " {33} 22 {98,99} 2 1 [98,99] (2 1)",
      .asp_b_str = "(8 7 6) 8 7 (5 4) [99] 6 (77) 5 (66)"
                                                    " 4 {99} 77 (2) 66 2 (1) 1",
      .result    = "(8) [7,2529,5417] (6 5 4) [33,99] [22,66,77,98] (2 1)"
                   " 8 {7,2529,5417} 6 5 4 {33,99} {22,66,77,98} 2 1"
    },

    { .asp_a_str  = NULL }
  } ;

static void
test_as_path_aggregate(void)
{
  uint fail_count_was, test_count_was ;
//uint i ;
  as_test_path  astp ;
  asp_aggregate_test test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_aggregate()") ;

  astp = astp_new() ;

  /* The specific (spot) tests
   */
  test = aggregate_test_table ;
  while (test->asp_a_str != NULL)
    {
      uint j ;

      for (j = 0 ; j < 2 ; ++j)
        {
          as_path  asp_a, asp_b ;
          const char* str_a, * str_b ;
          bool ok ;

          next_test() ;

          if (j == 0)
            {
              str_a = test->asp_a_str ;
              str_b = test->asp_b_str ;
            }
          else
            {
              str_a = test->asp_b_str ;
              str_b = test->asp_a_str ;
            } ;

          asp_a = as_path_from_str(str_a) ;

          ok = test_assert(asp_a != NULL,
                          "expected to convert string asp_a='%s' to as_path",
                                                                        str_a) ;

          asp_b = as_path_from_str(str_b) ;

          ok = ok &
              test_assert(asp_b != NULL,
                          "expected to convert string asp_b='%s' to as_path",
                                                                        str_b) ;
          if (ok)
            {
              as_path  asp_t ;
              const char* str_t ;

              asp_t = as_path_aggregate(asp_a, asp_b) ;

              str_t = as_path_str(asp_t) ;

              test_assert(strcmp(test->result, str_t) == 0,
                  "expected '%s' but got '%s', when aggregating '%s' with '%s'",
                                            test->result, str_t, str_a, str_b) ;

              if ((asp_t != asp_a) && (asp_t != asp_b))
                as_path_free(asp_t) ;
            }

          as_path_free(asp_a) ;
          as_path_free(asp_b) ;
        } ;

      ++test ;
    } ;

  astp_free(astp) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests  -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of asn_set_xxx
 *
 *   * asn_set_free()
 *   * asn_set_add()
 *   * asn_set_contains()
 *   * asn_set_from_str()
 */
typedef struct asn_set_test  asn_set_test_t ;
typedef const struct asn_set_test* asn_set_test ;

struct asn_set_test
{
  const char* str ;

  uint   len ;
  as_t   set[10] ;

  as_t   absent ;
} ;

static const asn_set_test_t  set_test_table[] =
  {
    { .str     = "",
      .len     = 0,
      .set     = {},
      .absent  = 1,
    },

    { .str     = "1",
      .len     = 1,
      .set     = {1},
      .absent  = 2,
    },

    { .str     = "1 2 4 5",
      .len     = 4,
      .set     = {1, 2, 4, 5},
      .absent  = 3,
    },

    { .str     = "2529 1 5417 1 6665 239 0xFFFF.0xFFFF 5417 240 2529",
      .len     = 7,
      .set     = {1, 239, 240, 2529, 5417, 6665, 0xFFFFFFFF},
      .absent  = 0xFFFFFFFE,
    },

    { .str     = "(1)",
    },

    { .str     = "0",
    },

    { .str     = "99999999999999999",
    },

    { .str  = NULL }
  } ;

static as_t asn_unique(as_t* used, uint n) ;

static void
test_asn_set(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  asn_set_test test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: asn_set_xxx()") ;

  /* The specific (spot) tests
   */
  test = set_test_table ;
  while (test->str != NULL)
    {
      asn_set asns ;
      bool ok ;

      next_test() ;

      asns = asn_set_from_str(test->str) ;

      if (test->absent != 0)
        test_assert(asns != NULL,
            "did NOT expect asn_set_from_str() to fail for '%s'", test->str) ;
      else
        test_assert(asns == NULL,
            "expected asn_set_from_str() to *fail* for '%s'", test->str) ;

      ok = test_assert(!asn_set_contains(asns, test->absent),
                 "did NOT expect to find %u in '%s'", test->absent, test->str) ;

      if (ok && (asns != NULL))
        {
          uint j ;

          ok = test_assert(asns->set.len == test->len,
              "expected asn_set length of %u, got %u for '%s", test->len,
                                                     asns->set.len, test->str) ;

          for (j = 0 ; ok && (j < test->len) ; ++j)
            {
              ok = test_assert(asn_set_contains(asns, test->set[j]),
                 "expected to find %u in '%s'", test->set[j], test->str) ;
            } ;

          if (ok)
            {
              asn_set_add(asns, test->absent) ;

              test_assert(!asns->searchable,
                "did NOT expect asn_set to be searchable after asn_set_add()") ;

              ok = test_assert(asn_set_contains(asns, test->absent),
                 "expected to find %u in '%s' after adding it",
                                                     test->absent, test->str) ;

              if (ok)
                ok = test_assert(asns->searchable,
                   "expected asn_set to be searchable after asn_set_check()") ;


              if (ok)
                test_assert(asns->set.len == (test->len + 1),
                 "expected asn_set length of %u, got %u for '%s", test->len + 1,
                                                     asns->set.len, test->str) ;
            } ;
        } ;

      asn_set_free(asns) ;

      ++test ;
    } ;

  /* Some random testing
   *
   * Generate unique ASNs at random, and add each one to the asn_set.
   *
   * Check that all generated ASN exist in the set, and that it is the right
   * length.
   *
   * For a while, generate unique ASN at random and check do not exist in the
   * set, and select from pool of ASN used and check that do exist in the set.
   */
  for (i = 0 ; i < 2000 ; ++i)
    {
      asn_set asns ;
      as_t asns_used[2000] ;
      uint count, j ;

      next_test() ;

      asns = NULL ;

      count = (i % 47) + 1 ;
      if ((i > 1000) && ((rand() % 10) == 0))
        count = i ;

      for (j = 0 ; j < count ; ++j)
        {
          asns_used[j] = asn_unique(asns_used, j) ;
          asns = asn_set_add(asns, asns_used[j]) ;
        } ;

      for (j = 0 ; j < count ; ++j)
        test_assert(asn_set_contains(asns, asns_used[j]),
                               "expected to find %u in asn_set", asns_used[j]) ;

      for (j = 0 ; j < (count * 2) ; ++j)
        {
          as_t asn ;

          if (rand() & 1)
            {
              asn = asns_used[rand() % count] ;
              test_assert(asn_set_contains(asns, asn),
                                        "expected to find %u in asn_set", asn) ;
            }
          else
            {
              asn = asn_unique(asns_used, count) ;
              test_assert(!asn_set_contains(asns, asn),
                                  "did NOT expect to find %u in asn_set", asn) ;
            } ;
        } ;

      test_assert(asns->set.len == count,
                     "expected asn_set length of %u, got %u", count,
                                                              asns->set.len) ;

      asn_set_free(asns) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests  -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

static as_t
asn_unique(as_t* used, uint n)
{
  while (1)
    {
      as_t asn ;
      uint s ;

      asn = rand() ;

      if (asn == 0)
        continue ;

      s = 0 ;
      while (1)
        {
          if (s >= n)
            return asn ;

          if (asn == used[s])
            break ;

          ++s ;
        } ;
    };
} ;

/*==============================================================================
 * Test of as_path_store()
 *
 * Generate a number of unique as_paths and store same -- checking that does
 * not find stored value and result is stored.
 *
 * At random, regenerate as_path and store same -- checking that does find
 * stored value with the expected reference count.
 *
 * At random, release the paths until all are released.
 */
enum { stored_count = 2000 } ;

static struct
{
  as_path   asp ;
  uint      count ;
} stored[stored_count] ;

static void
test_as_path_store(void)
{
  uint fail_count_was, test_count_was ;
  uint i, have ;
  as_test_path astp ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_store()") ;

  /* Generate and store 'stored_count' random but unique paths -- including
   * the empty path.
   *
   * Ensures unique by prepending an AS_SET.
   *
   * Checks that each stored value is unique and has the expected reference
   * count.
   */
  astp = astp_new() ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      as_path asp, asp_s ;
      uint count ;
      bool ok ;

      next_test() ;

      if (i == 0)
        count = 0 ;
      else
        count = (i % 17) + 1 ;

      make_test_path(astp, count, true /* small_rep */, all_asn, all_sorts) ;
      make_parse_test(astp, true /* as4 */) ;
      asp = as_path_parse(astp->parse, astp->parse_len, true  /* as4 */) ;

      if (i != 0)
        as_path_prepend_tx(asp, BGP_AS_SET, i, 1) ;

      asp_s = as_path_store(asp) ;

      if (i == 0)
        {
          test_assert(asp_s == as_path_empty_asp,
                       "expect empty path to store as the as_path_empty_asp") ;
          ok = test_assert(asp_s->vhash.ref_count == 3,
            "expected the stored empty asp to have reference count==3, got %u",
                                                       asp_s->vhash.ref_count) ;
        }
      else
        {
          test_assert(asp_s == asp, "expect new asp to store as itself") ;
          ok = test_assert(asp_s->vhash.ref_count == 2,
                "expected a stored new asp to have reference count==2, got %u",
                                                       asp_s->vhash.ref_count) ;
        } ;

      if (ok)
        ok = test_assert(asp_s->stored,
                          "expected the stored asp to be marked 'stored'") ;
      if (ok)
        ok = test_assert(asp_s->state & asps_processed,
                       "expected the stored asp to be marked 'processed'") ;

      stored[i].asp   = asp_s ;
      stored[i].count = asp_s->vhash.ref_count ;
    } ;

  astp_free(astp) ;

  /* Now, for a while and at random, create new as_path and then store it.
   */
  i = 0 ;
  while (i < stored_count)
    {
      uint j ;
      as_path asp, asp_s ;
      const char* str ;
      bool ok ;

      next_test() ;

      if (rand() & 3)
        j = rand() % stored_count ;
      else
        j = i++ ;

      str = as_path_str(stored[j].asp) ;
      asp = as_path_from_str(str) ;

      ok = test_assert(asp != NULL,
                        "did NOT expect as_path_from_str('%s') to fail", str) ;
      if (!ok)
        continue ;

      asp_s = as_path_store(asp) ;

      ok = test_assert(asp_s == stored[j].asp,
                                "expected to find stored value for '%s'", str) ;
      if (!ok)
        continue ;

      stored[j].count += 2 ;

      test_assert(asp_s->vhash.ref_count == stored[j].count,
            "expected a stored asp to have reference count==%u, got %u",
                                      stored[j].count, asp_s->vhash.ref_count) ;
    } ;

  /* Now, until the store is empty, release a stored item at random.
   */
  have = stored_count ;

  while(1)
    {
      as_path asp ;
      uint j ;
      bool ok ;

      next_test() ;

      j = rand() % have ;
      asp = stored[j].asp ;

      if (j == 0)
        assert(asp == as_path_empty_asp) ;
      else
        assert(asp != as_path_empty_asp) ;

      test_assert(asp->vhash.ref_count == stored[j].count,
          "expected a stored asp to have reference count==%u, got %u",
                                       stored[j].count, asp->vhash.ref_count) ;

      as_path_release(asp) ;

      if (stored[j].count == 1)
        {
          ok = test_assert(j == 0,
                            "*only* the empty path can have count==1") ;
          if (!ok)
            break ;

          test_assert(asp->vhash.ref_count == 1,
              "after as_path_release() expected empty asp to have"
                         " reference count==1, got %u", asp->vhash.ref_count) ;

          if (have == 1)
            break ;
        }
      else
        {
          assert(stored[j].count > 1) ;

          stored[j].count -= 2 ;

          if (stored[j].count == 0)
            {
              ok = test_assert(j != 0,
                            "did NOT expect the empty path to have count==2") ;
              if (!ok)
                break ;

              assert(have > j) ;

              have     -= 1 ;
              stored[j] = stored[have] ;

              stored[have].asp   = NULL ;
              stored[have].count = 0 ;
            }
          else
            {
              test_assert(asp->vhash.ref_count == stored[j].count,
                  "after as_path_release() expected stored asp to have"
                                                " reference count==%u, got %u",
                                       stored[j].count, asp->vhash.ref_count) ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests  -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of as_path_exclude_asns()
 *
 */
typedef struct asp_exclude_test  asp_exclude_test_t ;
typedef const struct asp_exclude_test* asp_exclude_test ;

struct asp_exclude_test
{
  const char* str_in ;
  const char* str_out ;
  const char* exclude ;
} ;

static const asp_exclude_test_t  exclude_test_table[] =
  {
    { .str_in  = "",
      .str_out = "",
      .exclude = "1 2 3 4 5 6 7 8 9 10",
    },

    { .str_in  = "1 2 3 4 5 6 7 8 9 10",
      .str_out = "",
      .exclude = "1 2 3 4 5 6 7 8 9 10",
    },

    { .str_in  = "1 2 (3 4) 5 {6,7} 8 [9] 10",
      .str_out = "",
      .exclude = "1 2 3 4 5 6 7 8 9 10",
    },

    { .str_in  = "41 42 (43 44) 45 {46,47} 48 [49] 410",
      .str_out = "41 42 (43 44) 45 {46,47} 48 [49] 410",
      .exclude = "1 2 3 4 5 6 7 8 9 10",
    },

    { .str_in  = "41 2 42 (43 1 44) 45 {7,46,47} 9 48 [7,49] 410 8",
      .str_out = "41 42 (43 44) 45 {46,47} 48 [49] 410",
      .exclude = "1 2 3 4 5 6 7 8 9 10",
    },

    { .str_in  = NULL }
  } ;

static void
test_as_path_exclude_asns(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  asp_exclude_test test ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: as_path_exclude_asns()") ;

  /* The specific (spot) tests
   */
  test = exclude_test_table ;
  while (test->str_in != NULL)
    {
      asn_set asns ;
      as_path asp, asp_s, asp_t ;
      const char* str ;
//    bool ok ;

      next_test() ;

      asp   = as_path_from_str(test->str_in) ;
      asp_s = as_path_store(asp) ;
      asp   = as_path_from_str(test->str_in) ;

      /* A NULL asn_set has no effect.
       */
      asp_t = as_path_exclude_asns(asp, NULL) ;

      test_assert(asp_t == asp,
               "did NOT expect as_path_exclude_asns(asp, NULL) to affect asp") ;
      str = as_path_str(asp) ;
      test_assert(strcmp(str, test->str_in) == 0,
               "expected '%s' from as_path_exclude_asns(asp, NULL), got '%s'",
                                                            test->str_in, str) ;

      asp_t = as_path_exclude_asns(asp_s, NULL) ;

      test_assert(asp_t == asp_s,
           "did NOT expect as_path_exclude_asns(asp_s, NULL) to affect asp_s") ;
      str = as_path_str(asp_s) ;
      test_assert(strcmp(str, test->str_in) == 0,
               "expected '%s' from as_path_exclude_asns(asp_s, NULL), got '%s'",
                                                            test->str_in, str) ;

      /* An empty asn_set has no effect.
       */
      asns = asn_set_from_str(rand() & 1 ? "" : NULL) ;

      test_assert(asns != NULL,
                       "did NOT expect asn_set_from_str(\"\") to return NULL") ;

      asp_t = as_path_exclude_asns(asp, asns) ;

      test_assert(asp_t == asp,
             "did NOT expect as_path_exclude_asns(asp, empty) to affect asp") ;
      str = as_path_str(asp) ;
      test_assert(strcmp(str, test->str_in) == 0,
             "expected '%s' from as_path_exclude_asns(asp, empty), got '%s'",
                                                            test->str_in, str) ;

      asp_t = as_path_exclude_asns(asp_s, asns) ;

      test_assert(asp_t == asp_s,
         "did NOT expect as_path_exclude_asns(asp_s, empty) to affect asp_s") ;
      str = as_path_str(asp_s) ;
      test_assert(strcmp(str, test->str_in) == 0,
             "expected '%s' from as_path_exclude_asns(asp_s, empty), got '%s'",
                                                            test->str_in, str) ;

      asn_set_free(asns) ;

      /* A not-empty asn_set may have some effect
       */
      asns = asn_set_from_str(test->exclude) ;

      asp_t = as_path_exclude_asns(asp, asns) ;
      str = as_path_str(asp_t) ;

      test_assert(asp_t == asp,
                        "did NOT expect as_path_exclude_asns() to change asp") ;
      test_assert(strcmp(str, test->str_out) == 0,
          "expected '%s' from as_path_exclude_asns('%s', '%s'), got '%s'",
                              test->str_out, test->str_in, test->exclude, str) ;

      asp_t = as_path_exclude_asns(asp_s, asns) ;
      str = as_path_str(asp_t) ;

      if (strcmp(test->str_in, test->str_out) != 0)
        test_assert(asp_t != asp_s,
                        "expected a new as_path from as_path_exclude_asns()") ;
      else
        test_assert(asp_t == asp_s,
                      "did NOT expect as_path_exclude_asns() to change asp_s") ;

      test_assert(strcmp(str, test->str_out) == 0,
          "expected '%s' from as_path_exclude_asns('%s', '%s'), got '%s'",
                              test->str_out, test->str_in, test->exclude, str) ;

      if (asp_t != asp_s)
        as_path_release(asp_t) ;
      as_path_release(asp) ;
      as_path_release(asp_s) ;
      asn_set_free(asns) ;

      ++test ;
    } ;

  /* Some random testing
   *
   * Generate unique ASNs at random, and add each one to the asn_set.
   *
   * Check that all generated ASN exist in the set, and that it is the right
   * length.
   *
   * For a while, generate unique ASN at random and check do not exist in the
   * set, and select from pool of ASN used and check that do exist in the set.
   */
  for (i = 0 ; i < 2000 ; ++i)
    {
#if 0
      asn_set asns ;
      as_t asns_used[2000] ;
      uint count, j ;

      next_test() ;

      asns = NULL ;

      count = (i % 47) + 1 ;
      if ((i > 1000) && ((rand() % 10) == 0))
        count = i ;

      for (j = 0 ; j < count ; ++j)
        {
          asns_used[j] = asn_unique(asns_used, j) ;
          asns = asn_set_add(asns, asns_used[j]) ;
        } ;

      for (j = 0 ; j < count ; ++j)
        test_assert(asn_set_contains(asns, asns_used[j]),
                               "expected to find %u in asn_set", asns_used[j]) ;

      for (j = 0 ; j < (count * 2) ; ++j)
        {
          as_t asn ;

          if (rand() & 1)
            {
              asn = asns_used[rand() % count] ;
              test_assert(asn_set_contains(asns, asn),
                                        "expected to find %u in asn_set", asn) ;
            }
          else
            {
              asn = asn_unique(asns_used, count) ;
              test_assert(!asn_set_contains(asns, asn),
                                  "did NOT expect to find %u in asn_set", asn) ;
            } ;
        } ;

      test_assert(asns->set.len == count,
                     "expected asn_set length of %u, got %u", count,
                                                              asns->set.len) ;

      asn_set_free(asns) ;
#endif
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests  -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

#if 0


/*==============================================================================
 * Test of attr_cluster stuff.
 *
 * For cluster list lengths from 0 to 100 (100 gives a >400 byte attribute),
 * four times:
 *
 *   * construct a random cluster list
 *
 *   * set the list and check contains required stuff
 *
 *     checks that can ask for the length of a NULL attr_cluster
 *
 *   * free the attr_cluster and create again
 *
 *     checks that free does not leave stuff behind, and accepts NULL
 *     attr_cluster (if free does leave stuff behind, will be found when
 *     test exists).
 *
 *   * store the attr_cluster and check contents
 *
 *     checks that can store NULL and empty not-NULL and get the same thing
 *     (for completeness; do not generally create empty non-NULL attr_cluster).
 *
 *     checks that uses embedded cluster list of possible, even if was not
 *     embedded before.
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_clust_simple(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_cluster construction and storage") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_cluster clust ;
      uint count ;
      uint ord ;
      bool ok ;

      next_test() ;

      if (i == 0)
        {
          count = 0 ;
          ord   = 0 ;
        }
      else
        {
          /* Want: ord = 1 for i =   1..100  -- count = 1..100
           *             2 for i = 101..200  -- count = 1..100
           *             3 for i = 201..300  -- count = 1..100
           *             4 for i = 301..400  -- count = 1..100
           */
          count = ((i - 1) % 100) + 1 ;
          ord   = ((i - 1) / 100) + 1 ;
        } ;

      /* Create an original cluster list, and then create an attr_cluster
       *
       * Check that the result is exactly as expected.
       */
      originals[i] = make_clust_list(count, ord) ;

      clust = attr_cluster_set((byte*)(originals[i]->list),
                                                     originals[i]->count) ;

      test_assert(attr_cluster_length(clust) == count,
                             "expected cluster length %u, got %u", count,
                                                  attr_cluster_length(clust)) ;
      if (count == 0)
        {
          test_assert(clust == NULL,
                     "expected clust == NULL for an empty cluster list") ;
        }
      else
        {
          test_assert(clust != NULL,
                      "expected clust != NULL for a cluster list length=%u",
                                                                       count) ;
        } ;

      if (clust != NULL)
        {
          if ((clust->list.len == count) && (count != 0))
            {
              ok = test_assert(memcmp(clust->list.body.v, originals[i]->list,
                                                               count * 4) == 0,
                                            "cluster list is not as expected") ;
              if (!ok)
                show_delta(clust->list.body.v, (byte*)(originals[i]->list),
                                                                        count) ;
            }
          else
            {
              const char* str ;

              str = attr_cluster_str(clust) ;

              ok = test_assert(strcmp(str, originals[i]->string) == 0,
                                       "cluster list strings not as expected") ;
              if (!ok)
                show_str_delta(str, originals[i]->string) ;
            } ;
        } ;

      /* Free and then recreate -- so have called free !
       */
      attr_cluster_free(clust) ;

      assert(count == originals[i]->count) ;
      clust = attr_cluster_set((byte*)(originals[i]->list), count) ;

      /* Now store the cluster list.
       *
       * At this point, for count == 0 we have a NULL cluster list -- stick in
       * test for storing non-NULL but empty one, too.
       */
      if (count == 0)
        {
          assert(clust == NULL) ;

          stored[0] = attr_cluster_store(NULL) ;

          test_assert(stored[0] == NULL,
              "expect NULL when storing a NULL attr_cluster") ;

          clust = attr_cluster_new(cluster_list_embedded_size) ;
          test_assert(clust->list.body.v == clust->embedded_list,
                                       "expected cluster list to be embedded") ;

          stored[0] = attr_cluster_store(clust) ;

          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_cluster") ;

          clust = attr_cluster_new(cluster_list_embedded_size + 1) ;
          test_assert(clust->list.body.v != clust->embedded_list,
                                "did NOT expect cluster list to be embedded") ;

          stored[0] = attr_cluster_store(clust) ;

          test_assert(stored[0] == NULL,
              "expect NULL when storing an empty attr_cluster") ;
        }
      else
        {
          attr_cluster s_clust ;

          assert(clust != NULL) ;

          stored[i] = s_clust = attr_cluster_store(clust) ;

          test_assert(s_clust == clust,
                                      "expect to store the original cluster") ;

          test_assert(s_clust->stored,
                                    "expect to stored cluster to be 'stored'") ;

          test_assert(s_clust->vhash.ref_count == 2,
                "expected reference count == 2 after attr_cluster_store(), "
                                           "got=%u", s_clust->vhash.ref_count) ;

          test_assert(attr_cluster_length(s_clust) == count,
                             "expected cluster length %u, got %u", count,
                                                 attr_cluster_length(s_clust)) ;

          if (count <= cluster_list_embedded_size)
            test_assert(s_clust->list.body.v == s_clust->embedded_list,
                     "expect count of %u to be held in embedded body", count) ;

          if ((s_clust->list.len == count) && (count != 0)
         && (memcmp(s_clust->list.body.v, originals[i]->list, count * 4) != 0))
            {
              test_assert(memcmp(s_clust->list.body.v, originals[i]->list,
                                                               count * 4) == 0,
                                    "stored cluster list is not as expected") ;
              show_delta(s_clust->list.body.v, (byte*)(originals[i]->list),
                                                                        count) ;
            }
          else
            {
              const char* str ;

              str = attr_cluster_str(s_clust) ;

              if (strcmp(str, originals[i]->string) != 0)
                {
                  test_assert(strcmp(str, originals[i]->string) == 0,
                               "stored cluster list strings not as expected") ;
                  show_str_delta(str, originals[i]->string) ;
                } ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_cluster_store().
 *
 *   * create new copy of each original, then release
 *
 *     tests release of not-stored value and release of NULL
 *
 *   * create another new copy of each original, and store it.
 *
 *     should find existing stored value and increment its count.
 *
 *   * do attr_cluster_lock() -- ref count should be increased
 *
 *   * do attr_cluster_release(), twice -- ref count should be reduced
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_clust_store(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_cluster_store") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_cluster clust, s_clust ;

      next_test() ;

      /* Create an attr_cluster, starting from NULL
       *
       * Release it again -- to test release of not-stored and NULL.
       */
      clust = attr_cluster_set((byte*)(originals[i]->list),
                                                          originals[i]->count) ;

      test_assert(attr_cluster_length(clust) == originals[i]->count,
                             "expected cluster length %u, got %u",
                              originals[i]->count, attr_cluster_length(clust)) ;

      attr_cluster_release(clust) ;

      /* Create an attr_cluster, starting from NULL
       *
       * Store it and check we get the previously stored value.
       */
      clust = attr_cluster_set((byte*)(originals[i]->list),
                                                          originals[i]->count) ;

      test_assert(attr_cluster_length(clust) == originals[i]->count,
                             "expected cluster length %u, got %u",
                              originals[i]->count, attr_cluster_length(clust)) ;

      s_clust = attr_cluster_store(clust) ;

      test_assert(s_clust == stored[i],
                           "expected to find previously stored attr_cluster") ;

      if (s_clust == NULL)
        continue ;

      test_assert(s_clust->stored,
                                "expect to stored cluster to be 'stored'") ;

      test_assert(s_clust->vhash.ref_count == 4,
            "expected reference count == 4 after second attr_cluster_store(), "
                                       "got=%u", s_clust->vhash.ref_count) ;

      /* Lock and check result
       */
      attr_cluster_lock(s_clust) ;

      test_assert(s_clust->vhash.ref_count == 6,
            "expected reference count == 6 after attr_cluster_lock(), "
                                       "got=%u", s_clust->vhash.ref_count) ;

      /* Release twice and check result
       */
      attr_cluster_release(s_clust) ;
      attr_cluster_release(s_clust) ;

      test_assert(s_clust->vhash.ref_count == 2,
            "expected reference count == 2 after attr_cluster_release(), "
                                       "got=%u", s_clust->vhash.ref_count) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_cluster_check().
 *
 * For all stored attr_cluster:
 *
 *   * attr_cluster_check() for randomly selected entries.
 *
 *   * attr_cluster_check() for unused
 *
 * Leaves the stored array as is.
 */
static void
test_clust_check(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_cluster_check()") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_cluster clust ;
      uint n ;
      bgp_id_t  check ;

      clust = stored[i] ;

      for (n = 0 ; n < 6 ; ++n)
        {
          if (i == 0)
            break ;

          next_test() ;

          check = ((bgp_id_t*)clust->list.body.v)[rand() % clust->list.len] ;

          test_assert(!attr_cluster_check(clust, check),
                           "expected to find bgp_id in attr_cluster_check()") ;
        } ;

      next_test() ;

      check = originals[i]->unused ;
      test_assert(attr_cluster_check(clust, check),
                       "expected NOT to find bgp_id in attr_cluster_check()") ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_cluster_out_prepare().
 *
 * For all stored attr_cluster:
 *
 *   * attr_cluster_out_prepare() and check the result.
 *
 * Leaves the stored array with one stored copy of each original.
 */
static void
test_clust_out_prepare(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_cluster_out_prepare()") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_cluster clust ;
      attr_cluster_out_t out[1] ;
      uint e_len, a_len, p_len ;
      byte a_flags, a_type, e_flags ;
      byte* p ;
      bool ok ;

      next_test() ;

      clust = stored[i] ;

      out->cluster_id = originals[i]->unused ;

      attr_cluster_out_prepare(out, clust) ;

      e_len = originals[i]->count * 4 ;

      test_assert(out->len[1] == e_len,
                              "expected len}1]=%u, got %u", e_len, out->len[1]) ;
      if ((out->len[1] == e_len) && (e_len != 0))
        {
          ok = test_assert(memcmp(out->part[1], originals[i]->list, e_len) == 0,
                                            "part[1] is not as expected") ;
          if (!ok)
            show_delta(out->part[1], (byte*)(originals[i]->list),
                                                          originals[i]->count) ;
        } ;

      e_len += 4 ;
      if (e_len > 255)
        e_flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED ;
      else
        e_flags = BGP_ATF_OPTIONAL ;

      p = out->part[0] ;

      a_flags = p[0] ;
      a_type  = p[1] ;

      if (a_flags & BGP_ATF_EXTENDED)
        {
          a_len = load_ns(&p[2]) ;
          p_len = 8 ;
          p += 4 ;
        }
      else
        {
          a_len = p[2] ;
          p += 3 ;
          p_len = 7 ;
        } ;

      ok = test_assert(out->len[0] == p_len,
                            "expected len[0]=%u, got=%u", p_len, out->len[0]) ;
      if (!ok)
        continue ;

      ok = test_assert(a_flags == e_flags,
                       "expected flags=0x%02x, got=0x%02x", e_flags, a_flags) ;
      if (!ok)
        continue ;

      ok = test_assert(a_type == BGP_ATT_CLUSTER_LIST,
                    "expected type=%u, got=%u", BGP_ATT_CLUSTER_LIST, a_type) ;
      if (!ok)
        continue ;

      ok = test_assert(a_len == e_len,
                        "expected attribute length=%u, got=%u", e_len, a_len) ;
      if (!ok)
        continue ;

      test_assert(load_l(p) == originals[i]->unused,
                              "did not get the expected prepended cluster-id") ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_cluster_out_release().
 *
 * For all stored attr_cluster:
 *
 *   * check that the reference count is as expected.
 *
 *   * release
 *
 * Leaves the stored array empty.
 */
static void
test_clust_release(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_cluster_out_release()") ;

  for (i = 0 ; i < stored_count ; ++i)
    {
      attr_cluster s_clust ;

      next_test() ;

      s_clust = stored[i] ;

      if (s_clust != NULL)
        test_assert(s_clust->vhash.ref_count == 2,
           "expected reference count == 2 before last attr_cluster_release(), "
                                       "got=%u", s_clust->vhash.ref_count) ;

      stored[i] = attr_cluster_release(s_clust) ;
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
static void show_delta_seg_properties(const as_path_seg_properties_t* got,
                                      const as_path_seg_properties_t* exp,
                                      const char* tag) ;

/*------------------------------------------------------------------------------
 * Show difference between the as_path we got, and the as_path we expected.
 */
static void
show_delta(const asp_item_t* got, const asp_item_t* exp, uint count)
{
  uint off, i, n ;

  off = 0 ;
  while (off < count)
    {
      if (got[off].qseg != exp[off].qseg)
        break ;

      if (got[off].asn != exp[off].asn)
        break ;

      if (got[off].count != exp[off].count)
        break ;

      ++off ;
    } ;

  if (off >= count)
    {
      test_assert(off < count, "found no difference in show_delta(%u)",
                                                                    count) ;
      return ;
    } ;

  if (off > 0)
    off = ((off - 1) / 4) * 4 ;

  n = off + 8 ;
  if (n > count)
    n = count ;

  fprintf(stderr, "\n  e%3d:", off) ;
  for (i = off ; i < n ; ++i)
    fprintf(stderr, " %x/0x%08x*%2d", exp[i].qseg, exp[i].asn,
                                                   exp[i].count) ;

  fprintf(stderr, "  ... total length = %u (items)", count) ;

  fprintf(stderr, "\n  g%3d:", off) ;
  for (i = off ; i < n ; ++i)
    fprintf(stderr, " %x/0x%08x*%2d", got[i].qseg, got[i].asn,
                                                   got[i].count) ;
} ;


/*------------------------------------------------------------------------------
 * Show difference between the cluster list we got, and the cluster list
 * we expected.
 */
static void
show_delta_properties(const as_path_properties_t* got,
                      const as_path_properties_t* exp)
{
  if (got->simple_sequence != exp->simple_sequence)
    fprintf(stderr, "\n   simple_sequence: got=%u, exp=%u",
                                   got->simple_sequence, exp->simple_sequence) ;

  if (got->total_length != exp->total_length)
    fprintf(stderr, "\n      total_length: got=%u, exp=%u",
                                   got->total_length, exp->total_length) ;

  if (got->left_most_asn != exp->left_most_asn)
    fprintf(stderr, "\n     left_most_asn: got=%u, exp=%u",
                                   got->left_most_asn, exp->left_most_asn) ;

  show_delta_seg_properties(&got->simple, &exp->simple, "simple") ;
  show_delta_seg_properties(&got->confed, &exp->confed, "confed") ;
} ;

static void
show_delta_seg_properties(const as_path_seg_properties_t* got,
                          const as_path_seg_properties_t* exp,
                          const char* tag)
{
  if (got->length != exp->length)
    fprintf(stderr, "\n      %s.length: got=%u, exp=%u", tag,
                                                   got->length, exp->length) ;

  if (got->seq_count != exp->seq_count)
    fprintf(stderr, "\n   %s.seq_count: got=%u, exp=%u", tag,
                                             got->seq_count, exp->seq_count) ;

  if (got->set_count != exp->set_count)
    fprintf(stderr, "\n   %s.set_count: got=%u, exp=%u", tag,
                                             got->set_count, exp->set_count) ;

  if (got->first_seg != exp->first_seg)
    fprintf(stderr, "\n   %s.first_seg: got=%u, exp=%u", tag,
                                             got->first_seg, exp->first_seg) ;

  if (got->first != exp->first)
    fprintf(stderr, "\n       %s.first: got=%u, exp=%u", tag,
                                             got->first, exp->first) ;

  if (got->last != exp->last)
    fprintf(stderr, "\n        %s.last: got=%u, exp=%u", tag,
                                             got->last, exp->last) ;

  if (got->first_asn != exp->first_asn)
    fprintf(stderr, "\n   %s.first_asn: got=%u, exp=%u", tag,
                                             got->first_asn, exp->first_asn) ;
} ;

/*==============================================================================
 * Making of test paths
 */

static uint       test_path_len ;
static asp_item_t test_path[8000] ;

static const char* astp_fill(as_test_path astp, asp_item_t* path, uint len) ;
static uint make_test_path_segment(as_seg_t seg, uint count, bool small_rep,
                                                             test_asn_t which) ;
static as_test_seg asts_free(as_test_seg asts) ;
static as_test_seg asts_new_prepend(path_list path, as_seg_t seg,
                                                       as_t asn[], uint count) ;
static as_seg_t random_seg(void) ;

/*------------------------------------------------------------------------------
 * Make an as_path_post_process() test path.
 *
 * This is designed to test the edge cases of post processing, which are:
 *
 *   * spotting repeated ASN, after removal of drops and redundant segments
 *
 *   * drop objects creating redundant segments and creating repeats.
 *
 *   * counts which exceed the maximum (which is 1 for sets)
 *
 *   * "missing" qAS_SET_START
 *
 *   * drop items with count == 0 and/or asn == BGP_ASN_NULL
 *
 * The paths created here are entirely unnatural.  More natural ones are
 * produced for other testing, which will also pass through post processing.
 */
static as_path
make_post_process_test(uint count)
{
  as_path  asp ;
  uint len ;
  qas_seg_t qseg ;

  assert( count < (sizeof(test_path) / (sizeof(asp_item_t) * 2)) ) ;

  static const as_t asns[] =
    {
       BGP_ASN_NULL,    //  1
       2529,            //  2
       5417,            //  3
       66666,           //  4
       0xFFFFF123,      //  5
    };

  static const uint counts[] =
    {
       0,                               // 1
       2,                               // 2
       3,                               // 3
       12,                              // 4
       as_max_count - 2,                // 5
       (as_max_count * 1133) / 399,     // 6
    };

  static const qas_seg_t qsegs[] =
    {
       qAS_SEQUENCE,
       qAS_CONFED_SEQUENCE,
       qAS_SET,
       qAS_SET        | qAS_SET_START,
       qAS_CONFED_SET,
       qAS_CONFED_SET | qAS_SET_START,
    };

  qseg = qsegs[rand() % 6] ;

  for (len = 0 ; len < count ; ++len)
    {
      /* ~66% chance of repeating the qseg
       */
      if (((uint)rand() % 100) < 50)
        qseg = qsegs[rand() % 6] ;

      test_path[len].asn   = asns[(uint)rand() % 5] ;
      test_path[len].count = counts[(uint)rand() %6] ;
      test_path[len].qseg  = qseg ;
    } ;

  test_path_len = count ;

  /* Make a new as_path and copy body across
   */
  asp = as_path_new(len) ;

  assert(len <= asp->path.size) ;
  if (len != 0)
    memcpy(asp->path.body.v, test_path, len * sizeof(asp_item_t)) ;

  asp->path.len = len ;
  return asp ;
} ;

/*------------------------------------------------------------------------------
 * Make a test path for general testing.
 *
 * Produces a number of segments, generated by make_test_path_segment().  Those
 * segments comprise a limited range of ASN, to exercise the spotting of
 * repeats.  The range includes edge cases for small/large ASN in the as_path.
 *
 * The 'count' controls the number of 'asp_item_t' items, which may be repeats.
 * The 'small_rep' argument limits the repeat size.
 *
 * The 'which' argument chooses the full ASN range ('all_asn'), or the subset
 * if the full range which are AS2 ('as2_only') or a separate range of private
 * ASN (including the limiting cases) ('private_only').
 *
 * The 'how' argument affects the selection of segments used in the test path.
 * The 'all_sorts' gives, at random, a path which is one of:
 *
 *   * random segments
 *
 *     The count is divided up into approximately 2, 4, or 8 parts.  The
 *     type of each segment is entirely random.
 *
 *     When 2 parts is selected, each part is randomly 2/8..6/8 of the original
 *     count, but at least 1 -- where the last part is limited so that the
 *     total == count.
 *
 *     Where 4 parts is selected it is 2/16..6/16.  For 8 parts 2/32..6/32.
 *
 *   * a single BGP_AS_SEQUENCE or BGP_AS_CONFED_SEQUENCE
 *
 *   * a single BGP_AS_CONFED_SEQUENCE followed by a single BGP_AS_SEQUENCE.
 *
 *     The count is divided between the two 1/4 or 1/2 to
 *
 *   * BGP_AS_SET or BGP_AS_CONFED_SET
 *
 *     Generates a single set if possible.  The set generation forces
 *     'small_rep', and forces the maximum size of the segment so that the
 *     *encoded* form is at most 255 ASN long -- before any sort/dedup.
 *
 *     This means encoding the generated test does not introduce an extra
 *     spurious set.  But also means that the encoding of over-large sets
 *     must be tested separately.
 *
 * For 'random_segs', only 'random segments' are created.  For 'no_confeds',
 * creates the same segments as 'all_sorts', but BGP_AS_CONFED_SEQUENCE is
 * forced to BGP_AS_SEQUENCE, and BGP_AS_CONFED_SET to BGP_AS_SET.
 *
 * Happily handles a count of zero: sets test_path_len == 0
 */
static void
make_test_path(as_test_path astp, uint count, bool small_rep,
                                              test_asn_t which, test_sort_t how)
{
  uint r_how ;
  const char* ret ;

  assert( count < (sizeof(test_path) / (sizeof(asp_item_t) * 2)) ) ;

  switch (how)
    {
      case all_sorts:
      case no_confeds:
        r_how = 7 ;
        break ;

      case random_segs:
        r_how = 3 ;
        break ;

      default:
        assert(false) ;
    } ;

  test_path_len = 0 ;

  if (count != 0)
    {
      uint len, r, d, n, left ;
      as_seg_t seg ;

      switch (r = (rand() % r_how))
        {
          /* Split count roughly in 2, 4, or 8 random segments -- 1/7th each
           */
          case 0:
          case 1:
          case 2:
            left = count ;
            n    = 1 << (r + 1)  ;      /* n = 2,  4 or  8      */
            d    = n * 4 ;              /* m = 8, 16 or 32      */
            while (left > 0)
              {
                n -= 1 ;

                if (n == 0)
                  len = left ;
                else
                  {
                    len = count * ((rand() % 5) + 2) / d ;

                    if      (len == 0)
                      len = 1 ;
                    else if (len > left)
                      len = left ;
                  } ;

                if (how == no_confeds)
                  seg = (rand() & 0x100) ? BGP_AS_SEQUENCE
                                         : BGP_AS_SET ;
                else
                  seg = random_seg() ;

                len = make_test_path_segment(seg, len, small_rep, which) ;
                left -= len ;
              } ;

            break ;

          /* A single BGP_AS_SEQUENCE or BGP_AS_CONFED_SEQUENCE -- 1/7, each
           */
          case 3:
          case 4:
            if (how == no_confeds)
              seg = BGP_AS_SEQUENCE ;
            else
              seg = (rand() & 0x100) ? BGP_AS_SEQUENCE
                                     : BGP_AS_CONFED_SEQUENCE ;

            make_test_path_segment(seg, count, small_rep, which) ;
            break ;

          /* A single BGP_AS_CONFED_SEQUENCE followed by a single
           * BGP_AS_SEQUENCE-- 1/7
           */
          case 5:
            if (how == no_confeds)
              seg = BGP_AS_SEQUENCE ;
            else
              seg = BGP_AS_CONFED_SEQUENCE ;

            len = count * ((rand() % 2) + 1) / 4 ;
            make_test_path_segment(seg, len, small_rep, which) ;
            make_test_path_segment(BGP_AS_SEQUENCE, count - len, small_rep,
                                                                        which) ;
            break ;

          /* A single (if can) BGP_AS_SET or BGP_AS_CONFED_SET -- 1/7
           *
           * For sets each segment is limited, so make_test_path_segment()
           * returns the actual count.
           */
          case 6:
            if (how == no_confeds)
              seg = BGP_AS_SET ;
            else
              seg = (rand() & 0x100) ? BGP_AS_SET
                                     : BGP_AS_CONFED_SET ;

            while (count > 0)
              {
                len = make_test_path_segment(seg, count, small_rep, which) ;
                count -= len ;
              } ;
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  /* Make a new as_test_path set the path according to the generated
   * test_path.
   */
  ret = astp_fill(astp, test_path, test_path_len) ;
  assert(ret == NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Make a segment of the given seg, containing 'count' items or fewer
 *
 * If the seg is BGP_AS_SET or BGP_AS_CONFED set, then ensures that the
 * length of the segment is at most 255 -- by reducing the count, if
 * necessary.
 */
static uint
make_test_path_segment(as_seg_t seg, uint count, bool small_rep,
                                                               test_asn_t which)
{
  uint count_r, asn_r, ecount, scount ;
  const as_t* asns ;
  qas_seg_t   qseg ;

  static bool asns_check = false ;

  static const as_t general_asns[] =
    {
       1,               //  1
       36,              //  2
       100,             //  3
       666,             //  4
       2529,            //  5
       5417,            //  6
       8762,            //  7
       9431,            //  8
       10666,           //  9
       15423,           // 10
       21787,           // 11
       26205,           // 12
       33984,           // 13
       47986,           // 14
       59215,           // 15
       64512,           // 16
       65534,           // 17
       65535,           // 18
       65536,           // 19 -- all > 65535 from now on
       68754,           // 20
       77777,           // 21
       89012,           // 22
       98716,           // 23
       0x00123456,      // 24
       0x01234567,      // 25
       0xFFFFFFFF,      // 26
    } ;

  static const as_t private_asns[] =
    {
       64512,           //  1
       64537,           //  2
       64561,           //  3
       64598,           //  4
       65515,           //  5
       65534,           //  6
    } ;

  enum
    {
      asn_as2_count  = 18,
      asn_as4_count  = 26,
      asn_priv_count =  6,
    } ;

  confirm(asn_as4_count  == (sizeof(general_asns) / sizeof(as_t))) ;
  confirm(asn_priv_count == (sizeof(private_asns) / sizeof(as_t))) ;

  static const uint counts[] =
    {
       1,          // 1
       2,          // 2
       5,          // 3
       10,         // 4  -- for sequences only from now on
       255,        // 5
       400,        // 6
    };

  if (!asns_check)
    {
      uint i ;

      asns_check = true;

      i = 0 ;
      while (general_asns[i] < 65536)
        ++ i ;

      assert(i == asn_as2_count) ;

      while (i < asn_as4_count)
        assert(general_asns[i++] > 65535) ;
    } ;

  if (count == 0)
    return 0 ;

  switch (seg)
    {
      case BGP_AS_SEQUENCE:
        qseg = qAS_SEQUENCE ;
        break ;

      case BGP_AS_SET:
        qseg = qAS_SET | qAS_SET_START ;
        break ;

      case BGP_AS_CONFED_SEQUENCE:
        qseg = qAS_CONFED_SEQUENCE ;
        break ;

      case BGP_AS_CONFED_SET:
        qseg = qAS_CONFED_SET | qAS_SET_START ;
        break ;

      default:
        assert(false) ;
    } ;

  if (small_rep || (qseg & qAS_SET))
    count_r = 3 ;
  else
    count_r = 6 ;

  switch (which)
    {
      case all_asn:
        asns  = general_asns ;
        asn_r = asn_as4_count ;
        break ;

      case as2_only:
        asns  = general_asns ;
        asn_r = asn_as2_count ;
        break ;

      case private_only:
        asns  = private_asns ;
        asn_r = asn_priv_count ;
        break ;

      default:
        assert(false) ;
    } ;

  ecount = 0 ;
  scount = 0 ;

  while (count-- != 0)
    {
      uint count ;

      count = 1 ;

      if ((rand() % 4) == 0)
        {
          count = counts[rand() % count_r] ;

          if ((qseg & qAS_SET) && ((scount + count) > 255))
            count = 255 - scount ;
        } ;

      test_path[test_path_len].asn   = asns[rand() % asn_r]  ;
      test_path[test_path_len].count = count ;
      test_path[test_path_len].qseg  = qseg ;

      qseg &= ~qAS_SET_START ;

      test_path_len += 1 ;
      scount        += count ;
      ecount        += 1 ;

      if ((qseg & qAS_SET) && (scount == 255))
        break ;
    } ;

  return ecount ;
} ;

/*------------------------------------------------------------------------------
 * Make a test seq for testing as_path_add_seq()/_add_confed_seq()
 *
 * This is a random segment with a single ASN, repeated a random number of
 * times (possibly a very large number of times).
 *
 * Uses same pool of ASN as make_test_path().
 */
static void
make_seq_test(as_test_path astp, add_seq_test test, test_asn_t which)
{
  const char* ret ;

  test->seg = random_seg() ;

  test_path_len = 0 ;

  make_test_path_segment(test->seg, 1, false /* not small_rep */, which) ;

  assert(test_path_len == 1) ;

  test->count = test_path[0].count ;
  test->asn   = test_path[0].asn ;

  /* Make a new as_test_path set the path according to the generated
   * test_path.
   */
  ret = astp_fill(astp, test_path, test_path_len) ;
  assert(ret == NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Change one ASN in the given as_test_path 'path', so that it is not a
 * private ASN.
 *
 * If hits a repeated ASN, changes the entire repeat.
 */
static void
make_not_private_test(as_test_path astp)
{
  as_test_seg  asts ;
  uint i, n ;
  as_t asn, was ;

  asts = ddl_head(astp->path) ;
  n = 0 ;
  while (asts != NULL)
    {
      n += asts->len ;
      asts = ddl_next(asts, list) ;
    } ;

  if (n == 0)
    return ;

  i = rand() % n ;

  asts = ddl_head(astp->path) ;
  while (i >= asts->len)
    {
      i -= asts->len ;
      asts = ddl_next(asts, list) ;
    } ;

  switch (rand() % 8)
    {
      case 0:
        asn = 64511 ;                   /* edge case    */
        break ;

      case 1:
        asn = 65535 ;                   /* edge case    */
        break ;

      case 2:
      case 3:
        asn = (rand() % 64511) + 1 ;
        break ;

      case 4:
        asn = 65536 + (rand() % 65536) ;
        break ;

      case 5:
        asn = 0xFFFFDFFF ;              /* edge case    */
        break ;

      case 6:
        asn = 0xFFFFE000 ;              /* edge case    */
        break ;

      case 7:
        asn = 0xFFFFE000 + (rand() % 0x1FFF);
        break ;

      default:
        assert(false) ;
    } ;

  was = asts->body[i] ;

  while ((i > 0) && (asts->body[i - 1] == was))
    --i ;

  do
    asts->body[i++] = asn ;
  while ((i < asts->len) && (asts->body[i] == was)) ;
} ;

/*------------------------------------------------------------------------------
 * Prepend a segment of the given type with the given length
 *
 * If the first segment is of the given type already, replace it.
 *
 * It's the length that matters... so fill with simple random-ish ASN...
 * may also test for handling arbitrary long segments.
 */
static void
test_path_prepend(as_test_path astp, as_seg_t seg, uint count)
{
  as_test_seg  asts ;
  uint i, r ;
  as_t asn ;

  asts = ddl_head(astp->path) ;

  if ((asts != NULL) && (asts->seg == seg))
    asts_free(ddl_pop(&asts, astp->path, list)) ;

  asts = asts_new_prepend(&astp->path, seg, NULL, count) ;

  r = 0 ;
  for (i = 0 ; i < count ; ++i)
    {
      if (r == 0)
        {
          asn = (rand() % 45000) + 1 ;
          r   = rand() % 17 ;
          if (r <= 10)
            r = 1 ;
          else
            r = r - 10 ;
        } ;

      asts->body[i] = asn ;
      --r ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Make parse test string from the 'path' in the given as_test_path.
 *
 * NB: does not change the as_test_path 'path', so that can generate both
 *     as4 and as2 encodings of the same path.
 *
 * NB: allocates 6 extra bytes for fudge tests.
 */
static void
make_parse_test(as_test_path astp, bool as4)
{
  as_test_seg asts ;
  uint size, len, asn_size ;
  byte* enc, * p ;

  if (astp->parse != NULL)
    free(astp->parse) ;

  asn_size = as4 ? 4 : 2 ;

  /* Scan to establish the outside size, assuming every ASN is encoded as a
   * separate segment (!)
   */
  asts = ddl_head(astp->path) ;
  size = 0 ;

  while (asts != NULL)
    {
      size += asts->len * (asn_size + 2) ;
      asts  = ddl_next(asts, list) ;
    } ;

  enc = malloc(size + 6) ;
  memset(enc, 0, size + 6) ;

  asts = ddl_head(astp->path) ;
  p = enc ;
  while (asts != NULL)
    {
      uint i ;
      bool set ;

      set = (asts->seg == BGP_AS_SET) ||
            (asts->seg == BGP_AS_CONFED_SET) ;

      i   = 0 ;
      while (i < asts->len)
        {
          uint s ;

          s = asts->len - i ;

          if (!set)
            {
              uint n ;

              n = (rand() % asts->len) + 1 ;
              if (n < s)
                s = n ;
            } ;

          if (s > 255)
            {
              assert(!set) ;
              s = 255 ;
            } ;

          *p++ = asts->seg ;
          *p++ = s ;

          while (s--)
            {
              as_t asn ;

              asn = asts->body[i++] ;

              if (as4)
                {
                  store_nl(p, asn) ;
                  p += 4 ;
                }
              else
                {
                  if (asn > 65535)
                    asn = 23456 ;

                  store_ns(p, asn) ;
                  p += 2 ;
                } ;
            } ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  len = p - enc ;
  assert(len <= size) ;

  astp->parse     = enc ;
  astp->parse_len = len ;
} ;

/*------------------------------------------------------------------------------
 * Show what was presented for testing
 */
static void
show_test_path(void)
{
  uint o ;

  if (test_path_len == 0)
    fprintf(stderr, "\n  t%3d: length = 0", 0) ;

  o = 0 ;
  while (o < test_path_len)
    {
      uint n, i ;

      n = o + 8 ;
      if (n > test_path_len)
        n = test_path_len ;

      fprintf(stderr, "\n  t%3d:", o) ;
      for (i = o ; i < n ; ++i)
        fprintf(stderr, " %x/0x%08x*%2d", test_path[i].qseg,
                                          test_path[i].asn,
                                          test_path[i].count) ;
      o = n ;
    } ;
} ;

/*==============================================================================
 * as_test_path and as_test_seg functions.
 *
 */
static as_test_seg asts_new(as_seg_t seg_type) ;
static void astp_append_path(as_test_path astp_a, as_test_path astp_b) ;
static void asts_append_x_n(as_test_seg asts, as_t asn, uint count) ;
static void asts_append(as_test_seg asts, as_t asn[], uint count) ;
static void asts_prepend(as_test_seg asts, as_t asn[], uint count) ;
static uint asts_length(as_test_seg asts) ;
static void asts_sort_dedup(as_test_seg asts) ;
static as_test_seg asts_copy(as_test_seg asts, bool as4) ;
static void asts_trans(as_test_seg asts) ;
static as_test_seg asts_copy_sort_dedup(as_test_seg asts, bool as4) ;
static void asts_purge(as_test_seg asts, as_test_seg sub) ;

/*------------------------------------------------------------------------------
 * Create a new, empty as_test_path
 */
static as_test_path
astp_new(void)
{
  as_test_path new ;

  new = malloc(sizeof(as_test_path_t)) ;

  memset(new, 0, sizeof(as_test_path_t)) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Reset given as_test_path
 */
static void
astp_reset(as_test_path astp)
{
  as_test_seg asts ;

  while ((asts = ddl_pop(&asts, astp->path, list)) != NULL)
    asts_free(asts) ;

  if (astp->parse != NULL)
    free(astp->parse) ;

  if (astp->comp != NULL)
    free(astp->comp) ;

  if (astp->enc != NULL)
    free(astp->enc) ;

  if (astp->extract != NULL)
    free(astp->extract) ;

  memset(astp, 0, sizeof(as_test_path_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Free given as_test_path
 */
static as_test_path
astp_free(as_test_path astp)
{
  astp_reset(astp) ;

  free(astp) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Take the body of of the given as_path and:
 *
 *  * reset the given as_test_path
 *
 *  * construct 'path' from the as_path -- checking for validity, and
 *    discarding redundant segments and asp_drop stuff -- sort and dedup any
 *    sets.
 *
 *    NB: retains the ASN as present in the given as_path.
 *
 *  * construct compressed as_path in astp->comp with length astp->comp_len
 *
 *  * fill in the astp->p properties
 *
 * Returns:  NULL <=> OK
 *           otherwise, message indicating issue with the body of the as_path
 */
static const char*
post_process(as_test_path astp, as_path asp)
{
  const char* ret ;

  /* Reset the given astp, and fill 'path' from the given as_path's path.
   */
  ret = astp_fill(astp, asp->path.body.v, asp->path.len) ;
  if (ret != NULL)
    return ret ;

  /* Sort and dedup any sets
   */
  astp_sort_dedup(astp) ;

  /* Rebuild the as_path form in the astp->comp
   */
  astp_compress(astp, false /* no need to sort/dedup */, true /* as4 */) ;

  /* Fill in the properties
   */
  astp_properties(astp, true /* as4 */) ;

  /* OK
   */
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Fill the given as_test_path from the given as_path body.
 *
 * Resets the contents of the given astp, and constructs 'path', verbatim from
 * the given as_path body -- but stripping out redundant segments and
 * any asp_drop items.  Preserves the ASN.
 *
 * Happily handles a length of zero: resets the astp to empty, with NULL path
 *
 * Returns:  NULL <=> OK
 *           otherwise, message indicating issue with the body of the as_path
 */
static const char*
astp_fill(as_test_path astp, asp_item_t* path, uint len)
{
  as_test_seg  asts ;
  uint      p ;
  qas_seg_t qseg ;

  astp_reset(astp) ;            /* discard any existing path etc.       */

  /* Scan the as_path body and construct a new path in the astp.
   *
   * Discard: asp_drop stuff
   */
  asts = NULL ;
  qseg = qAS_SEG_NULL ;
  for (p = 0 ; p < len ; ++p)
    {
      if ((path[p].count == 0) || (path[p].asn == BGP_ASN_NULL))
        {
          if ((qseg & qAS_SET) && (qseg != path[p].qseg))
            qseg = qAS_SEG_NULL ;

          continue ;
        } ;

      if ((asts == NULL) || (path[p].qseg != qseg))
        {
          as_seg_t  seg ;

          switch (path[p].qseg)
            {
              case qAS_SEQUENCE:
                seg = BGP_AS_SEQUENCE ;
                break ;

              case qAS_SET:
              case qAS_SET | qAS_SET_START:
                seg = BGP_AS_SET ;
                break ;

              case qAS_CONFED_SEQUENCE:
                seg = BGP_AS_CONFED_SEQUENCE ;
                break ;

              case qAS_CONFED_SET:
              case qAS_CONFED_SET | qAS_SET_START:
                seg = BGP_AS_CONFED_SET ;
                break ;

              default:
                return "invalid qseg value" ;
            } ;

          asts = asts_new(seg) ;
          ddl_append(astp->path, asts, list) ;

          qseg = path[p].qseg & ~qAS_SET_START ;
        } ;

      asts_append_x_n(asts, path[p].asn, path[p].count) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Transform all ASN in the given as_test_path to BGP_ASN_TRANS.
 *
 * Does NOT sort/dedup any sets.
 */
static void
astp_trans(as_test_path astp)
{
  as_test_seg asts ;

  /* Sort and dedup and sets
   */
  asts = ddl_head(astp->path) ;
  while (asts != NULL)
    {
      asts_trans(asts) ;

      asts = ddl_next(asts, list) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Sort and dedup any sets in the given as_test_path.
 *
 * Does nothing with an empty path, or with empty sets.
 *
 * Preserves the ASN.
 */
static void
astp_sort_dedup(as_test_path astp)
{
  as_test_seg asts ;

  /* Sort and dedup and sets
   */
  asts = ddl_head(astp->path) ;
  while (asts != NULL)
    {
      if ((asts->seg == BGP_AS_SET) || (asts->seg == BGP_AS_CONFED_SET))
        asts_sort_dedup(asts) ;

      asts = ddl_next(asts, list) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Compress given as_test_path -- constructing the astp->comp
 *
 * Works from the 'path', which is not changed.
 *
 * If 'sort_dedup' will sort and dedup a copy of each set before compressing it.
 *
 * If !'as4', will convert all ASN > 65535 to 23456.
 *
 * Will happily generate an empty astp->comp.
 */
static void
astp_compress(as_test_path astp, bool sort_dedup, bool as4)
{
  as_test_seg asts ;
  uint len, p ;
  uint comp_size ;

  /* Scan to establish the (maximum) compressed length -- in asp_item_t.
   *
   * Actual length may be smaller if any set is subject to 'sort_dedup'.
   */
  asts = ddl_head(astp->path) ;
  len = 0 ;

  while (asts != NULL)
    {
      if (asts->len != 0)
        {
          uint i ;

          i = 0 ;
          while (i < asts->len)
            {
              as_t asn ;

              asn = asts->body[i++] ;
              len += 1 ;

              while ((i < asts->len) && (asn == asts->body[i]))
                 ++i ;
            } ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  /* Make new compressed form.
   */
  if (astp->comp != NULL)
    free(astp->comp) ;

  comp_size = ((len + 15) / 8) * 8 * sizeof(asp_item_t) ;

  astp->comp = malloc(comp_size) ;
  memset(astp->comp, 0, comp_size) ;

  asts = ddl_head(astp->path) ;
  p = 0 ;

  while (asts != NULL)
    {
      if (asts->len != 0)
        {
          as_test_seg this ;
          uint i ;
          bool set ;
          qas_seg_t qseg ;

          if (sort_dedup)
            set = (asts->seg == BGP_AS_SET) ||
                                        (asts->seg == BGP_AS_CONFED_SET) ;
          else
            set = false ;

          if (set)
            this = asts_copy_sort_dedup(asts, as4) ;
          else
            this = asts ;

          switch (asts->seg)
            {
              case BGP_AS_SEQUENCE:
                qseg = qAS_SEQUENCE ;
                break ;

              case BGP_AS_SET:
                qseg = qAS_SET | qAS_SET_START ;
                break ;

              case BGP_AS_CONFED_SEQUENCE:
                qseg = qAS_CONFED_SEQUENCE ;
                break ;

              case BGP_AS_CONFED_SET:
                qseg = qAS_CONFED_SET | qAS_SET_START ;
                break ;

              default:
                assert(false) ;
            } ;

          i = 0 ;
          while (i < this->len)
            {
              as_t asn ;
              uint count ;

              count = 1 ;

              asn = this->body[i++] ;

              if ((asn > 65535) && !as4)
                asn = BGP_ASN_TRANS ;

              while (i < this->len)
                {
                  as_t asx ;

                  asx = this->body[i] ;

                  if ((asx > 65535) && !as4)
                    asx = BGP_ASN_TRANS ;

                  if (asn != asx)
                    break ;

                  ++i ;
                  ++count ;
                } ;

              if (count > as_max_count)
                count = as_max_count ;

              astp->comp[p].asn   = asn ;
              astp->comp[p].count = count ;
              astp->comp[p].qseg  = qseg ;

              ++p ;
              qseg &= ~qAS_SET_START ;
            } ;

          if (set)
            asts_free(this) ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  if (!sort_dedup)
    assert(p == len) ;
  else
    assert(p <= len) ;

  astp->comp_len = p ;
} ;

/*------------------------------------------------------------------------------
 * Fill in the given as_test_path properties
 *
 * The 'as4' affects the left_most_asn and the first_asn.
 *
 * NB: does *not* sort/dedup the sets -- so the counts refelect the state of
 *     any sets exactly as they are.
 *
 * The astp needs to have been compressed, with sort_dedup and the same 'as4'
 * setting if the first and last values are to be correct.
 */
static void
astp_properties(as_test_path astp, bool as4)
{
  as_test_seg asts ;
  uint len, p ;
  bool seen_simple, seen_confed ;
  asp_item_t* comp ;
  uint *p_last ;

  memset(&astp->p, 0, sizeof(as_path_properties_t)) ;

  /* We need to fill in the following:
   *
   *   astp->p.simple_sequence  = true iff the as_path is a single
   *                              BGP_AS_SEQUENCE, or is empty.
   *
   *   astp->p.total_length     = asp->p.simple.length + asp->p.confed.length
   *
   *   astp->p.left_most_asn    = if have confed: asp->p.confed.left_most_asn
   *                                           else: asp->p.simple.left_most_asn
   *
   *   astp->p.simple:
   *
   *         .length       = number of ASN (including repeats) in any
   *                         BGP_AS_SEQUENCE segments plus the the number
   *                         of BGP_AS_SET segments.
   *
   *                         ie: the AS_PATH length for selection purposes,
   *                             not counting any Confed stuff.
   *
   *         .seq_count    = number of BGP_AS_SEQUENCE segments
   *
   *         .set_count    = number of BGP_AS_SET segments
   *
   *         .first_seg    = seg of first simple segment, if any
   *                         BGP_AS_SEG_NULL <=> none
   *
   *         .first        = offset in the path of the first simple segment.
   *
   *                         Points at the segment marker, except where the
   *                         offset is zero and the first segment is
   *                         BGP_AS_SEQUENCE, when the segment marker is
   *                         implied.
   *
   *         .last         = offset in the path of the end + 1 of the last
   *                         simple segment.
   *
   *                         0 <=> there are no simple segments
   *
   *         .first_asn    = if the first simple segment is BGP_AS_SEQUENCE,
   *                         then this is the first ASN in that segment.
   *
   *                         Is BGP_ASN_NULL otherwise.
   *
   *   astp->p.confed:
   *
   *         .length       = number of ASN (including repeats) in any
   *                         BGP_AS_CONFED_SEQUENCE segments plus the the number
   *                         of BGP_AS_CONFED_SET segments.
   *
   *                         ie: the extra AS_PATH length for selection purposes,
   *                             if Confed stuff is counted.
   *
   *         .seq_count    = number of BGP_AS_CONFED_SEQUENCE segments
   *
   *         .set_count    = number of BGP_AS_CONFED_SET segments
   *
   *         .first_seg    = seg of first confed segment, if any
   *                         BGP_AS_SEG_NULL <=> none
   *
   *         .first        = offset in the path of the first confed segment.
   *
   *         .last         = offset in the path of the end + 1 of the last
   *                         confed segment.
   *
   *                         0 <=> there are no confed segments
   *
   *         .first_asn    = if the first segment is BGP_AS_CONFED_SEQUENCE,
   *                         then this is the first ASN in that segment.
   *
   *                         Is BGP_ASN_NULL otherwise.
   *
   *                         NB: confed stuff should only appear at the front
   *                             of an AS_PATH -- so confed.first_asn is set
   *                               *only* if the absolutely first segment is a
   *                             BGP_AS_CONFED_SEQUENCE.  This is unlike
   *                             simple.first_asn, which is set if the first
   *                             simple segment is a BGP_AS_SEQUENCE.
   *
   * We can fill this in from the astp->path, apart from the first and last
   * offsets, for which we need to scan the compressed form itself.
   */
  seen_simple = false ;
  seen_confed = false ;

  asts = ddl_head(astp->path) ;

  while (asts != NULL)
    {
      if (asts->len != 0)
        {
          switch (asts->seg)
            {
              case BGP_AS_SEQUENCE:
                astp->p.simple.length += asts_length(asts) ;

                if (!seen_simple)
                  {
                    astp->p.simple.first_seg  = BGP_AS_SEQUENCE ;
                    astp->p.simple.first_asn  = asts->body[0] ;

                    seen_simple = true ;

                    if (!seen_confed)
                      astp->p.left_most_asn = asts->body[0] ;
                  } ;

                astp->p.simple.seq_count += 1 ;
                break ;

              case BGP_AS_SET:
                astp->p.simple.length += asts_length(asts) ;

                if (!seen_simple)
                  {
                    astp->p.simple.first_seg  = BGP_AS_SET ;
                    astp->p.simple.first_asn  = BGP_ASN_NULL ;

                    seen_simple = true ;
                  } ;

                astp->p.simple.set_count += 1 ;
                break ;

              case BGP_AS_CONFED_SEQUENCE:
                astp->p.confed.length += asts_length(asts) ;

                if (!seen_confed)
                  {
                    astp->p.confed.first_seg  = BGP_AS_CONFED_SEQUENCE ;
                    if (!seen_simple)
                      astp->p.confed.first_asn  = asts->body[0] ;

                    seen_confed = true ;

                    if (!seen_simple)
                      astp->p.left_most_asn = asts->body[0] ;
                  } ;

                astp->p.confed.seq_count += 1 ;
                break ;

              case BGP_AS_CONFED_SET:
                astp->p.confed.length += asts_length(asts) ;

                if (!seen_confed)
                  {
                    astp->p.confed.first_seg  = BGP_AS_CONFED_SET ;
                    astp->p.confed.first_asn  = BGP_ASN_NULL ;

                    seen_confed = true ;
                  } ;

                astp->p.confed.set_count += 1 ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  if (!as4)
    {
      if (astp->p.left_most_asn > 65535)
        astp->p.left_most_asn = BGP_ASN_TRANS ;
      if (astp->p.simple.first_asn > 65535)
        astp->p.simple.first_asn = BGP_ASN_TRANS ;
      if (astp->p.confed.first_asn > 65535)
        astp->p.confed.first_asn = BGP_ASN_TRANS ;
    } ;

  /* Scan the compressed form to pick up the first/last offsets.
   */
  comp = astp->comp ;
  len  = astp->comp_len ;

  seen_simple = false ;
  seen_confed = false ;

  p_last = &astp->p.simple.last ;
  for (p = 0 ; p < len ; ++p)
    {
      switch (comp[p].qseg)
        {
          case qAS_SEQUENCE:
          case qAS_SET:
          case qAS_SET | qAS_SET_START:
            if (!seen_simple)
              {
                astp->p.simple.first = p ;
                seen_simple = true ;
              } ;

            *p_last = p ;
            p_last = &astp->p.simple.last ;
            break ;

          case qAS_CONFED_SEQUENCE:
          case qAS_CONFED_SET:
          case qAS_CONFED_SET | qAS_SET_START:
            if (!seen_confed)
              {
                astp->p.confed.first = p ;
                seen_confed = true ;
              } ;

            *p_last = p ;
            p_last = &astp->p.confed.last ;
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  *p_last = p ;

  /* Finish off by setting the p.simple_sequence and p.total_length
   */
  astp->p.simple_sequence = ( astp->p.simple.set_count +
                              astp->p.confed.seq_count +
                              astp->p.confed.set_count ) == 0 ;
  astp->p.total_length    = astp->p.simple.length + astp->p.confed.length ;
} ;

/*------------------------------------------------------------------------------
 * Is the given as_test_path 'confed_ok'
 *
 * To be 'confed_ok' must be:
 *
 *   * empty
 *
 *   * no confed segments at all
 *
 *   * confed segments only
 *
 *   * confed segments followed by (only) simple segments
 *
 * So is not 'confed_ok' if finds a (not-empty) confed segment after any
 * (not-empty) simple segment.
 */
static bool
astp_confed_ok(as_test_path astp)
{
  as_test_seg asts ;
  bool seen_simple ;

  asts = ddl_head(astp->path) ;
  seen_simple = false ;

  while (asts != NULL)
    {
      if (asts->len != 0)
        {
          switch (asts->seg)
            {
              case BGP_AS_SEQUENCE:
              case BGP_AS_SET:
                seen_simple = true ;
                break ;

              case BGP_AS_CONFED_SEQUENCE:
              case BGP_AS_CONFED_SET:
                if (seen_simple)
                  return false ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Delete confed segments from the given as_test_path and return count of
 * number deleted.
 */
static uint
astp_confed_delete(as_test_path astp)
{
  as_test_seg next ;
  uint count ;

  next = ddl_head(astp->path) ;
  count = 0 ;

  while (next != NULL)
    {
      as_test_seg asts ;

      asts = next ;
      next = ddl_next(asts, list) ;

      switch (asts->seg)
        {
          case BGP_AS_SEQUENCE:
          case BGP_AS_SET:
            break ;

          case BGP_AS_CONFED_SEQUENCE:
          case BGP_AS_CONFED_SET:
            if (asts->len != 0)
              ++count ;

            ddl_del(astp->path, asts, list) ;
            asts_free(asts) ;

            break ;

          default:
            assert(false) ;
        } ;

    } ;

  return count ;
} ;

/*------------------------------------------------------------------------------
 * Sweep confed segments to the front of the given as_test_path, and return
 * count of the number of segments moved.
 */
static uint
astp_confed_sweep(as_test_path astp)
{
  as_test_seg next, simple ;
  uint count ;

  next = ddl_head(astp->path) ;
  simple = NULL ;
  count = 0 ;

  while (next != NULL)
    {
      as_test_seg asts ;

      asts = next ;
      next = ddl_next(asts, list) ;

      if (asts->len == 0)
        continue ;

      switch (asts->seg)
        {
          case BGP_AS_SEQUENCE:
          case BGP_AS_SET:
            if (simple == NULL)
              simple = asts ;
            break ;

          case BGP_AS_CONFED_SEQUENCE:
          case BGP_AS_CONFED_SET:
            if (simple != NULL)
              {
                ddl_del(astp->path, asts, list) ;
                ddl_in_before(simple, astp->path, asts, list) ;
                ++count ;
              } ;
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  return count ;
} ;

/*------------------------------------------------------------------------------
 * Reconcile given astp_2 with given astp_4, updating the 'path' in astp_2.
 */
static void
astp_reconcile_as4(as_test_path astp_2, as_test_path astp_4)
{
  as_test_seg next ;
  uint as2_len ;
  uint as4_len ;
  bool as4_confed ;

  /* Make sure tidy and any Confed stuff in asp2 is at the front.
   */
  astp_sort_dedup(astp_2) ;
  astp_sort_dedup(astp_4) ;

  astp_confed_sweep(astp_2) ;

  /* Count the non-confed length of astp_2
   */
  next = ddl_head(astp_2->path) ;
  as2_len = 0 ;
  while (next != NULL)
    {
      as_test_seg asts ;

      asts = next ;
      next = ddl_next(asts, list) ;

      switch (asts->seg)
        {
          case BGP_AS_SEQUENCE:
            as2_len += asts->len ;
            break ;

          case BGP_AS_SET:
            if (asts->len != 0)
              as2_len += 1 ;
            break ;

          case BGP_AS_CONFED_SEQUENCE:
          case BGP_AS_CONFED_SET:
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  /* Count the length of astp_4 -- looking out for any confed stuff.
   */
  next = ddl_head(astp_4->path) ;
  as4_len    = 0 ;
  as4_confed = false ;
  while ((next != NULL) && !as4_confed)
    {
      as_test_seg asts ;

      asts = next ;
      next = ddl_next(asts, list) ;

      switch (asts->seg)
        {
          case BGP_AS_SEQUENCE:
            as4_len += asts->len ;
            break ;

          case BGP_AS_SET:
            if (asts->len != 0)
              as4_len += 1 ;
            break ;

          case BGP_AS_CONFED_SEQUENCE:
          case BGP_AS_CONFED_SET:
            as4_confed = true ;
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  /* If as4_len <= as2_len, replace last as as4_len items in the astp_2 path by
   * the astp_4 path.
   *
   * Otherwise, stick a simple set on the back of the astp_2 path, and then
   * purge it (the set) of any ASN in the original astp_2 path.
   */
  if ((as4_len <= as2_len) && !as4_confed)
    {
      uint keep ;

      keep = as2_len - as4_len ;

      next = ddl_head(astp_2->path) ;
      while (next != NULL)
        {
          as_test_seg asts ;
          bool drop ;

          asts = next ;
          next = ddl_next(asts, list) ;

          drop = (keep == 0) ;
          switch (asts->seg)
            {
              case BGP_AS_SEQUENCE:
                if (!drop)
                  {
                    if (keep < asts->len)
                      asts->len = keep ;

                    keep -= asts->len ;
                  } ;
                break ;

              case BGP_AS_SET:
                if (!drop)
                  keep -= 1 ;
                else
                  drop = true ;

                break ;

              case BGP_AS_CONFED_SEQUENCE:
              case BGP_AS_CONFED_SET:
                drop = false ;
                break ;

              default:
                assert(false) ;
            } ;

          if (drop)
            {
              ddl_del(astp_2->path, asts, list) ;
              asts_free(asts) ;
            } ;
        } ;

      astp_append_path(astp_2, astp_4) ;
    }
  else
    {
      astp_extract(astp_2) ;
      astp_extract(astp_4) ;

      asts_purge(astp_4->extract, astp_2->extract) ;

      if (astp_4->extract->len != 0)
        {
          as_test_seg asts ;

          asts = asts_copy(astp_4->extract, true /* as4 */) ;
          ddl_append(astp_2->path, asts, list) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Append given astp_b 'path' to the given astp_a 'path'.
 */
static void
astp_append_path(as_test_path astp_a, as_test_path astp_b)
{
  as_test_seg asts_a, asts_b ;

  asts_a = ddl_tail(astp_a->path) ;
  asts_b = (astp_b != NULL) ? ddl_head(astp_b->path) : NULL ;

  while (1)
    {
      if (asts_b == NULL)
        return ;

      if (asts_b->len != 0)
        break ;

      asts_b = ddl_next(asts_b, list) ;
    } ;

  if ((asts_a != NULL) && ( (asts_a->seg == BGP_AS_SEQUENCE) ||
                            (asts_a->seg == BGP_AS_CONFED_SEQUENCE) ))
    {
      if (asts_a->seg == asts_b->seg)
        {
          asts_append(asts_a, asts_b->body, asts_b->len) ;

          asts_b = ddl_next(asts_b, list) ;
        } ;
    } ;

  while (asts_b != NULL)
    {
      if (asts_b->len != 0)
        {
          asts_a = asts_copy(asts_b, true /* as4 */) ;
          ddl_append(astp_a->path, asts_a, list) ;
        } ;

      asts_b = ddl_next(asts_b, list) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Walk the 'path' for the given as_test_path and generate the 'extract',
 * containing all ASN used in the 'path', in ASN order.
 *
 * Extracts ASN as they are.
 */
static void
astp_extract(as_test_path astp)
{
  as_test_seg asts, extract ;

  if (astp->extract != NULL)
    free(astp->extract) ;

  extract = asts_new(BGP_AS_SET) ;

  asts = ddl_head(astp->path) ;
  while (asts != NULL)
    {
      if (asts->len != 0)
        asts_append(extract, asts->body, asts->len) ;

      asts = ddl_next(asts, list) ;
    } ;

  asts_sort_dedup(extract) ;

  astp->extract = extract ;
} ;

/*------------------------------------------------------------------------------
 * Return an ASN at random which is present in the given as_test_path
 *
 * Uses the current 'extract', but creates one if none is present.
 *
 * Works with ASN as they are.
 */
static as_t
astp_present(as_test_path astp)
{
  as_t present ;

  if (astp->extract == NULL)
    astp_extract(astp) ;

  if (astp->extract->len != 0)
    present = astp->extract->body[rand() % astp->extract->len] ;
  else
    present = BGP_ASN_NULL ;

  return present ;
} ;

/*------------------------------------------------------------------------------
 * Count number of times the given ASN is present in the given as_test_path.
 *
 * Works with ASN as they are.
 */
static uint
astp_present_count(as_test_path astp, as_t asn)
{
  as_test_seg asts ;
  uint count ;

  count = 0 ;

  asts = ddl_head(astp->path) ;
  while (asts != NULL)
    {
      uint i ;

      for (i = 0 ; i < asts->len ; ++i)
        {
          if (asts->body[i] == asn)
            ++count ;
        } ;

      asts = ddl_next(asts, list) ;
    } ;

  return count ;
} ;

/*------------------------------------------------------------------------------
 * Return an ASN at random which is not present in the given as_test_path
 *
 * Uses the current 'extract', but creates one if none is present.
 *
 * Works with ASN as they are.
 */
static as_t
astp_not_present(as_test_path astp)
{
  as_t not_present ;

  if (astp->extract == NULL)
    astp_extract(astp) ;

  while (1)
    {
      uint i, n ;

      do
        not_present = rand() ;
      while (not_present == 0) ;

      n = astp->extract->len ;
      i = 0 ;
      while (1)
        {
          as_t present ;

          if (i == n)
            return not_present ;

          present = astp->extract->body[i++] ;

          if (present > not_present)
            return not_present ;

          if (present == not_present)
            break ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return highest ASN -- BGP_ASN_NULL if none
 *
 * Uses the current 'extract', but creates one if none is present.
 *
 * Works with ASN as they are.
 */
static as_t
astp_highest_asn(as_test_path astp)
{
  uint n ;

  if (astp->extract == NULL)
    astp_extract(astp) ;

  n = astp->extract->len ;

  if (n == 0)
    return BGP_ASN_NULL ;

  return astp->extract->body[n-1] ;
} ;

/*------------------------------------------------------------------------------
 * Encode the given as_test_path as as4 or as as2
 *
 * The as_test_path may have been parsed as an as4 or as2 path -- so the ASN
 * may have been squeezed to as2, even if the required encoding is as4.
 *
 * Uses the given 'out':
 *
 *   * if out->seg is BGP_AS_SEQUENCE, drops leading Confed stuff (if any)
 *
 *   * if out->seg is BGP_AS_SEQUENCE or BGP_AS_CONFED_SEQUENCE, will prepend
 *     0, 1 or 2 ASN as per out->prepend_count and out->prepend_asn[].
 *
 * This creates the same encoded form as as_path_encode().
 *
 * Sets astp->enc and enc_len -- generates the body of the attribute *only*
 * (does not generate the attribute red-tape).
 *
 * Returns:  true <=> one or more ASN were > 65535 AND !as4 requested
 */
static bool
astp_encode(as_test_path astp, bool as4, bool as4_parse, as_path_out out)
{
  as_test_seg asts ;
  uint enc_size, enc_len ;
  byte* enc ;
  bool as4_flag, seen_simple, prepend ;
  path_list_t enc_path ;

  /* Scan the path and build copy:
   *
   *   * discarding any empty segments
   *
   *   * discarding leading Confed segments if out->seg = BGP_AS_SEQUENCE
   *
   *   * replacing ASN > 65535 if as4_parse.
   *
   *   * sorting and deduping sets
   *
   *   * prepending as required.
   */
  seen_simple = false ;
  prepend  = (out->prepend_count > 0) &&
                                     ( (out->seg == BGP_AS_SEQUENCE) ||
                                       (out->seg == BGP_AS_CONFED_SEQUENCE) ) ;
  ddl_init(enc_path) ;
  asts = ddl_head(astp->path) ;
  while (asts != NULL)
    {
      bool take ;

      take = (asts->len != 0) ;

      if ( (asts->seg == BGP_AS_CONFED_SEQUENCE) ||
           (asts->seg == BGP_AS_CONFED_SET) )
        {
          if ((out->seg == BGP_AS_SEQUENCE) && !seen_simple)
            take = false ;
        } ;

      if (take)
        {
          as_test_seg this ;

          seen_simple = seen_simple || (asts->seg == BGP_AS_SEQUENCE)
                                    || (asts->seg == BGP_AS_SET) ;

          this = asts_copy(asts, as4_parse) ;

          if ( (this->seg == BGP_AS_SET) ||
               (this->seg == BGP_AS_CONFED_SET) )
            asts_sort_dedup(this) ;

          if (prepend)
            {
              if (this->seg == out->seg)
                asts_prepend(this, out->prepend_asn, out->prepend_count) ;
              else
                asts_new_prepend(&enc_path, out->seg, out->prepend_asn,
                                                      out->prepend_count) ;

              prepend = false ;
            } ;

          ddl_append(enc_path, this, list) ;
        } ;
      asts = ddl_next(asts, list) ;
    } ;

  if (prepend)
    asts_new_prepend(&enc_path, out->seg, out->prepend_asn,
                                          out->prepend_count) ;

  /* Scan to calculate size of the encoded attribute
   */
  enc_size = 0 ;
  asts = ddl_head(enc_path) ;
  while (asts != NULL)
    {
      enc_size += (((asts->len + 254) / 255) * 2) ;
      enc_size += asts->len * (as4 ? 4 : 2) ;

      asts = ddl_next(asts, list) ;
    } ;

  /* Encode the path now we have adjusted it as required.
   */
  if (astp->enc != NULL)
    free(astp->enc) ;

  as4_flag = false ;
  seen_simple = false ;

  enc_len = 0 ;
  if (enc_size == 0)
    enc = NULL ;
  else
    {
      byte* p ;

      enc = malloc(enc_size) ;
      memset(enc, 0, enc_size) ;

      p = enc ;
      while ((asts = ddl_pop(&asts, enc_path, list)) != NULL)
        {
          uint i, n ;

          seen_simple = seen_simple || (asts->seg == BGP_AS_SEQUENCE)
                                    || (asts->seg == BGP_AS_SET) ;

          i = 0 ;
          n = asts->len ;
          while (n > 0)
            {
              uint s ;

              s = n % 255 ;
              if (s == 0)
                s = 255 ;

              n -= s ;

              *p++ = asts->seg ;
              *p++ = s ;

              while (s > 0)
                {
                  as_t asn ;

                  asn = asts->body[i++] ;

                  if (as4)
                    {
                      store_nl(p, asn) ;
                      p += 4 ;
                    }
                  else
                    {
                      if (asn > 65535)
                        {
                          asn = BGP_ASN_TRANS ;
                          as4_flag = seen_simple ;
                        } ;

                      store_ns(p, asn) ;
                      p += 2 ;
                    } ;

                  s -= 1 ;
                } ;
            } ;

          asts_free(asts) ;
        } ;

      enc_len = p - enc ;
    } ;

  assert(enc_len == enc_size) ;

  astp->enc     = enc ;
  astp->enc_len = enc_len ;

  return as4_flag ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, empty as_test_seg of the given seg type
 */
static as_test_seg
asts_new(as_seg_t seg)
{
  as_test_seg  new ;

  new = malloc(sizeof(as_test_seg_t)) ;

  memset(new, 0, sizeof(as_test_seg_t)) ;

  new->seg = seg ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Create new segment and prepend it to the given path.
 */
static as_test_seg
asts_new_prepend(path_list path, as_seg_t seg, as_t asn[], uint count)
{
  as_test_seg asts ;

  asts = asts_new(seg) ;

  ddl_prepend(*path, asts, list) ;

  asts_prepend(asts, asn, count) ;

  return asts ;
} ;

/*------------------------------------------------------------------------------
 * Make room for 'count' new ASN in the given asts.
 *
 * Does not change asts->len -- just asts->size.
 */
static void
asts_make_room(as_test_seg asts, uint count)
{
  if (count > (asts->size - asts->len))
    {
      uint new_size ;

      new_size = ((asts->size + count + 16) / 8) * 8 ;

      if (asts->size == 0)
        asts->body = malloc(new_size * sizeof(as_t)) ;
      else
        asts->body = realloc(asts->body, new_size * sizeof(as_t)) ;

      memset(&(asts->body[asts->len]), 0, &(asts->body[new_size]) -
                                                   &(asts->body[asts->len]) ) ;
      asts->size = new_size ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Create a new as_test_seg which is a copy of the given as_test_seg.
 *
 * If !as4, squash all ASN > 65535 to ASN_TRANS.
 */
static as_test_seg
asts_copy(as_test_seg asts, bool as4)
{
  as_test_seg  new ;

  new = malloc(sizeof(as_test_seg_t)) ;
  memcpy(new, asts, sizeof(as_test_seg_t)) ;

  ddl_init_pair(new, list) ;

  if (asts->size == 0)
    asts->body = NULL ;
  else
    {
      new->body = malloc(asts->size * sizeof(as_t)) ;
      memcpy(new->body, asts->body, asts->size * sizeof(as_t)) ;

      if (!as4)
        asts_trans(new) ;
    } ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Squash all ASN > 65535 to ASN_TRANS in the given as_test_seg.
 */
static void
asts_trans(as_test_seg asts)
{
  uint i ;

  for (i = 0 ; i < asts->len ; ++i)
    if (asts->body[i] > 65535)
      asts->body[i] = BGP_ASN_TRANS ;
} ;

/*------------------------------------------------------------------------------
 * Free the given as_test_seg object
 */
static as_test_seg
asts_free(as_test_seg asts)
{
  if (asts != NULL)
    {
      if (asts->body != NULL)
        free(asts->body) ;

      free(asts) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Append given ASN 'count' times at the end of the given as_test_seg.
 *
 * Advances asts->len and extends the asts->size and asts->body as required.
 */
static void
asts_append_x_n(as_test_seg asts, as_t asn, uint count)
{
  uint i ;

  asts_make_room(asts, count) ;

  for (i = 0 ; i < count ; ++i)
    asts->body[asts->len + i] = asn ;

  asts->len += count ;
} ;

/*------------------------------------------------------------------------------
 * Append 'count' ASN to the end of the given as_test_seg.
 *
 * If the 'asn' pointer is NULL, simply append 'count' zeros.
 *
 * Advances asts->len and extends the asts->size and asts->body as required.
 */
static void
asts_append(as_test_seg asts, as_t asn[], uint count)
{
  if (count > 0)
    {
      asts_make_room(asts, count) ;

      if (asn == NULL)
        memset(&asts->body[asts->len],   0, count * sizeof(as_t)) ;
      else
        memcpy(&asts->body[asts->len], asn, count * sizeof(as_t)) ;

      asts->len += count ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Append 'count' ASN to the end of the given as_test_seg.
 *
 * If the 'asn' pointer is NULL, simply append 'count' zeros.
 *
 * Advances asts->len and extends the asts->size and asts->body as required.
 */
static void
asts_prepend(as_test_seg asts, as_t asn[], uint count)
{
  if (count > 0)
    {
      asts_make_room(asts, count) ;

      if (asts->len != 0)
        memmove(&asts->body[count], &asts->body[0], asts->len * sizeof(as_t)) ;

      asts->len += count ;

      if (asn == NULL)
        memset(&asts->body[0],   0, count * sizeof(as_t)) ;
      else
        memcpy(&asts->body[0], asn, count * sizeof(as_t)) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get effective length of the given as_test_seg.
 *
 * Effective length of a set segment is 1.
 *
 * Effective length of a sequence segment will be the number of ASN, except
 * where an ASN is repeated too often.
 */
static uint
asts_length(as_test_seg asts)
{
  uint i, length ;

  switch (asts->seg)
    {
      case BGP_AS_SEQUENCE:
      case BGP_AS_CONFED_SEQUENCE:
        break ;

      case BGP_AS_SET:
      case BGP_AS_CONFED_SET:
        if (asts->len > 0)
          return 1 ;
        else
          return 0 ;

      default:
        assert(false) ;
    } ;

  length = 0 ;
  i      = 0 ;
  while (i < asts->len)
    {
      uint count ;
      as_t asn ;

      count = i ;
      asn = asts->body[i++] ;

      while ((i < asts->len) && (asn == asts->body[i]))
        ++i ;

      count = i - count ;

      if (count > as_max_count)
        length += as_max_count;
      else
        length += count ;
    } ;

  return length ;
}

/*------------------------------------------------------------------------------
 * Sort and dedup the given as_test_seg.
 */
static void
asts_sort_dedup(as_test_seg asts)
{
  uint i, n ;
  as_t* v ;

  assert((asts->seg == BGP_AS_SET) || (asts->seg == BGP_AS_CONFED_SET)) ;

  v = asts->body ;
  n = asts->len ;

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
              as_t t ;

              t    = v[j] ;
              v[j] = v[i] ;
              v[i] = t ;
            } ;
        } ;
    } ;

  asts->len = n ;
} ;

/*------------------------------------------------------------------------------
 * Create a new as_test_seg which is a copy of the given as_test_seg, then sort
 * and dedup same.
 */
static as_test_seg
asts_copy_sort_dedup(as_test_seg asts, bool as4)
{
  as_test_seg  new ;

  new = asts_copy(asts, as4) ;
 asts_sort_dedup(new) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Purge from the given as_test_seg all instances of the given sub as_test_seg.
 */
static void
asts_purge(as_test_seg asts, as_test_seg sub)
{
  uint i, n ;
  as_t* b ;

  b = asts->body ;
  n = asts->len ;

  for (i = 0 ; (i < sub->len) && (n > 0) ; ++i)
    {
      as_t sub_asn ;
      uint p, q ;

      sub_asn = sub->body[i] ;

      q = 0 ;

      for (p = 0 ; p < n ; ++p)
        {
          as_t item ;

          item = b[p] ;

          if (item != sub_asn)
            b[q++] = item ;
        } ;

      n = q ;
    } ;

  asts->len = n ;
} ;

/*------------------------------------------------------------------------------
 * return a randomly selected segment -- of any type
 */
static as_seg_t random_seg(void)
{
  static const as_seg_t segs[] =
    {
      BGP_AS_SEQUENCE,
      BGP_AS_SET,
      BGP_AS_CONFED_SEQUENCE,
      BGP_AS_CONFED_SET,
    } ;

  return segs[rand() % 4] ;
} ;

