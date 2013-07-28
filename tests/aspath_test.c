#include <zebra.h>

#include "stdio.h"

#include "qlib_init.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_attr_store.h"

#define VT100_RESET "\x1b[0m"
#define VT100_RED "\x1b[31m"
#define VT100_GREEN "\x1b[32m"
#define VT100_YELLOW "\x1b[33m"
#define OK VT100_GREEN "OK" VT100_RESET
#define FAILED VT100_RED "failed" VT100_RESET

static int failed = 0;

/*------------------------------------------------------------------------------
 *
 */

/* specification for a test - what the results should be */
struct test_spec
{
  const char *shouldbe; /* the string the path should parse to */
  const char *shouldbe_delete_confed; /* ditto, but once confeds are deleted */
  const unsigned int hops; /* aspath_count_hops result */
  const unsigned int confeds; /* aspath_count_confeds */
  const int private_as; /* whether the private_as check should pass or fail */
#define NOT_ALL_PRIVATE 0
#define ALL_PRIVATE 1
  const as_t does_loop; /* an ASN which should trigger loop-check */
  const as_t doesnt_loop; /* one which should not */
  const as_t first; /* the first ASN, if there is one */
#define NULL_ASN 0
};

struct test_segment {
  const char *name;
  const char *desc;
  const u_char asdata[1024];
  int len;
  struct test_spec sp;
} ;

struct aspath_test {
  const char *desc;
  const struct test_segment *segment;
  const char *shouldbe;  /* String it should evaluate to */
  const enum as4 { AS4_DATA, AS2_DATA }
          as4;  /* whether data should be as4 or not (ie as2) */
  const int result;     /* expected result for bgp_attr_parse */
  const int cap;        /* capabilities to set for peer */
  const char attrheader [1024];
  size_t len;
} ;

struct test_pair {
  const struct test_segment *test1;
  const struct test_segment *test2;
  struct test_spec sp;
} ;


/*==============================================================================
 *
 */
static struct test_segment test_segments[] ;
static struct aspath_test aspath_tests [] ;
static struct test_pair prepend_tests[] ;
static struct test_pair reconcile_tests[] ;
static struct test_pair aggregate_tests[] ;


static void empty_get_test(void) ;
static void parse_test (struct test_segment *t) ;
static void empty_prepend_test (struct test_segment *t) ;
static void prepend_test (struct test_pair *t) ;
static void aggregate_test (struct test_pair *t) ;
static void as4_reconcile_test (struct test_pair *t) ;
static void cmp_test (void) ;
static void attr_test (struct aspath_test *t) ;

/*------------------------------------------------------------------------------
 *
 */
int
main (int argc, char **argv)
{
  int i = 0;

  qlib_init_first_stage(0);     /* Absolutely first     */
  host_init(argv[0]) ;

  bgp_master_init ();

#if 0
  bgp_attr_init ();
#endif

  while (test_segments[i].name)
    {
      printf ("test %u\n", i);
      parse_test (&test_segments[i]);
      empty_prepend_test (&test_segments[i++]);
    }

  i = 0;
  while (prepend_tests[i].test1)
    {
      printf ("prepend test %u\n", i);
      prepend_test (&prepend_tests[i++]);
    }

  i = 0;
  while (aggregate_tests[i].test1)
    {
      printf ("aggregate test %u\n", i);
      aggregate_test (&aggregate_tests[i++]);
    }

  i = 0;

  while (reconcile_tests[i].test1)
    {
      printf ("reconcile test %u\n", i);
      as4_reconcile_test (&reconcile_tests[i++]);
    }

  i = 0;

  cmp_test();

  i = 0;

  empty_get_test();

  i = 0;

  while (aspath_tests[i].desc)
    {
      printf ("aspath_attr test %d\n", i);
      attr_test (&aspath_tests[i++]);
    }

  printf ("failures: %d\n", failed);
  printf ("aspath count: %u\n", as_path_count());

  return (failed + as_path_count());
}

/*==============================================================================
 * test segments to parse and validate, and use for other tests
 */
static struct test_segment test_segments [] =
{
  { /* 0 */
    "seq1",
    "seq(8466,3,52737,4096)",
    { 0x2,0x4, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00 },
    10,
    { "8466 3 52737 4096",
      "8466 3 52737 4096",
      4, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 1 */
    "seq2",
    "seq(8722) seq(4)",
    { 0x2,0x1, 0x22,0x12,
      0x2,0x1, 0x00,0x04 },
    8,
    { "8722 4",
      "8722 4",
      2, 0, NOT_ALL_PRIVATE, 4, 5, 8722, },
  },
  { /* 2 */
    "seq3",
    "seq(8466,3,52737,4096,8722,4)",
    { 0x2,0x6, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00,
               0x22,0x12, 0x00,0x04},
    14,
    { "8466 3 52737 4096 8722 4",
      "8466 3 52737 4096 8722 4",
       6, 0, NOT_ALL_PRIVATE, 3, 5, 8466 },
  },
  { /* 3 */
    "seqset",
    "seq(8482,51457) set(5204)",
    { 0x2,0x2, 0x21,0x22, 0xc9,0x01,
      0x1,0x1, 0x14,0x54 },
    10,
    { "8482 51457 {5204}",
      "8482 51457 {5204}",
      3, 0, NOT_ALL_PRIVATE, 5204, 51456, 8482},
  },
  { /* 4 */
    "seqset2",
    "seq(8467, 59649) set(4196,48658) set(17322,30745)",
    { 0x2,0x2, 0x21,0x13, 0xe9,0x01,
      0x1,0x2, 0x10,0x64, 0xbe,0x12,
      0x1,0x2, 0x43,0xaa, 0x78,0x19 },
    18,
    { "8467 59649 {4196,48658} {17322,30745}",
      "8467 59649 {4196,48658} {17322,30745}",
      4, 0, NOT_ALL_PRIVATE, 48658, 1, 8467},
  },
  { /* 5 */
    "multi",
    "seq(6435,59408,21665) set(2457,61697,4369), seq(1842,41590,51793)",
    { 0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1,
      0x1,0x3, 0x09,0x99, 0xf1,0x01, 0x11,0x11,
      0x2,0x3, 0x07,0x32, 0xa2,0x76, 0xca,0x51 },
    24,
    { "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      7, 0, NOT_ALL_PRIVATE, 51793, 1, 6435 },
  },
  { /* 6 */
    "confed",
    "confseq(123,456,789)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15 },
    8,
    { "(123 456 789)",
      "",
      0, 3, NOT_ALL_PRIVATE, 789, 1, NULL_ASN },
  },
  { /* 7 */
    "confed2",
    "confseq(123,456,789) confseq(111,222)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15,
      0x3,0x2, 0x00,0x6f, 0x00,0xde },
    14,
    { "(123 456 789) (111 222)",
      "",
      0, 5, NOT_ALL_PRIVATE, 111, 1, NULL_ASN },
  },
  { /* 8 */
    "confset",
    "confset(456,123,789)",
    { 0x4,0x3, 0x01,0xc8, 0x00,0x7b, 0x03,0x15 },
    8,
    { "[123,456,789]",
      "[123,456,789]",
      0, 1, NOT_ALL_PRIVATE, 123, 1, NULL_ASN },
  },
  { /* 9 */
    "confmulti",
    "confseq(123,456,789) confset(222,111) seq(8722) set(4196,48658)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15,
      0x4,0x2, 0x00,0xde, 0x00,0x6f,
      0x2,0x1, 0x22,0x12,
      0x1,0x2, 0x10,0x64, 0xbe,0x12 },
    24,
    { "(123 456 789) [111,222] 8722 {4196,48658}",
      "8722 {4196,48658}",
      2, 4, NOT_ALL_PRIVATE, 123, 1, NULL_ASN },
  },
  { /* 10 */
    "seq4",
    "seq(8466,2,52737,4096,8722,4)",
    { 0x2,0x6, 0x21,0x12, 0x00,0x02, 0xce,0x01, 0x10,0x00,
               0x22,0x12, 0x00,0x04},
    14,
    { "8466 2 52737 4096 8722 4",
      "8466 2 52737 4096 8722 4",
      6, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  { /* 11 */
    "tripleseq1",
    "seq(8466,2,52737) seq(4096,8722,4) seq(8722)",
    { 0x2,0x3, 0x21,0x12, 0x00,0x02, 0xce,0x01,
      0x2,0x3, 0x10,0x00, 0x22,0x12, 0x00,0x04,
      0x2,0x1, 0x22,0x12},
    20,
    { "8466 2 52737 4096 8722 4 8722",
      "8466 2 52737 4096 8722 4 8722",
      7, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  { /* 12 */
    "someprivate",
    "seq(8466,64512,52737,65535)",
    { 0x2,0x4, 0x21,0x12, 0xfc,0x00, 0xce,0x01, 0xff,0xff },
    10,
    { "8466 64512 52737 65535",
      "8466 64512 52737 65535",
      4, 0, NOT_ALL_PRIVATE, 65535, 4, 8466 },
  },
  { /* 13 */
    "allprivate",
    "seq(65534,64512,64513,65535)",
    { 0x2,0x4, 0xff,0xfe, 0xfc,0x00, 0xfc,0x01, 0xff,0xff },
    10,
    { "65534 64512 64513 65535",
      "65534 64512 64513 65535",
      4, 0, ALL_PRIVATE, 65534, 4, 65534 },
  },
  { /* 14 */
    "long",
    "seq(8466,3,52737,4096,34285,<repeated 49 more times>)",
    { 0x2,0xfa, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed, },
    502,
    { "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285",

      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285",
      250, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 15 */
    "seq1extra",
    "seq(8466,3,52737,4096,3456)",
    { 0x2,0x5, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x0d,0x80 },
    12,
    { "8466 3 52737 4096 3456",
      "8466 3 52737 4096 3456",
      5, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 16 */
    "empty",
    "<empty>",
    {},
    0,
    { "", "", 0, 0, 0, 0, 0, 0 },
  },
  { /* 17 */
    "redundantset",
    "seq(8466,3,52737,4096,3456) set(7099,8153,8153,8153)",
    { 0x2,0x5, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x0d,0x80,
      0x1,0x4, 0x1b,0xbb, 0x1f,0xd9, 0x1f,0xd9, 0x1f,0xd9 },
    22,
    {
     /* We shouldn't ever /generate/ such paths. However, we should
      * cope with them fine.
      */
     "8466 3 52737 4096 3456 {7099,8153}",
      "8466 3 52737 4096 3456 {7099,8153}",
      6, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 18 */
    "reconcile_lead_asp",
    "seq(6435,59408,21665) set(23456,23456,23456), seq(23456,23456,23456)",
    { 0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1,
      0x1,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0,
      0x2,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0 },
    24,
    { "6435 59408 21665 {23456} 23456 23456 23456",
      "6435 59408 21665 {23456} 23456 23456 23456",
      7, 0, NOT_ALL_PRIVATE, 23456, 1, 6435 },
  },
  { /* 19 */
    "reconcile_new_asp",
    "set(2457,61697,4369), seq(1842,41591,51793)",
    {
      0x1,0x3, 0x09,0x99, 0xf1,0x01, 0x11,0x11,
      0x2,0x3, 0x07,0x32, 0xa2,0x77, 0xca,0x51 },
    16,
    { "{2457,4369,61697} 1842 41591 51793",
      "{2457,4369,61697} 1842 41591 51793",
      4, 0, NOT_ALL_PRIVATE, 51793, 1, 2457 },
  },
  { /* 20 */
    "reconcile_confed",
    "confseq(123,456,789) confset(456,124,788) seq(6435,59408,21665)"
    " set(23456,23456,23456), seq(23456,23456,23456)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15,
      0x4,0x3, 0x01,0xc8, 0x00,0x7c, 0x03,0x14,
      0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1,
      0x1,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0,
      0x2,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0 },
    40,
    { "(123 456 789) [124,456,788] 6435 59408 21665"
      " {23456} 23456 23456 23456",
      "6435 59408 21665 {23456} 23456 23456 23456",
      7, 4, NOT_ALL_PRIVATE, 23456, 1, 6435 },
  },
  { /* 21 */
    "reconcile_start_trans",
    "seq(23456,23456,23456) seq(6435,59408,21665)",
    { 0x2,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0,
      0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1, },
    16,
    { "23456 23456 23456 6435 59408 21665",
      "23456 23456 23456 6435 59408 21665",
      6, 0, NOT_ALL_PRIVATE, 21665, 1, 23456 },
  },
  { /* 22 */
    "reconcile_start_trans4",
    "seq(1842,41591,51793) seq(6435,59408,21665)",
    { 0x2,0x3, 0x07,0x32, 0xa2,0x77, 0xca,0x51,
      0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1, },
    16,
    { "1842 41591 51793 6435 59408 21665",
      "1842 41591 51793 6435 59408 21665",
      6, 0, NOT_ALL_PRIVATE, 41591, 1, 1842 },
  },
  { /* 23 */
    "reconcile_start_trans_error",
    "seq(23456,23456,23456) seq(6435,59408)",
    { 0x2,0x3, 0x5b,0xa0, 0x5b,0xa0, 0x5b,0xa0,
      0x2,0x2, 0x19,0x23, 0xe8,0x10, },
    14,
    { "23456 23456 23456 6435 59408",
      "23456 23456 23456 6435 59408",
      5, 0, NOT_ALL_PRIVATE, 59408, 1, 23456 },
  },
  { /* 24 */
    "redundantset2",
    "seq(8466,3,52737,4096,3456) set(7099,8153,8153,8153,7099)",
    { 0x2,0x5, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x0d,0x80,
      0x1,0x5, 0x1b,0xbb, 0x1f,0xd9, 0x1f,0xd9, 0x1f,0xd9, 0x1b,0xbb,},
    24,
    {
     /* We should weed out duplicate set members. */
     "8466 3 52737 4096 3456 {7099,8153}",
      "8466 3 52737 4096 3456 {7099,8153}",
      6, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 25 */
    "zero-size overflow",
    "#ASNs = 0, data = seq(8466 3 52737 4096 3456)",
    { 0x2,0x0, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x0d,0x80 },
    12,
    { NULL, NULL,
      0, 0, 0, 0, 0, 0 },
  },
  { /* 26  */
    "zero-size overflow + valid segment",
    "seq(#AS=0:8466 3 52737),seq(4096 3456)",
    { 0x2,0x0, 0x21,0x12, 0x00,0x03, 0xce,0x01,
      0x2,0x2, 0x10,0x00, 0x0d,0x80 },
    14
    ,
    { NULL, NULL,
      0, 0, 0, 0, 0, 0 },
  },
  { /* 27  */
    "invalid segment type",
    "type=8(4096 3456)",
    { 0x8,0x2, 0x10,0x00, 0x0d,0x80 },
    14
    ,
    { NULL, NULL,
      0, 0, 0, 0, 0, 0 },
  },  { NULL, NULL, {0}, 0, { NULL, 0, 0 } }
};

/*==============================================================================
 *
 */
static struct aspath_test aspath_tests [] =
{
  /* 0 */
  {
    "basic test",
    &test_segments[0],
    "8466 3 52737 4096",
    AS2_DATA, 0,
    0,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      10,
    },
    3,
  },
  /* 1 */
  {
    "length too short",
    &test_segments[0],
    "8466 3 52737 4096",
    AS2_DATA, -1,
    0,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      8,
    },
    3,
  },
  /* 2 */
  {
    "length too long",
    &test_segments[0],
    "8466 3 52737 4096",
    AS2_DATA, -1,
    0,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      12,
    },
    3,
  },
  /* 3 */
  {
    "incorrect flag",
    &test_segments[0],
    "8466 3 52737 4096",
    AS2_DATA, -1,
    0,
    { BGP_ATF_TRANSITIVE|BGP_ATF_OPTIONAL,
      BGP_ATT_AS_PATH,
      10,
    },
    3,
  },
  /* 4 */
  {
    "as4_path, with as2 format data",
    &test_segments[0],
    "8466 3 52737 4096",
    AS2_DATA, -1,
    0,
    { BGP_ATF_TRANSITIVE|BGP_ATF_OPTIONAL,
      BGP_ATT_AS4_PATH,
      10,
    },
    3,
  },
  /* 5 */
  {
    "as4, with incorrect attr length",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_RCV,
    { BGP_ATF_TRANSITIVE|BGP_ATF_OPTIONAL,
      BGP_ATT_AS4_PATH,
      10,
    },
    3,
  },
  /* 6 */
  {
    "basic 4-byte as-path",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, 0,
    PEER_CAP_AS4_RCV|PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      18,
    },
    3,
  },
  /* 7 */
  {
    "4b AS_PATH: too short",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_RCV|PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      16,
    },
    3,
  },
  /* 8 */
  {
    "4b AS_PATH: too long",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_RCV|PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      20,
    },
    3,
  },
  /* 9 */
  {
    "4b AS_PATH: too long2",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_RCV|PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE,
      BGP_ATT_AS_PATH,
      22,
    },
    3,
  },
  /* 10 */
  {
    "4b AS_PATH: bad flags",
    &test_segments[0],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_RCV|PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE|BGP_ATF_OPTIONAL,
      BGP_ATT_AS_PATH,
      18,
    },
    3,
  },
  /* 11 */
  {
    "4b AS_PATH: confed",
    &test_segments[6],
    "8466 3 52737 4096",
    AS4_DATA, -1,
    PEER_CAP_AS4_ADV,
    { BGP_ATF_TRANSITIVE|BGP_ATF_OPTIONAL,
      BGP_ATT_AS4_PATH,
      14,
    },
    3,
  },
  { NULL, NULL, NULL, 0, 0, 0, { 0 }, 0 },
};

/*==============================================================================
 * prepending tests
 */
static struct test_pair prepend_tests[] =
{
  /* 0 */
  { &test_segments[0], &test_segments[1],
    { "8466 3 52737 4096 8722 4",
      "8466 3 52737 4096 8722 4",
      6, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  /* 1 */
  { &test_segments[1], &test_segments[3],
    { "8722 4 8482 51457 {5204}",
      "8722 4 8482 51457 {5204}",
      5, 0, NOT_ALL_PRIVATE, 5204, 1, 8722 }
  },
  /* 2 */
  { &test_segments[3], &test_segments[4],
    { "8482 51457 {5204} 8467 59649 {4196,48658} {17322,30745}",
      "8482 51457 {5204} 8467 59649 {4196,48658} {17322,30745}",
      7, 0, NOT_ALL_PRIVATE, 5204, 1, 8482 },
  },
  /* 3 */
  { &test_segments[4], &test_segments[5],
    { "8467 59649 {4196,48658} {17322,30745} 6435 59408 21665"
      " {2457,4369,61697} 1842 41590 51793",
      "8467 59649 {4196,48658} {17322,30745} 6435 59408 21665"
      " {2457,4369,61697} 1842 41590 51793",
      11, 0, NOT_ALL_PRIVATE, 61697, 1, 8467 }
  },
  /* 4 */
  { &test_segments[5], &test_segments[6],
    { "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      7, 0, NOT_ALL_PRIVATE, 1842, 1, 6435 },
  },
  /* 5 */
  { &test_segments[6], &test_segments[7],
    { "(123 456 789) (123 456 789) (111 222)",
      "",
      0, 8, NOT_ALL_PRIVATE, 111, 1, 0 }
  },
  { &test_segments[7], &test_segments[8],
    { "(123 456 789) (111 222) [123,456,789]",
      "",
      0, 6, NOT_ALL_PRIVATE, 111, 1, 0 }
  },
  { &test_segments[8], &test_segments[9],
    { "[123,456,789] (123 456 789) [111,222] 8722 {4196,48658}",
      "[123,456,789] (123 456 789) [111,222] 8722 {4196,48658}",
      2, 5, NOT_ALL_PRIVATE, 456, 1, NULL_ASN },
  },
  { &test_segments[9], &test_segments[8],
    { "(123 456 789) [111,222] 8722 {4196,48658} [123,456,789]",
      "8722 {4196,48658} [123,456,789]",
      2, 5, NOT_ALL_PRIVATE, 48658, 1, NULL_ASN },
  },
  { &test_segments[14], &test_segments[11],
    { "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 2 52737 4096 8722 4 8722",

      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 2 52737 4096 8722 4 8722",
      257, 0, NOT_ALL_PRIVATE, 4096, 1000, 8466 },
  },
  { NULL, NULL, { NULL, 0, 0, 0, 0, 0, 0, } },
};

/*==============================================================================
 *
 */
static struct test_pair reconcile_tests[] =
{
  { &test_segments[18], &test_segments[19],
    { "6435 59408 21665 {2457,4369,61697} 1842 41591 51793",
      "6435 59408 21665 {2457,4369,61697} 1842 41591 51793",
      7, 0, NOT_ALL_PRIVATE, 51793, 1, 6435 },
  },
  { &test_segments[19], &test_segments[18],
    /* AS_PATH (19) has more hops than NEW_AS_PATH,
     * so just AS_PATH should be used (though, this practice
     * is bad imho).
     */
    { "{2457,4369,61697} 1842 41591 51793 6435 59408 21665 {23456} 23456 23456 23456",
      "{2457,4369,61697} 1842 41591 51793 6435 59408 21665 {23456} 23456 23456 23456",
      11, 0, NOT_ALL_PRIVATE, 51793, 1, 6435 },
  },
  { &test_segments[20], &test_segments[19],
    { "(123 456 789) [124,456,788] 6435 59408 21665"
      " {2457,4369,61697} 1842 41591 51793",
      "6435 59408 21665 {2457,4369,61697} 1842 41591 51793",
      7, 4, NOT_ALL_PRIVATE, 51793, 1, 6435 },
  },
  { &test_segments[21], &test_segments[22],
    { "1842 41591 51793 6435 59408 21665",
      "1842 41591 51793 6435 59408 21665",
      6, 0, NOT_ALL_PRIVATE, 51793, 1, 1842 },
  },
  { &test_segments[23], &test_segments[22],
    { "23456 23456 23456 6435 59408 1842 41591 51793 6435 59408 21665",
      "23456 23456 23456 6435 59408 1842 41591 51793 6435 59408 21665",
      11, 0, NOT_ALL_PRIVATE, 51793, 1, 1842 },
  },
  { NULL, NULL, { NULL, 0, 0, 0, 0, 0, 0, } },
};

static struct test_pair aggregate_tests[] =
{
  { &test_segments[0], &test_segments[2],
    { "8466 3 52737 4096 {4,8722}",
      "8466 3 52737 4096 {4,8722}",
      5, 0, NOT_ALL_PRIVATE, 4, 1, 8466 },
  },
  { &test_segments[2], &test_segments[0],
    { "8466 3 52737 4096 {4,8722}",
      "8466 3 52737 4096 {4,8722}",
      5, 0, NOT_ALL_PRIVATE, 8722, 1, 8466 },
  },
  { &test_segments[2], &test_segments[10],
    { "8466 {2,3,4,4096,8722,52737}",
      "8466 {2,3,4,4096,8722,52737}",
      2, 0, NOT_ALL_PRIVATE, 8722, 5, 8466 },
  },
  { &test_segments[10], &test_segments[2],
    { "8466 {2,3,4,4096,8722,52737}",
      "8466 {2,3,4,4096,8722,52737}",
      2, 0, NOT_ALL_PRIVATE, 2, 20000, 8466 },
  },

  { &test_segments[5], &test_segments[18],
    { "6435 59408 21665 {1842,2457,4369,23456,41590,51793,61697}",
      "6435 59408 21665 {1842,2457,4369,23456,41590,51793,61697}",
      4, 0, NOT_ALL_PRIVATE, 41590, 1, 6435 },
  },

  { NULL, NULL, { NULL, 0, 0}  },
};

/*==============================================================================
 *
 */
struct compare_tests
{
  int test_index1;
  int test_index2;
#define CMP_RES_YES 1
#define CMP_RES_NO 0
  char shouldbe_cmp;
  char shouldbe_confed;
} left_compare [] =
{
  { 0, 1, CMP_RES_NO, CMP_RES_NO },
  { 0, 2, CMP_RES_YES, CMP_RES_NO },
  { 0, 11, CMP_RES_YES, CMP_RES_NO },
  { 0, 15, CMP_RES_YES, CMP_RES_NO },
  { 0, 16, CMP_RES_NO, CMP_RES_NO },
  { 1, 11, CMP_RES_NO, CMP_RES_NO },
  { 6, 7, CMP_RES_NO, CMP_RES_YES },
  { 6, 8, CMP_RES_NO, CMP_RES_NO },
  { 7, 8, CMP_RES_NO, CMP_RES_NO },
  { 1, 9, CMP_RES_YES, CMP_RES_NO },
  { 0, 9, CMP_RES_NO, CMP_RES_NO },
  { 3, 9, CMP_RES_NO, CMP_RES_NO },
  { 0, 6, CMP_RES_NO, CMP_RES_NO },
  { 1, 6, CMP_RES_NO, CMP_RES_NO },
  { 0, 8, CMP_RES_NO, CMP_RES_NO },
  { 1, 8, CMP_RES_NO, CMP_RES_NO },
  { 11, 6, CMP_RES_NO, CMP_RES_NO },
  { 11, 7, CMP_RES_NO, CMP_RES_NO },
  { 11, 8, CMP_RES_NO, CMP_RES_NO },
  { 9, 6, CMP_RES_NO, CMP_RES_YES },
  { 9, 7, CMP_RES_NO, CMP_RES_YES },
  { 9, 8, CMP_RES_NO, CMP_RES_NO },
};

/*==============================================================================
 *
 */
static int validate (as_path as, const struct test_spec *sp) ;

/*------------------------------------------------------------------------------
 * Test for aspath_empty_get().
 */
static void
empty_get_test (void)
{
#if 0
  struct as_path as = as_path_empty_get ();
  struct test_spec sp = { "", "", 0, 0, 0, 0, 0, 0 };

  printf ("empty_get_test, as: %s\n",aspath_print (as));
  if (!validate (as, &sp))
    printf ("%s\n", OK);
  else
    printf ("%s!\n", FAILED);

  printf ("\n");

  aspath_free (as);
#endif
}

/* basic parsing test */
static void
parse_test (struct test_segment *t)
{
#if 0
  struct aspath *asp;

  printf ("%s: %s\n", t->name, t->desc);

  asp = make_aspath (t->asdata, t->len, 0);

  printf ("aspath: %s\nvalidating...:\n", aspath_print (asp));

  if (!validate (asp, &t->sp))
    printf (OK "\n");
  else
    printf (FAILED "\n");

  printf ("\n");

  if (asp)
    aspath_unintern (&asp);
#endif
}

/* prepend testing */
static void
prepend_test (struct test_pair *t)
{
#if 0
  struct aspath *asp1, *asp2, *ascratch;

  printf ("prepend %s: %s\n", t->test1->name, t->test1->desc);
  printf ("to %s: %s\n", t->test2->name, t->test2->desc);

  asp1 = make_aspath (t->test1->asdata, t->test1->len, 0);
  asp2 = make_aspath (t->test2->asdata, t->test2->len, 0);

  ascratch = aspath_dup (asp2);
  aspath_unintern (&asp2);

  asp2 = aspath_prepend (asp1, ascratch);

  printf ("aspath: %s\n", aspath_print (asp2));

  if (!validate (asp2, &t->sp))
    printf ("%s\n", OK);
  else
    printf ("%s!\n", FAILED);

  printf ("\n");
  aspath_unintern (&asp1);
  aspath_free (asp2);
#endif
}

/* empty-prepend testing */
static void
empty_prepend_test (struct test_segment *t)
{
#if 0
  struct aspath *asp1, *asp2, *ascratch;

  printf ("empty prepend %s: %s\n", t->name, t->desc);
#if 0
  asp1 = make_aspath (t->asdata, t->len, 0);
  asp2 = aspath_empty ();

  ascratch = aspath_dup (asp2);
  aspath_unintern (&asp2);

  asp2 = aspath_prepend (asp1, ascratch);

  printf ("aspath: %s\n", aspath_print (asp2));

  if (!validate (asp2, &t->sp))
    printf (OK "\n");
  else
    printf (FAILED "!\n");
#endif
  printf ("\n");
  if (asp1)
    aspath_unintern (&asp1);
  aspath_free (asp2);
#endif
}

/* as2+as4 reconciliation testing */
static void
as4_reconcile_test (struct test_pair *t)
{
#if 0
  struct aspath *asp1, *asp2, *ascratch;

  printf ("reconciling %s:\n  %s\n", t->test1->name, t->test1->desc);
  printf ("with %s:\n  %s\n", t->test2->name, t->test2->desc);

  asp1 = make_aspath (t->test1->asdata, t->test1->len, 0);
  asp2 = make_aspath (t->test2->asdata, t->test2->len, 0);

  ascratch = aspath_reconcile_as4 (asp1, asp2);

  if (!validate (ascratch, &t->sp))
    printf (OK "\n");
  else
    printf (FAILED "!\n");

  printf ("\n");
  aspath_unintern (&asp1);
  aspath_unintern (&asp2);
  aspath_free (ascratch);
#endif
}


/* aggregation testing */
static void
aggregate_test (struct test_pair *t)
{
#if 0
  struct aspath *asp1, *asp2, *ascratch;

  printf ("aggregate %s: %s\n", t->test1->name, t->test1->desc);
  printf ("with %s: %s\n", t->test2->name, t->test2->desc);

  asp1 = make_aspath (t->test1->asdata, t->test1->len, 0);
  asp2 = make_aspath (t->test2->asdata, t->test2->len, 0);

  ascratch = aspath_aggregate (asp1, asp2);

  if (!validate (ascratch, &t->sp))
    printf (OK "\n");
  else
    printf (FAILED "!\n");

  printf ("\n");
  aspath_unintern (&asp1);
  aspath_unintern (&asp2);
  aspath_free (ascratch);
/*  aspath_unintern (ascratch);*/
#endif
}

/* cmp_left tests  */
static void
cmp_test (void)
{
#if 0
  unsigned int i;
#define CMP_TESTS_MAX \
  (sizeof(left_compare) / sizeof (struct compare_tests))

  for (i = 0; i < CMP_TESTS_MAX; i++)
    {
      struct test_segment *t1 = &test_segments[left_compare[i].test_index1];
      struct test_segment *t2 = &test_segments[left_compare[i].test_index2];
      struct aspath *asp1, *asp2;

      printf ("left cmp %s: %s\n", t1->name, t1->desc);
      printf ("and %s: %s\n", t2->name, t2->desc);

      asp1 = make_aspath (t1->asdata, t1->len, 0);
      asp2 = make_aspath (t2->asdata, t2->len, 0);

      if (aspath_cmp_left (asp1, asp2) != left_compare[i].shouldbe_cmp
          || aspath_cmp_left (asp2, asp1) != left_compare[i].shouldbe_cmp
          || aspath_cmp_left_confed (asp1, asp2)
               != left_compare[i].shouldbe_confed
          || aspath_cmp_left_confed (asp2, asp1)
               != left_compare[i].shouldbe_confed)
        {
          failed++;
          printf (FAILED "\n");
          printf ("result should be: cmp: %d, confed: %d\n",
                  left_compare[i].shouldbe_cmp,
                  left_compare[i].shouldbe_confed);
          printf ("got: cmp %d, cmp_confed: %d\n",
                  aspath_cmp_left (asp1, asp2),
                  aspath_cmp_left_confed (asp1, asp2));
          printf("path1: %s\npath2: %s\n", aspath_print (asp1),
                 aspath_print (asp2));
        }
      else
        printf (OK "\n");

      printf ("\n");
      aspath_unintern (&asp1);
      aspath_unintern (&asp2);
    }
#endif
}

static int
handle_attr_test (struct aspath_test *t)
{
#if 0
  struct bgp bgp = { 0 };
  struct peer peer = { 0 };
  int ret;
  int initfail = failed;
  struct aspath *asp;
  size_t datalen ;
  char host[] = { "none" } ;
  bgp_attr_parser_args_t args[1] ;

  asp = make_aspath (t->segment->asdata, t->segment->len, 0);

  peer.ibuf = stream_new (BGP_MSG_MAX_L);
  peer.obuf = stream_fifo_new ();
  peer.bgp  = &bgp;
  peer.host = host ;
#if 0
  peer.fd = -1;
#endif
  peer.cap = t->cap;

  memset (args, 0, sizeof (args));

  args->peer = &peer ;
  args->s    = peer.ibuf ;

  stream_put (peer.ibuf, t->attrheader, t->len);
  datalen = aspath_put (peer.ibuf, asp, t->as4 == AS4_DATA);

  stream_push_endp(peer.ibuf, t->len + datalen) ;

  ret = bgp_attr_parse (args, NULL, 0);

  if (ret != t->result)
    {
      printf ("bgp_attr_parse returned %d, expected %d\n", ret, t->result);
      printf ("datalen %d\n", (int)datalen);
      failed++;
    }
  if (ret != 0)
    goto out;

  if (args->attr.aspath == NULL)
    {
      printf ("aspath is NULL!\n");
      failed++;
    }

  if (args->attr.aspath && strcmp (args->attr.aspath->str, t->shouldbe))
    {
      printf ("attr str and 'shouldbe' mismatched!\n"
              "attr str:  %s\n"
              "shouldbe:  %s\n",
              args->attr.aspath->str, t->shouldbe);
      failed++;
    }

out:
  if (args->attr.aspath)
    aspath_unintern (&args->attr.aspath);
  if (asp)
    aspath_unintern (&asp);
  return failed - initfail;
#endif
}









static void
attr_test (struct aspath_test *t)
{
    printf ("%s\n", t->desc);
    printf ("%s\n\n", handle_attr_test (t) ? FAILED : OK);
}




/* make an aspath from a data stream */
static struct aspath *
make_aspath (const u_char *data, size_t len, int use32bit)
{
  struct stream *s = NULL;
  struct aspath *as;

  if (len)
    {
      s = stream_new (len);
      stream_put (s, data, len);
    }
#if 0
  as = aspath_parse (s, len, use32bit, 0);
#else
  as = NULL ;
#endif

  if (s)
    stream_free (s);
  return as;
}

static void
printbytes (const u_char *bytes, int len)
{
  int i = 0;
  while (i < len)
    {
      if (i % 2)
        printf ("%02hhx%s", bytes[i], " ");
      else
        printf ("0x%02hhx", bytes[i]);
      i++;
    }
  printf ("\n");
}

/* validate the given aspath */
static int
validate (as_path as, const struct test_spec *sp)
{
#if 0
  size_t bytes, bytes4;
  int fails = 0;
  const u_char *out;
  static struct stream *s;
  struct aspath *asinout, *asconfeddel, *asstr, *as4;

  if (as == NULL && sp->shouldbe == NULL)
    {
      printf ("Correctly failed to parse\n");
      return fails;
    }

  out = aspath_snmp_pathseg (as, &bytes);
  asinout = make_aspath (out, bytes, 0);

  /* Excercise AS4 parsing a bit, with a dogfood test */
  if (!s)
    s = stream_new (4096);
  bytes4 = aspath_put (s, as, 1);
  as4 = make_aspath (STREAM_DATA(s), bytes4, 1);

  asstr = aspath_str2aspath (sp->shouldbe);

  asconfeddel = aspath_delete_confed_seq (aspath_dup (asinout));

  printf ("got: %s\n", aspath_print(as));

  /* the parsed path should match the specified 'shouldbe' string.
   * We should pass the "eat our own dog food" test, be able to output
   * this path and then input it again. Ie the path resulting from:
   *
   *   aspath_parse(aspath_put(as))
   *
   * should:
   *
   * - also match the specified 'shouldbe' value
   * - hash to same value as original path
   * - have same hops and confed counts as original, and as the
   *   the specified counts
   *
   * aspath_str2aspath() and shouldbe should match
   *
   * We do the same for:
   *
   *   aspath_parse(aspath_put(as,USE32BIT))
   *
   * Confederation related tests:
   * - aspath_delete_confed_seq(aspath) should match shouldbe_confed
   * - aspath_delete_confed_seq should be idempotent.
   */
  if (strcmp(aspath_print (as), sp->shouldbe)
         /* hash validation */
      || (aspath_key_make (as) != aspath_key_make (asinout))
         /* by string */
      || strcmp(aspath_print (asinout), sp->shouldbe)
         /* By 4-byte parsing */
      || strcmp(aspath_print (as4), sp->shouldbe)
         /* by various path counts */
      || (aspath_count_hops (as) != sp->hops)
      || (aspath_count_confeds (as) != sp->confeds)
      || (aspath_count_hops (asinout) != sp->hops)
      || (aspath_count_confeds (asinout) != sp->confeds))
    {
      failed++;
      fails++;
      printf ("shouldbe:\n%s\n", sp->shouldbe);
      printf ("as4:\n%s\n", aspath_print (as4));
      printf ("hash keys: in: %d out->in: %d\n",
              aspath_key_make (as), aspath_key_make (asinout));
      printf ("hops: %d, counted %d %d\n", sp->hops,
              aspath_count_hops (as),
              aspath_count_hops (asinout) );
      printf ("confeds: %d, counted %d %d\n", sp->confeds,
              aspath_count_confeds (as),
              aspath_count_confeds (asinout));
      printf ("out->in:\n%s\nbytes: ", aspath_print(asinout));
      printbytes (out, bytes);
    }
         /* basic confed related tests */
  if ((aspath_print (asconfeddel) == NULL
          && sp->shouldbe_delete_confed != NULL)
      || (aspath_print (asconfeddel) != NULL
          && sp->shouldbe_delete_confed == NULL)
      || strcmp(aspath_print (asconfeddel), sp->shouldbe_delete_confed)
         /* delete_confed_seq should be idempotent */
      || (aspath_key_make (asconfeddel)
          != aspath_key_make (aspath_delete_confed_seq (asconfeddel))))
    {
      failed++;
      fails++;
      printf ("confed_del: %s\n", aspath_print (asconfeddel));
      printf ("should be: %s\n", sp->shouldbe_delete_confed);
    }
      /* aspath_str2aspath test */
  if ((aspath_print (asstr) == NULL && sp->shouldbe != NULL)
      || (aspath_print (asstr) != NULL && sp->shouldbe == NULL)
      || strcmp(aspath_print (asstr), sp->shouldbe))
    {
      failed++;
      fails++;
      printf ("asstr: %s\n", aspath_print (asstr));
    }

    /* loop, private and first as checks */
  if ((sp->does_loop && aspath_loop_check (as, sp->does_loop) == 0)
      || (sp->doesnt_loop && aspath_loop_check (as, sp->doesnt_loop) != 0)
      || (aspath_private_as_check (as) != sp->private_as)
      || (aspath_firstas_check (as,sp->first)
          && sp->first == 0))
    {
      failed++;
      fails++;
      printf ("firstas: %d,  got %d\n", sp->first,
              aspath_firstas_check (as,sp->first));
      printf ("loop does: %d %d, doesnt: %d %d\n",
              sp->does_loop, aspath_loop_check (as, sp->does_loop),
              sp->doesnt_loop, aspath_loop_check (as, sp->doesnt_loop));
      printf ("private check: %d %d\n", sp->private_as,
              aspath_private_as_check (as));
    }
  aspath_unintern (&asinout);
  aspath_unintern (&as4);

  aspath_free (asconfeddel);
  aspath_free (asstr);
  stream_reset (s);

  return fails;
#endif
}


/*==============================================================================
 * Basic tests for the as_path functions and basic mechanics
 *
 */
static void as_path_post_process_test(void) ;

static as_path as_path_prepare_test(const asp_item_t* items,
                                                     const asp_item_t* append) ;
static void as_path_show(FILE* where, as_path asp) ;
static bool as_path_post_process_test_show(FILE* where, as_path asp,
                                   const char* title, bool shown, bool failed) ;

/*------------------------------------------------------------------------------
 * Test the post processing.
 *
 * This is key to generating canonical as_path objects, and sweeps up various
 * edge cases.
 *
 */
struct as_path_post_process_test
{
  const char* title ;

  bool        show ;
  bool        stop ;

  bool        invalid ;
  uint        expect_len ;

  uint        length_confed ;
  uint        length_simple ;

  uint        set_count ;
  uint        confed_set_count ;
  uint        confed_seq_count ;

  as_seg_t    last_seg ;

  asp_item_t  items[32] ;

  asp_item_t  append[12] ;              /* first MUST be asp_segment    */
} ;

static const struct as_path_post_process_test as_path_post_process_tests[] ;

/*------------------------------------------------------------------------------
 * Run a bunch of tests to ensure that the as_path_post_process() function
 * will cope with all sorts of valid, but not canonical, paths and boil down
 * to the correct canonical form.
 *
 * In the process, constructs and tears down as_path objects of a variety of
 * sizes.
 */
static void
as_path_post_process_test(void)
{
#if 0
  const struct as_path_post_process_tests* test ;

  test = as_path_post_process_tests ;

  while (test->title != NULL)
    {
      as_path     asp ;
      bool        check_invalid, invalid ;
      const char* err_msg ;
      as_seg_t expect_last_seg ;
      bool expect_simple ;
      uint expect_length_total ;
      bool shown ;

      if (test->stop)
        fprintf(stderr, "+++ STOP on: '%s'\n", test->title) ;

      asp = as_path_prepare_test(test->items, test->append) ;

      expect_simple = !test->invalid && ( (test->set_count
                                         + test->confed_set_count
                                         + test->confed_seq_count) == 0) ;

      expect_length_total = test->length_simple + test->length_confed ;

      expect_last_seg = test->last_seg ;
      if ((expect_last_seg == BGP_AS_SEG_NULL)
                                                 && (expect_length_total != 0))
        expect_last_seg = BGP_AS_SEQUENCE ;

      invalid = !as_path_post_process(asp) ;

      err_msg = as_path_check_valid(asp, false /* check last_seg */, !invalid) ;
      check_invalid = (err_msg != NULL) ;

      shown   = false ;

      if (invalid != test->invalid)
        {
          shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                              shown, true) ;
          if (invalid)
            fprintf(stderr, "*** is INVALID but expected Valid\n") ;
          else
            fprintf(stderr, "*** is Valid but expected INVALID\n") ;
        } ;

      if (invalid != check_invalid)
        {
          shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                              shown, true) ;
          if (invalid)
            fprintf(stderr, "*** is INVALID but check says Valid\n") ;
          else
            fprintf(stderr, "*** is Valid but check says '%s'\n", err_msg) ;
        } ;

      if (!invalid && !test->invalid)
        {
          if (expect_last_seg != asp->last_seg)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect last_seg=%u, got=%u\n",
                                               expect_last_seg, asp->last_seg) ;

            } ;

          if (test->expect_len != asp->path.len)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect_len=%u, got=%u\n",
                                              test->expect_len, asp->path.len) ;
            } ;

          if (expect_length_total != asp->p.total_length)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect total_length=%u, got=%u\n",
                                     expect_length_total, asp->p.total_length) ;
            } ;

          if (test->length_simple != asp->p.simple.length)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect simple.length=%u, got=%u\n",
                                    test->length_simple, asp->p.simple.length) ;
            } ;

          if (test->length_confed != asp->p.confed.length)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect confed.length=%u, got=%u\n",
                                    test->length_confed, asp->p.confed.length) ;
            } ;

          if (expect_simple != asp->p.simple_sequence)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              if (asp->p.simple_sequence)
                fprintf(stderr, "*** is Simple but expect Not Simple\n") ;
              else
                fprintf(stderr, "*** is Not Simple but expect Simple\n") ;
            } ;

          if (test->set_count != asp->p.simple.set_count)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect simple.set_count=%u, got=%u\n",
                                     test->set_count, asp->p.simple.set_count) ;
            } ;

          if (test->confed_set_count != asp->p.confed.set_count)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect confed.set_count=%u, got=%u\n",
                              test->confed_set_count, asp->p.confed.set_count) ;
            } ;

          if (test->confed_seq_count != asp->p.confed.seq_count)
            {
              shown = as_path_post_process_test_show(stderr, asp, test->title,
                                                                  shown, true) ;
              fprintf(stderr, "*** expect confed.seq_count=%u, got=%u\n",
                              test->confed_seq_count, asp->p.confed.seq_count) ;
            } ;
        } ;

      if (!test->show && !shown)
        as_path_post_process_test_show(stderr, asp, test->title, shown, false) ;

      as_path_free(asp) ;
      ++test ;
    } ;
#endif
} ;

static bool
as_path_post_process_test_show(FILE* where, as_path asp, const char* title,
                                                         bool shown,
                                                         bool failed)
{
  if (!shown)
    {
      fprintf(where, "\nTest: %s%s\n", title, failed ? " *** FAILED" : "") ;
      as_path_show(where, asp) ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Create an asp_path and copy the given items to it.
 *
 * Run the as_path_check_valid() find the last_seg, and set it.  Note that
 * since the as_path is !asp->processed, the check will not reject repeats
 * or other things that as_path_post_process() will remove.
 *
 * If the first item in the given append list is 0, there s nothing more to
 * do.
 *
 * If the first item in the given append list is an asp_segment, proceed to
 * perform as_path_append_seg() and as_path_append_asn() as required.  Note
 * that for this, the as_path_check_valid() MUST have returned valid.  This is
 * for testing of the as_path_append_xxx() functions.
 *
 * If the first item in the given append list is an asp_repeat, then
 * append "raw" the following ASN, and keep on going until get a 0 item.  This
 * is so can generate huge number of ASN, to test that case in
 * as_path_post_process().
 */
static as_path
as_path_prepare_test(const asp_item_t* items, const asp_item_t* append)
{
#if 0
  as_path     asp ;
  asp_item_t  item ;
  const char* err_msg ;
  uint        len ;

  asp = as_path_new(0) ;

  len = 0 ;
  while ((item = *items++) != asp_test_term)
    len = as_path_add_item(asp, len, item) ;

  asp->path.len = len ;

  err_msg = as_path_check_valid(asp, true /* set last_seg */,
                                            false /* not known to be valid */) ;
  item = *append++ ;

  while (item == 0)
    return asp ;

  if ((item >= asp_segment) && (item <= asp_segment_last))
    {
      assert(err_msg == NULL) ;

      do
        {
          const asp_item_t* p ;
          asp_item_t  seg_item ;
          uint count ;

          assert((item >= asp_segment) && (item <= asp_segment_last)) ;

          seg_item = item ;

          p = append ;
          while ((item = *p) <= asp_large_last)
            {
              ++p ;
              ++count ;

              item = *p ;
              if ((item >= asp_repeat) && (item <= asp_repeat_last))
                {
                  count += item & asp_repeat_mask ;
                  ++p ;
                } ;
            } ;

          as_path_append_seg(asp, seg_item - asp_segment, count) ;

          if (asp->path.len == 0)
            {
              qassert(asp->last_seg == BGP_AS_SEG_NULL) ;
              qassert(seg_item == (asp_segment + BGP_AS_SEQUENCE)) ;
            } ;

          p = append ;
          while ((item = *p) <= asp_large_last)
            {
              as_t asn ;

              asn   = item ;
              count = 1 ;

              item = *++p ;
              if ((item >= asp_repeat) && (item <= asp_repeat_last))
                {
                  count += item & asp_repeat_mask ;

                  if (item & asp_q_value)
                    asn |= asp_q_bit ;
                  ++p ;
                } ;

              while (count-- != 0)
                as_path_append_asn(asp, asn) ;
            } ;

          append = p ;
          item   = *append++ ;
        }
      while (item != asp_test_term) ;
    }
  else if ((item >= asp_repeat) && (item <= asp_segment_last))
    {
      do
        {
          as_t asn ;
          uint count ;

          assert((item >= asp_repeat) && (item <= asp_repeat_last)) ;

          asn = *append++ ;

          count = (item & asp_repeat_mask) + 1 ;

          while (count-- != 0)
            {
              asp->path.len = as_path_add_item(asp, asp->path.len,
                                                             asn & ~asp_q_bit) ;
              if (asn > asp_small_last)
                asp->path.len = as_path_add_item(asp, asp->path.len,
                           asp_repeat + ((asn & asp_q_bit) ? asp_q_value : 0)) ;
            } ;

          item = *append++ ;
        }
      while (item != asp_term) ;
    }
  else
    assert(false) ;

  return asp ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Show contents of as_path.
 */
static void
as_path_show(FILE* where, as_path asp)
{
#if 0
  uint        ptr ;
  asp_item_t* path ;
  asp_item_t  item ;

  fprintf(where, "  last_seg=%u  len=%u %s\n",
                     asp->last_seg,
                     asp->path.len,
                     (asp->path.body == asp->embedded_path) ? "-- embedded"
                                                            : "") ;

  fprintf(where, "  total_length=%u  length_simple=%u  length_confed=%u\n",
                    asp->p.total_length,
                    asp->p.simple.length,
                    asp->p.confed.length) ;

  fprintf(where, "  %s  "
                     "set_count=%u  confed_set_count=%u  confed_seq_count=%u\n",
                    asp->p.simple_sequence ? "Simple" : "Not Simple",
                    asp->p.simple.set_count,
                    asp->p.confed.set_count,
                    asp->p.confed.seq_count) ;

  ptr = 0 ;
  path = asp->path.body ;

  if (path == NULL)
    {
      fprintf(where, "  NULL path body !!!\n") ;
      return ;
    } ;

  while (ptr < asp->path.len)
    {
      fprintf(where, "  %3d: ", ptr) ;

      item = path[ptr++] ;

      if   (item <= asp_small_last)
        {
          confirm(asp_small == 0) ; /* 0..asp_small_last is "small" */

          asp_item_t rep ;

          fprintf(where, "%10u", item) ;

          if ((ptr < asp->path.len) &&
                          (((rep = path[ptr]) & asp_repeat_sig) == asp_repeat))
            {
              fprintf(where, " x %u", (rep & asp_repeat_mask) + 1) ;

              if (((rep & asp_repeat_mask) == 0) ||
                                             ((rep & asp_q_value) != 0))
                {
                  fprintf(where, " ??? 0x%08X", rep) ;

                  if ((rep & asp_repeat_mask) == 0)
                    fprintf(where, " repeat count == 0 !!!") ;
                  if ((rep & asp_q_value) != 0)
                    fprintf(where, " qbit != 0 !!!") ;
                } ;

              ++ptr ;
            } ;
        }
      else if (item <= asp_large_last)
        {
          asp_item_t rep ;

          if ((ptr < asp->path.len) &&
                           (((rep = path[ptr]) & asp_repeat_sig) == asp_repeat))
            {
              if (rep & asp_q_value)
                item |= asp_q_bit ;

              fprintf(where, "0x%08X (qbit=%u)", item,
                                                  (rep & asp_q_value) ? 1 : 0) ;
              if (rep & asp_repeat_mask)
                fprintf(where, " x %u", (rep & asp_repeat_mask) + 1) ;

              ++ptr ;
            }
          else
            fprintf(where, "0x%08X ??? large ASN but missing repeat !!!",
                                                                 item) ;
        }
      else if (item <= asp_repeat_last)
        {
          fprintf(where, "0x%08X ??? detached repeat count !!!", item) ;
        }
      else if (item <= asp_segment_last)
        {
          if (as_path_seg(item))
            fprintf(where, "__Segment %u__", item - asp_segment);
          else
            fprintf(where, "0x%08X ??? invalid segment item !!!", item) ;
        }
      else
        {
          fprintf(where, "0x%08X ??? invalid item !!!", item) ;
        } ;

      fprintf(where, "\n") ;
    } ;

  fprintf(where, "  %3d: ", ptr) ;
  item = path[ptr] ;
  if (item == asp_term)
    fprintf(where, "--- end ---\n") ;
  else
    fprintf(where, "0x%08X ??? invalid terminator !!!\n", item) ;
#endif
} ;

/*------------------------------------------------------------------------------
 *
 */
static const struct as_path_post_process_test as_path_post_process_tests[] =
{
#if 0
    /************************************************************************
     * Tests for simple paths with no repeated ASn and no repeat counts.
     *
     * Checking that identifies ASN correctly, and does NOT see repeated
     * ASN where there are none -- even for large ASN that differ only in
     * their "q" bit.
     */
    { .title          = "Empty as_path",
      .length_simple  = 0,
      .expect_len     = 0,
      .items  = { asp_test_term },
    },

    { .title          = "Simple, short as_path -- no repeats",
      .length_simple  = 4,
      .expect_len     = 4,
      .items  = { 2529,
                  666,
                  1,
                  46709,
                  asp_test_term },
    },

    { .title          = "Simple, exactly 8 items -- no repeats",
      .length_simple  = 8,
      .expect_len     = 8,
      .items  = { 12123,
                  25417,
                  32529,
                  4666,
                  51,
                  6200,
                  73886,
                  88888,
                  asp_test_term },
    },

    { .title          = "Simple, more than 8 items -- no repeats",
      .length_simple  = 11,
      .expect_len     = 11,
      .items  = { 5417,
                  2529,
                  666,
                  1,
                  200,
                  77777,
                  2137,
                  77777,                        /* Not a repeat */
                  2136,
                  2134,
                  46709,
                  asp_test_term },
    },

    { .title          = "Large ASNs -- differing in qbit only (a)"
                                                               " -- no repeats",
      .length_simple  = 3,
      .expect_len     = 6,
      .items  = { 0xFFFFD00A,
                  asp_repeat + 0,
                  0xFFFFD00A,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFD00A,
                  asp_repeat + 0,               /* Not a repeat */
                  asp_test_term },
    },

    { .title          = "Large ASNs -- differing in qbit only (b)"
                                                               " -- no repeats",
      .length_simple  = 3,
      .expect_len     = 6,
      .items  = { 0xFFFFC00B,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFC00B,
                  asp_repeat + 0,
                  0xFFFFC00B,
                  asp_repeat + asp_q_value + 0, /* Not a repeat */
                  asp_test_term },
    },

    { .title          = "Large ASNs -- same qbits == 0 -- minimum value"
                                                               " -- no repeats",
      .length_simple  = 3,
      .expect_len     = 6,
      .items  = { 0xFFFFC000,
                  asp_repeat + 0,
                  0xFFFFC001,
                  asp_repeat + 0,
                  0xFFFFC000,
                  asp_repeat + 0,               /* Not a repeat */
                  asp_test_term },
    },

    { .title          = "Large ASNs -- same qbits == 1 -- maximum value"
                                                               " -- no repeats",
      .length_simple  = 3,
      .expect_len     = 6,
      .items  = { 0xFFFFDFFE,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFDFFE,
                  asp_repeat + asp_q_value + 0, /* Not a repeat */
                  asp_test_term },
    },

    { .title          = "Mix of large and small ASN -- starting with large",
      .length_simple  = 9,
      .expect_len     = 11,
      .items  = { 0xFFFFDFFF,
                  asp_repeat + asp_q_value + 0,
                  123,
                  4567,
                  0xFFFFDFFE,
                  asp_repeat + asp_q_value + 0,
                  77787,
                  0xFFFFBFFF,
                  77787,                        /* Not a repeat */
                  7,
                  0xFFFFBFFF,
                  asp_test_term },
    },

    { .title          = "Mix of large and small ASN"
                                              " -- starting with maximum small",
      .length_simple  = 10,
      .expect_len     = 13,
      .items  = { 0xFFFFBFFF,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 0,
                  123,
                  4567,
                  0xFFFFC000,
                  asp_repeat + 0,
                  77787,
                  0xFFFFC000,
                  asp_repeat + 0,               /* Not a repeat */
                  0xFFFFBFFF,
                  7,
                  0xFFFFBFFF,
                  asp_test_term },
    },

    { .title          = "Min to max ASN (includes 0)",
      .length_simple  = 15,
      .expect_len     = 19,
      .items  = { 0,                    /* valid for these purposes     */
                  1,
                  20,
                  300,
                  4000,
                  50000,
                  600000,
                  7000000,
                  80000000,
                  900000000,
                  0xFFFFBFFF,
                  0xFFFFC000,
                  asp_repeat + 0,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFDFFF,
                  asp_repeat + 0,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 0,
                  asp_test_term },
    },

    /************************************************************************
     * Tests to ensure rejects all forms of nonsense, wrt ASN and repeat
     * counts.  There are further tests below, for when segments are
     * involved.
     */
    { .title          = "Rubbish value -- first reserved value -- at start",
      .invalid        = true,
      .items  = { asp_reserved,
                  1,
                  20,
                  asp_test_term },
    },

    { .title          = "Rubbish value -- last reserved value"
                                                          " -- after small ASN",
      .invalid        = true,
      .items  = { 1,
                  asp_reserved_last,
                  20,
                  asp_test_term },
    },

    { .title          = "Rubbish value -- first reserved value"
                                                          " -- after large ASN",
      .invalid        = true,
      .items  = { 0xFFFFC245,
                  asp_repeat + asp_q_value + 0,
                  asp_reserved,
                  20,
                  asp_test_term },
    },

    { .title          = "Rubbish value -- last reserved value"
                                                          " -- after small ASN",
      .invalid        = true,
      .items  = { 0xFFFFC245,
                  asp_repeat + asp_q_value + 0,
                  asp_reserved_last,
                  20,
                  asp_test_term },
    },

    { .title          = "Broken segment marker at start",
      .invalid        = true,
      .items  = { asp_segment + 0,
                  1,
                  20,
                  asp_test_term },
    },

    { .title          = "Broken segment marker after small ASN",
      .invalid        = true,
      .items  = { 1,
                  asp_segment + 5,
                  20,
                  asp_test_term },
    },

    { .title          = "Broken segment marker after large ASN",
      .invalid        = true,
      .length_simple  = 4,
      .items  = { 0xFFFFC245,
                  asp_repeat + asp_q_value + 0,
                  asp_segment + 5,
                  20,
                  asp_test_term },
    },

    { .title          = "Invalid large -- end where repeat should be",
      .invalid        = true,
      .items  = { 1,
                  2,
                  0xFFFFC000,
                  asp_test_term },
    },

    { .title          = "Invalid large -- small ASN where repeat should be",
      .invalid        = true,
      .items  = { 0xFFFFDFFF,
                  11,
                  21,
                  0xFFFFC000,
                  41,
                  asp_test_term },
    },

    { .title          = "Invalid large -- large ASN where repeat should be",
      .invalid        = true,
      .length_simple  = 4,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  11,
                  21,
                  0xFFFFC000,   /* broken       */
                  0xFFFFDFFF,
                  asp_repeat + 0,
                  2222,
                  asp_test_term },
    },

    { .title          = "Invalid large -- segment where repeat should be",
      .invalid        = true,
      .length_simple  = 4,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  11,
                  21,
                  0xFFFFDFFF,   /* broken       */
                  asp_segment + BGP_AS_SET,
                  2222,
                  asp_test_term },
    },

    { .title          = "Invalid large -- rubbish where repeat should be",
      .invalid        = true,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  11,
                  21,
                  0xFFFFD456,   /* broken       */
                  asp_reserved_last,
                  2222,
                  asp_test_term },
    },

    { .title          = "Invalid large"
                                    " -- broken segment where repeat should be",
      .invalid        = true,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  11,
                  21,
                  0xFFFFD456,   /* broken       */
                  asp_segment + 255,
                  2222,
                  asp_test_term },
    },

    { .title          = "Detached repeat count -- at start, before small",
      .invalid        = true,
      .items  = { asp_repeat + 77,
                  2529,
                  asp_test_term },
    },

    { .title          = "Detached repeat count -- at start, before large",
      .invalid        = true,
      .items  = { asp_repeat + 66,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 3,
                  asp_test_term },
    },

    { .title          = "Detached repeat count -- after repeated small",
      .invalid        = true,
      .items  = { 2526,
                  asp_repeat + 5,
                  asp_repeat + 77,
                  asp_test_term },
    },

    { .title          = "Detached repeat count -- after large",
      .invalid        = true,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  asp_repeat + 77,
                  asp_test_term },
    },

    { .title          = "Detached repeat count -- after segment",
      .invalid        = true,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_repeat  + 77,
                  asp_test_term },
    },

    /************************************************************************
     * Tests for repeat counts -- in the absence of repeated ASN
     */
    { .title          = "Invalid 0 repeat count on small ASN",
      .invalid        = true,
      .items  = { 0xFFFFBFFF,
                  asp_repeat + 0,
                  asp_test_term },
    },

    { .title          = "Invalid 0 repeat count with qbit on small ASN",
      .invalid        = true,
      .items  = { 0,
                  asp_repeat + asp_q_value + 0,
                  asp_test_term },
    },

    { .title          = "Invalid non-zero repeat count with qbit on small ASN",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + asp_q_value + 4,
                  asp_test_term },
    },

    { .title          = "Repeat counts on small ASN -- leading",
      .length_simple  = (1 + 4) + 1 + (1 + 2) + 1,
      .expect_len     = 6,
      .items  = { 2529,
                  asp_repeat + 4,
                  123,
                  4567,
                  asp_repeat + 2,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeat counts on small ASN -- leading and trailing",
      .length_simple  = (1 + 4) + 1 + (1 + 2),
      .expect_len     = 5,
      .items  = { 2529,
                  asp_repeat + 4,
                  123,
                  4567,
                  asp_repeat + 2,
                  asp_test_term },
    },

    { .title          = "Repeat counts on small ASN -- middle",
      .length_simple  = 1 + (1 + 4) + 1 + (1 + 2) + 1,
      .expect_len     = 7,
      .items  = { 5417,
                  2529,
                  asp_repeat + 4,
                  123,
                  4567,
                  asp_repeat + 2,
                  524754,
                  asp_test_term },
    },

    { .title          = "Repeat counts on large ASN -- leading",
      .length_simple  = (1 + 4) + (1 + 0) + (1 + 2) + 1,
      .expect_len     = 7,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 4,
                  0xFFFFC000,
                  asp_repeat + 0,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 2,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeat counts on large ASN -- leading and trailing",
      .length_simple  = (1 + 4) + (1 + 0) + (1 + 2),
      .expect_len     = 6,
      .items  = { 0xFFFFC123,
                  asp_repeat + asp_q_value + 4,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFDFFF,
                  asp_repeat + 2,
                  asp_test_term },
    },

    { .title          = "Repeat counts on large ASN -- middle",
      .length_simple  = 1 + (1 + 4) + (1 + 0) + (1 + 2) + 1,
      .expect_len     = 8,
      .items  = { 2529,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 4,
                  0xFFFFC000,
                  asp_repeat + 0,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 2,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeat counts on mixed ASN",
      .length_simple  = (1 + 5) + 1 + (1 + 4) + (1 + 3) + (1 + 0) + (1 + 2) + 1,
      .expect_len     = 12,
      .items  = { 78787,
                  asp_repeat + 5,
                  2529,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 4,
                  5417,
                  asp_repeat + 3,
                  0xFFFFC000,
                  asp_repeat + 0,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 2,
                  7,
                  asp_test_term },
    },

    /************************************************************************
     * Tests for merging repeated ASN -- without repeat counts.
     */
    { .title          = "Repeated small ASN x 2 -- leading",
      .length_simple  = 2 + 3,
      .expect_len     = 5,
      .items  = { 2529,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 -- leading",
      .length_simple  = 3 + 3,
      .expect_len     = 5,
      .items  = { 2529,
                  2529,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 -- leading",
      .length_simple  = 7 + 3,
      .expect_len     = 5,
      .items  = { 2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  2529,         /* 4 */
                  2529,         /* 5 */
                  2529,         /* 6 */
                  2529,         /* 7 */
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 2 -- middle",
      .length_simple  = 1 + 2 + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 -- middle",
      .length_simple  = 1 + 3 + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,
                  2529,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 -- middle",
      .length_simple  = 1 + 7 + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  2529,         /* 4 */
                  2529,         /* 5 */
                  2529,         /* 6 */
                  2529,         /* 7 */
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 2 -- trailing",
      .length_simple  = 4 + 2,
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 -- trailing",
      .length_simple  = 4 + 3,
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 -- trailing",
      .length_simple  = 4 + 7,
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  2529,         /* 4 */
                  2529,         /* 5 */
                  2529,         /* 6 */
                  2529,         /* 7 */
                  asp_test_term },
    },

    /************************************************************************
     * Tests for merging repeated ASN -- with repeat counts.
     */
    { .title          = "Repeated small ASN x 2 with repeat count -- leading",
      .length_simple  = (1 + 200 + 1) + 3,
      .expect_len     = 5,
      .items  = { 2529,
                  asp_repeat + 200,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 with repeat count -- leading",
      .length_simple  = (1 + 1 + 777 + 1) + 3,
      .expect_len     = 5,
      .items  = { 2529,
                  2529,
                  asp_repeat + 777,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 with repeat count -- leading",
      .length_simple  = (3 + 100 + 2 + 200 + 2 + 300) + 3,
      .expect_len     = 5,
      .items  = { 2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  asp_repeat + 100,
                  2529,         /* 4 */
                  2529,         /* 5 */
                  asp_repeat + 200,
                  2529,         /* 6 */
                  2529,         /* 7 */
                  asp_repeat + 300,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 2 with repeat count -- middle",
      .length_simple  = 1 + (2 + 200) + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 with repeat count -- middle",
      .length_simple  = 1 + (1 + 100 + 1 + 200 + 1) + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,
                  asp_repeat + 100,
                  2529,
                  asp_repeat + 200,
                  2529,
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 with repeat count -- middle",
      .length_simple  = 1 + (3 + 100 + 3 + 200 + 1) + 3,
      .expect_len     = 6,
      .items  = { 1,
                  2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  asp_repeat + 100,
                  2529,         /* 4 */
                  2529,         /* 5 */
                  2529,         /* 6 */
                  asp_repeat + 200,
                  2529,         /* 7 */
                  123,
                  4567,
                  7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 2 with repeat count -- trailing",
      .length_simple  = 4 + (1 + 100 + 1),
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,
                  asp_repeat + 100,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 3 with repeat count -- trailing",
      .length_simple  = 4 + (1 + 100 + 2 + 200),
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,
                  asp_repeat + 100,
                  2529,
                  2529,
                  asp_repeat + 200,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN x 7 with repeat count -- trailing",
      .length_simple  = 4 + (3 + 100 + 2 + 200 + 2),
      .expect_len     = 6,
      .items  = { 1,
                  123,
                  4567,
                  7,
                  2529,         /* 1 */
                  2529,         /* 2 */
                  2529,         /* 3 */
                  asp_repeat + 100,
                  2529,         /* 4 */
                  2529,         /* 5 */
                  asp_repeat + 200,
                  2529,         /* 6 */
                  2529,         /* 7 */
                  asp_test_term },
    },

    /************************************************************************
     * Tests for merging of repeat counts for small ASN, where the repeat
     * count is not valid.
     */
    { .title          = "Repeated small ASN with repeat count 0"
                                                   " -- leading, first invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with repeat count 0"
                                                  " -- leading, second invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with repeat count 0"
                                                    " -- leading, last invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + 0,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with repeat count 0"
                                                    " -- middle, first invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with repeat count 0"
                                                   " -- middle, second invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with repeat count 0"
                                                     " -- middle, last invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + 0,
                  22,
                  asp_test_term },
    },



    { .title          = "Repeated small ASN with qbit"
                                                  " -- trailing, first invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                 " -- trailing, second invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                   " -- trailing, last invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  asp_test_term },
    },



    { .title          = "Repeated small ASN with qbit"
                                                   " -- leading, first invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                  " -- leading, second invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                    " -- leading, last invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                    " -- middle, first invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                   " -- middle, second invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                     " -- middle, last invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  22,
                  asp_test_term },
    },



    { .title          = "Repeated small ASN with qbit"
                                                  " -- trailing, first invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                 " -- trailing, second invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit"
                                                   " -- trailing, last invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 7,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                  " -- trailing, first invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                 " -- trailing, second invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                   " -- trailing, last invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  asp_test_term },
    },



    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                   " -- leading, first invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                  " -- leading, second invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                    " -- leading, last invalid",
      .invalid        = true,
      .items  = { 2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                    " -- middle, first invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                   " -- middle, second invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                     " -- middle, last invalid",
      .invalid        = true,
      .items  = { 11,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  22,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                  " -- trailing, first invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                 " -- trailing, second invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with qbit and repeat count 0"
                                                   " -- trailing, last invalid",
      .invalid        = true,
      .items  = { 33,
                  2529,
                  asp_repeat + 1,
                  2529,
                  2529,
                  asp_repeat + 200,
                  2529,
                  2529,
                  asp_repeat + asp_q_value + 0,
                  asp_test_term },
    },

    /************************************************************************
     * Test for repeat count overflow when merging repeats.
     */
    { .title          = "Many repeated small ASN"
                                              "-- at limit before overflow (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,

      .stop = true,

       .items  = { 2529,                 /*    1         */
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  2529,
                  asp_test_term },
    },

    { .title          = "Many repeated small ASN"
                                              "-- at limit before overflow (2)",
      .length_simple  = asp_repeat_max + 1 + 12 + 1,
      .expect_len     = 4,
      .items  = { 2529,                 /*    1         */
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  2529,
                  asp_repeat + 12,
                  5417,
                  asp_test_term },
    },

    { .title          = "Many repeated large ASN"
                                              "-- at limit before overflow (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { asp_large + 123,              /*    1         */
                  asp_repeat + asp_q_value + 0,
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  asp_large + asp_q_bit + 123,
                  asp_test_term },
    },

    { .title          = "Many repeated large ASN"
                                              "-- at limit before overflow (2)",
      .length_simple  = asp_repeat_max + 1 + 12 + 1,
      .expect_len     = 4,
      .items  = { asp_large + 123,      /*    1         */
                  asp_repeat + 0,
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  asp_large + 123,
                  asp_repeat + 12,
                  5417,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with large repeat counts"
                                              "-- at limit before overflow (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  asp_repeat + 1,       /*    2         */
                  2529,                 /*    3         */
                  2529,                 /*    4         */
                  asp_repeat + 2042,    /* 2046         */
                  2529,                 /* 2047         */
                  2529,                 /* 2048         */
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with large repeat counts"
                                              "-- at limit before overflow (2)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  asp_repeat + 1,       /*    2         */
                  2529,                 /*    3         */
                  2529,                 /*    4         */
                  asp_repeat + 2036,    /* 2040         */
                  2529,                 /* 2041         */
                  2529,                 /* 2042         */
                  asp_repeat + 6,       /* 2048         */
                  asp_test_term },
    },

    { .title          = "Many repeated small ASN -- just overflows (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  2529,                 /*    2         */
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  2529,
                  asp_test_term },
    },

    { .title          = "Many repeated small ASN -- just overflows (2)",
      .length_simple  = asp_repeat_max + 1 + 12 + 1,
      .expect_len     = 4,
      .items  = { 2529,                 /*    1         */
                  2529,                 /*    2         */
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  2529,
                  asp_repeat + 12,
                  5417,
                  asp_test_term },
    },

    { .title          = "Many repeated large ASN -- just overflows (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { asp_large + 123,              /*    1 + 1     */
                  asp_repeat + asp_q_value + 1,
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  asp_large + asp_q_bit + 123,
                  asp_test_term },
    },

    { .title          = "Many repeated large ASN -- just overflows (2)",
      .length_simple  = asp_repeat_max + 1 + 12 + 1,
      .expect_len     = 4,
      .items  = { asp_large + 123,      /*    1 + 1     */
                  asp_repeat + 1,
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  asp_large + 123,
                  asp_repeat + 12,
                  5417,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with large repeat counts"
                                                      "-- just overflows (1)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  asp_repeat + 1,       /*    2         */
                  2529,                 /*    3         */
                  2529,                 /*    4         */
                  asp_repeat + 2043,    /* 2047         */
                  2529,                 /* 2048         */
                  2529,                 /* 2049         */
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with large repeat counts"
                                                        "-- just overflows (2)",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  asp_repeat + 1,       /*    2         */
                  2529,                 /*    3         */
                  2529,                 /*    4         */
                  asp_repeat + 2036,    /* 2040         */
                  2529,                 /* 2041         */
                  2529,                 /* 2042         */
                  asp_repeat + 7,       /* 2049         */
                  asp_test_term },
    },

    { .title          = "Many repeated small ASN -- huge overflow",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,                 /*    1         */
                  2529,                 /*    2         */
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max,
                  2529,
                  asp_repeat + 200,
                  2529,
                  asp_test_term },
    },

    { .title          = "Many repeated large ASN -- huge overflow",
      .length_simple  = asp_repeat_max + 1 + 1,
      .expect_len     = 3,
      .items  = { asp_large + 999,      /*    1 + 1     */
                  asp_repeat + 1,
                  asp_test_term },
      .append = { asp_repeat + asp_repeat_max - 1,
                  asp_large + 999,
                  asp_repeat + 150,
                  asp_large + 999,
                  asp_repeat + 0,
                  5417,
                  asp_test_term },
    },

    { .title          = "Repeated small ASN with large repeat counts"
                                                             "-- huge overflow",
      .length_simple  = asp_repeat_max + 1,
      .expect_len     = 2,
      .items  = { 2529,
                  asp_repeat + 2000,
                  2529,
                  2529,
                  asp_repeat + 1000,
                  2529,
                  2529,
                  asp_repeat +  500,
                  asp_test_term },
    },

    /************************************************************************
     * Test for not redundant segment markers and no crossing repeats
     */
    { .title          = "Not redundant mix of sequences"
                                                   " -- start and end SEQUENCE",
      .length_simple  = (1 + 3) + 1 + (1 + 500) ,
      .length_confed  = (1 + 4) + 1,
      .expect_len     = 8,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 2529,
                  asp_repeat + 3,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat +  500,
                  asp_test_term },
    },

    { .title          = "Not redundant mix of sequences"
                                            " -- start and end CONFED_SEQUENCE",
      .length_simple  = (1 + 4) + 1,
      .length_confed  = (1 + 3) + 1 + (1 + 500),
      .expect_len     = 9,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 2,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat +  500,
                  asp_test_term },
    },

    { .title          = "Not redundant mix of sequences"
                                       " -- start CONFED_SEQUENCE end SEQUENCE",
      .length_simple  = (1 + 4) + 1 + (1 + 2),
      .length_confed  = (1 + 3) + 1 + (1 + 500),
      .expect_len     = 12,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 2,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat +  500,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 2,
                  asp_test_term },
    },

    { .title          = "Not redundant mix of segments"
                                                   " -- start SET end SEQUENCE",
      .length_simple  = (1) + (1 + 4) + 1 + (1) + (1 + 2),
      .length_confed  = 0,
      .expect_len     = 10,
      .last_seg       = BGP_AS_SEQUENCE,
      .set_count      = 2,
      .items  = { asp_segment + BGP_AS_SET,
                  2529,
                  asp_repeat + 3,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_repeat +  500,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 2,
                  asp_test_term },
    },

    { .title          = "Not redundant mix of segments"
                                                   " -- start SEQUENCE end SET",
      .length_simple  = (1 + 3) + 1 + (1) + (1 + 500) + (1),
      .length_confed  = 0,
      .expect_len     = 9,
      .last_seg       = BGP_AS_SET,
      .set_count      = 2,
      .items  = { 2529,
                  asp_repeat + 3,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_repeat + 4,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat +  500,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_repeat + 2,
                  asp_test_term },
    },

    { .title          = "Not redundant mix of many segments (1)",
      .length_simple  = 1 + (1) + 1 + (1) + (1) + 1 + (1) + (1) + (1),
      .length_confed  = (1) + 1 + (1) + (1) + (1) + (1) + 1,
      .expect_len     = 31,
      .last_seg       = BGP_AS_SET,
      .set_count        = 6,
      .confed_set_count = 5,
      .confed_seq_count = 2,
     .items  = { 2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_segment + BGP_AS_SET,
                  2529,
                  asp_test_term },
    },

    /************************************************************************
     * Redundant segment markers revealing repeats
     */
    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                            " -- reveal repeat -- small ASN -- no repeat count",
      .length_simple  = 8,
      .length_confed  = 0,
      .expect_len     = 6,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (1)",
      .length_simple  = 8 + 3 + 4,
      .length_confed  = 0,
      .expect_len     = 6,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (2)",
      .length_simple  = 8 + 4,
      .length_confed  = 0,
      .expect_len     = 6,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (3)",
      .length_simple  = 8 + 3,
      .length_confed  = 0,
      .expect_len     = 6,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 0",
      .length_simple  = 2 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 0,
      .expect_len     = 8,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 1",
      .length_simple  = 2 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 0,
      .expect_len     = 8,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                                         " -- no reveal repeat -- qbit = 1 & 0",
      .length_simple  = 2 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 0,
      .expect_len     = 10,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SEQUENCE in SEQUENCE"
                                         " -- no reveal repeat -- qbit = 0 & 1",
      .length_simple  = 2 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 0,
      .expect_len     = 10,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  2529,
                  0xFFFFC000,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                            " -- reveal repeat -- small ASN -- no repeat count",
      .length_simple  = 1,
      .length_confed  = 7,
      .expect_len     = 7,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  2529,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (1)",
      .length_simple  = 2,
      .length_confed  = (1 + 3) + (1 + 4) + 4,
      .expect_len     = 8,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (2)",
      .length_simple  = 1,
      .length_confed  = 2 + (1 + 4) + 4,
      .expect_len     = 7,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  2529,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (3)",
      .length_simple  = 2,
      .length_confed  = (1 + 3) + 5,
      .expect_len     = 8,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 0",
      .length_simple  = 1,
      .length_confed  = 1 + (1 + 5) + (1 + 4) + 4,
      .expect_len     = 9,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 1",
      .length_simple  = 2,
      .length_confed  = (1 + 5) + (1 + 4) + 4,
      .expect_len     = 9,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                                         " -- no reveal repeat -- qbit = 1 & 0",
      .length_simple  = 1,
      .length_confed  = 1 + (1 + 5) + (1 + 4) + 4,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in CONFED_SEQUENCE"
                                         " -- no reveal repeat -- qbit = 0 & 1",
      .length_simple  = 2,
      .length_confed  = (1 + 5) + (1 + 4) + 4,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  2529,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_CONFED_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                            " -- reveal repeat -- small ASN -- no repeat count",
      .length_simple  = 7,
      .length_confed  = 1,
      .expect_len     = 8,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (1)",
      .length_simple  = (1 + 3) + (1 + 4) + 4,
      .length_confed  = 2,
      .expect_len     = 9,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (2)",
      .length_simple  = 2 + (1 + 4) + 4,
      .length_confed  = 1,
      .expect_len     = 8,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                          " -- reveal repeat -- small ASN -- repeat counts (3)",
      .length_simple  = (1 + 3) + 5,
      .length_confed  = 2,
      .expect_len     = 9,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  asp_repeat + 3,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 0",
      .length_simple  = 1 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 1,
      .expect_len     = 10,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                                     " -- reveal repeat -- large ASN qbit = 1",
      .length_simple  = (1 + 5) + (1 + 4) + 4,
      .length_confed  = 2,
      .expect_len     = 10,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant CONFED_SET in SEQUENCE"
                                         " -- no reveal repeat -- qbit = 1 & 0",
      .length_simple  = 1 + (1 + 5) + (1 + 4) + 4,
      .length_confed  = 1,
      .expect_len     = 12,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  0xFFFFDFFF,
                  asp_repeat + asp_q_value + 5,
                  asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFDFFF,
                  asp_repeat + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    { .title          = "Redundant SET in SEQUENCE"
                                         " -- no reveal repeat -- qbit = 0 & 1",
      .length_simple  = (1 + 5) + (1 + 4) + 4,
      .length_confed  = 2,
      .expect_len     = 12,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  2529,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + 5,
                  asp_segment + BGP_AS_SET,
                  asp_segment + BGP_AS_SEQUENCE,
                  0xFFFFC000,
                  asp_repeat + asp_q_value + 4,
                  2529,
                  7777,
                  2529,
                  1234,
                  asp_test_term },
    },

    /************************************************************************
     * Sorting and de-dup of sets
     */
    { .title          = "Sort and de-dup SET -- 1 small ASN",
      .length_simple  = 1,
      .length_confed  = 0,
      .expect_len     = 2,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  0,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET -- 1 small ASN",
      .length_simple  = 0,
      .length_confed  = 1,
      .expect_len     = 2,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET -- small ASN -- no change",
      .length_simple  = 1,
      .length_confed  = 0,
      .expect_len     = 11,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  0,
                  10,
                  200,
                  3000,
                  40000,
                  500000,
                  6000000,
                  70000000,
                  800000000,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET -- small ASN -- no change",
      .length_simple  = 0,
      .length_confed  = 1,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  0,
                  10,
                  200,
                  3000,
                  40000,
                  500000,
                  6000000,
                  70000000,
                  800000000,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET -- small ASN -- sort only",
      .length_simple  = 1,
      .length_confed  = 0,
      .expect_len     = 11,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_small_last,
                  800000000,
                  70000000,
                  6000000,
                  500000,
                  40000,
                  3000,
                  200,
                  10,
                  0,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET -- small ASN -- sort only",
      .length_simple  = 0,
      .length_confed  = 1,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  10,
                  0,
                  3000,
                  500000,
                  800000000,
                  6000000,
                  200,
                  70000000,
                  40000,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET -- small ASN -- sort & de-dup",
      .length_simple  = 1,
      .length_confed  = 0,
      .expect_len     = 11,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_small_last,
                  800000000,
                  70000000,
                  6000000,
                  500000,
                  40000,
                  3000,
                  200,
                  10,
                  0,
                  0,
                  10,
                  200,
                  3000,
                  40000,
                  500000,
                  6000000,
                  70000000,
                  800000000,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET -- small ASN"
                                                            " -- sort & de-dup",
      .length_simple  = 0,
      .length_confed  = 1,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  10,
                  0,
                  3000,
                  500000,
                  800000000,
                  6000000,
                  200,
                  70000000,
                  40000,
                  asp_small_last,
                  0,
                  3000,
                  800000000,
                  200,
                  70000000,
                  40000,
                  800000000,
                  200,
                  70000000,
                  200,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET -- small ASN "
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 1,
      .length_confed  = 0,
      .expect_len     = 11,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_small_last,
                  800000000,
                  70000000,
                  asp_repeat + 1,
                  6000000,
                  500000,
                  40000,
                  3000,
                  200,
                  10,
                  0,
                  asp_repeat + 77,
                  0,
                  10,
                  200,
                  3000,
                  asp_repeat + asp_repeat_max,
                  40000,
                  500000,
                  6000000,
                  70000000,
                  800000000,
                  asp_small_last,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET -- small ASN"
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 0,
      .length_confed  = 1,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  10,
                  0,
                  3000,
                  500000,
                  800000000,
                  asp_repeat + asp_repeat_max,
                  6000000,
                  200,
                  70000000,
                  40000,
                  asp_small_last,
                  asp_repeat + 77,
                  0,
                  3000,
                  800000000,
                  200,
                  70000000,
                  asp_repeat + 1,
                  40000,
                  800000000,
                  200,
                  70000000,
                  200,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET and CONFED_SET -- small ASN "
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 1,
      .length_confed  = 1,
      .expect_len     = 11,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_SET,
                  800000000,
                  asp_repeat + 1,
                  6000000,
                  40000,
                  200,
                  0,
                  asp_repeat + 77,
                  0,
                  200,
                  asp_repeat + asp_repeat_max,
                  40000,
                  6000000,
                  800000000,
                  asp_segment + BGP_AS_CONFED_SET,
                  3000,
                  500000,
                  asp_repeat + asp_repeat_max,
                  70000000,
                  asp_small_last,
                  asp_repeat + 77,
                  3000,
                  70000000,
                  asp_repeat + 1,
                  70000000,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET and SET -- small ASN "
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 1,
      .length_confed  = 1,
      .expect_len     = 12,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  10,
                  3000,
                  500000,
                  asp_repeat + asp_repeat_max,
                  70000000,
                  asp_small_last,
                  asp_repeat + 77,
                  3000,
                  70000000,
                  asp_repeat + 1,
                  70000000,
                  asp_segment + BGP_AS_SET,
                  800000000,
                  asp_repeat + 1,
                  6000000,
                  40000,
                  200,
                  0,
                  asp_repeat + 77,
                  0,
                  200,
                  asp_repeat + asp_repeat_max,
                  40000,
                  6000000,
                  800000000,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup SET and CONFED_SET -- mixed ASN "
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 1,
      .length_confed  = 1,
      .expect_len     = 16,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_SET,
                  6000000,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  200,
                  0xFFFFC123,
                  asp_repeat + 0,
                  0,
                  0xFFFFC123,
                  asp_repeat + 99,
                  200,
                  asp_repeat + asp_repeat_max,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 9,
                  6000000,
                  asp_segment + BGP_AS_CONFED_SET,
                  3000,
                  0xFFFFD321,
                  asp_repeat + 0,
                  70000000,
                  asp_repeat + asp_repeat_max,
                  0xFFFFD321,
                  asp_repeat + asp_q_value + 99,
                  asp_small_last,
                  asp_repeat + 77,
                  3000,
                  70000000,
                  asp_repeat + 1,
                  0xFFFFD321,
                  asp_repeat + 6,
                  asp_test_term },
    },

    { .title          = "Sort and de-dup CONFED_SET and SET -- mixed ASN "
                                          "-- sort & de-dup -- discard repeats",
      .length_simple  = 1,
      .length_confed  = 1,
      .expect_len     = 16,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  3000,
                  0xFFFFD321,
                  asp_repeat + 0,
                  70000000,
                  asp_repeat + asp_repeat_max,
                  0xFFFFD321,
                  asp_repeat + asp_q_value + 99,
                  asp_small_last,
                  asp_repeat + 77,
                  3000,
                  70000000,
                  asp_repeat + 1,
                  0xFFFFD321,
                  asp_repeat + 6,
                  asp_segment + BGP_AS_SET,
                  6000000,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 0,
                  200,
                  0xFFFFC123,
                  asp_repeat + 0,
                  0,
                  0xFFFFC123,
                  asp_repeat + 99,
                  200,
                  asp_repeat + asp_repeat_max,
                  0xFFFFC123,
                  asp_repeat + asp_q_value + 9,
                  6000000,
                  asp_test_term },
    },

    /************************************************************************
     * Invalid termination of sets
     */
    { .title          = "SET marker immediately followed by rubbish",
      .expect_len     = 2,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_reserved,
                  asp_test_term },
    },

    { .title          = "CONFED_SET marker immediately followed by rubbish",
      .expect_len     = 2,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  asp_reserved_last,
                  asp_test_term },
    },

    { .title          = "SET marker immediately followed by broken segment",
      .expect_len     = 2,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_segment + 9,
                  asp_test_term },
    },

    { .title          = "CONFED_SET marker immediately"
                                                  " followed by broken segment",
      .expect_len     = 2,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  asp_segment + 0,
                  asp_test_term },
    },

    { .title          = "SET marker immediately"
                                         " followed by broken small ASN repeat",
      .expect_len     = 3,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  77,
                  asp_repeat + 0,
                  asp_test_term },
    },

    { .title          = "CONFED_SET marker immediately"
                                         " followed by broken small ASN repeat",
      .expect_len     = 3,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  77,
                  asp_repeat + asp_q_value + 3,
                  asp_test_term },
    },

    { .title          = "SET marker immediately"
                                   " followed by broken large ASN -- no repeat",
      .expect_len     = 2,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  0xFFFFD666,
                  asp_test_term },
    },

    { .title          = "CONFED_SET marker immediately"
                              " followed by broken large ASN -- rubbish repeat",
      .expect_len     = 3,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  0xFFFFD666,
                  asp_reserved + 77,
                  asp_test_term },
    },

    { .title          = "SET terminated by rubbish",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  77,
                  22,
                  77,
                  asp_reserved,
                  asp_test_term },
    },

    { .title          = "CONFED_SET terminated by rubbish",
      .expect_len     = 5,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  asp_large + 667,
                  asp_repeat + 0,
                  67676,
                  asp_large + 667,
                  asp_repeat + 0,
                  asp_reserved_last,
                  asp_test_term },
    },

    { .title          = "SET terminated by broken segment",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  44,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  44,
                  asp_segment + 9,
                  asp_test_term },
    },

    { .title          = "CONFED_SET terminated by broken segment",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  asp_large + 1234,
                  asp_repeat + 3,
                  99,
                  asp_large + 1234,
                  asp_repeat + 4,
                  asp_segment + 0,
                  asp_test_term },
    },

    { .title          = "SET terminated by broken small ASN repeat",
      .expect_len     = 6,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 8,
                  77,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 8,
                  asp_repeat + 0,
                  asp_test_term },
    },

    { .title          = "CONFED_SET terminated by broken small ASN repeat",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  77,
                  33,
                  77,
                  asp_repeat + asp_q_value + 3,
                  asp_test_term },
    },

    { .title          = "SET terminated by broken large ASN -- no repeat",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  0xFFFFD666,
                  asp_test_term },
    },

    { .title          = "CONFED_SET terminated by"
                                          " broken large ASN -- rubbish repeat",
      .expect_len     = 4,
      .invalid        = true,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 0,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  999,
                  111,
                  999,
                  0xFFFFD666,
                  asp_reserved + 77,
                  asp_test_term },
    },

    /************************************************************************
     * Tests for as_path_append_seg() and as_path_append_asn()
     */
    { .title          = "append SEQUENCE to empty as_path -- mix of ASN",
      .expect_len     = 9,
      .length_simple  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { asp_test_term },
      .append = { asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append SET to empty as_path -- mix of ASN",
      .expect_len     = 9,
      .length_simple  = 1,
      .invalid        = false,
      .last_seg       = BGP_AS_SET,
      .set_count      = 1,
      .items  = { asp_test_term },
      .append = { asp_segment + BGP_AS_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 2,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append CONFED_SEQUENCE to empty as_path -- mix of ASN",
      .expect_len     = 10,
      .length_confed  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append CONFED_SET to empty as_path -- mix of ASN",
      .expect_len     = 9,
      .length_confed  = 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SET,
      .confed_set_count = 1,
      .items  = { asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 2,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append SEQUENCE to existing SEQUENCE -- mix of ASN",
      .expect_len     = 12,
      .length_simple  = 3 + 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_SEQUENCE,
      .items  = { 1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append SET to existing SEQUENCE -- mix of ASN",
      .expect_len     = 12,
      .length_simple  = 3 + (1),
      .invalid        = false,
      .last_seg       = BGP_AS_SET,
      .set_count      = 1,
      .items  = { 1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 2,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append CONFED_SEQUENCE to existing SEQUENCE"
                                                               " -- mix of ASN",
      .expect_len     = 13,
      .length_simple  = 3,
      .length_confed  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { 1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append CONFED_SET to existing SEQUENCE -- mix of ASN",
      .expect_len     = 12,
      .length_simple  = 3,
      .length_confed  = 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SET,
      .confed_set_count = 1,
      .items  = { 1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 2,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append SEQUENCE to existing CONFED_SEQUENCE"
                                                               " -- mix of ASN",
      .expect_len     = 14,
      .length_simple  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .length_confed  = 3,
      .invalid        = false,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append SET to existing CONFED_SEQUENCE -- mix of ASN",
      .expect_len     = 13,
      .length_simple  = (1),
      .length_confed  = 3,
      .invalid        = false,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 2,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append CONFED_SEQUENCE to existing CONFED_SEQUENCE"
                                                               " -- mix of ASN",
      .expect_len     = 13,
      .length_confed  = 3 + 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append CONFED_SET to existing CONFED_SEQUENCE"
                                                               " -- mix of ASN",
      .expect_len     = 13,
      .length_confed  = 3 + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SET,
      .confed_set_count = 1,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  1,
                  20,
                  2529,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 2,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append SEQUENCE to existing SET -- mix of ASN",
      .expect_len     = 14,
      .length_simple  = (1) + 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .length_confed  = 0,
      .invalid        = false,
      .last_seg       = BGP_AS_SEQUENCE,
      .set_count        = 1,
      .confed_set_count = 0,
      .confed_seq_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append SET to existing SET -- mix of ASN",
      .expect_len     = 13,
      .length_simple  = (1) + (1),
      .length_confed  = 0,
      .invalid        = false,
      .last_seg       = BGP_AS_SET,
      .set_count        = 2,
      .confed_set_count = 0,
      .confed_seq_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 2,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append CONFED_SEQUENCE to existing SET -- mix of ASN",
      .expect_len     = 14,
      .length_simple  = (1),
      .length_confed  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .set_count        = 1,
      .confed_set_count = 0,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append CONFED_SET to existing SET -- mix of ASN",
      .expect_len     = 13,
      .length_simple  = (1),
      .length_confed  = (1),
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .confed_seq_count = 0,
      .items  = { asp_segment + BGP_AS_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 2,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append SEQUENCE to existing CONFED_SET"
                                                               " -- mix of ASN",
      .expect_len     = 14,
      .length_simple  = 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .length_confed  = (1),
      .invalid        = false,
      .last_seg       = BGP_AS_SEQUENCE,
      .confed_set_count = 1,
      .confed_seq_count = 0,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append SET to existing CONFED_SET -- mix of ASN",
      .expect_len     = 13,
      .length_simple  = (1),
      .length_confed  = (1),
      .invalid        = false,
      .last_seg       = BGP_AS_SET,
      .set_count        = 1,
      .confed_set_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + 2,
                  12,
                  666,
                  asp_test_term },
    },

    { .title          = "append CONFED_SEQUENCE to existing CONFED_SET"
                                                               " -- mix of ASN",
      .expect_len     = 14,
      .length_confed  = (1) + 2 + (1 + 0) + (1 + 21) + (1 + 4) + 1,
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SEQUENCE,
      .confed_set_count = 1,
      .confed_seq_count = 1,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SEQUENCE,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 0,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  asp_test_term },
    },

    { .title          = "append CONFED_SET to existing CONFED_SET"
                                                               " -- mix of ASN",
      .expect_len     = 13,
      .length_confed  = (1) + (1),
      .invalid        = false,
      .last_seg       = BGP_AS_CONFED_SET,
      .confed_set_count = 2,
      .confed_seq_count = 0,
      .items  = { asp_segment + BGP_AS_CONFED_SET,
                  1,
                  2529,
                  20,
                  asp_test_term },
      .append = { asp_segment + BGP_AS_CONFED_SET,
                  2529,
                  5417,
                  asp_large + 1234,
                  asp_repeat + 2,
                  666,
                  asp_repeat + 21,
                  asp_large + 1234,
                  asp_repeat + asp_q_value + 4,
                  12,
                  666,
                  asp_test_term },
    },
#endif
    /* Terminator
     */
    { .title  = NULL }
} ;
