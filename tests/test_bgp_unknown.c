#include <misc.h>
#include <zebra.h>

#include "stdio.h"

#include "qlib_init.h"
#include "command.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"

/*==============================================================================
 * bgpd/bgp_unknown.c torture tests
 *
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
typedef struct unk_attr  unk_attr_t ;
typedef struct unk_attr* unk_attr ;

struct unk_attr
{
  byte        flags ;
  byte        type ;
  const char* body ;            /* NULL <=> none        */
} ;

typedef struct unk_attr_set  unk_attr_set_t ;
typedef struct unk_attr_set* unk_attr_set ;

struct unk_attr_set
{
  const char* name ;
  unk_attr_t  set[] ;
} ;

typedef uint type_counts[256] ;

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_unk_sort(void) ;
static void test_unk_copy(void) ;
static void test_unk_transitive(void) ;
static void test_unk_store(void) ;
static void test_unk_add_stored(void) ;

static byte* make_unknown(unk_attr ts, uint* p_length) ;
static byte* expect_unknowns(unk_attr_t* ts, uint* p_length,
                                                               bool opt_trans) ;
static attr_unknown_state_t expect_state(unk_attr_t* ts, bool opt_trans) ;
static void count_scan(type_counts counts, unk_attr_t* ts) ;
static void show_delta(const byte* got, const byte* expect, uint len) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
  qlib_init_first_stage(0);     /* Absolutely first             */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start BGP Unknown Attribute testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  bgp_attr_start() ;            /* wind up the entire attribute store   */

  test_unk_sort() ;
  test_unk_copy() ;
  test_unk_transitive() ;
  test_unk_store() ;
  test_unk_add_stored() ;

  bgp_attr_finish() ;           /* close it down again                  */

  fprintf(stderr, "Finished BGP Unknown Attribute testing") ;

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
static unk_attr_set_t set_0 =
  {
    /* Empty
     */
    .name = "Set 0 -- empty set",
    .set  =
    {
      { .body = NULL }
    }
  } ;

static unk_attr_set_t set_1 =
  {
    /* No repeats, mix of all kinds of attributes, but no flag oddities.
     */
    .name = "Set 1 -- mixed bag, valid flags",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE,    /* well-known   */
        .type  = 77,
        .body  = "set_1_77_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 12,
        .body  = "set_1_12_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 200,
        .body  = "set_1_200_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE,    /* well-known   */
        .type  = 22,
        .body  = "set_1_22_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 97,
        .body  = "set_1_97_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 36,
        .body  = "set_1_36_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 199,
        .body  = "set_1_199_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 121,
        .body  = "set_1_121_1 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

/* Set_1a is Optional-Transitives from Set_1, plus the not-repeated
 * set_1ax entry.
 *
 * See test_unk_add_stored()
 */
static unk_attr_t set_1ax =
  {
        .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 1,
        .body  = "set_1a_1_1 Optional-Transitive",
  } ;

static unk_attr_set_t set_1a =
  {
    /* No repeats, mix of all kinds of attributes, but no flag oddities.
     */
    .name = "Set 1a -- stored Set 1 plus Optional-Transitive",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 1,
        .body  = "set_1a_1_1 Optional-Transitive",
      },

      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 12,
        .body  = "set_1_12_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 97,
        .body  = "set_1_97_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 199,
        .body  = "set_1_199_1 Optional-Transitive",
      },
      { .body = NULL }
    }
  };

/* Set_1b is the same as Set_1, plus the not-repeated set_1bx entry.
 *
 * See test_unk_add_stored()
 */
static unk_attr_t set_1bx =
  {
        .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED | 13,
        .type  = 1,
        .body  = "set_1b_1_1 Optional-Non-Transitive",
  } ;

static unk_attr_set_t set_1b =
  {
    .name = "Set 1b -- stored Set 1 plus Optional-Non-Transitive",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED | 13,
        .type  = 1,
        .body  = "set_1b_1_1 Optional-Non-Transitive",
      },

      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 12,
        .body  = "set_1_12_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 97,
        .body  = "set_1_97_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,
        .type  = 199,
        .body  = "set_1_199_1 Optional-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_2 =
  {
    /* No repeats, mix of all kinds of attributes, with flag oddities.
     *
     * Some zero length bodies.
     */
    .name = "Set 2 -- no repeats, some odd flags",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_2_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_2_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_2_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_2_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_2_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_2_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_2_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_2_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 1,
        .body  = "",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 17,
        .body  = "",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 45,
        .body  = "",
      },
      { .flags = BGP_ATF_TRANSITIVE | 9,
        .type  = 2,
        .body  = "",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED ,
        .type  = 18,
        .body  = "",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 46,
        .body  = "",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_3 =
  {
    /* No repeats, mix of all kinds of attributes, with flag oddities
     * and some genuinely long attributes.
     */
    .name = "Set 3 -- no repeats, some odd flags and some long attributes",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_3_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_3_41_1 Optional-Transitive"
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  32 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  64 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  96 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 128 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 160 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 192 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 224 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 256 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 288 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 320 */
                        "0123456789ABCDEF" "0123456789ABCDEF", /* 352 */
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_3_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_3_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_3_5_1 Optional-Transitive"
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  32 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  64 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  96 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 128 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 160 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 192 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 224 */
                        "0123456789ABCDEF" "0123456789ABCDEF", /* 256 */
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_3_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_2_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_2_50_1 Optional-Non-Transitive"
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  32 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  64 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /*  96 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 128 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 160 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 192 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 224 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 256 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 288 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 320 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 352 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 384 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 416 */
                        "0123456789ABCDEF" "0123456789ABCDEF"  /* 448 */
                        "0123456789ABCDEF" "0123456789ABCDEF", /* 480 */
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_4 =
  {
    /* All repeated, mix of all kinds of attributes, with flag oddities.
     */
    .name = "Set 4 -- all repeated, some odd flags",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_4_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_4_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_4_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_4_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_4_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_4_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_4_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_4_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_4_13_2 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_4_41_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_4_72_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_4_27_2 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_4_5_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_4_91_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_4_3_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_4_50_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_5 =
  {
    /* One repeat -- Optional-Transitive and Optional-Non-Transitive
     */
    .name = "Set 5 -- one repeat Optional-Transitive & Optional-Non-Transitive",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_5_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_5_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_5_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_5_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_5_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_5_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_5_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_5_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 41,
        .body  = "set_5_41_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_6 =
  {
    /* No Optional-Transitive
     */
    .name = "Set 6 -- No Optional-Transitive",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_6_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_6_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_6_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_6_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_6_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 41,
        .body  = "set_6_41_1 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_7 =
  {
    /* No Optional-Non-Transitive
     */
    .name = "Set 7 -- No Optional-Non-Transitive",
    .set  =
    {
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_7_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_7_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_7_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_7_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_7_3_1 Optional-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_8 =
  {
    /* No Well-known
     */
    .name = "Set 8 -- No Well-Known",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_8_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_8_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_8_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_8_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_8_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_8_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 41,
        .body  = "set_8_41_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_9 =
  {
    /* Optional-Transitive Only -- with no repeats
     */
    .name = "Set 9 -- Optional-Transitive only",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_9_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_9_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_9_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_9_50_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 41,
        .body  = "set_9_41_2 Optional-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_10 =
  {
    /* Optional-Transitive Only -- with some repeats
     */
    .name = "Set 10 -- Optional-Transitive only, some repeats",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,
        .body  = "set_10_41_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,
        .body  = "set_10_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_10_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_10_50_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 41,            /* repeat       */
        .body  = "set_10_41_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,             /* repeat       */
        .body  = "set_10_5_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,             /* repeat       */
        .body  = "set_10_3_2 Optional-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_11 =
  {
    /* Optional-Non-Transitive Only -- with no repeats
     */
    .name = "Set 11 -- Optional-Non-Transitive only, no repeats",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | 7,
        .type  = 41,
        .body  = "set_11_41_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 5,
        .body  = "set_11_5_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 3,
        .body  = "set_11_3_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_11_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 41,
        .body  = "set_11_41_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_12 =
  {
    /* Optional-Non-Transitive Only -- with some repeats
     */
    .name = "Set 12 -- Optional-Non-Transitive only, some repeats",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | 7,
        .type  = 41,
        .body  = "set_12_41_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 5,
        .body  = "set_12_5_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 3,
        .body  = "set_12_3_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_12_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 41,
        .body  = "set_12_41_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 5,
        .body  = "set_12_5_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 3,
        .body  = "set_12_3_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

static unk_attr_set_t set_13 =
  {
    /* Mix of types -- but all Optional-Transitive repeated
     */
    .name = "Set 13 -- Mixed types, but all Optional-Transitive repeated",
    .set  =
    {
      { .flags = BGP_ATF_OPTIONAL | 7,
        .type  = 41,
        .body  = "set_13_41_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_13_13_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,            /* repeated as Optional-Non-Transitive  */
        .body  = "set_13_41_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_13_72_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_13_27_1 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,             /* repeated as Optional-Transitive      */
        .body  = "set_13_5_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_13_91_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 3,             /* repeated as Well-Known               */
        .body  = "set_13_3_1 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_13_50_1 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED,
        .type  = 13,
        .body  = "set_13_13_2 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | 7,
        .type  = 41,            /* repeated as Optional-Non-Transitive  */
        .body  = "set_13_41_3 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL,
        .type  = 72,
        .body  = "set_13_72_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED | 9,
        .type  = 27,
        .body  = "set_13_27_2 Well-known, Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE,
        .type  = 5,            /* repeated as Optional-Transitive       */
        .body  = "set_13_5_2 Optional-Transitive",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED,
        .type  = 91,
        .body  = "set_13_91_2 Optional-Non-Transitive",
      },
      { .flags = BGP_ATF_TRANSITIVE,
        .type  = 3,
        .body  = "set_13_3_2 Well-Known",
      },
      { .flags = BGP_ATF_OPTIONAL | BGP_ATF_PARTIAL | 12,
        .type  = 50,
        .body  = "set_13_50_2 Optional-Non-Transitive",
      },
      { .body = NULL }
    }
  };

/*------------------------------------------------------------------------------
 * Table of sets of attributes.
 */
static unk_attr_set unk_table[] =
    {
        &set_0,
        &set_1,
        &set_2,
        &set_3,
        &set_4,
        &set_5,
        &set_6,
        &set_7,
        &set_8,
        &set_9,
        &set_10,
        &set_11,
        &set_12,
        &set_13,
        NULL
    };

/*==============================================================================
 * Test coverage:
 *
 *  * attr_unknown_start()       -- see main()
 *  * attr_unknown_finish()      -- see main()
 *
 *  * attr_unknown_new()         -- see test_unk_copy()
 *
 *  * attr_unknown_store()       -- see test_unk_store() & test_unk_add_stored()
 *  * attr_unknown_free()        -- see test_unk_sort(), test_unk_copy()
 *                                                   & test_unk_transitive()
 *
 *  * attr_unknown_lock()        -- see test_unk_store()
 *  * attr_unknown_release()     -- see test_unk_store() & test_unk_add_stored()
 *
 *  * attr_unknown_copy()        -- see test_unk_copy() & test_unk_add_stored()
 *  * attr_unknown_transitive()  -- see test_unk_transitive()
 *
 *  * attr_unknown_add()         -- see nearly all tests
 *
 *  * attr_unknown_out_prepare() -- too trivial to test
 *
 *  * attr_unknown_sort()        -- see test_unk_sort()
 *
 *  * attr_unknown_get_item()    -- too trivial to test
 */

/*==============================================================================
 * Test of attr_unknown_sort().
 *
 * For all the above sets:
 *
 *   1) add attributes to an unknown object -- attr_unknown_add()
 *
 *   2) sort the result and check the state -- attr_unknown_sort()
 *
 *   3) free the result -- attr_unknown_free()
 */
static void
test_unk_sort(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  unk_attr_set set ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_unknown_sort()") ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown x_unk ;
      unk_attr tx ;
      attr_unknown_state_t e_state, state ;

      next_test() ;

      x_unk = NULL ;                    /* NB: empty set yields NULL    */

      tx = set->set ;
      while (tx->body != NULL)
        {
          byte*  a_ptr ;
          uint   a_len ;

          a_ptr = make_unknown(tx, &a_len) ;
          x_unk = attr_unknown_add(x_unk, a_ptr) ;

          ++tx ;
        }

      state = attr_unknown_sort(x_unk) ;
      if (x_unk != NULL)
        e_state = expect_state(set->set, false /* not opt_trans */)
                                                                | unks_sorted ;
      else
        e_state = unks_null ;

      test_assert(state == e_state,
              "expected state=0x%02x, got=0x%02x after attr_unknown_sort()\n"
              "        (set=\"%s\")", e_state, state, set->name) ;

      attr_unknown_free(x_unk) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_unknown_copy().
 *
 * For all the above sets:
 *
 *   1) add attributes to an unknown object -- attr_unknown_add()
 *
 *   2) copy the result and check the state -- attr_unknown_copy()
 *
 *   3) free the result(s) -- attr_unknown_free()
 *
 * Repeat the test, starting with a new (empty) attr_unknown.
 *
 * Repeat the test, doing (at random) an attr_unknown_copy() while accumulating
 * the attributes.
 */
static void
test_unk_copy(void)
{
  uint fail_count_was, test_count_was ;
  uint t ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_unknown_copy()") ;

  for (t = 0 ; t < 3 ; ++t)
    {
      uint i ;
      unk_attr_set set ;

      for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
        {
          attr_unknown x_unk, y_unk ;
          unk_attr tx ;
          byte*  expect ;
          uint   e_len, y_len ;
          attr_unknown_state_t e_state, y_state ;

          next_test() ;

          if (t != 1)
            x_unk = NULL ;
          else
            x_unk = attr_unknown_new() ;

          tx = set->set ;
          while (tx->body != NULL)
            {
              byte*  a_ptr ;
              uint   a_len ;

              a_ptr = make_unknown(tx, &a_len) ;
              x_unk = attr_unknown_add(x_unk, a_ptr) ;

              if ((t == 2) && ((rand() % 4) == 0))
                {
                  attr_unknown y_unk ;

                  y_unk = attr_unknown_copy(x_unk) ;

                  attr_unknown_free(x_unk) ;
                  x_unk = y_unk ;
                } ;

              ++tx ;
            }

          expect = expect_unknowns(set->set, &e_len,
                                                    false /* not opt_trans */) ;
          y_unk = attr_unknown_copy(x_unk) ;

          if (x_unk == NULL)
            {
              test_assert(y_unk == NULL,
                            "expect NULL from attr_unknown_copy(NULL)\n"
                            "        (set=\"%s\", test %d)", set->name, t) ;
              test_assert(e_len == 0,
                            "expect to expect nothing if y_unk == NULL\n"
                            "        (set=\"%s\", test %d)", set->name, t) ;
            }
          else
            {
              test_assert(y_unk != NULL,
                  "do not expect NULL from attr_unknown_copy(x_unk != NULL)\n"
                  "        (set=\"%s\", test %d)", set->name, t) ;
            } ;

          if (y_unk != NULL)
            {
              y_state = y_unk->state ;
              y_len   = y_unk->len ;
            }
          else
            {
              y_state = (unks_sorted | unks_stashed) ;
              y_len   = 0 ;
            } ;

          e_state = expect_state(set->set, false /* not opt_trans */)
                                                  | unks_sorted | unks_stashed ;

          test_assert(y_state == e_state,
                "expected state=0x%02x, got=0x%02x after attr_unknown_copy()\n"
                "        (set=\"%s\", test %d)", e_state, y_state,
                                                                 set->name, t) ;

          test_assert(y_len == e_len,
                  "expected stashed len=%d, got=%d after attr_unknown_copy()\n"
                  "        (set=\"%s\", test %d)", e_len, y_len,
                                                           set->name, t) ;

          if ( (y_len == e_len) && (e_len != 0)
                               && (memcmp(y_unk->body, expect, e_len) != 0) )
            {
              test_assert(memcmp(y_unk->body, expect, e_len) == 0,
                    "stashed body not as expected after attr_unknown_copy()\n"
                    "        (set=\"%s\", test %d)", set->name, t) ;

              show_delta(y_unk->body, expect, e_len) ;
            } ;

          attr_unknown_free(x_unk) ;
          attr_unknown_free(y_unk) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_unknown_transitive().
 *
 * For all the above sets:
 *
 *   1) add attributes to an unknown object -- attr_unknown_add()
 *
 *   2) reduce to Optional-Transitive and check -- attr_unknown_transitive()
 *
 *   3) free the result(s) -- attr_unknown_free()
 *
 */
static void
test_unk_transitive(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  unk_attr_set set ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_unknown_transitive()") ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown x_unk ;
      unk_attr tx ;
      byte*  expect ;
      uint   e_len, x_len ;
      attr_unknown_state_t e_state, x_state ;
      bool opt_trans ;

      next_test() ;

      tx = set->set ;
      x_unk = NULL ;
      while (tx->body != NULL)
        {
          byte*  a_ptr ;
          uint   a_len ;

          a_ptr = make_unknown(tx, &a_len) ;
          x_unk = attr_unknown_add(x_unk, a_ptr) ;

          ++tx ;
        } ;

      if (x_unk == NULL)
        assert(set->set[0].body == NULL) ;

      expect = expect_unknowns(set->set, &e_len, true /* opt_trans */) ;
      opt_trans = attr_unknown_transitive(x_unk) ;
      e_state = expect_state(set->set, true /* opt_trans */)
                                              | unks_sorted | unks_stashed ;

      if (x_unk != NULL)
        {
          x_state = x_unk->state ;
          x_len   = x_unk->len ;
        }
      else
        {
          x_state = (unks_sorted | unks_stashed) ;
          x_len   = 0 ;
        } ;

      test_assert(x_state == e_state,
          "expected state=0x%02x, got=0x%02x after attr_unknown_transitive()\n"
          "        (set=\"%s\")", e_state, x_state, set->name) ;

      if (e_len != 0)
        test_assert(opt_trans,
            "expected 'true' return from attr_unknown_transitive()\n"
            "        (set=\"%s\")", set->name) ;
      else
        test_assert(!opt_trans,
            "expected 'false' return from attr_unknown_transitive()\n"
            "        (set=\"%s\")", set->name) ;

      test_assert(x_len == e_len,
             "expected stashed len=%d, got=%d after attr_unknown_transitive()\n"
             "        (set=\"%s\")", e_len, x_len, set->name) ;

      if ( (x_len == e_len) && (e_len != 0)
                           && (memcmp(x_unk->body, expect, e_len) != 0) )
        {
          test_assert(memcmp(x_unk->body, expect, e_len) == 0,
             "stashed body not as expected after attr_unknown_transitive()\n"
             "        (set=\"%s\")", set->name) ;

          show_delta(x_unk->body, expect, e_len) ;
        } ;

      attr_unknown_free(x_unk) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_unknown_store().
 *
 * For all the above sets:
 *
 *   1) add attributes to an unknown object -- attr_unknown_add()
 *
 *   2) store and check -- attr_unknown_store()
 *
 *   3) repeat (1) and (2), checking that 2nd time get the stored value.
 *
 *   4) repeat (1) and (2), releasing the attributes once before the
 *      second store -- attr_unknown_release()
 *
 *   5) release the stored values and check empty -- attr_unknown_release()
 */
static void
test_unk_store(void)
{
  enum { stored_count = 100 } ;
  static attr_unknown stored[stored_count] ;

  uint fail_count_was, test_count_was ;
  uint i ;
  unk_attr_set set ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_unknown_store()") ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown x_unk ;
      unk_attr tx ;
      byte*  expect ;
      uint   e_len, x_len ;
      attr_unknown_state_t e_state, x_state ;

      next_test() ;

      tx = set->set ;
      x_unk = NULL ;
      while (tx->body != NULL)
        {
          byte*  a_ptr ;
          uint   a_len ;

          a_ptr = make_unknown(tx, &a_len) ;
          x_unk = attr_unknown_add(x_unk, a_ptr) ;

          ++tx ;
        } ;

      if (x_unk == NULL)
        assert(set->set[0].body == NULL) ;

      x_unk = attr_unknown_store(x_unk) ;

      expect = expect_unknowns(set->set, &e_len, true /* opt_trans */) ;
      e_state = expect_state(set->set, true /* opt_trans */)
                                              | unks_sorted | unks_stashed ;

      if (x_unk != NULL)
        {
          test_assert(x_unk->stored,
                      "expected stored after attr_unknown_store()\n"
                      "        (set=\"%s\")", set->name) ;

          test_assert(x_unk->vhash.ref_count == 2,
                   "expected reference count == 2 after attr_unknown_store(), "
                   "have %u\n"
                   "        (set=\"%s\")", x_unk->vhash.ref_count, set->name) ;

          x_state = x_unk->state ;
          x_len   = x_unk->len ;
        }
      else
        {
          x_state = (unks_sorted | unks_stashed) ;
          x_len   = 0 ;
        } ;

      test_assert(x_state == e_state,
          "expected state=0x%02x, got=0x%02x after attr_unknown_store()\n"
          "        (set=\"%s\")", e_state, x_state, set->name) ;

      test_assert(x_len == e_len,
             "expected stashed len=%d, got=%d after attr_unknown_store()\n"
             "        (set=\"%s\")", e_len, x_len, set->name) ;

      if ( (x_len == e_len) && (e_len != 0)
                           && (memcmp(x_unk->body, expect, e_len) != 0) )
        {
          test_assert(memcmp(x_unk->body, expect, e_len) == 0,
             "stashed body not as expected after attr_unknown_store()\n"
             "        (set=\"%s\")", set->name) ;

          show_delta(x_unk->body, expect, e_len) ;
        } ;

      stored[i] = x_unk ;
    } ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown x_unk ;
      unk_attr tx ;

      next_test() ;

      tx = set->set ;
      x_unk = NULL ;
      while (tx->body != NULL)
        {
          byte*  a_ptr ;
          uint   a_len ;

          a_ptr = make_unknown(tx, &a_len) ;
          x_unk = attr_unknown_add(x_unk, a_ptr) ;

          ++tx ;
        } ;

      if (x_unk == NULL)
        assert(set->set[0].body == NULL) ;

      x_unk = attr_unknown_store(x_unk) ;

      test_assert(stored[i] == x_unk,
             "failed to find previously stored value\n"
             "        (set=\"%s\")", set->name) ;

      if (x_unk != NULL)
        {
          test_assert(x_unk->vhash.ref_count == 4,
            "expected reference count == 4 after second attr_unknown_store()\n"
            "        (set=\"%s\")", set->name) ;
        } ;
    } ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown x_unk ;
      unk_attr tx ;

      next_test() ;

      x_unk = stored[i] ;
      attr_unknown_release(x_unk) ;

      if (x_unk != NULL)
        {
          test_assert(x_unk->vhash.ref_count == 2,
            "expected reference count == 2 after attr_unknown_release()\n"
            "        (set=\"%s\")", set->name) ;
        } ;

      tx = set->set ;
      x_unk = NULL ;
      while (tx->body != NULL)
        {
          byte*  a_ptr ;
          uint   a_len ;

          a_ptr = make_unknown(tx, &a_len) ;
          x_unk = attr_unknown_add(x_unk, a_ptr) ;

          ++tx ;
        } ;

      if (x_unk == NULL)
        assert(set->set[0].body == NULL) ;

      x_unk = attr_unknown_store(x_unk) ;

      test_assert(stored[i] == x_unk,
             "failed to find previously stored value\n"
             "        (set=\"%s\")", set->name) ;

      if (x_unk != NULL)
        {
          test_assert(x_unk->vhash.ref_count == 4,
            "expected reference count == 4 after second attr_unknown_store(), "
                                                                     "got=%u\n"
            "        (set=\"%s\")", x_unk->vhash.ref_count, set->name) ;
        } ;
    } ;

  for (i = 0 ; (set = unk_table[i]) != NULL ; ++i)
    {
      attr_unknown s_unk ;

      next_test() ;

      s_unk = stored[i] ;

      if (s_unk != NULL)
        {
          attr_unknown_lock(s_unk) ;

          test_assert(s_unk->vhash.ref_count == 6,
            "expected reference count == 6 after attr_unknown_lock(), "
                                                                     "got %u\n"
            "        (set=\"%s\")", s_unk->vhash.ref_count, set->name) ;

          attr_unknown_release(s_unk) ;

          test_assert(s_unk->vhash.ref_count == 4,
            "expected reference count == 4 after attr_unknown_release(), "
                                                                     "got %u\n"
            "        (set=\"%s\")", s_unk->vhash.ref_count, set->name) ;
        } ;

      attr_unknown_release(s_unk) ;
      attr_unknown_release(s_unk) ;
    } ;

  test_assert(attr_unknown_vhash->entry_count == 0,
      "expected no entries left in the unknown_vhash, have %u",
                                              attr_unknown_vhash->entry_count) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of attr_unknown_add() after attr_unknown_store().
 *
 * For all the above sets:
 *
 *   1) add attributes to an unknown object -- attr_unknown_add()
 *
 *   2) store and check -- attr_unknown_store()
 *
 *   3) add an extra attribute to set_1 and check we get what we expect
 */
static void
test_unk_add_stored(void)
{
  uint fail_count_was, test_count_was ;
  uint i ;
  attr_unknown s_unk ;
  unk_attr tx ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  test: attr_unknown_add() after attr_unknown_store()") ;

  /* Construct and store set_1.
   */
  tx = set_1.set ;
  s_unk = NULL ;
  while (tx->body != NULL)
    {
      uint   a_len ;
      byte*  a_ptr ;

      a_ptr = make_unknown(tx, &a_len) ;
      s_unk = attr_unknown_add(s_unk, a_ptr) ;

      ++tx ;
    } ;

  assert(s_unk != NULL) ;
  s_unk = attr_unknown_store(s_unk) ;
  assert(s_unk != NULL) ;

  test_assert(s_unk->stored,
              "expected stored after attr_unknown_store()\n"
              "        (set=\"%s\")", set_1.name) ;

  test_assert(s_unk->vhash.ref_count == 2,
           "expected reference count == 2 after attr_unknown_store(), "
           "have %u\n"
           "        (set=\"%s\")", s_unk->vhash.ref_count, set_1.name) ;

  /* Now add set_1ax/set_1bx to s_unk and make sure we get set_1a/set_1b
   */
  for (i = 0 ; i < 2 ; ++i)
    {
      unk_attr_set set ;
      attr_unknown x_unk, y_unk ;
      byte*  expect ;
      uint   e_len ;
      attr_unknown_state_t e_state ;
      uint   a_len ;
      byte*  a_ptr ;

      next_test() ;

      if (i == 0)
        {
          tx  = &set_1ax ;
          set = &set_1a ;
        }
      else
        {
          tx  = &set_1bx ;
          set = &set_1b ;
        } ;

      a_ptr = make_unknown(tx, &a_len) ;
      x_unk = attr_unknown_add(s_unk, a_ptr) ;
      assert(x_unk != NULL) ;

      test_assert(x_unk != s_unk,
              "expected new attr_unknown after attr_unknown_add()\n"
              "        (set=\"%s\")", set->name) ;

      test_assert(s_unk->vhash.ref_count == 2,
           "expected reference count == 2 after attr_unknown_add(), "
           "have %u\n"
           "        (set=\"%s\")", s_unk->vhash.ref_count, set->name) ;

      y_unk = attr_unknown_copy(x_unk) ;
      assert(y_unk != NULL) ;

      expect  = expect_unknowns(set->set, &e_len, false /* not opt_trans */) ;
      e_state = expect_state(set->set, false /* not opt_trans */)
                                              | unks_sorted | unks_stashed ;

      test_assert(y_unk->state == e_state,
          "expected state=0x%02x, got=0x%02x after attr_unknown_store()\n"
          "        (set=\"%s\")", e_state, y_unk->state, set->name) ;

      test_assert(y_unk->len == e_len,
             "expected stashed len=%d, got=%d after attr_unknown_store()\n"
             "        (set=\"%s\")", e_len, y_unk->len, set->name) ;

      if ( (y_unk->len == e_len) && (e_len != 0)
                           && (memcmp(y_unk->body, expect, e_len) != 0) )
        {
          test_assert(memcmp(y_unk->body, expect, e_len) == 0,
             "stashed body not as expected after attr_unknown_store()\n"
             "        (set=\"%s\")", set->name) ;

          show_delta(y_unk->body, expect, e_len) ;
        } ;

      attr_unknown_release(x_unk) ;
      attr_unknown_release(y_unk) ;
    } ;

  attr_unknown_release(s_unk) ;

  test_assert(attr_unknown_vhash->entry_count == 0,
      "expected no entries left in the unknown_vhash, have %u",
                                              attr_unknown_vhash->entry_count) ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test support functions
 */

/*------------------------------------------------------------------------------
 * Make a single unknown attribute from a given unk_attr
 *
 * NB: for simplicity, the attribute value is an ordinary string.  It really
 *     makes no difference that '\0' cannot be part of the tested values.
 *
 * NB: uses a static buffer of fixed size for this -- for simplicity.
 */
static byte*
make_unknown(unk_attr ts, uint* p_length)
{
  uint   length ;
  byte*  unk ;
  uint l ;
  byte flags ;

  length = 0 ;
  l      = 0 ;
  flags  = 0 ;

  if (ts->body != NULL)
    {
      l = strlen(ts->body) ;

      flags = ts->flags | (l > 255 ? BGP_ATF_EXTENDED : 0) ;

      length = (1 + 1) + (flags & BGP_ATF_EXTENDED ? 2 : 1) + l ;
    } ;

  if (length != 0)
    {
      byte*  p ;

      unk = malloc(length) ;

      p = unk ;

      *p++ = flags ;
      *p++ = ts->type ;

      if (flags & BGP_ATF_EXTENDED)
        {
          *p++ = l >> 8 ;
          *p++ = l & 0xFF ;
        }
      else
        *p++ = l ;

      if (l != 0)
        {
          memcpy(p, ts->body, l) ;
          p += l ;
        } ;

      assert((p - unk) == length) ;
    }
  else
    unk = NULL ;

  *p_length = length ;
  return unk ;
} ;

/*------------------------------------------------------------------------------
 * Work out what we expect to get from the given set of attributes.
 *
 * Either what we expect from a simple copy, or what we expect after extracting
 * only the opt_trans.
 *
 * For simplicity -- uses a static buffer.
 */
static byte*
expect_unknowns(unk_attr_t* ts, uint* p_length, bool opt_trans)
{
  uint     length ;
  byte*    p ;
  uint     type ;
  type_counts counts ;

  static byte unks[16 * 1024] ;

  count_scan(counts, ts) ;

  p      = unks ;
  length = 0 ;
  for (type = 0 ; type <= 255 ; ++type)
    {
      unk_attr tx ;

      if (counts[type] == 0)
        continue ;

      if (opt_trans && (counts[type] != 1))
        continue ;

      tx = ts ;
      do
        {
          byte flags ;
          uint l ;

          while (1)
            {
              assert(tx->body != NULL) ;

              if (tx->type == type)
                break ;

              ++tx ;
            } ;

          if (opt_trans)
            {
              if ( (tx->flags & (BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE))
                             != (BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE) )
                break ;
            } ;

          /* Spit out the canonical form
           */
          flags = tx->flags & (BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE
                                                | BGP_ATF_PARTIAL) ;
          l = strlen(tx->body) ;
          if (l > 255)
            flags |= BGP_ATF_EXTENDED ;

          assert((length + 4 + l) <- sizeof(unks)) ;

          if (opt_trans)
            flags |= BGP_ATF_PARTIAL ;

          *p++ = flags ;
          *p++ = tx->type ;

          length += 2 ;

          if (flags & BGP_ATF_EXTENDED)
            {
              *p++ = l >> 8 ;
              *p++ = l & 0xFF ;

              length += 2 + l ;
            }
          else
            {
              *p++ = l ;

              length += 1 + l ;
            } ;

          if (l != 0)
            {
              memcpy(p, tx->body, l) ;
              p += l ;
            } ;

          /* Reduce count of this type of attribute, step past what we just
           * did and continue.
           */
          counts[type] -= 1 ;
          ++tx ;
        }
      while (counts[type] > 0) ;
    } ;

  assert((p - unks) == length) ;

  *p_length = length ;
  return unks ;
} ;

/*------------------------------------------------------------------------------
 * Work out what state expect to get from the given set of attributes.
 */
static attr_unknown_state_t
expect_state(unk_attr_t* ts, bool opt_trans)
{
  unk_attr tx ;
  attr_unknown_state_t state ;
  type_counts counts ;

  count_scan(counts, ts) ;
  state = 0 ;

  for (tx = ts ; (tx->body != NULL) ; ++tx)
    {
      assert(counts[tx->type] != 0) ;

      if (counts[tx->type] > 1)
        {
          if (!opt_trans)
            state |= unks_duplicate ;
          else
            continue ;
        } ;

      if (tx->flags & BGP_ATF_OPTIONAL)
        {
          if (tx->flags & BGP_ATF_TRANSITIVE)
            state |= unks_opt_trans ;
          else if (!opt_trans)
            state |= unks_opt_non_trans ;
        }
      else
        {
          if (!opt_trans)
            state |= unks_well_known ;
        } ;
    } ;

  return state ;
} ;

/*------------------------------------------------------------------------------
 * Scan and count how many times each type appears.
 */
static void
count_scan(type_counts counts, unk_attr_t* ts)
{
  memset(counts, 0, sizeof(type_counts)) ;

  while (ts->body != NULL)
    {
      counts[ts->type] += 1 ;
      ++ts ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Show difference between the attribute set we got, and the attribute set
 * we expected.
 */
static void
show_delta(const byte* got, const byte* exp, uint len)
{
  uint off, sp, np, l, ll, bp ;
  bool red_tape ;

  off = 0 ;
  while (1)
    {
      if (got[off] != exp[off])
        break ;

      ++off ;
      if (off < len)
        continue ;

      test_assert(off < len, "found no difference in show_delta()") ;
      return ;
    } ;

  sp = 0 ;
  np = 0 ;

  while (1)
    {
      byte flags ;
      uint lg, le, i ;
      char ext[44] ;

      red_tape = true ;
      np = sp + 8 ;
      bp = sp ;
      l  = 0 ;
      ll = 0 ;

      if (off <= (sp + 2))
        break ;

      flags = got[sp] ;
      if (flags & BGP_ATF_EXTENDED)
        {
          if (off <= (sp + 3))
            break ;

          lg = (got[sp + 2] << 8) + got[sp + 3] ;
          le = (exp[sp + 2] << 8) + exp[sp + 3] ;

          bp = sp + 4 ;
          ll = 2 ;
        }
      else
        {
          lg = got[sp + 2] ;
          le = exp[sp + 2] ;

          bp = sp + 3 ;
          ll = 1 ;
        } ;

      assert(lg == le) ;

      l  = lg ;
      np = bp + l ;
      assert(np <= len) ;

      red_tape = false ;
      if (np > off)
        break ;

      for (i = 0 ; (i < 40) && (i < l) ; ++i)
        ext[i] = got[bp + i] ;

      if (i < l)
        {
          ext[i++] = '.' ;
          ext[i++] = '.' ;
          ext[i++] = '.' ;
        } ;
      ext[i] = '\0' ;

      fprintf(stderr, "\n  =%3d: %02x %02x %3d(%d) \"%s\"",
                                           sp, got[sp], got[sp+1], l, ll, ext) ;

      sp = np ;
    } ;

  if (red_tape)
    {
      uint i ;

      if (np > len)
        np = len ;

      fprintf(stderr, "\n  e%3d:", sp) ;
      for (i = sp ; i < np ; ++i)
        fprintf(stderr, " %02x", exp[i]) ;

      fprintf(stderr, "\n  g%3d:", sp) ;
      for (i = sp ; i < np ; ++i)
        fprintf(stderr, " %02x", got[i]) ;
    }
  else
    {
      uint i, j ;
      char ext[44] ;

      fprintf(stderr, "\n  =%3d: %02x %02x %3d(%d)",
                                               sp, got[sp], got[sp+1], l, ll) ;

      j = off - bp ;
      while (j != 0)
        {
          for (i = 0 ; (i < 40) && (i < j) ; ++i)
            ext[i] = got[bp + i] ;
          ext[i] = '\0' ;

          j  -= i ;
          bp += i ;

          fprintf(stderr, " \"%s\"", ext) ;

          if (j != 0)
            fprintf(stderr, "\n  =%3d: .. .. ... . ", bp) ;
        } ;

      j = len ;
      if ((j - bp) > 16)
        j = bp + 16 ;

      fprintf(stderr, "\n  e%3d: .. .. ... . ", bp) ;
      for (i = bp ; i < j ; ++i)
        fprintf(stderr, " %02x", exp[i]) ;

      fprintf(stderr, "\n  g%3d: .. .. ... . ", bp) ;
      for (i = bp ; i < j ; ++i)
        fprintf(stderr, " %02x", got[i]) ;
    } ;
} ;
