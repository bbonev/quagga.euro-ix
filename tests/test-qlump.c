#include "misc.h"
#include "vargs.h"
#include <stdio.h>
#include <stdlib.h>
#include "qlib_init.h"
#include "command.h"

#include "qlump.h"

#define MCHECK_H

#ifdef MCHECK_H
#include <mcheck.h>
#endif

/*==============================================================================
 * qlump torture tests
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

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_qlump_register_type(void) ;
static void test_qlump_init(void) ;
static void test_qlump_set_alias(void) ;
static void test_qlump_clear(void) ;
static void test_qlump_alias_clear(void) ;
static void test_qlump_alias_re_init(void) ;
static void test_qlump_extend(void) ;
static void test_qlump_store(void) ;
static void test_qlump_copy(void) ;
static void test_qlump_copy_store(void) ;
static void test_qlump_free_body(void) ;
static void test_qlump_bubble(void) ;
static void test_qlump_exch_sections(void) ;
static void test_qlump_rev_section(void) ;
static void test_qlump_swap_items(void) ;
static void test_qlump_sort(void) ;
static void test_qlump_sort_dedup(void) ;


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

  fprintf(stderr, "Start qlump testing: srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  test_qlump_register_type() ;  /* and register the test types  */

  test_qlump_init() ;

  test_qlump_set_alias() ;

  test_qlump_clear() ;

  test_qlump_alias_clear() ;

  test_qlump_alias_re_init() ;

  test_qlump_extend() ;

  test_qlump_store() ;

  test_qlump_copy() ;

  test_qlump_copy_store() ;

  test_qlump_free_body() ;

  test_qlump_bubble() ;

  test_qlump_exch_sections() ;

  test_qlump_rev_section() ;

  test_qlump_swap_items() ;

  test_qlump_sort() ;

  test_qlump_sort_dedup() ;

  fprintf(stderr, "Finished qlump testing") ;

  if (fail_count == 0)
    fprintf(stderr, " -- OK\n"
                    "...should now report NO remaining memory utilisation\n") ;
  else
    fprintf(stderr, " *** %u FAILURES\n", fail_count) ;

  host_finish() ;
  qexit(0, true /* mem_stats */) ;
}

/*==============================================================================
 * We test various types of qlump.
 *
 * Our test object encapsulates the qlump, and contains an embedded a_body for
 * some types.
 *
 * These are identified by their ttype, and the qlump_type is given in the
 * table below.
 *
 * These are registered as part of the test_qlump_register_type.
 */
static usize test_qlump_alloc(qlump ql, usize new_size, bool store,
                                                              qlump_type_c qt) ;
static void test_qlump_free(qlump ql, void* body, usize size, qlump_type_c qt) ;

typedef enum ttype ttype_t ;

enum ttype
{
  ttype_null   = 0,
  ttype_first  = 1,

  /* The simple types:  no embedded a_body.
   *                    a variety of size_min, size_unit_m1 etc.
   *                    size_term == 0
   *
   * The size of the item is in the name.
   */
  ttype_s1    = ttype_first,
  ttype_s4,
  ttype_s24,
  ttype_s11,

  /* The embedded types:  embedded a_body -- before and after qlump
   *                      a variety of size_min, size_unit_m1 etc.
   *                      size_term == 0
   */
  ttype_e1,
  ttype_e4,
  ttype_e16,
  ttype_e9,

  /* The simple, term types:  no embedded a_body.
   *                          a variety of size_min, size_unit_m1 etc.
   *                          a variety of size_term > 0
   */
  ttype_s1t,
  ttype_s8t,
  ttype_s32t,
  ttype_s15t,

  /* The embedded, term types:  embedded a_body -- after and before qlump
   *                            a variety of size_min, size_unit_m1 etc.
   *                            a variety of size_term > 0
   */
  ttype_e1t,
  ttype_e4t,
  ttype_e16t,
  ttype_e9t,

  /* The number of test types
   */
  ttype_count,

  ttype_last = ttype_count - 1,
} ;

/*------------------------------------------------------------------------------
 * General test object.
 */
enum {
  test_unit_max           =  64,

  test_items_max          = 250,        /* 1..250 in test_vector        */
  test_embedded_items_max =  14,

  /* The maximum size of an embedded body.
   */
  test_embedded_max = test_unit_max  * test_embedded_items_max,

  /* Allow for extension of body to many times the number of initial
   * items -- eg: for qlump_extend(), qlump_bubble() and qlump_swap_items().
   */
  test_vector_max   = test_items_max * 4,

  /* The maximum size of an alias
   */
  test_alias_max    = test_items_max * test_unit_max,
} ;

static byte test_alias[test_alias_max] ;

typedef struct test_object* test_object ;
typedef struct test_object  test_object_t ;

struct test_object
{
  ulen          tv_len ;

  byte          embedded_a[test_embedded_max] ;
  uint          guard_a ;

  ulen          tv_alias_len ;

  qlump_t       ql ;

  ttype_t       ttype ;
  qlump_type_c  qt ;

  size_t        a_size ;
  void*         a_body ;

  bool          stored ;
  size_t        ap_size ;
  void*         ap_body ;

  ulen          tv_cp ;

  byte          embedded_b[test_embedded_max] ;
  uint          guard_b ;

  void*         embedded ;

  byte          test_vector[test_vector_max] ;
} ;

/*------------------------------------------------------------------------------
 * Table of test qlump_types
 */
static const qlump_type_t test_qt[] =
{
  [ttype_null] = { 0 },                 /* all zero             */

  [ttype_s1] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 1,                /* 1 byte               */

      .size_add     = 5,
      .size_unit_m1 = 32 - 1,

      .size_min     = 64,

      .size_min_unit_m1 = 4 - 1,

      .embedded_size   = 0,             /* no embedded          */
      .embedded_offset = 0,
    },

  [ttype_s4] =
    {  .alloc        = test_qlump_alloc,
       .free         = test_qlump_free,

       .unit         = 4,               /* 4 byte               */

       .size_add     = 3,
       .size_unit_m1 = 8 - 1,

       .size_min     = 7,

       .size_min_unit_m1 = 4 - 1,

       .embedded_size   = 0,             /* no embedded          */
       .embedded_offset = 0,
    },

  [ttype_s24] =
    {  .alloc        = test_qlump_alloc,
       .free         = test_qlump_free,

       .unit         = 24,              /* 24 byte              */

       .size_add     = 0,
       .size_unit_m1 = 2 - 1,

       .size_min     = 1,

       .size_min_unit_m1 = 0,

       .embedded_size   = 0,             /* no embedded          */
       .embedded_offset = 0,
    },

  [ttype_s11] =
    {  .alloc        = test_qlump_alloc,
       .free         = test_qlump_free,

       .unit         = 11,               /* 11 byte              */

       .size_add     = 1,
       .size_unit_m1 = 0,

       .size_min     = 0,

       .size_min_unit_m1 = 0,

       .embedded_size   = 0,             /* no embedded          */
       .embedded_offset = 0,
    },

  [ttype_e1] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 1,                /* 1 byte               */

      .size_add     = 5,
      .size_unit_m1 = 32 - 1,

      .size_min     = 48,

      .size_min_unit_m1 = 4 - 1,

      .embedded_size   = 14,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_a),
    },

  [ttype_e4] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 4,                /* 4 byte               */

      .size_add     = 9,
      .size_unit_m1 = 4 - 1,

      .size_min     = 11,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 12,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_b),
    },

  [ttype_e16] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 16,               /* 16 byte              */

      .size_add     = 1,
      .size_unit_m1 = 2 - 1,

      .size_min     = 1,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 3,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_a),
    },

  [ttype_e9] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 9,                /* 9 byte               */

      .size_add     = 5,
      .size_unit_m1 = 2 - 1,

      .size_min     = 1,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 7,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_b),
    },

  [ttype_s1t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 1,                /* 1 byte               */

      .size_add     = 0,
      .size_unit_m1 = 0,

      .size_min     = 0,

      .size_term    = 1,

      .size_min_unit_m1 = 4 - 1,

      .embedded_size   = 0,             /* no embedded          */
      .embedded_offset = 0,
    },

  [ttype_s8t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 8,                /* 8 byte               */

      .size_add     = 2,
      .size_unit_m1 = 2 - 1,

      .size_term    = 2,

      .size_min     = 0,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 0,             /* no embedded          */
      .embedded_offset = 0,
    },

  [ttype_s32t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 32,               /* 32 byte              */

      .size_add     = 0,
      .size_unit_m1 = 1 - 1,

      .size_term    = 1,

      .size_min     = 1,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 0,             /* no embedded          */
      .embedded_offset = 0,
    },

  [ttype_s15t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 15,               /* 15 byte              */

      .size_add     = 1,
      .size_unit_m1 = 2 - 1,

      .size_term    = 3,

      .size_min     = 0,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 0,             /* no embedded          */
      .embedded_offset = 0,
    },

  [ttype_e1t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 1,                /* 1 byte               */

      .size_add     = 5,
      .size_unit_m1 = 32 - 1,

      .size_term    = 1,

      .size_min     = 64,

      .size_min_unit_m1 = 4 - 1,

      .embedded_size   = 14,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_b),
    },

  [ttype_e4t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 4,                /* 4 byte               */

      .size_add     = 9,
      .size_unit_m1 = 4 - 1,

      .size_term    = 2,

      .size_min     = 11,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 12,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_a),
    },

  [ttype_e16t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 16,               /* 16 byte              */

      .size_add     = 1,
      .size_unit_m1 = 2 - 1,

      .size_term    = 3,

      .size_min     = 1,

      .size_min_unit_m1 = 1 - 1,

      .embedded_size   = 3,             /* too small for size_term      */
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_b),
    },

  [ttype_e9t] =
    { .alloc        = test_qlump_alloc,
      .free         = test_qlump_free,

      .unit         = 9,                /* 9 byte               */

      .size_term    = 1,

      .size_add     = 0,
      .size_unit_m1 = 0,

      .size_min     = 0,

      .size_min_unit_m1 = 0,

      .embedded_size   = 7,
      .embedded_offset = qlump_embedded_offset(test_object_t, ql, embedded_a),
    },
} ;

/*==============================================================================
 * Test object and test case handling.
 */
typedef struct test_case  test_case_t ;
typedef struct test_case* test_case ;

struct test_case
{
  qlump_state_t state ;         /* initial state for case       */
  ttype_t       tt ;            /* mtype for case               */
  uint          len ;           /* initial len for case         */

  uint          req ;           /* request for case             */

  /* Iteration control
   */
  uint          len_next ;
  uint          req_next ;
} ;

enum { test_case_count_max = 129 } ;

static void test_object_check(test_object to, bool should_embed, uint req) ;
static void test_vector_fill(test_object to, uint len, byte* b) ;

/*------------------------------------------------------------------------------
 * Test allocator
 */
static usize
test_qlump_alloc(qlump ql, usize new_size, bool store, qlump_type_c qt)
{
  test_object to ;

  size_t new_byte_size, old_byte_size ;
  bool   extend ;

  to = (test_object)((char*)ql - offsetof(test_object_t, ql)) ;
    assert(&to->ql == ql) ;

  extend = false ;
  old_byte_size = 0 ;

  if (ql->state == qls_normal)
    {
      extend = (ql->size != 0) && !store ;

      old_byte_size = (size_t)ql->size * qt->unit ;

      test_assert(to->a_size == old_byte_size,
                                   "size not consistent with last allocation") ;
      if (old_byte_size != 0)
        test_assert(to->a_body  == ql->body.v,
                                   "body not consistent with last allocation") ;

      to->stored = store && (old_byte_size != 0) ;
      if (to->stored)
        {
          to->ap_size = to->a_size ;
          to->ap_body = to->a_body ;
        } ;

      if (!extend)
        old_byte_size = 0 ;
    }
  else
    {
      ql->state = qls_normal ;

      test_assert(to->a_size == 0,
                                 "not qls_normal, but have an old allocation") ;
      test_assert(to->a_body  == NULL,
                             "not qls_normal, but have an old allocated body") ;
    } ;

  new_byte_size = (size_t)new_size * qt->unit ;

  if (extend)
    ql->body.v = XREALLOC(ql->mtype, ql->body.v, new_byte_size) ;
  else
    ql->body.v = XMALLOC(ql->mtype, new_byte_size) ;

  to->a_size = new_byte_size ;
  to->a_body = ql->body.v ;

  memset(ql->body.c + old_byte_size, 0xFF, new_byte_size - old_byte_size) ;

  return ql->size = new_size ;
} ;

/*------------------------------------------------------------------------------
 * Test free
 */
static void
test_qlump_free(qlump ql, void* body, usize size, qlump_type_c qt)
{
  test_object to ;
  size_t old_byte_size ;

  to = (test_object)((char*)ql - offsetof(test_object_t, ql)) ;
    assert(&to->ql == ql) ;

  old_byte_size = (size_t)size * qt->unit ;

  if (to->stored)
    {
      test_assert(to->ap_size == old_byte_size,
                               "size not consistent with previous allocation") ;
      test_assert(to->ap_body == body,
                               "body not consistent with previous allocation") ;

      to->stored  = false ;
      to->ap_size = 0 ;
      to->ap_body = NULL ;
    }
  else
    {
      test_assert(to->a_size == old_byte_size,
                                   "size not consistent with last allocation") ;
      test_assert(to->a_body == body,
                                   "body not consistent with last allocation") ;

      to->a_size = 0 ;
      to->a_body = NULL ;
    } ;

  XFREE(ql->mtype, body) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise test_object for given ttype.
 *
 * Initialise the qlump unset or full of rubbish
 */
static void
test_object_init(test_object to, ttype_t tt, bool unset)
{
  memset(to, 100+tt, sizeof(test_object_t)) ;

  to->tv_len     = 0 ;
  memset(to->test_vector, 0, test_vector_max) ;

  to->guard_a    = (uint)((uintptr_t)(&to->guard_b)) ;
  to->tv_alias_len = 0 ;

  to->ttype      = tt ;
  to->qt         = &test_qt[tt] ;

  to->a_size     = 0 ;
  to->a_body     = NULL ;

  to->stored     = false ;
  to->ap_size    = 0 ;
  to->ap_body    = NULL ;

  to->tv_cp      = 0 ;

  to->guard_a    = (uint)((uintptr_t)(&to->guard_a)) ;

  if (to->qt->embedded_size == 0)
    to->embedded = NULL ;
  else
    {
      assert(to->qt->embedded_size <= test_embedded_items_max) ;
      assert((to->qt->embedded_size * to->qt->unit) <= test_embedded_max) ;

      if (to->qt->embedded_offset < 0)
        to->embedded = to->embedded_a ;
      else
        to->embedded = to->embedded_b ;
    } ;

  if (unset)
    to->ql.state = qls_unset ;
} ;

/*------------------------------------------------------------------------------
 * Finished
 *
 * See test_object_check() for significance of 'embed' and 'req'.
 */
static void
test_object_done(test_object to, bool embed, uint req)
{
  bool was_unset ;
  ushort mtype ;

  test_object_check(to, embed, req) ;   /* check valid          */

  was_unset = (to->ql.state == qls_unset) ;
  mtype     = to->ql.mtype ;

  qlump_free_body(&to->ql) ;

  if (was_unset)
    test_assert(to->ql.state == qls_unset,
             "was qls_unset but is=%d after qlump_free_body()", to->ql.state) ;
  else
    test_assert(to->ql.state == qls_normal,
                   "expect qls_normal after qlump_free_body(), but is=%d",
                                                                to->ql.state) ;
  test_assert(to->ql.body.v == NULL,
               "expect a_body = NULL after qlump_free_body(), but is not") ;
  test_assert(to->ql.size == 0,
               "expect size = 0 after qlump_free_body(), but is=%u",
                                                             to->ql.size) ;
  test_assert(to->ql.len == 0,
               "expect len = 0 after qlump_free_body(), but is=%u",
                                                              to->ql.len) ;
  test_assert(to->ql.cp == 0,
               "expect cp = 0 after qlump_free_body(), but is=%u",
                                                             to->ql.cp) ;
  test_assert(to->ql.mtype == mtype,
           "expect mtype unchanged after qlump_free_body(), was=%u but is=%u",
                                                         mtype, to->ql.mtype) ;

  test_assert(to->a_size == 0, "after qlump_free_body(), but a_size=%lu",
                                                                   to->a_size) ;
  test_assert(to->a_body == NULL,
                                "after qlump_free_body(), but a_body != NULL") ;

  memset(to, 0, sizeof(test_object_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Check that given test_object is valid.
 *
 * Checks for embedded body:
 *
 *   * if is qls_normal and 'should_embed':
 *
 *       req + size_term must be > size_embedded.
 *
 *     When starting from an empty (or alias or unset) qlump, an initial
 *     allocation should be satisfied by the embedded body, if the req is not
 *     zero and will fit.
 *
 *     When doing qlump_reduce, should use the embedded body if the result is
 *     not zero length and will fit.
 *
 *   * if is qls_embedded:
 *
 *       req + size_term must be <= size_embedded.
 *
 *     Should never use the embedded body if is too small !
 */
static void
test_object_check(test_object to, bool should_embed, uint req)
{
  if (to->a_size == 0)
    assert(to->a_body == NULL) ;
  else
    assert(to->a_body != NULL) ;

  switch (to->ql.state)
   {
     case qls_unset:
       test_assert(to->a_size == 0, "qls_unset, but a_size=%lu", to->a_size) ;

       break ;

     case qls_normal:
       test_assert(((size_t)to->ql.size * to->qt->unit) == to->a_size,
           "qls_normal, but size(%u) * unit(%u) do not match a_size(%lu)",
                                       to->ql.size, to->qt->unit, to->a_size) ;

       test_assert(to->ql.body.v == to->a_body,
                                            "qls_normal, but body != a_body") ;

       test_assert(to->ql.body.v != test_alias,
                                        "qls_normal, but body == test_alias") ;
       test_assert(to->ql.body.v != to->embedded_a,
                                        "qls_normal, but body == embedded_a") ;
       test_assert(to->ql.body.v != to->embedded_b,
                                        "qls_normal, but body == embedded_b") ;

       test_assert(to->ttype == to->ql.mtype,
         "qls_normal, but ttype=%u != mtype=%d", to->ttype, to->ql.mtype) ;

       if (should_embed && (req != 0))
         test_assert((req + to->qt->size_term) > to->qt->embedded_size,
             "qls_normal, but req=%u, size_term=%u and embedded_size=%u,"
             " so should be embedded", req, to->qt->size_term,
                                                        to->qt->embedded_size) ;
       break ;

     case qls_embedded:
       test_assert(to->qt->embedded_size > 0,
               "qls_embedded, but embedded_size == 0 !!") ;

       test_assert(to->ql.size == to->qt->embedded_size,
               "qls_embedded, embedded_size=%u, but size=%u",
                                          to->qt->embedded_size, to->ql.size) ;

       test_assert(to->ql.body.v == to->embedded,
                                "qls_embedded, but a_body not set correctly") ;

       test_assert(to->ttype == to->ql.mtype,
           "qls_embedded, but ttype=%u != mtype=%d", to->ttype, to->ql.mtype) ;

       test_assert((req + to->qt->size_term) <= to->qt->embedded_size,
             "qls_embedded, but req=%u, size_term=%u and embedded_size=%u,"
             " so should not be embedded", to->ql.len, to->qt->size_term,
                                                        to->qt->embedded_size) ;
       break ;

     case qls_alias:
       test_assert(to->ql.size == 0, "qls_alias, but size=%u", to->ql.size) ;

       test_assert(to->a_size == 0, "qls_alias, but a_size=%lu", to->a_size) ;

       if (to->ql.len != 0)
         test_assert(to->ql.body.v == test_alias,
                 "qls_alias with len=%u, but a_body!=test_alias", to->ql.len) ;

       test_assert(to->ttype == to->ql.mtype,
              "qls_alias, but ttype=%u != mtype=%d", to->ttype, to->ql.mtype) ;

       break ;

     case qls_alias_term:
       test_assert(to->ql.size == 0, "qls_alias_term, but size=%u",
                                                                 to->ql.size) ;
       test_assert(to->a_size == 0, "qls_alias_term, but a_size=%lu",
                                                                   to->a_size) ;
       if (to->ql.len != 0)
         test_assert(to->ql.body.v == test_alias,
                 "qls_alias with len=%u, but a_body!=test_alias", to->ql.len) ;

       test_assert(to->ttype == to->ql.mtype,
         "qls_alias_term, but ttype=%u != mtype=%d", to->ttype, to->ql.mtype) ;

       break ;

     default:
       test_assert(false, "invalid ql.state=%d", to->ql.state) ;
   } ;

  test_assert(!to->stored, "part way through qlump_store() ???") ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for generating test cases -- see test_case_next().
 */
static void
test_case_init(test_case tc)
{
  memset(tc, 0, sizeof(test_case_t)) ;

  confirm(0 < ttype_first) ;
} ;

/*------------------------------------------------------------------------------
 * Step to the next test case -- including the first
 *
 * This covers tests related to qlump_extend().
 *
 *   * step to next mtype  -- tt == ttype_null => this is the first case
 *                            tt == ttype_last => go on to the next req
 *
 *   * step to next req -- unless 'req_zero', when returns 0 for each len.
 *
 *      -- for qls_alias:   0..64, then 64 random values 65..test_items_max
 *
 *      -- for all others:  0
 *
 *                          len - 3 .. 64 if len > 16
 *                          1..64,        if len <= 16
 *
 *                              NB: test_embedded_items_max < 16
 *
 *                          then random values 65..test_items_max
 *
 *   * step to next len
 *
 *      -- for qls_alias:   only 1 len -- 0
 *
 *      -- for all others:  0..64, then 64 random values 65..test_items_max
 *
 *   * step to next state does:
 *
 *      qls_unset    -- first
 *
 *      qls_normal   -- next, which includes qls_embedded where possible
 *
 *      qls_alias/qls_alias_term
 *
 *                   -- since these are the same as far as qlump handling is
 *                      concerned, flips at random between the two.
 *
 *   * end
 */
static bool
test_case_next(test_case tc, bool req_zero)
{
  /* For some test cases we want to test from 0..maximum number of embedded
   * items + 1 -- so we test 0..16.
   */
  confirm(test_embedded_items_max < 16) ;

  /* We test lengths 0..64 and then 64 random, longer lengths.
   */
  confirm(test_case_count_max == (65 + 64)) ;

  /* Step through the mtypes -- looking out for first test case, and last
   * mtype.
   */
  ++tc->tt ;

  if ((tc->tt > ttype_first) && (tc->tt <= ttype_last))
    return true ;

  /* First case is delivered by forcing to end of non-existent state.
   */
  if (tc->tt == ttype_first)
    {
      tc->state    = qls_max_value + 1 ;

      tc->req_next = test_case_count_max ;
      tc->len_next = test_case_count_max ;
    } ;

  tc->tt = ttype_first ;                /* back to first        */

  /* Worry about completing req, then len, then states
   */
  if (tc->req_next >= test_case_count_max)
    {
      if (tc->len_next >= test_case_count_max)
        {
          switch (tc->state)
            {
              case qls_max_value + 1:   /* initial state        */
                tc->state = qls_unset ;
                break ;

              case qls_unset:
                tc->state = qls_normal ;
                break ;

              case qls_normal:
                tc->state = qls_alias ;
                break ;

              case qls_alias:
              case qls_alias_term:
                return false ;                  /* all done             */

              case qls_embedded:
              default:
                assert(false) ;
            } ;

          tc->len_next = 0 ;
        } ;

      /* Various starting lengths, depending on state and len_next
       */
      switch (tc->state)
        {
          case qls_unset:
            tc->len      = 0 ;          /* only one starting length     */
            tc->len_next = test_case_count_max ;  /* no more thereafter */
            break ;

          case qls_normal:
          case qls_alias:
          case qls_alias_term:
            if (tc->len_next <= 64)
              tc->len = tc->len_next ;
            else
              tc->len = 65 + (rand() % (test_items_max - 65 + 1)) ;

            tc->len_next += 1 ;
            break ;

          case qls_embedded:
          default:
            assert(false) ;
        } ;

      tc->req_next = 0 ;
    } ;

  /* Various req, depending on state, len and req_next
   */
  switch (tc->state)
    {
      case qls_unset:
        if (tc->req_next <= 64)
          tc->req = tc->req_next ;
        else
          tc->req = 65 + (rand() % (test_items_max - 65 + 1)) ;

        tc->req_next++ ;
        break ;

      case qls_alias:
      case qls_alias_term:
        tc->state = (rand() % 2) ? qls_alias : qls_alias_term ;

        fall_through ;

      case qls_normal:
        if (tc->req_next == 0)
          {
            tc->req   = 0 ;
          }
        else if (tc->req_next <= 64)
          {
            if ((tc->len > 16) && (tc->req_next < (tc->len - 3)))
              tc->req_next = tc->len - 3 ;

            tc->req = tc->req_next ;
          }
        else
          {
            tc->req = 65 + (rand() % (test_items_max - 65 + 1)) ;
          } ;

        break ;

      case qls_embedded:
      default:
        assert(false) ;
    } ;

  if (req_zero)
    tc->req_next = test_case_count_max ;
  else
    tc->req_next += 1 ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Skip remaining 'req' test cases
 */
static void
test_case_skip_req(test_case tc)
{
  tc->req_next = test_case_count_max ;
} ;

/*------------------------------------------------------------------------------
 * Fill test_object and test_vector for the current test case.
 *
 * Returns the test case 'req'.
 */
static uint
test_case_gen(test_object to, test_case tc, bool fill)
{
  test_object_init(to, tc->tt, false /* not unset */) ;

  switch (tc->state)
    {
      case qls_unset:
        to->ql.state = qls_unset ;
        fill = false ;
        break ;

      case qls_normal:
        qlump_init(&to->ql, tc->len, tc->tt) ;

        to->ql.len = tc->len ;

        /* qlump_init() should embed if can, unless req == 0
         */
        test_object_check(to, tc->len != 0, tc->len) ;
        break ;

      case qls_alias:
      case qls_alias_term:
        to->ql.state  = tc->state ;
        to->ql.mtype  = tc->tt ;
        to->ql.size   = 0 ;
        to->ql.body.v = test_alias ;
        to->ql.len    = tc->len ;
        break ;

      default:
        assert(false) ;
    } ;

  if (fill)
    test_vector_fill(to, tc->len, to->ql.body.v) ;

  return tc->req ;
} ;

/*==============================================================================
 * Mash test_vector to match qlump operation, so can verify.
 */
static void test_vector_fill_prepare(test_object to, uint len, byte* b) ;
static void test_vector_fill_body(test_object to, uint len, byte* b) ;

/*------------------------------------------------------------------------------
 * Fill test vector and given body (if any) to the given length
 *
 * The given 'to' has 'len' entries in the body pointed at by 'b'.
 *
 * The body may be:  NULL          -- in which case len == 0
 *
 *                   test_alias    -- where all aliased test objects point
 *
 *                   to->embedded  -- for embedded
 *
 *                   actual body   -- normal operation
 *
 * The to->test_vector contains the ordinals 1..len of the len items in
 * the initial body value.
 *
 * The body value has its first and last bytes set to the same ordinal, and
 * any bytes between are filled with a marching pattern, starting with the
 * ordinal.
 *
 * NB: test object *must* be initialised, and given body *must* have the
 *     required space.
 */
static void
test_vector_fill(test_object to, uint len, byte* b)
{
  test_vector_fill_prepare(to, len, b) ;
  test_vector_fill_body(to, len, b) ;
} ;

/*------------------------------------------------------------------------------
 * Fill test vector and given body (if any) to the given length, with
 * random values.
 *
 * This is the same as test_vector_fill(), except that the ordinals do not
 * run 1..len, they are put in random order.  Further, the 'rep' count
 * specifies how many times to produce a repeated value.  (Note that each
 * time a repeat is tried, two items are selected and one is written over the
 * other.
 *
 * The given 'to' has 'len' entries in the body pointed at by 'b'.
 *
 * The body may be:  NULL          -- in which case len == 0
 *
 *                   test_alias    -- where all aliased test objects point
 *
 *                   to->embedded  -- for embedded
 *
 *                   actual body   -- normal operation
 *
 * The to->test_vector contains the ordinals 1..len of the len items in
 * the initial body value.
 *
 * The body value has its first and last bytes set to the same ordinal, and
 * any bytes between are filled with a marching pattern, starting with the
 * ordinal.
 *
 * NB: test object *must* be initialised, and given body *must* have the
 *     required space.
 */
static void
test_vector_fill_random(test_object to, uint len, byte* b, uint rep)
{
  byte* tv ;
  uint  i ;

  test_vector_fill_prepare(to, len, b) ;

  /* Random shuffle for the to->test_vector
   */
  tv = to->test_vector ;
  for (i = 0 ; i < len ; ++i)
    {
      uint j ;

      j = i + (rand() % (len - i)) ;

      if (j != i)
        {
          byte t ;
          t = tv[i] ;
          tv[i] = tv[j] ;
          tv[j] = t ;
        } ;
    } ;

  /* Random repetitions
   */
  while ((rep > 0) && (len > 1))
    {
      --rep ;
      tv[rand() % len ] = tv[rand() % len ] ;
    } ;

  test_vector_fill_body(to, len, b) ;
} ;

/*------------------------------------------------------------------------------
 * Prepare test vector for the given length
 *
 * The given 'to' is to have 'len' entries'.
 *
 * The body may be:  NULL          -- in which case len == 0
 *
 *                   test_alias    -- where all aliased test objects point
 *
 *                                    to->tv_alias_len are set
 *
 *                   to->embedded  -- for embedded
 *
 *                   actual body   -- normal operation
 *
 * The to->test_vector is set to contain the ordinals 1..len of the len items
 * in the initial body value.
 *
 * NB: test object *must* be initialised, and given body *must* have the
 *     required space.
 */
static void
test_vector_fill_prepare(test_object to, uint len, byte* b)
{
  byte* tv ;
  uint  i, unit ;

  memset(to->test_vector, 0, test_vector_max) ;

  assert(len <= test_items_max) ;

  confirm(test_items_max < 255) ;

  unit = to->qt->unit ;

  if (b == NULL)
    {
      to->tv_len       = 0 ;
      to->tv_alias_len = 0 ;

      assert(len == 0) ;
    }
  else if (b == test_alias)
    {
      to->tv_len       = len ;
      to->tv_alias_len = len ;
    }
  else if (b == to->embedded)
    {
      assert((b == to->embedded_a) || (b == to->embedded_b)) ;
      assert(sizeof(to->embedded_a) == sizeof(to->embedded_b)) ;
      assert((len * unit) <= sizeof(to->embedded_a)) ;

      to->tv_len       = len ;
      to->tv_alias_len = 0 ;
    }
  else
    {
      assert((len * unit) <= to->a_size) ;
      to->tv_len       = len ;
      to->tv_alias_len = 0 ;
    } ;

  tv = to->test_vector ;
  for (i = 1 ; i <= len ; ++i)
    *tv++ = i ;
} ;

/*------------------------------------------------------------------------------
 * From the 'len' ordinals in the to->test_vector set the item values in the
 * given body.
 *
 * Each unit in the body has its first and last (if any) byte set to the
 * ordinal from the to->test_vector, and any bytes between are filled with
 * a marching pattern, starting with the ordinal.
 */
static void
test_vector_fill_body(test_object to, uint len, byte* b)
{
  byte* tv ;
  uint  i, unit ;

  if (b == NULL)
    assert(len == 0) ;

  unit = to->qt->unit ;
  tv   = to->test_vector ;

  for (i = 0 ; i < len ; ++i)
    {
      byte  v ;

      v = *tv++ ;

      if (b != NULL)
        {
          byte vx ;
          uint j ;

          vx = v ;
          for (j = 0 ; j < unit - 1 ; ++j)
            {
              *b++ = vx ;
              vx += 0x55 ;
            } ;

          *b++ = v ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Chop end off test vector
 */
static void
test_vector_chop(test_object to, uint len)
{
  assert(len <= to->tv_len) ;

  if (len < test_vector_max)
    memset(to->test_vector + len, 0, test_vector_max - len) ;

  to->tv_len = len ;
  if (to->tv_alias_len != 0)
    to->tv_alias_len = len ;
} ;

/*------------------------------------------------------------------------------
 * Do analogue of qlump_bubble() in the test_vector.
 */
static void
test_vector_bubble(test_object to, uint at, uint r, uint n)
{
  byte  temp[test_vector_max] ;
  uint  a ;

  memcpy(temp, to->test_vector, test_vector_max) ;

  assert((at + r) <= test_vector_max) ;
  assert((at + n) <= test_vector_max) ;

  if (at < test_vector_max)
    memset(to->test_vector + at, 0, test_vector_max - at) ;

  if ((at + r) >= to->tv_len)
    a = 0 ;
  else
    {
      if (at >= to->tv_len)
        a = 0 ;
      else
        {
          a = to->tv_len - at - r ;

          assert((at + n + a) <= test_vector_max) ;
          assert(a > 0) ;

          memcpy(to->test_vector + at + n, temp + at + r, a) ;
        } ;
    } ;

  to->tv_len = at + n + a ;
} ;

/*------------------------------------------------------------------------------
 * Do analogue of qlump_swap_items() in the test_vector.
 */
static void
test_vector_swap(test_object to, uint size, uint a, uint na, uint b, uint nb)
{
  byte  temp[test_vector_max] ;
  byte* p ;
  uint  q, nq ;

  assert(size <= test_vector_max) ;

  /* Clamp everything within size
   */
  if ((a + na) > size)
    {
      if (a > size)
        a = size ;

      na = size - a ;
    } ;

  if ((b + nb) > size)
    {
      if (b > size)
        b = size ;

      nb = size - b ;
    } ;

  /* Get in order
   */
  if (a > b)
    {
      q  = a ;
      a  = b ;
      b  = q ;

      nq = na ;
      na = nb ;
      nb = nq ;
    } ;

  /* Any overlap belongs to a
   */
  if ((a + na) > b)
    {
      uint eb ;

      eb = b + nb ;
      b  = a + na ;

      if (b < eb)
        nb = eb - b ;
      else
        nb = 0 ;
    } ;

  /* The gap between a and b and the stuff beyond
   */
  q  = a + na ;
  nq = b - q ;

  /* Copy stuff to emulate swap.
   */
  p = &to->test_vector[a] ;

  if ((na + nq + nb) > 0)
    memcpy(&temp[a], p, na + nq + nb) ;
                                /* copy stuff to swap   */

  if (nb > 0)
    memcpy(p, &temp[b], nb) ;   /* b into place         */
  p += nb ;

  if (nq > 0)
    memcpy(p, &temp[q], nq) ;   /* q into place         */
  p += nq ;

  if (na > 0)
    memcpy(p, &temp[a], na) ;   /* a into place         */
} ;

/*------------------------------------------------------------------------------
 * Do analogue of qlump_sort() in the test_vector.
 */
static void
test_vector_sort(test_object to)
{
  byte* tv ;
  uint i, n ;

  tv = to->test_vector ;
  n  = to->tv_len ;

  for (i = 0 ; (n > 1) && (i < (n - 1)) ; ++i)
    {
      uint j ;

      for (j = i+1 ; j < n ; ++j)
        {
          if (tv[j] < tv[i])
            {
              byte t ;

              t     = tv[i] ;
              tv[i] = tv[j] ;
              tv[j] = t ;
            } ;
        } ;
    } ;

  to->tv_len = n ;
} ;

/*------------------------------------------------------------------------------
 * Do analogue of qlump_sort_dedup() in the test_vector.
 */
static void
test_vector_sort_dedup(test_object to)
{
  byte* tv ;
  uint i, n ;

  tv = to->test_vector ;
  n  = to->tv_len ;

  for (i = 0 ; (n > 1) && (i < (n - 1)) ; ++i)
    {
      uint j ;

      for (j = i+1 ; j < n ; ++j)
        {
          while (tv[j] == tv[i])
            {
              n -= 1 ;

              if (j == n)
                break ;

              tv[j] = tv[n] ;
            } ;

          if (tv[j] < tv[i])
            {
              byte t ;

              t     = tv[i] ;
              tv[i] = tv[j] ;
              tv[j] = t ;
            } ;
        } ;
    } ;

  to->tv_len = n ;
} ;

/*------------------------------------------------------------------------------
 * Check that test vector and contents of qlump match.
 */
static void
test_vector_check(test_object to)
{
  byte* tv ;
  byte* b ;
  uint i, unit, l ;

  if (!test_assert(to->tv_len <= to->ql.len,
                               "tv_len=%u but len=%u", to->tv_len, to->ql.len))
    return ;

  if (to->ql.state == qls_unset)
    return ;

  if (!test_assert(to->ttype == to->ql.mtype,
            "not qls_unset, but ttype=%u != mtype=%d", to->ttype, to->ql.mtype))
    return ;

  unit = to->qt->unit ;
  tv   = to->test_vector ;
  b    = to->ql.body.v ;

  if      (b == NULL)
    l = 0 ;
  else if (b == test_alias)
    l = to->tv_alias_len ;
  else if (b == to->embedded)
    l = to->qt->embedded_size ;
  else
    l = to->a_size / unit ;

  for (i = 0 ; i < to->ql.len ; ++i)
    {
      byte v ;

      v = *tv++ ;

      if (v == 0)
        b += unit ;
      else
        {
          byte vx ;
          uint j ;

          if (!test_assert(i < l, "test vector length mismatch, item=%u", i))
            return ;

          vx = v ;
          for (j = 0 ; j < unit - 1 ; ++j)
            {
              if (!test_assert(*b == vx,
                            "test vector mismatch, item=%u byte=%u", i, j))
                return ;

              ++b ;
              vx += 0x55 ;
            } ;

          if (!test_assert(*b == v,
                        "test vector mismatch, item=%u byte=%u", i, j))
            return ;

          ++b ;
        } ;
    } ;
} ;

/*==============================================================================
 * Testing of qlump_register_type().
 *
 * Try all forms of broken types.
 *
 * Also, register the test qlump types.
 */

/*------------------------------------------------------------------------------
 * Various gash qlump_type_t
 */
static const qlump_type_t gash_qt_1 =
{
  .alloc        = NULL,                 /* missing              */
  .free         = qlump_free,

  .unit         = 1,

  .size_add     = 32,
  .size_unit_m1 = 32 - 1,

  .size_min     = 64,

  .size_min_unit_m1 = 4 - 1,

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_2 =
{
  .alloc        = qlump_alloc,
  .free         = NULL,                 /* missing              */

  .unit         = 1,

  .size_add     = 32,
  .size_unit_m1 = 32 - 1,

  .size_min     = 64,

  .size_min_unit_m1 = 4 - 1,

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_3 =
{
  .alloc        = NULL,                 /* missing              */
  .free         = NULL,                 /* missing              */

  .unit         = 1,

  .size_add     = 32,
  .size_unit_m1 = 32 - 1,

  .size_min     = 64,

  .size_min_unit_m1 = 4 - 1,

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_4 =
{
  .alloc        = qlump_alloc,
  .free         = qlump_free,

  .unit         = 0,                    /* invalid              */

  .size_add     = 32,
  .size_unit_m1 = 32 - 1,

  .size_min     = 64,

  .size_min_unit_m1 = 4 - 1,

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_5 =
{
  .alloc        = qlump_alloc,
  .free         = qlump_free,

  .unit         = 1,

  .size_add     = 0,                    /* note that .size_min != 0     */
  .size_unit_m1 = 64 + (32 - 1),        /* invalid              */

  .size_min     = 1,

  .size_min_unit_m1 = 4 - 1,

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_6 =
{
  .alloc        = qlump_alloc,
  .free         = qlump_free,

  .unit         = 32,

  .size_add     = 0,                    /* note that size_min == 0      */
  .size_unit_m1 = 0,                    /* this is valid                */

  .size_min     = 0,                    /* note that size_add == 0      */

  .size_min_unit_m1 = 77,               /* invalid              */

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_7 =
{
  .alloc        = qlump_alloc,
  .free         = qlump_free,

  .unit         = 11,

  .size_add     = 1,
  .size_unit_m1 = 1,                    /* this is valid                */

  .size_min     = 1,

  .size_min_unit_m1 = 3,                /* also valid                   */

  .embedded_size   = 0,
  .embedded_offset = 0,
} ;

static const qlump_type_t gash_qt_8 =
{
  .alloc        = qlump_alloc,
  .free         = qlump_free,

  .unit         = 11,

  .size_add     = 1,
  .size_unit_m1 = 1,                    /* this is valid                */

  .size_min     = 1,

  .size_min_unit_m1 = 3,                /* also valid                   */

  .embedded_size   = 0,
  .embedded_offset = 1,                 /* different !          */
} ;


/*------------------------------------------------------------------------------
 * Table of stuff to register, and what return we expect to get.
 */
struct test_register
{
  const qlump_type_t*   qt ;
  const mtype_t         mtype ;
  const char*           how ;
  const qlump_register_ret_t exp ;
} ;

static const struct test_register  test_register_table[] =
{
    /* First, the gash registrations which we expect will, mostly, fail.
     */
    { .qt    = &gash_qt_7,
      .mtype = MTYPE_NULL,
      .how   = " 1: mtype == MTYPE_NULL",
      .exp   = qlrr_invalid_mtype,
    },
    { .qt    = &gash_qt_7,
      .mtype = MTYPE_MAX,
      .how   = " 2: mtype == MTYPE_MAX",
      .exp   = qlrr_invalid_mtype,
    },
    { .qt    = &gash_qt_7,
      .mtype = MTYPE_MAX + 7117,
      .how   = " 3: mtype == MTYPE_MAX + 7177",
      .exp   = qlrr_invalid_mtype,
    },
    { .qt    = &gash_qt_1,
      .mtype = MTYPE_MAX - 1,
      .how   = " 4: missing .alloc",
      .exp   = qlrr_functions,
    },
    { .qt    = &gash_qt_2,
      .mtype = MTYPE_MAX - 1,
      .how   = " 5: missing .free",
      .exp   = qlrr_functions,
    },
    { .qt    = &gash_qt_3,
      .mtype = MTYPE_MAX - 1,
      .how   = " 6: missing .alloc and .free",
      .exp   = qlrr_functions,
    },
    { .qt    = &gash_qt_4,
      .mtype = MTYPE_MAX - 1,
      .how   = " 7: .unit = 0",
      .exp   = qlrr_zero_unit,
    },
    { .qt    = &gash_qt_5,
      .mtype = MTYPE_MAX - 1,
      .how   = " 8: .size_unit_m1 != (2^n)-1",
      .exp   = qlrr_size_unit_m1,
    },
    { .qt    = &gash_qt_6,
      .mtype = MTYPE_MAX - 1,
      .how   = " 9: .size_min_unit_m1 != (2^n)-1",
      .exp   = qlrr_size_min_unit_m1,
    },
    { .qt    = &gash_qt_7,
      .mtype = MTYPE_MAX - 1,
      .how   = "10: register a valid type",
      .exp   = qlrr_ok,
    },
    { .qt    = &gash_qt_8,
      .mtype = MTYPE_MAX - 1,
      .how   = "11: re-register different type",
      .exp   = qlrr_reregister,
    },

    /* Second, register the test types
     */
    { .qt    = &test_qt[ttype_s1],
      .mtype = ttype_s1,
      .how   = "12: register 'ttype_s1'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s4],
      .mtype = ttype_s4,
      .how   = "13: register 'ttype_s4'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s24],
      .mtype = ttype_s24,
      .how   = "14: register 'ttype_s24'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s11],
      .mtype = ttype_s11,
      .how   = "15: register 'ttype_s11'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e1],
      .mtype = ttype_e1,
      .how   = "16: register 'ttype_e1'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e4],
      .mtype = ttype_e4,
      .how   = "17: register 'ttype_e4'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e16],
      .mtype = ttype_e16,
      .how   = "18: register 'ttype_e16'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e9],
      .mtype = ttype_e9,
      .how   = "19: register 'ttype_e9'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s1t],
      .mtype = ttype_s1t,
      .how   = "20: register 'ttype_s1t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s8t],
      .mtype = ttype_s8t,
      .how   = "21: register 'ttype_s8t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s32t],
      .mtype = ttype_s32t,
      .how   = "22: register 'ttype_s32t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_s15t],
      .mtype = ttype_s15t,
      .how   = "23: register 'ttype_s15t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e1t],
      .mtype = ttype_e1t,
      .how   = "24: register 'ttype_e1t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e4t],
      .mtype = ttype_e4t,
      .how   = "25: register 'ttype_e4t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e16t],
      .mtype = ttype_e16t,
      .how   = "26: register 'ttype_e16t'",
      .exp   = qlrr_ok,
    },
    { .qt    = &test_qt[ttype_e9t],
      .mtype = ttype_e9t,
      .how   = "27: register 'ttype_e9t'",
      .exp   = qlrr_ok,
    },

    { .qt   = NULL      }
} ;

/*------------------------------------------------------------------------------
 * Test the registration of qlump_type
 */
static void
test_qlump_register_type(void)
{
  uint fail_count_was, test_count_was ;
  const struct test_register* q ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_register_type()") ;

  q = test_register_table ;
  while (q->qt != NULL)
    {
      qlump_register_ret_t get ;

      next_test() ;

      get = qlump_register_type(q->mtype, q->qt, true /* test */) ;

      test_assert(q->exp == get, "for '%s' expected ret=%d, got=%d",
                                                          q->how, q->exp, get) ;
      ++q ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_init()
 *
 * Not much to test here -- the heavy lifting is done by qlump_extend().
 *
 * Just check that for req == 0, we end up with a nice, clean, empty qlump,
 * and that for req == 1, we end upo with a nice clean not-empty qlump.
 *
 * After each qlump_init(), does a qlump_free_body() as part of
 * test_object_done().
 */
static void
test_qlump_init(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t to[1] ;
  ttype_t       tt ;

  uint          req ;
  void*         body ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_init()") ;

  for (req = 0 ; req <= 1 ; req++)
    {
      for (tt = ttype_first ; tt <= ttype_last ; ++tt)
        {
          next_test() ;

          test_object_init(to, tt, false /* rubbish */) ;

          body = qlump_init(&to->ql, req, tt) ;

          if (req == 0)
            {
              test_assert(to->ql.state == qls_normal,
                             "expect qls_normal after qlump_init(0), but is=%d",
                                                                 to->ql.state) ;
              test_assert(to->ql.size == 0,
                         "expect size==0 after qlump_init(0), but is=%u",
                                                                 to->ql.size) ;
              test_assert(body == NULL,
                           "expect body==NULL after qlump_init(0), but isn't") ;
            }
          else
            {
              if (to->qt->embedded_size < (req + to->qt->size_term))
                test_assert(to->ql.state == qls_normal,
                           "expect qls_normal after qlump_init(%u), but is=%d",
                                                            req, to->ql.state) ;
              else
                test_assert(to->ql.state == qls_embedded,
                          "expect qls_embedded after qlump_init(%u), but is=%d",
                                                            req, to->ql.state) ;

              test_assert(to->ql.size >= (req + to->qt->size_term),
                       "expect size >= %u after qlump_init(%u), but is=%u",
                                   req + to->qt->size_term, req, to->ql.size) ;

              test_assert(body != NULL,
                         "expect body after qlump_init(%u), but is NULL", req) ;
            } ;

          test_assert(body == to->ql.body.v,
                           "expect return body == ql.body after qlump_init()") ;

          test_assert(to->ql.len == 0,
                       "expect len==0 after qlump_init(), but is=%u",
                                                               to->ql.len) ;

          test_assert(to->ql.cp == 0,
                         "expect cp==0 after qlump_init(), but is=%u",
                                                                   to->ql.cp) ;

          /* qlump_init() should embed, unless req == 0.
           */
          test_object_done(to, req != 0, req) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_set_alias()
 *
 * After each qlump_set_alias(), does a qlump_free_body() as part of
 * test_object_done().
 */
static void
test_qlump_set_alias(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t to[1] ;
  ttype_t       tt ;
  byte          temp[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_set_alias()") ;

  uint req ;

  for (req = 0 ; req <= 100 ; req++)
    {
      uint len ;

      if (req <= 64)
        len = req ;
      else
        len = 65 + (rand() % (test_items_max - 65 + 1)) ;

      for (tt = ttype_first ; tt <= ttype_last ; ++tt)
        {
          uint state ;
          uint alias_type ;

          alias_type = (rand() % 1) ? qls_alias : qls_alias_term ;

          for (state = 0 ; state <= 2 ; ++state)
            {
              next_test() ;

              test_object_init(to, tt, false /* rubbish */) ;

              switch (state)
                {
                  case 0:               /* start unset                  */
                    to->ql.state = qls_unset ;
                    break ;

                  case 1:               /* start with some other alias  */
                    to->ql.state = (alias_type == qls_alias) ? qls_alias_term
                                                             : qls_alias ;
                    to->ql.mtype  = tt ;
                    to->ql.size   = 0 ;
                    to->ql.len    = rand() % 200 ;
                    to->ql.cp     = rand() % 200 ;
                    to->ql.body.v = temp ;
                    break ;

                  case 2:               /* start with some body         */
                    qlump_init(&to->ql, req, tt) ;

                    to->ql.len = rand() % (req + 1) ;
                    break ;
                } ;

              test_vector_fill(to, len, test_alias) ;

              qlump_set_alias(&to->ql, alias_type, test_alias, len, tt) ;

              if (len == 0)
                {
                  test_assert(to->ql.state == qls_normal,
                           "expect qls_normal after qlump_set_alias(0)"
                                                " but state=%u", to->ql.state) ;
                  test_assert(to->ql.body.v == NULL,
                      "expect body==NULL after qlump_set_alias(0)") ;
                }
              else
                {
                  test_assert(to->ql.state == alias_type,
                         "expect state=%u after qlump_set_alias() but state=%u",
                                                     alias_type, to->ql.state) ;
                  test_assert(to->ql.body.v == test_alias,
                      "expect body==test_alias after qlump_set_alias()") ;
                } ;

              test_assert(to->ql.size == 0,
                  "expect size=0 after qlump_set_alias(), but is %u",
                                                                  to->ql.size) ;

              test_assert(to->ql.len == len,
                  "expect len=%u after qlump_set_alias(), but is %u",
                                                              len, to->ql.len) ;

              test_assert(to->ql.cp == 0,
                  "expect cp=0 after qlump_set_alias(), but is %u",
                                                                   to->ql.cp) ;
              test_vector_check(to) ;

              test_object_done(to, false /* not embed */, 0 /* not embed*/) ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_clear()
 *
 * Start with qlump in all possible states, with len and cp zero and not
 * zero, and verify that result is as expected:
 */
static void
test_qlump_clear(void)
{
  uint fail_count_was, test_count_was ;

  qlump_t   ql[1] ;
  uint      st, req ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_clear()") ;

  for (st = 0 ; st < qls_max_value ; st++)
    {
      for (req = 0 ; req <= 7 ; ++req)
        {
          uint  size ;
          uint  mtype ;
          void* body ;

          next_test() ;

          switch (st)
            {
              case qls_unset:
              case qls_normal:
                if (req & 4)
                  size = (rand() % 2000) + 1 ;
                else
                  size = 0 ;

                body = (void*)((uintptr_t)rand() | 1) ;
                break ;

              case qls_embedded:
                size = (rand() % 15) + 1 ;
                body = (void*)ql ;
                break ;

              case qls_alias:
              case qls_alias_term:
                size = 0 ;
                body = test_alias ;
                break ;

              default:
                assert(false) ;
            } ;

          if (req & 1)
            ql->cp = (rand() % 2000) + 1 ;
          else
            ql->cp = 0 ;

          if (req & 2)
            ql->len = (rand() % 2000) + 1 ;
          else
            ql->len = 0 ;

          ql->state  = st ;
          ql->mtype  = mtype = rand() % 12 ;
          ql->size   = size ;
          ql->body.v = body ;

          qlump_clear(ql) ;

          test_assert(ql->len == 0,
                         "expect len==0 after qlump_clear(), got %u", ql->len) ;
          test_assert(ql->cp == 0,
                         "expect cp==0 after qlump_clear(), got %u", ql->cp) ;
          test_assert(ql->mtype == mtype,
             "expect mtype unchanged after qlump_clear(), was=%u got=%u",
                                                             mtype, ql->mtype) ;

          test_assert(ql->size == size,
            "expect size unchanged after qlump_clear() but was=%u got=%u",
                                                               size, ql->size) ;

          switch (st)
            {
              case qls_unset:
                test_assert(ql->state == st,
                  "for qls_unset, expect state unchanged after qlump_clear(),"
                    " but got=%u", ql->state) ;

                test_assert(ql->body.v == body,
                  "for qls_unset, expect body unchanged after qlump_clear()") ;

                break ;

              case qls_normal:
                test_assert(ql->state == st,
                  "for qls_normal, expect state unchanged after qlump_clear(),"
                    " but got=%u", ql->state) ;

                if (size != 0)
                  test_assert(ql->body.v == body,
                      "for qls_normal with size !=0,"
                                 " expect body unchanged after qlump_clear()") ;
                else
                  test_assert(ql->body.v == NULL,
                      "for qls_normal with size !=0,"
                                 " expect body unchanged after qlump_clear()") ;


                break ;

              case qls_embedded:
                test_assert(ql->state == st,
                  "for qls_embedded,"
                  " expect state unchanged after qlump_clear(),"
                  " but got=%u", ql->state) ;

                test_assert(ql->body.v == body,
                  "for qls_embedded,"
                                 " expect body unchanged after qlump_clear()") ;
                break ;

              case qls_alias:
              case qls_alias_term:
                assert((size == 0) && (ql->size ==0)) ;

                test_assert(ql->state == qls_normal,
                  "for qls_alias/qls_alias_term,"
                  " expect state els_normal after qlump_clear(),"
                  " but got=%u", ql->state) ;

                test_assert(ql->body.v == NULL,
                    "for qls_alias/qls_alias_term,"
                                     " expect body==NULL after qlump_clear()") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_alias_clear()
 *
 * Start with qlump in all possible states, with len and cp zero and not
 * zero, and verify that result is as expected:
 */
static void
test_qlump_alias_clear(void)
{
  uint fail_count_was, test_count_was ;

  qlump_t   ql[1] ;
  uint      st, req ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_alias_clear()") ;

  for (st = 0 ; st < qls_max_value ; st++)
    {
      for (req = 0 ; req <= 7 ; ++req)
        {
          uint  len ;
          uint  cp ;
          uint  size ;
          uint  mtype ;
          void* body ;

          next_test() ;

          switch (st)
            {
              case qls_unset:
              case qls_normal:
                if (req & 4)
                  size = (rand() % 2000) + 1 ;
                else
                  size = 0 ;

                body = (void*)((uintptr_t)rand() | 1) ;
                break ;

              case qls_embedded:
                size = (rand() % 15) + 1 ;
                body = (void*)ql ;
                break ;

              case qls_alias:
              case qls_alias_term:
                size = 0 ;
                body = test_alias ;
                break ;

              default:
                assert(false) ;
            } ;

          if (req & 1)
            cp = (rand() % 2000) + 1 ;
          else
            cp = 0 ;

          if (req & 2)
            len = (rand() % 2000) + 1 ;
          else
            len = 0 ;

          ql->state  = st ;
          ql->mtype  = mtype = rand() % 12 ;
          ql->cp     = cp ;
          ql->len    = len ;
          ql->size   = size ;
          ql->body.v = body ;

          qlump_alias_clear(ql) ;

          test_assert(ql->mtype == mtype,
             "expect mtype unchanged after qlump_alias_clear(), was=%u got=%u",
                                                             mtype, ql->mtype) ;
          switch (st)
            {
              case qls_unset:
              case qls_normal:
              case qls_embedded:
                test_assert(ql->state == st,
                  "for qls_unset/_normal/_embedded,"
                    " expect state unchanged after qlump_alias_clear(),"
                    " but got=%u", ql->state) ;

                test_assert(ql->body.v == body,
                  "for qls_unset/_normal/_embedded,"
                  " expect body unchanged after qlump_alias_clear()") ;

                test_assert(ql->size == size,
                    "for qls_unset/_normal/_embedded,"
                      " expect size unchanged after qlump_alias_clear(),"
                      " was=%u but got=%u", size, ql->size) ;

                test_assert(ql->len == len,
                    "for qls_unset/_normal/_embedded,"
                      " expect len unchanged after qlump_alias_clear(),"
                      " was=%u but got=%u", len, ql->len) ;

                test_assert(ql->cp == cp,
                    "for qls_unset/_normal/_embedded,"
                      " expect cp unchanged after qlump_alias_clear(),"
                      " was=%u but got=%u", cp, ql->cp) ;
                break ;

              case qls_alias:
              case qls_alias_term:
                assert(size == 0) ;

                test_assert(ql->state == qls_normal,
                  "for qls_alias/qls_alias_term,"
                  " expect state els_normal after qlump_alias_clear(),"
                  " but got=%u", ql->state) ;

                test_assert(ql->size == 0,
                  "for qls_alias/qls_alias_term,"
                  " expect size==0 after qlump_alias_clear(), but got=%u",
                                                                     ql->size) ;
                test_assert(ql->len == 0,
                  "for qls_alias/qls_alias_term,"
                           " expect len==0 after qlump_alias_clear(), got %u",
                                                                      ql->len) ;
                test_assert(ql->cp == 0,
                  "for qls_alias/qls_alias_term,"
                            " expect cp==0 after qlump_alias_clear(), got %u",
                                                                       ql->cp) ;

                test_assert(ql->body.v == NULL,
                    "for qls_alias/qls_alias_term,"
                    " expect body==NULL after qlump_alias_clear()") ;
                break ;

              default:
                assert(false) ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_re_init()
 *
 * This is almost a clone of test for qlump_extend(), except that for alias
 * we expect an empty qlump.
 */
static void
test_qlump_alias_re_init(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_alias_re_init()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, false /* all req */))
    {
      uint  req, state_was, size_was ;
      bool  should_embed ;

      next_test() ;

      req = test_case_gen(to, tc, false /* no fill */) ;

      state_was = to->ql.state ;

      if (state_was != qls_unset)
        assert(to->ql.mtype == to->ttype) ;

      size_was = to->ql.size ;

      qlump_re_init(&to->ql, req, to->ttype) ;

      test_assert(to->ql.len == 0,
                   "expect len==0 after qlump_re_init(), got %u", to->ql.len) ;
      test_assert(to->ql.cp == 0,
                     "expect cp==0 after qlump_re_init(), got %u", to->ql.cp) ;
      test_assert(to->ql.mtype == to->ttype,
                            "expect mytpe==%u after qlump_re_init(), got %u",
                                                      to->ttype, to->ql.mtype) ;

      switch (state_was)
        {
          case qls_unset:
          case qls_alias:
          case qls_alias_term:
            /* If was unset -- will now be set.
             *
             * If was alias -- that will have been discarded.
             *
             * If req == 0, will be an empty qls_normal.  Otherwise will be
             * qls_embedded (if at all possible) or qls_normal.
             */
            test_assert( (to->ql.state == qls_embedded) ||
                         (to->ql.state == qls_normal),
                "for qls_unset/qls_alias/qls_alias_term,"
                "expect qls_normal/qls_embedded after"
                " qlump_re_init(), got %u", to->ql.state) ;

            if (req == 0)
              {
                test_assert(to->ql.size == 0,
                    "for qls_unset/qls_alias/qls_alias_term,"
                    " expect size==0 after qlump_re_init(0), got %u",
                                                                 to->ql.size) ;
                test_assert(to->ql.body.v == NULL,
                    "for qls_unset/qls_alias/qls_alias_term,"
                    " expect body==NULL after qlump_re_init(0)") ;
              } ;

            should_embed = req != 0 ;   /* embed unless req == 0        */
            break ;

          case qls_normal:
            /* Was normal -- will still be so, unless was empty and the req
             *               can be satisfied by the embedded body.
             */
            if (size_was == 0)
              {
                if (req == 0)
                  {
                    /* If was an empty qlump, and request was 0, expect to
                     * still have an empty qlump -- size_term notwithstanding.
                     */
                    test_assert(to->ql.state == qls_normal,
                        "when size==0 and req=0,"
                        "expect qls_normal after qlump_re_init(), got %u",
                                                                 to->ql.state) ;
                    test_assert(to->ql.size == 0,
                        "when size==0 and req=0,"
                        "expect size==0 after qlump_re_init(), got %u",
                                                                  to->ql.size) ;
                    test_assert(to->ql.body.v == NULL,
                        "when size==0 and req=0,"
                        " expect body==NULL after qlump_re_init()") ;

                    should_embed = false ; /* not embedded, req == 0    */
                  }
                else
                  {
                    /* If was an empty qlump, but request > 0, expect to have
                     * a qls_embedded or qls_normal of suitable size.
                     */
                    test_assert( (to->ql.state == qls_embedded) ||
                                 (to->ql.state == qls_normal),
                          "when size==0 but req=%u,"
                          " expect qls_normal/qls_embedded after"
                                " qlump_re_init(), got %u", req, to->ql.state) ;

                    should_embed = true ; /* embedded, if possible      */
                  } ;
              }
            else
              {
                /* If was a not-empty qlump -- expect that to still be the case,
                 * though if req is big enough, may have extended the qlump.
                 */
                test_assert(to->ql.state == qls_normal,
                              "expect qls_normal after qlump_re_init(), got %u",
                                                                 to->ql.state) ;
                should_embed = false ;  /* not embedded         */
              };
            break ;

          case qls_embedded:
            /* Was embedded -- will still be so, unless was the req cannot be
             *                 satisfied by the embedded body.
             */
            test_assert( (to->ql.state == qls_embedded) ||
                         (to->ql.state == qls_normal),
                "expect qls_normal/qls_embedded after"
                " qlump_re_init(qls_embedded), got %u", to->ql.state) ;

            should_embed = true ;       /* should remain embedded if possible */
            break ;

          default:
            assert(false) ;
        } ;

      if (req != 0)
        {
          /* We expect a body adequate for non-zero number of items
           */
          test_assert(to->ql.size >= (req + to->qt->size_term),
              "expect size=%u > req=%u + size_term=%u qlump_re_init()",
                                          to->ql.size, req, to->qt->size_term) ;
          test_assert(to->ql.body.v != NULL,
              "expect body!=NULL after qlump_re_init()") ;
        } ;

      test_object_done(to, should_embed, req) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_extend()
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 * It also generates many new lengths -- smaller and larger.
 *
 * Uses the test_vector stuff to check that promotion of embedded and alias
 * to normal qlump does copy across the required data.
 */
static void
test_qlump_extend(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_extend()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, false /* all req */))
    {
      uint req, state_was, size_was, len_was, cp_was ;
      bool should_embed ;

      next_test() ;

      req = test_case_gen(to, tc, true /* fill */) ;

      state_was = to->ql.state ;

      if (state_was != qls_unset)
        assert(to->ql.mtype == to->ttype) ;

      size_was = to->ql.size ;
      len_was  = to->ql.len ;
      cp_was   = to->ql.cp ;

      qlump_extend(&to->ql, req, to->ttype) ;

      switch (state_was)
        {
          case qls_unset:
            /* Was unset -- will now be set.
             *
             * If req == 0 and size_term == 0, will be an empty qls_normal.
             * Otherwise will be qls_embedded (if possible) or qls_normal.
             */
            test_assert( (to->ql.state == qls_embedded) ||
                         (to->ql.state == qls_normal),
                "for qls_unset, expect qls_normal/qls_embedded after"
                " qlump_extend(), got %u", to->ql.state) ;

            if ((req == 0) && (to->qt->size_term == 0))
              {
                test_assert(to->ql.size == 0,
                    "for qls_unset, with req==0 and size_term==0"
                    " expect size==0 after qlump_extend(0), got %u",
                                                                 to->ql.size) ;
                test_assert(to->ql.body.v == NULL,
                    "for qls_unset, with req==0 and size_term==0"
                    "expect body==NULL after qlump_extend(0)") ;

                should_embed = false ;
              }
            else
              should_embed = true ;

            break ;

          case qls_normal:
            /* Was normal -- will still be so, unless was empty and req !=0
             *               or size_term != 0, in which case could be
             *               qls_embedded.
             */
            test_assert(to->ql.len == len_was,
                     "expect len unchanged after qlump_extend(), was %u got %u",
                                                          len_was, to->ql.len) ;
            test_assert(to->ql.cp == cp_was,
                      "expect cp unchanged after qlump_extend(), was %u got %u",
                                                            cp_was, to->ql.cp) ;
            test_assert(to->ql.mtype == to->ttype,
                   "expect mytpe unchanged after qlump_extend(), was %u got %u",
                                                      to->ttype, to->ql.mtype) ;
            if (size_was == 0)
              {
                if ((req == 0) && (to->qt->size_term == 0))
                  {
                    /* If was an empty qlump, and request was 0, and no
                     * size_term, expect to still have an empty qlump.
                     */
                    test_assert(to->ql.state == qls_normal,
                        "when qls_normal, size==0 and req==0,"
                        "expect qls_normal after qlump_extend(), got %u",
                                                                 to->ql.state) ;
                    test_assert(to->ql.size == 0,
                        "when qls_normal, size==0 and req==0,"
                        "expect size==0 after qlump_extend(), got %u",
                                                                  to->ql.size) ;
                    test_assert(to->ql.body.v == NULL,
                        "when qls_normal, size==0 and req==0,"
                        " expect body==NULL after qlump_extend()") ;

                    should_embed = false ;      /* remains empty        */
                  }
                else
                  {
                    /* If was an empty qlump, but request > 0 or size_term > 0,
                     * expect to have a qls_embedded or qls_normal of suitable
                     * size.
                     */
                    test_assert( (to->ql.state == qls_embedded) ||
                                 (to->ql.state == qls_normal),
                          "when qls_normal, size==0 and req=%u,"
                          " expect qls_normal/qls_embedded after"
                                " qlump_extend(), got %u", req, to->ql.state) ;

                    should_embed = true ;       /* if possible          */
                  } ;
              }
            else
              {
                /* If was a not-empty qlump -- expect that to still be the case,
                 * though if req is big enough, may have extended the qlump.
                 */
                test_assert(to->ql.state == qls_normal,
                             "when qls_normal, size != 0,"
                             " expect qls_normal after qlump_extend(), got %u",
                                                                 to->ql.state) ;
                should_embed = false ;          /* remains not empty    */
              };
            break ;

          case qls_embedded:
            /* Was embedded -- will still be so, unless was the req cannot be
             *                 satisfied by the embedded body.
             */
            test_assert( (to->ql.state == qls_embedded) ||
                         (to->ql.state == qls_normal),
                "when qls_embedded, expect qls_normal/qls_embedded after"
                " qlump_extend(), got %u", to->ql.state) ;

            test_assert(to->ql.len == len_was,
                     "expect len unchanged after qlump_extend(), was %u got %u",
                                                          len_was, to->ql.len) ;
            test_assert(to->ql.cp == cp_was,
                      "expect cp unchanged after qlump_extend(), was %u got %u",
                                                            cp_was, to->ql.cp) ;
            test_assert(to->ql.mtype == to->ttype,
                   "expect mytpe unchanged after qlump_extend(), was %u got %u",
                                                      to->ttype, to->ql.mtype) ;

            should_embed = true ;               /* if possible          */
            break ;

          case qls_alias:
          case qls_alias_term:
            /* Was alias -- that will have been discarded.
             *
             * If req == 0, will be an empty qls_normal.  Otherwise will be
             * qls_embedded (if at all possible) or qls_normal.
             */
            test_assert( (to->ql.state == qls_embedded) ||
                         (to->ql.state == qls_normal),
                "for qls_alias/qls_alias_term"
                " expect qls_normal/qls_embedded after qlump_extend(), got %u",
                                                                 to->ql.state) ;

            if ((req == 0) && (to->qt->size_term == 0))
              {
                test_assert(to->ql.size == 0,
                  "for qls_alias/qls_alias_term, with req==0 and size_term==0"
                  " expect size==0 after qlump_extend(), got %u",
                                                                  to->ql.size) ;
                test_assert(to->ql.body.v == NULL,
                  "for qls_alias/qls_alias_term, with req==0 and size_term==0"
                  "expect body==NULL after qlump_extend()") ;

                should_embed = false ;
              }
            else
              should_embed = true ;

            if (req < to->tv_len)
              test_vector_chop(to, req) ;

            to->tv_alias_len = 0 ;

            break ;

          default:
            assert(false) ;
        } ;

      if ((req + to->qt->size_term) != 0)
        {
          /* We expect a body adequate for non-zero number of items
           */
          test_assert(to->ql.size >= (req + to->qt->size_term),
              "expect size=%u > req=%u + size_term=%u qlump_re_init()",
                                          to->ql.size, req, to->qt->size_term) ;
          test_assert(to->ql.body.v != NULL,
              "expect body!=NULL after qlump_re_init()") ;
        } ;

      test_vector_check(to) ;

      test_object_done(to, should_embed, req) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_store()
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 *
 * It also generates many new lengths -- smaller and larger -- which are used
 * to ensure that the edge cases of storing a value with a length greater
 * than the current size are all taken care of.
 *
 * Uses the test_vector stuff to check that promotion of embedded and alias
 * to normal qlump does copy across the required data.
 */
static void
test_qlump_store(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_store()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, false /* all req */))
    {
      uint req, state_was, len_was, cp_was, mtype_was ;
      bool should_embed ;

      next_test() ;

      req = test_case_gen(to, tc, true /* fill */) ;

      state_was = to->ql.state ;
      mtype_was = to->ql.mtype ;
      cp_was    = to->ql.cp ;

      switch (state_was)
        {
          case qls_unset:
            test_case_skip_req(tc) ;    /* only one case for qls_unset  */

            len_was  = 0 ;
            cp_was   = 0 ;
            break ;

          case qls_normal:
          case qls_embedded:
            to->ql.len = req ;
            len_was    = req ;
            break ;

          case qls_alias:
          case qls_alias_term:
            test_case_skip_req(tc) ;    /* only one case for qls_unset  */

            len_was   = to->ql.len ;
            break ;

          default:
            assert(false) ;
        } ;

      if (state_was != qls_unset)
        assert(to->ql.mtype == to->ttype) ;

      qlump_store(&to->ql) ;

      test_assert(to->ql.mtype == mtype_was,
          "expect mtype unchanged after qlump_store(), but was=%u got=%u",
                                                      mtype_was, to->ql.mtype) ;
      if (state_was == qls_unset)
        {
          /* Was unset -- will now be unset and very empty.
           */
          test_assert(to->ql.state == qls_unset,
                          "for qls_unset, expect qls_unset after"
                          " qlump_store(), got %u", to->ql.state) ;

          test_assert(to->ql.len == 0,
                    "for qls_unset,"
                    " expect len==0 after qlump_store(), got %u", to->ql.len) ;
        }
      else
        {
          if (to->ql.len == 0)
            test_assert(to->ql.state == qls_normal,
                          "for len==0, expect qls_normal after qlump_store(),"
                                                      " got %u", to->ql.state) ;
          else
            test_assert( (to->ql.state == qls_normal) ||
                           (to->ql.state == qls_embedded),
                           "for len!=0, expect qls_normal/qls_embedded,"
                           " after qlump_store(), got=%u", to->ql.state) ;

          test_assert(to->ql.len == len_was,
                   "not qls_unset, so expect len unchanged after qlump_store(),"
                                        " was=%u got=%u", len_was, to->ql.len) ;
        } ;

      if (to->ql.len == 0)
        {
          test_assert(to->ql.size == 0,
                      "for len==0, expect size==0 after qlump_store(),"
                                                       " got=%u", to->ql.size) ;
          test_assert(to->ql.body.v == NULL,
                      "for len==0, expect body==NULL after qlump_store()") ;

          test_assert(to->ql.cp == 0,
                    "for len == 0, expect cp==0 after qlump_store(),"
                                                         " got=%u", to->ql.cp) ;
          should_embed = false ;
        }
      else
        {
          uint size ;

          test_assert(to->ql.cp == cp_was,
                    "for len != 0, expect cp unchanged after qlump_store(),"
                                          " was=%u got=%u", cp_was, to->ql.cp) ;

          size = to->ql.len + to->qt->size_term ;

          assert(size != 0) ;

          if (size <= to->qt->embedded_size)
            {
              size = to->qt->embedded_size ;
              should_embed = true ;
            }
          else
            {
              size = (size + to->qt->size_min_unit_m1) &
                                                     ~to->qt->size_min_unit_m1 ;
              should_embed = false ;
            } ;

          test_assert(to->ql.size == size,
                      "for len==%u, size_term=%u, expect size==%u"
                      " after qlump_store(), got %u",
                             to->ql.len, to->qt->size_term, size, to->ql.size) ;
        } ;

      to->tv_alias_len = 0 ;
      if (to->tv_len > to->ql.len)
        test_vector_chop(to, to->ql.len) ;

      test_vector_check(to) ;

      test_object_done(to, should_embed, req) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_copy()
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 *
 * It also generates many new lengths -- smaller and larger -- which are used
 * to ensure that the edge cases of storing a value with a length greater
 * than the current size are all taken care of.
 *
 * Uses the test_vector stuff to check that promotion of embedded and alias
 * to normal qlump does copy across the required data.
 */
static void
test_qlump_copy(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  src[1] ;
  test_object_t  dst[1] ;
  test_case_t    tc[1] ;
  byte           dst_alias[8] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_copy()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only zero req */))
    {
      uint src_case, src_next ;

      src_next = 0 ;
      while ((src_case = src_next) < 2)
        {
          uint dst_case, dst_next ;

          if (tc->state != qls_normal)
            src_next = 2 ;
          else
            src_next += 1 ;

          /* Generate the src -- all types and states and a range of lengths
           */
          test_case_gen(src, tc, true /* fill */) ;

          if (src_case == 1)
            {
              /* Increase the len somewhere beyond the size...
               *
               * ...for qls_normal and qls_embedded, only.
               */
              assert( (src->ql.state == qls_normal) ||
                      (src->ql.state == qls_embedded) ) ;

              src->ql.len = src->ql.size + (rand() % 30) + 1 ;
            } ;

          /* Now generate the dst
           */
          if (src->ql.state == qls_unset)
            dst_next = 0 ;              /* start with unset dst */
          else
            dst_next = 1 ;              /* dst must match src   */

          while ((dst_case = dst_next) < 7)
            {
              uint  src_len, src_cp, size_need, size_was, mtype_was ;
              void* body_was ;
              bool  should_embed ;

              next_test() ;

              dst_next += 1 ;

              if (dst_case == 0)
                {
                  assert(src->ql.state == qls_unset) ;

                  test_object_init(dst, ttype_null, true /* unset */) ;

                  src_len   = 0 ;
                  src_cp    = 0 ;
                  size_need = 0 ;
                }
              else
                {
                  test_object_init(dst, src->ttype, false /* all rubbish */) ;

                  memset(dst, 0, sizeof(qlump_t)) ;

                  if (src->ql.state == qls_unset)
                    {
                      src_cp    = 0 ;
                      src_len   = 0 ;
                      size_need = 0 ;
                    }
                  else
                    {
                      src->ql.cp = rand() ;

                      src_cp    = src->ql.cp ;
                      src_len   = src->ql.len ;
                      size_need = src->ql.len + src->qt->size_term ;
                    } ;

                  dst->ql.mtype = dst->ttype ;
                  dst->ql.cp    = ~src_cp ;
                  dst->ql.len   = ~src_len ;
                } ;

              switch (dst_case)
                {
                  case 0:
                    /* src and dst are unset
                     */
                    assert( (src->ql.state == qls_unset) &&
                            (dst->ql.state == qls_unset) ) ;

                    dst->ql.body.v = (void*)1 ; /* not NULL !   */
                    break ;

                  case 1:
                    /* dst is an alias of whatever length
                     */
                    dst->ql.state  = rand() % 2 ? qls_alias : qls_alias_term ;
                    dst->ql.body.v = dst_alias ;
                    dst->ql.size   = 0 ;
                    break ;

                  case 2:
                    /* dst is a zero size qls_normal
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = dst_alias ;
                    dst->ql.size   = 0 ;
                    break ;

                  case 3:
                    /* dst is a qls_normal, size just short of what is required.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    if (size_need > 1)
                      test_qlump_alloc(&dst->ql, size_need - 1, false, dst->qt);
                    break ;

                  case 4:
                    /* dst is a qls_normal, size is exactly what is required.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    if (size_need > 0)
                      test_qlump_alloc(&dst->ql, size_need, false, dst->qt);
                    break ;

                  case 5:
                    /* dst is a qls_normal, size is more than what is required.
                     *
                     * This is the last case, unless has embedded body.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    test_qlump_alloc(&dst->ql, size_need + (rand() & 30) + 1,
                                                               false, dst->qt) ;
                    if (dst->qt->embedded_size == 0)
                      dst_next = 7 ;
                    break ;

                  case 6:
                    /* dst is a qls_embedded
                     */
                    dst->ql.state  = qls_embedded ;
                    dst->ql.body.v = dst->embedded ;
                    dst->ql.size   = dst->qt->embedded_size ;
                    break ;

                  default:
                    assert(false) ;
                } ;

              mtype_was = dst->ql.mtype ;
              body_was  = dst->ql.body.v ;
              size_was  = dst->ql.size ;

              qlump_copy(&dst->ql, &src->ql) ;

              test_assert(dst->ql.mtype == mtype_was,
                "expect mtype unchanged after qlump_copy(), but was=%u got=%u",
                                                     mtype_was, dst->ql.mtype) ;

              test_assert(dst->ql.len == src_len,
                          "copy qls_unset to qls_unset, expect len==0"
                          " but got=%u", dst->ql.len) ;

              test_assert(dst->ql.cp == src_cp,
                          "copy qls_unset to qls_unset, expect cp==0"
                          " but got=%u", dst->ql.cp) ;

              if (dst_case == 0)
                {
                  /* src and dst unset -- expect empty, unset qlump.
                   */
                  test_assert(dst->ql.state == qls_unset,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect qls_unset, but got=%u", dst->ql.state) ;

                  test_assert(dst->ql.body.v == body_was,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect body unchanged") ;

                  test_assert(dst->ql.size == size_was,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect size unchanged,"
                              " was=%u but got=%u", size_was, dst->ql.size) ;

                  should_embed = false ;
                }
              else
                {
                  /* dst not unset
                   *
                   * Should have have adjusted to cope with src_len.
                   */
                  test_assert( (dst->ql.state == qls_normal) ||
                               (dst->ql.state == qls_embedded),
                              "after qlump_copy() expect qls_normal/_embedded,"
                              " but got=%u", dst->ql.state) ;

                  if (size_was == 0)
                    {
                      if (size_need == 0)
                        {
                          test_assert(dst->ql.body.v == NULL,
                            "dst size==required size==0,"
                            " so after qls_copy() expect body==NULL") ;

                          should_embed = false ;
                        }
                      else
                        {
                          test_assert(dst->ql.body.v != body_was,
                              "dst size==0 required size != 0,"
                              " so after qls_copy() expect new body") ;

                          should_embed = true ;
                        } ;
                    }
                  else
                    {
                      if (size_was >= size_need)
                        {
                          test_assert(dst->ql.body.v == body_was,
                              "dst size >= required size,"
                              " so after qls_copy() expect old body") ;

                          should_embed = false ;
                        }
                      else
                        should_embed = (size_was  <  dst->qt->embedded_size)
                                    && (size_need <= dst->qt->embedded_size) ;
                    } ;

                  dst->tv_alias_len = 0 ;
                  dst->tv_len       = src->tv_len ;

                  memcpy(dst->test_vector, src->test_vector, test_vector_max) ;

                  test_vector_check(dst) ;
                } ;

              test_object_done(dst, should_embed, dst->ql.len) ;
            } ;

          test_object_done(src, false /* no embed */, 0 /* not material */) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_copy_store()
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 *
 * It also generates many new lengths -- smaller and larger -- which are used
 * to ensure that the edge cases of storing a value with a length greater
 * than the current size are all taken care of.
 *
 * Uses the test_vector stuff to check that promotion of embedded and alias
 * to normal qlump does copy across the required data.
 */
static void
test_qlump_copy_store(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  src[1] ;
  test_object_t  dst[1] ;
  test_case_t    tc[1] ;
  byte           dst_alias[8] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_copy_store()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only zero req */))
    {
      uint src_case, src_next ;

      src_next = 0 ;
      while ((src_case = src_next) < 2)
        {
          uint dst_case, dst_next ;

          if (tc->state != qls_normal)
            src_next = 2 ;
          else
            src_next += 1 ;

          /* Generate the src -- all types and states and a range of lengths
           */
          test_case_gen(src, tc, true /* fill */) ;

          if (src_case == 1)
            {
              /* Increase the len somewhere beyond the size...
               *
               * ...for qls_normal and qls_embedded, only.
               */
              assert( (src->ql.state == qls_normal) ||
                      (src->ql.state == qls_embedded) ) ;

              src->ql.len = src->ql.size + (rand() % 30) + 1 ;
            } ;

          /* Now generate the dst
           */
          if (src->ql.state == qls_unset)
            dst_next = 0 ;              /* start with unset dst */
          else
            dst_next = 1 ;              /* dst must match src   */

          while ((dst_case = dst_next) < 8)
            {
              uint  src_len, src_cp, size_need, size_was, mtype_was ;
              void* body_was ;
              bool  should_embed ;

              next_test() ;

              dst_next += 1 ;

              if (dst_case == 0)
                {
                  assert(src->ql.state == qls_unset) ;

                  test_object_init(dst, ttype_null, true /* unset */) ;

                  src_len   = 0 ;
                  src_cp    = 0 ;
                  size_need = 0 ;
                }
              else
                {
                  test_object_init(dst, src->ttype, false /* all rubbish */) ;

                  memset(dst, 0, sizeof(qlump_t)) ;

                  if (src->ql.state == qls_unset)
                    {
                      src_cp    = 0 ;
                      src_len   = 0 ;
                      size_need = 0 ;
                    }
                  else
                    {
                      src->ql.cp = rand() ;

                      src_cp    = src->ql.cp ;
                      src_len   = src->ql.len ;
                      size_need = src->ql.len + src->qt->size_term ;
                    } ;

                  dst->ql.mtype = dst->ttype ;
                  dst->ql.cp    = ~src_cp ;
                  dst->ql.len   = ~src_len ;
                } ;

              switch (dst_case)
                {
                  case 0:
                    /* src and dst are unset
                     */
                    assert( (src->ql.state == qls_unset) &&
                            (dst->ql.state == qls_unset) ) ;

                    dst->ql.body.v = (void*)1 ; /* not NULL !   */
                    break ;

                  case 1:
                    /* dst is an alias of whatever length
                     */
                    dst->ql.state  = rand() % 2 ? qls_alias : qls_alias_term ;
                    dst->ql.body.v = dst_alias ;
                    dst->ql.size   = 0 ;
                    break ;

                  case 2:
                    /* dst is a zero size qls_normal
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = dst_alias ;
                    dst->ql.size   = 0 ;
                    break ;

                  case 3:
                    /* dst is a qls_normal, size just short of what is required.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    if (size_need > 1)
                      test_qlump_alloc(&dst->ql, size_need - 1, false, dst->qt);
                    break ;

                  case 4:
                    /* dst is a qls_normal, size is exactly what is required.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    if (size_need > 0)
                      test_qlump_alloc(&dst->ql, size_need, false, dst->qt);
                    break ;

                  case 5:
                    /* dst is a qls_normal, size is just than what is required.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    test_qlump_alloc(&dst->ql, size_need + (rand() & 3) + 1,
                                                               false, dst->qt) ;
                    break ;

                  case 6:
                    /* dst is a qls_normal, size is more than what is required.
                     *
                     * This is the last case, unless has embedded body.
                     */
                    dst->ql.state  = qls_normal ;
                    dst->ql.body.v = NULL ;
                    dst->ql.size   = 0 ;

                    test_qlump_alloc(&dst->ql, size_need + (rand() & 30) + 1,
                                                               false, dst->qt) ;
                    if (dst->qt->embedded_size == 0)
                      dst_next = 8 ;
                    break ;

                  case 7:
                    /* dst is a qls_embedded
                     */
                    dst->ql.state  = qls_embedded ;
                    dst->ql.body.v = dst->embedded ;
                    dst->ql.size   = dst->qt->embedded_size ;
                    break ;

                  default:
                    assert(false) ;
                } ;

              mtype_was = dst->ql.mtype ;
              body_was  = dst->ql.body.v ;
              size_was  = dst->ql.size ;

              qlump_copy_store(&dst->ql, &src->ql) ;

              test_assert(dst->ql.mtype == mtype_was,
                "expect mtype unchanged after qlump_copy(), but was=%u got=%u",
                                                     mtype_was, dst->ql.mtype) ;

              test_assert(dst->ql.len == src_len,
                          "copy qls_unset to qls_unset, expect len==0"
                          " but got=%u", dst->ql.len) ;

              test_assert(dst->ql.cp == src_cp,
                          "copy qls_unset to qls_unset, expect cp==0"
                          " but got=%u", dst->ql.cp) ;

              if (dst_case == 0)
                {
                  /* src and dst unset -- expect empty, unset qlump.
                   */
                  test_assert(dst->ql.state == qls_unset,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect qls_unset, but got=%u", dst->ql.state) ;

                  test_assert(dst->ql.body.v == body_was,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect body unchanged") ;

                  test_assert(dst->ql.size == size_was,
                              "after qlump_copy() qls_unset to qls_unset,"
                              " expect size unchanged,"
                              " was=%u but got=%u", size_was, dst->ql.size) ;

                  should_embed = false ;
                }
              else
                {
                  /* dst not unset
                   *
                   * Should have have adjusted to cope with src_len.
                   */
                  test_assert( (dst->ql.state == qls_normal) ||
                               (dst->ql.state == qls_embedded),
                              "after qlump_copy() expect qls_normal/_embedded,"
                              " but got=%u", dst->ql.state) ;

                  if (size_was == 0)
                    {
                      if (size_need == 0)
                        {
                          test_assert(dst->ql.body.v == NULL,
                            "dst size==required size==0,"
                            " so after qls_copy() expect body==NULL") ;

                          should_embed = false ;
                        }
                      else
                        {
                          test_assert(dst->ql.body.v != body_was,
                              "dst size==0 required size != 0,"
                              " so after qls_copy() expect new body") ;

                          should_embed = true ;
                        } ;
                    }
                  else
                    should_embed = true ;

                  dst->tv_alias_len = 0 ;
                  dst->tv_len       = src->tv_len ;

                  memcpy(dst->test_vector, src->test_vector, test_vector_max) ;

                  test_vector_check(dst) ;
                } ;

              test_object_done(dst, should_embed, dst->ql.len) ;
            } ;

          test_object_done(src, false /* no embed */, 0 /* not material */) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_free_body()
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 *
 * We don't need any 'req' lengths, so we don't generate those.
 */
static void
test_qlump_free_body(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_free_body()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only one req */))
    {
      uint mtype_was, state_was ;

      next_test() ;

      test_case_gen(to, tc, false /* no fill */) ;

      state_was = to->ql.state ;
      mtype_was = to->ql.mtype ;

      qlump_free_body(&to->ql) ;

      if (state_was == qls_unset)
        test_assert(to->ql.state == qls_unset,
                          "for qls_unset, expect qls_unset after"
                          " qlump_free_body(), got %u", to->ql.state) ;
      else
        test_assert(to->ql.state == qls_normal,
                          "not qls_unset, so expect qls_normal after"
                          " qlump_free_body(), got %u", to->ql.state) ;

      test_assert(to->ql.mtype == mtype_was,
          "expect mtype unchanged after qlump_free_body(), but was=%u got=%u",
                                                      mtype_was, to->ql.mtype) ;

      test_assert(to->ql.size == 0,
             "expect size==0 after qlump_free_body(), got %u", to->ql.size) ;

      test_assert(to->ql.len == 0,
             "expect len==0 after qlump_free_body(), got %u", to->ql.len) ;

      test_assert(to->ql.cp == 0,
             "expect cp==0 after qlump_free_body(), got %u", to->ql.cp) ;

      test_assert(to->ql.body.v == NULL,
             "expect body==NULL after qlump_free_body()") ;

      test_object_done(to, false /* no embed */, 0 /* not relevant */) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test qlump_bubble(), qlump_add_space() & qlump_drop_items()
 *
 * qlump_add_space() and qlump_drop_items() are very thin shims on top of
 * qlump_bubble().  Those are tested by calling qlump_drop_items() at random
 * for test cases where nothing is being added, and by calling
 * qlump_add_space() at random where nothing is being dropped.
 *
 * The test case generator generates all sorts of qlump, and many lengths/sizes.
 *
 * We then generate test cases on top of that:
 *
 *   * (a) using the given ql->len
 *
 *     (b) for qls_normal/_embedded -- ql->len > ql->size.
 *
 *   * (a) at = 0
 *
 *     (b) at = 1..ql->len-1 -- random selection
 *
 *     (c) at = ql->len
 *
 *     (d) at > ql->len      -- random selection
 *
 *     (e) at > ql->size     -- random selection, for qls_normal/_embedded
 *
 *   * (a) r = 0
 *
 *     (b) len + r < ql->len -- random selection
 *
 *     (c) len + r == ql->len
 *
 *     (d) at + r > ql->len  -- random selection
 *
 *     (e) at + r > ql->size -- random selection, for qls_normal/_embedded
 *
 *   * (a) n = 0
 *
 *     (b) n = 1..r-1        -- random selection
 *
 *     (c) n = r
 *
 *     (d) n = r + 1
 *
 *     (e) n > r + 1         -- random selection
 */
static void test_bubble(test_object to, test_case tc, uint size, uint len,
                                                      uint at, uint r, uint n) ;

static void
test_qlump_bubble(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr,
             "  qlump_bubble()/_add_items()/_drop_items()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only one req */))
    {
      uint len_case, len_next ;
      uint base_state, base_len ;
      uint base_size, len, at, n, r ;

      len = at = n = r = 0 ;

      if (tc->state == qls_unset)
        continue ;                      /* skip qls_unset cases */

      test_case_gen(to, tc, false /* fill */) ;

      base_state = to->ql.state ;
      base_size  = to->ql.size ;
      base_len   = to->ql.len ;

      test_object_done(to, false, 0) ;

      len_next = 0 ;
      while ((len_case = len_next) < 3)
        {
          uint at_case, at_next ;

          len_next += 1 ;

          switch (len_case)
            {
              case 0:
                len  = base_len ;       /* base case            */

                if ((base_state != qls_normal) && (base_state != qls_embedded))
                  len_next = 3 ;

                else if (len == base_size)
                  len_next = 2 ;

                break ;         /* use given ql->len    */

              case 1:
                assert( (base_state == qls_normal) ||
                        (base_state == qls_embedded) ) ;

                len = base_size ;
                break ;

              case 2:
                assert( (base_state == qls_normal) ||
                        (base_state == qls_embedded) ) ;

                len = base_size + (rand() % 20) + 1 ;
                break ;

              default:
                assert(false) ;
            } ;

          at_next = 0 ;
          while ((at_case = at_next) < 10)
            {
              uint r_case, r_next, t ;

              at_next += 1 ;

              switch (at_case)
                {
                  case 0:
                    /* at = 0
                     */
                    at = 0 ;

                    if (len < 6)
                      {
                        /* for short ql->len, skip some cases
                         */
                        at_next = 6 - len ;
                      } ;

                    break ;

                  case 1:
                  case 2:
                  case 3:
                  case 4:
                    /* at = random value in 1..len-1
                     */
                    at = 1 + (rand() % (len - 1)) ;
                    break ;

                  case 5:
                    /* at = len
                     */
                    at = len ;
                    break ;

                  case 6:
                    /* at = len + 1
                     */
                    at = len + 1 ;
                    break ;

                  case 7:
                    /* at = some value between len and base_size
                     *
                     * or, if base_size <= len, some value > ql->len
                     */
                    t = base_size ;
                    if (t <= len)
                      {
                        t = len + 33 ;
                        at_next = 10 ;
                      } ;

                    at = len + (rand() % (t - len)) + 1 ;

                    break ;

                  case 8:
                    /* at = base_size
                     *
                     * if base_size <= len, case 7 above will skip this.
                     */
                    at = base_size ;

                    break ;

                  case 9:
                    /* at = base_size + rand()
                     *
                     * if base_size <= len, case 7 above will skip this.
                     */
                    at = base_size + (rand() % 21) + 7;

                    break ;

                  default:
                    assert(false) ;
                } ;

              r_next = 0 ;
              while ((r_case = r_next) < 10)
                {
                  uint n_case, n_next ;

                  r_next += 1 ;

                  switch (r_case)
                    {
                      case 0:
                        /* r = 0
                         */
                        r = 0 ;

                        if      (at >= len)
                          r_next = 6 ;
                        else if ((len - at) < 6)
                          {
                            /* for short (len - at), skip cases
                             */
                            r_next = 6 - (len - at) ;
                          } ;

                        break ;

                      case 1:
                      case 2:
                      case 3:
                      case 4:
                        /* at + r = random value in 1..len-1
                         *
                         * Case 1 skips this if (to->ql.len - at) < 2
                         */
                        assert((len - at) >= 2) ;

                        r = (rand() % (len - 1 - at)) + 1;
                        break ;

                      case 5:
                        /* at + r = len -- r > 0
                         *
                         * Case 1 skips this if at >= to->ql.len
                         */
                        assert(at < len) ;

                        r = len - at ;
                        break ;

                      case 6:
                        /* at + r = len + 1 -- r > 0
                         *
                         * or, if at > len, r = 1
                         */
                        if (at < len)
                          r = (len - at) + 1 ;
                        else
                          r = 1 ;
                        break ;

                      case 7:
                        /* at + r = some value between len and base_size
                         *
                         * or, if base_size <= len, some value > ql->len
                         */
                        if (base_size > len)
                          t = base_size - len ;
                        else
                          {
                            t = 33 ;
                            r_next = 10 ;
                          } ;

                        r = (rand() % t ) + 1 ;

                        break ;

                      case 8:
                        /* at + r = base_size -- r > 0
                         *
                         * if base_size <= len, case 7 above will skip this.
                         */
                        assert(base_size > len) ;

                        r = base_size - len ;
                        break ;

                      case 9:
                        /* at + r = base_size + rand()
                         *
                         * if base_size <= len, case 7 above will skip this.
                         */
                        assert(base_size > len) ;

                        r = base_size - len + (rand() % 21) + 7 ;
                        break ;

                      default:
                        assert(false) ;
                    } ;

                  n_next = 0 ;
                  while ((n_case = n_next) < 10)
                    {
                      n_next += 1 ;

                      switch (n_case)
                        {
                          case 0:
                            /* n = 0
                             */
                            n = 0 ;

                            if (r < 6)
                              n_next = 6 - r ;

                            break ;

                          case 1:
                          case 2:
                          case 3:
                          case 4:
                            /* 0 < n < r -- at random
                             *
                             * Case 1 skips this if r < 2
                             */
                            assert(r >= 2) ;

                            n = (rand() % (r - 1)) + 1 ;
                            break ;

                          case 5:
                            /* n = r
                             *
                             * Case 1 skips this if r == 0
                             */
                            assert(r >= 1) ;

                            n = r ;
                            break ;

                          case 6:
                            /* n = r + 1
                             */
                            n = r + 1 ;
                            break ;

                          case 7:
                          case 8:
                          case 9:
                            n = r + ((n_case - 7) * 10)
                                                      + (rand() % 10) + 1 ;
                            break ;

                          default:
                            assert(false) ;
                        } ;

                      test_bubble(to, tc, base_size, len, at, r, n) ;
                    } ;
                } ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

static void
test_bubble(test_object to, test_case tc, uint base_size, uint len,
                                                        uint at, uint r, uint n)
{
  enum do_qlump_bubble_test
  {
    do_qlump_bubble,
    do_qlump_add_items,
    do_qlump_drop_items,
  } what ;

  uint new_len, old_state, old_size, old_mtype, q ;
  bool should_embed ;

  next_test() ;

  test_case_gen(to, tc, true /* fill */) ;

  to->ql.len = len ;            /* override for some cases */

  old_state = to->ql.state ;
  old_mtype = to->ql.mtype ;
  old_size  = to->ql.size ;

  assert(base_size == old_size) ;

  q = 0 ;
  if (n == 0)
    q += 2 ;
  if (r == 0)
    q += 1 ;

  what = do_qlump_bubble ;      /* default              */

  switch (q)
    {
      case 0:                   /* r != 0, n != 0       */
        break ;

      case 1:                   /* r == 0, n != 0       */
        if ((rand() % 4) == 0)
          what = do_qlump_add_items ;
        break ;

      case 2:                   /* r != 0, n == 0       */
        if ((rand() % 4) == 0)
          what = do_qlump_drop_items ;
        break ;

      case 3:                   /* r == 0, n == 0       */
        switch (rand() % 4)
          {
            case 0:
              what = do_qlump_drop_items ;
              break ;

            case 1:
            case 2:
              break ;

            case 3:
              what = do_qlump_add_items ;
              break ;

            default:
              assert(false) ;
          } ;
        break ;

      default:
        assert(false) ;
    } ;

  what = do_qlump_bubble ;      /* default              */

  switch (what)
    {
      case do_qlump_bubble:
        qlump_bubble(&to->ql, at, r, n) ;
        break ;

      case do_qlump_add_items:
        qlump_add_space(&to->ql, at, n) ;
        break ;

      case do_qlump_drop_items:
        qlump_drop_items(&to->ql, at, r) ;
        break ;

      default:
        assert(false) ;
    } ;

  if ((at + r) > len)
    new_len = at + n ;
  else
    new_len = len - r + n ;

  test_assert(old_mtype == to->ql.mtype,
      "expect mtype unchanged by qlump_bubble,"
      " but was=%u got=%u", old_mtype, to->ql.mtype) ;

  if ((old_state == qls_normal) && (old_size != 0))
    {
      test_assert(to->ql.state == qls_normal,
          "was qls_normal, size !=0,"
          " so expect qls_normal"
          " after qlump_bubble(), got=%u", to->ql.state) ;

      should_embed = false ;
    }
  else if (((new_len + to->qt->size_term) == 0)
                             && (old_size == 0))
    {
      test_assert(to->ql.state == qls_normal,
          "new_len + size_term == 0, and size ==0,"
          " so expect qls_normal"
          " after qlump_bubble(), got=%u", to->ql.state) ;

      test_assert(to->ql.size == 0,
          "new_len + size_term == 0, and size ==0,"
          " so expect size==0"
          " after qlump_bubble(), got=%u", to->ql.size) ;

      test_assert(to->ql.body.v == NULL,
          "new_len + size_term == 0, and size ==0,"
          " so expect body==NULL"
          " after qlump_bubble()") ;

      should_embed = false ;
    }
  else
    {
      test_assert( (to->ql.state == qls_normal) ||
                   (to->ql.state == qls_embedded),
          "was not qls_normal,"
          " and new_len + size_term != 0"
          " so expect qls_normal/_embedded"
          " after qlump_bubble(), got=%u", to->ql.state) ;

      should_embed = true ;
    } ;

  test_assert(to->ql.len == new_len,
      "len was=%u, at=%u, r=%u, n=%u,"
      " expect len=%u but got=%u",
      len, at, r, n, new_len, to->ql.len) ;

  test_assert((to->ql.len + to->qt->size_term)
                                      <= to->ql.size,
       "len is=%u, size_term=%u, but size=%u",
       to->ql.len, to->qt->size_term, to->ql.size) ;

  to->tv_alias_len = 0 ;

  test_vector_bubble(to, at, r, n) ;
  test_vector_check(to) ;

  test_object_done(to, should_embed, new_len) ;
} ;

/*==============================================================================
 * Testing qlump_exch_sections()
 *
 */
extern void qlump_t_exch_sections(byte* p_a, byte* p_b, usize n) ;

/*------------------------------------------------------------------------------
 * Test the mechanics of exchanging two sections of a string of bytes.
 *
 * The underlying mechanicals swap sections of between 1 and 16 bytes, so
 * objective here is to test across boundaries, and all lengths upto 64.
 *
 * Mangles a 256 byte buffer -- so all bytes are unique and we can check
 * for valid result.
 */
static void
test_qlump_exch_sections(void)
{
  uint fail_count_was, test_count_was ;

  byte  work[256] ;
  byte  expect[256] ;

  uint  n, off_a, off_b ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_exch_sections()") ;

  for (n = 0 ; n <= 64 ; ++n)
    {
      for (off_a = 32 ; off_a <= 64 ; ++off_a)
        {
          for (off_b = 160 ; off_b < 192 ; ++off_b)
            {
              uint b ;
              byte v ;

              next_test() ;

              v = (n + off_a + off_b) & 0xFF ;

              for (b = 0 ; b < 256 ; ++b)
                work[b] = (v++ & 0xFF) ;

              memcpy(expect, work, 256) ;

              if (n > 0)
                {
                  memcpy(&expect[off_a], &work[off_b], n) ;
                  memcpy(&expect[off_b], &work[off_a], n) ;
                } ;

              qlump_t_exch_sections(&work[off_a], &work[off_b], n) ;

              test_assert(memcmp(expect, work, 256) == 0,
                  "not the expected result for off_a=%u, off_b=%u, n=%u",
                                                              off_a, off_b, n) ;

              qlump_t_exch_sections(&work[off_b], &work[off_a], n) ;

              for (b = 0 ; b < 256 ; ++b)
                if (!test_assert(work[b] == (v++ & 0xFF),
                    "exchange back did not restore byte=%u", b))
                   break ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Testing qlump_rev_section()
 *
 */
extern void qlump_t_rev_section(byte* p, ulen n) ;

/*------------------------------------------------------------------------------
 * Test the mechanics of reversing sections of strings of bytes.
 *
 * Bangs reversing of sections against exchanging sections, which is already
 * tested.
 *
 * The underlying mechanicals reverse sections of between 1 and 16 bytes, so
 * objective here is to test across boundaries, and all lengths upto 64.
 *
 * Mangles a 256 byte buffer -- so all bytes are unique and we can check
 * for valid result.
 */
static void
test_qlump_rev_section(void)
{
  uint fail_count_was, test_count_was ;

  byte  work[256] ;

  uint  n, off_a, off_b ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_rev_section()") ;

  /* Simple test of reversing 0..64 byte sections
   */
  for (n = 0 ; n <= 64 ; ++n)
    {
      uint b ;
      byte v ;

      next_test() ;

      v = '0' ;

      b = 0 ;
      while (b <= 128)
        work[b++] = v++ ;

      qlump_t_rev_section(work, n) ;

      v = '0' + n ;
      b = 0 ;
      while (b < n)
        {
          --v ;
          test_assert(work[b] == v,
                            "reverse, n=%u, wrong at byte=%u", n, b) ;
          ++b ;
        } ;

      v = '0' + n ;
      while (b <= 128)
        {
          test_assert(work[b] == v,
                         "reverse, n=%u, had some effect on byte=%u", n, b) ;
          ++v ;
          ++b ;
        } ;
    } ;

  /* Test reversing of sections against exchanging of stuff
   */
  for (n = 0 ; n <= 64 ; ++n)
    {
      for (off_a = 32 ; off_a <= 64 ; ++off_a)
        {
          for (off_b = 160 ; off_b < 192 ; ++off_b)
            {
              uint b ;
              byte v ;

              next_test() ;

              v = (n + off_a + off_b) & 0xFF ;

              for (b = 0 ; b < 256 ; ++b)
                work[b] = (v++ & 0xFF) ;

              qlump_t_exch_sections(&work[off_a], &work[off_b], n) ;

              qlump_t_rev_section(&work[off_a], n) ;
              qlump_t_rev_section(&work[off_b], n) ;
              qlump_t_rev_section(&work[off_a + n], off_b - off_a - n) ;
              qlump_t_rev_section(&work[off_a], off_b - off_a + n) ;

              for (b = 0 ; b < 256 ; ++b)
                if (!test_assert(work[b] == (v++ & 0xFF),
                    "exchange and reverses did not restore byte=%u", b))
                  break ;
            } ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of qlump_swap_items().
 *
 * The heavy lifting has been tested already -- test_qlump_exch_sections() and
 * test_qlump_rev_section().
 *
 * Here we hammer through the test cases (with only one request length), and
 * for each one try:
 *
 *   (a) a reasonable swap -- within the test case length.
 *
 *   (b) a reasonable swap, but with a & b reversed.
 *
 *   (c) a random swap -- with start points within the current length,
 *                        but lengths which may overlap and/or overrun the
 *                        current length.
 *
 *   (d) for qls_normal and qls_embedded, set the length at or beyond the
 *       size and run a random swap.
 */
static void
test_qlump_swap_items(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_swap_items()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only one req */))
    {
      uint base_state, base_len, base_size ;
      uint swap_case, swap_next ;
      bool should_embed ;
      uint a, na, b, nb ;

      if (tc->state == qls_unset)
        continue ;                      /* skip qls_unset cases */

      test_case_gen(to, tc, false /* fill */) ;

      base_state = to->ql.state ;
      base_size  = to->ql.size ;
      base_len   = to->ql.len ;

      test_object_done(to, false, 0) ;

      a = na = b = nb = 0 ;             /* pacify compiler      */

      swap_next = 0 ;
      while ((swap_case = swap_next) < 5)
        {
          uint len, t, ng, q ;
          uint state_was, mtype_was, size_was, len_was, cp_was ;

          swap_next += 1 ;

          len = base_len ;

          switch (swap_case)
            {
              case 0:
                /* Choose sections to swap, based on the length.
                 *
                 * Occasionally, make sure swap lengths are equal.
                 */
                t = len ;

                if (t == 0)
                  a = 0 ;
                else
                  {
                    a  = rand() % t ;
                    t -= a ;
                  } ;

                na = rand() % (t + 1) ;
                t -= na ;

                ng = rand() % (t + 1) ;
                t -= ng ;

                b  = a + na + ng ;

                if ((t >= na) && ((rand() % 5) == 0))
                  nb = na ;
                else
                  nb = rand() % (t + 1) ;

                break ;

              case 1:
                /* Same as case 0, but with a & b swapped
                 */
                q  = a ;
                a  = b ;
                b  = q ;

                q  = na ;
                na = nb ;
                nb = q ;

                break ;

              case 4:
                /* Set len at or beyond the base_size, the do random swap
                 * within that.
                 */
                assert( (base_state == qls_normal) ||
                        (base_state == qls_embedded) ) ;

                len = base_size + (rand() % (base_size + 1)) + (rand() % 3) ;

                fall_through ;

              case 2:
                /* Random swap -- starting within the current length.
                 *
                 * May overlap and/or overrun the current length.
                 */
                if (len == 0)
                  a = na = b = nb = 0 ;
                else
                  {
                    a  = rand() % len ;
                    na = rand() % ((len / 2) + 1)  ;
                    b  = rand() % len ;
                    nb = rand() % ((len / 2) + 1) ;
                  } ;

                break ;

              case 5:
                /* Set len at or beyond the base_size, the do random swap
                 * beyond that.
                 */
                assert( (base_state == qls_normal) ||
                        (base_state == qls_embedded) ) ;

                len = base_size + (rand() % (base_size + 1)) + (rand() % 3) ;

                fall_through ;

              case 3:
                /* Random swap -- starting possibly beyond the current length.
                 *
                 * May overlap and/or overrun the current length.
                 *
                 * For all but qls_nromal and qls_embedded, this is the last
                 * case.
                 */
                a  = rand() % ((len + 1) * 2) ;
                na = rand() % (len + 1) ;
                b  = rand() % ((len + 1) * 2) ;
                nb = rand() % (len + 1) ;

                if ((base_state != qls_normal) && (base_state != qls_embedded))
                  swap_next = 6 ;

                break ;
          } ;

          next_test() ;

          test_case_gen(to, tc, true /* fill */) ;

          to->ql.len = len ;        /* override for some cases      */

          state_was = to->ql.state ;
          mtype_was = to->ql.mtype ;
          size_was  = to->ql.size ;
          len_was   = to->ql.len ;
          cp_was    = to->ql.cp ;

          qlump_swap_items(&to->ql, a, na, b, nb) ;

          to->tv_alias_len = 0 ;

          switch (state_was)
            {
              case qls_unset:
                assert(false) ;
                break ;

              case qls_normal:
                /* Was normal -- will still be so, unless was empty, in which
                 *               case should embed if possible, unless zero
                 *               length.
                 */
                should_embed = (size_was == 0) && (len_was != 0) ;

                break ;

              case qls_embedded:
                /* Was embedded -- will still be so, if possible.
                 */
                should_embed = true ;
                break ;

              case qls_alias:
              case qls_alias_term:
                /* Was alias -- that will have been discarded.  Should embed,
                 *              if possible, unless was zero length.
                 */
                should_embed = (len_was != 0) ;
                break ;

              default:
                assert(false) ;
            } ;

          test_assert(to->ql.len == len_was,
               "expect len unchanged after qlump_swap_items(), was %u got %u",
                                                          len_was, to->ql.len) ;
          test_assert(to->ql.cp == cp_was,
                "expect cp unchanged after qlump_swap_items(), was %u got %u",
                                                            cp_was, to->ql.cp) ;
          test_assert(to->ql.mtype == mtype_was,
             "expect mytpe unchanged after qlump_swap_items(), was %u got %u",
                                                      mtype_was, to->ql.mtype) ;

          test_assert( (to->ql.state == qls_embedded) ||
                       (to->ql.state == qls_normal),
              "expect qls_normal/qls_embedded after qlump_swap_items(), got %u",
                                                                 to->ql.state) ;

          test_vector_swap(to, to->ql.size, a, na, b, nb) ;
          test_vector_check(to) ;

          test_object_done(to, should_embed, len_was) ;
        } ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of qlump_sort().
 *
 */
static uint cmp_unit ;

static int
test_qlump_cmp(const void* a, const void* b)
{
  return memcmp(a, b, cmp_unit) ;
} ;

static void
test_qlump_sort(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_sort()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, true /* only one req */))
    {
      if (tc->state == qls_unset)
        continue ;                      /* skip qls_unset cases */

      next_test() ;

      test_case_gen(to, tc, false /* fill */) ;
      test_vector_fill_random(to, tc->len, to->ql.body.v, 0) ;

      cmp_unit = to->qt->unit ;
      qlump_sort(&to->ql, test_qlump_cmp) ;

      test_vector_sort(to) ;
      test_vector_check(to) ;

      test_object_done(to, false /* embed*/, 0) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

/*==============================================================================
 * Test of qlump_sort_dedup().
 *
 */
static void
test_qlump_sort_dedup(void)
{
  uint fail_count_was, test_count_was ;

  test_object_t  to[1] ;
  test_case_t    tc[1] ;

  fail_count_was = fail_count ;
  test_count_was = test_count ;

  fprintf(stderr, "  qlump_sort_dedup()") ;

  test_case_init(tc) ;

  while (test_case_next(tc, false /* many req */))
    {
      uint rep ;

      if (tc->state == qls_unset)
        continue ;                      /* skip qls_unset cases */

      next_test() ;

      /* takes no notice of the req value, but uses the generation of that
       * to run the test many times for each length, with random degrees of
       * repetition.
       */
      test_case_gen(to, tc, false /* fill */) ;

      if ((tc->len > 1) && (rand() % 10))       /* 10% no repetition    */
        rep = rand() % tc->len ;
      else
        rep = 0 ;

      test_vector_fill_random(to, tc->len, to->ql.body.v, rep) ;

      cmp_unit = to->qt->unit ;
      qlump_sort_dedup(&to->ql, test_qlump_cmp) ;

      test_vector_sort_dedup(to) ;
      test_vector_check(to) ;

      test_object_done(to, false /* embed*/, 0) ;
    } ;

  if (fail_count_was == fail_count)
    fprintf(stderr, " -- %d tests -- OK\n", test_count - test_count_was) ;
  else
    fprintf(stderr, "\n  *** %d failures\n", fail_count - fail_count_was) ;
} ;

