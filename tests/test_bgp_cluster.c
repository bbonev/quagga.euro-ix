#include <misc.h>
#include <zebra.h>

#include "stdio.h"

#include "qlib_init.h"
#include "command.h"

#include "bgpd/bgp.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"

/*==============================================================================
 * bgpd/bgp_cluster.c torture tests
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
enum { clust_max = 100 } ;      /* maximum length we test to !  */

typedef struct clust_list  clust_list_t ;
typedef struct clust_list* clust_list ;

struct clust_list
{
  uint  count ;

  const char* string ;

  bgp_id_t unused ;

  bgp_id_t list[clust_max] ;
};

/*------------------------------------------------------------------------------
 * Prototypes
 */
static void test_clust_simple(void) ;
static void test_clust_store(void) ;
static void test_clust_check(void) ;
static void test_clust_out_prepare(void) ;
static void test_clust_release(void) ;

static clust_list make_clust_list(uint count, uint ord) ;
static void show_delta(const byte* got, const byte* exp, uint count) ;
static void show_str_delta(const char* got, const char* exp) ;

/*------------------------------------------------------------------------------
 * Your actual test program.
 */
int
main(int argc, char **argv)
{
  qlib_init_first_stage(0);     /* Absolutely first             */
  host_init(argv[0]) ;

  srand(srand_seed) ;           /* reproducible                 */

  fprintf(stderr, "Start BGP Cluster-List Attribute testing: "
                                     "srand(%u), fail_limit=%u, test_stop=%u\n",
                                            srand_seed, fail_limit, test_stop) ;

  bgp_attr_start() ;            /* wind up the entire attribute store   */

  test_clust_simple() ;
  test_clust_store() ;
  test_clust_check() ;
  test_clust_out_prepare() ;
  test_clust_release() ;

  bgp_attr_finish() ;           /* close it down again                  */

  fprintf(stderr, "Finished BGP Cluster-List Attribute testing") ;

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
 *  * attr_cluster_start()         -- see main()
 *  * attr_cluster_finish()        -- see main()
 *
 *  * attr_cluster_new()           -- see test_clust_simple()
 *  * attr_cluster_store()         -- see test_clust_simple()
 *                                                          & test_clust_store()
 *  * attr_cluster_free()          -- see test_clust_simple()
 *
 *  * attr_cluster_lock()          -- test_clust_store()
 *  * attr_cluster_release()       -- test_clust_store() & test_clust_release()
 *
 *  * attr_cluster_set()           -- see test_clust_simple()
 *                                                          & test_clust_store()
 *
 *  * attr_cluster_out_prepare()   -- see test_clust_out_prepare()
 *
 *  * attr_cluster_check()         -- see test_clust_check(void)
 *
 *  * attr_cluster_length()        -- see test_clust_simple()
 *                                                          & test_clust_store()
 *  * attr_cluster_str()           -- see test_clust_simple()
 */
enum { stored_count = 401 } ;

static attr_cluster stored[stored_count] ;
static clust_list   originals[stored_count] ;

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
                              "expected len[1]=%u, got %u", e_len, out->len[1]) ;
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

/*==============================================================================
 * Test support functions
 */

/*------------------------------------------------------------------------------
 * Make a random cluster-id list of given length
 *
 * LS 4 bits of each cluster-id is per the given 'ord', so can construct a
 * number of cluster lists at one length, and know they differ.
 *
 * Creates and sets an unused-id, which is guaranteed not to appear in the
 * cluster list.
 */
static clust_list
make_clust_list(uint count, uint ord)
{
  clust_list cl ;
  uint i ;
  char* p ;

  assert(count <= clust_max) ;

  cl = malloc(sizeof(clust_list_t)) ;

  memset(cl, 0, sizeof(clust_list_t)) ;

  cl->count  = count ;
  cl->unused = rand() ;

  for (i = 0 ; i <= count ; ++i)
    {
      bgp_id_t id ;

      do
        id = ((uint)rand() << 4) + ord ;
      while (id == cl->unused) ;

      cl->list[i] = id ;
    } ;

  cl->string = p = malloc((16 * count) + 1) ;

  for (i = 0 ; i < count ; ++i)
    {
      if (i != 0)
        *p++ = ' ' ;

      inet_ntop(AF_INET, &cl->list[i], p, 16) ;

      while (*p != '\0')
        ++p ;
    } ;

  *p = '\0' ;

  return cl ;
} ;

/*------------------------------------------------------------------------------
 * Show difference between the cluster list we got, and the cluster list
 * we expected.
 */
static void
show_delta(const byte* got, const byte* exp, uint count)
{
  uint off, len, i ;

  off = 0 ;
  len = count * 4 ;
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

  off = (off / 4) * 4 ;

  fprintf(stderr, "\n  e%3d:", off) ;
  for (i = off ; i < (off + 4) ; ++i)
    fprintf(stderr, " %02x", exp[i]) ;

  fprintf(stderr, "  ... total length = %u (bytes)", len) ;

  fprintf(stderr, "\n  g%3d:", off) ;
  for (i = off ; i < (off + 4) ; ++i)
    fprintf(stderr, " %02x", got[i]) ;
} ;


/*------------------------------------------------------------------------------
 * Show difference between the cluster string we got, and the cluster string
 * we expected.
 */
static void
show_str_delta(const char* got, const char* exp)
{
  uint off, len, e_len, g_len, i ;
  char ext[51] ;

  e_len = strlen(exp) ;
  g_len = strlen(got) ;

  if (e_len > g_len)
    len = e_len ;
  else
    len = g_len ;

  off = 0 ;
  while (1)
    {
      if (got[off] != exp[off])
        break ;

      ++off ;
      if (off < (len + 1))
        continue ;

      test_assert(off < (len + 1), "found no difference in show_delta()") ;
      return ;
    } ;

  if (off > 12)
    off -= 12 ;
  else
    off  = 0 ;

  for (i = off ; (i < e_len) && (i < (off + 50)) ; ++i)
    ext[i - off] = exp[i] ;
  ext[i] = '\0' ;

  fprintf(stderr, "\n  e%3d: \"%s\" ...len=%u", off, ext, e_len) ;

  for (i = off ; (i < e_len) && (i < (off + 50)) ; ++i)
    ext[i - off] = got[i] ;
  ext[i] = '\0' ;

  fprintf(stderr, "\n  g%3d: \"%s\" ...len=%u", off, ext, g_len) ;
} ;


