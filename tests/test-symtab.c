#include <zebra.h>
#include "misc.h"
#include "qlib_init.h"
#include "command.h"
#include "symtab.h"
#include "jhash.h"

#include <stdlib.h>

/* Symtab torture tests
 *
 */

struct test_value
{
  int   val ;

  bool  defined ;
  bool  seen ;

  char  name[] ;
} ;

/* prototypes */
void assert_true(int result, const char * message);
int main(int argc, char **argv);
static void test_hashes(void) ;
void test_symbol_table_new(void);
void test_symbol_table_lookup(void);
void call_back_function_set(symbol sym, void* value);
void call_back_function_change(symbol sym, void* value);
void call_back_function_unset(symbol sym, void* value);
void test_call_back(void);
void test_ref(void);
void test_ref_heavy(void);

static void scan_symbol_table(symbol_table table) ;

void
assert_true(int result, const char * message)
{
  if (!result)
    {
      printf("Assert failed: %s\n", message);
    }
}

int
main(int argc, char **argv)
{
  qlib_init_first_stage(0);     /* Absolutely first     */
  host_init(argv[0]) ;

  test_hashes();

  test_symbol_table_new();
  test_symbol_table_lookup();
#if 0
  test_call_back();
  test_ref();
  test_ref_heavy();
#endif

  return 0;
}

static int
test_symbol_cmp(const void* val, const void* name)
{
  return strcmp(((const struct test_value*)val)->name, name) ;
} ;

static int value_count = 0 ;

static struct test_value*
test_symbol_make(const char* name, int val)
{
  struct test_value* value ;

  value = calloc(1, sizeof(struct test_value) + strlen(name) + 1) ;
  strcpy(value->name, name) ;

  value->val     = val ;
  value->defined = true ;
  value->seen    = false ;

  ++value_count ;

  return value ;
} ;

static void
test_symbol_free(void* val)
{
  assert_true(!((struct test_value*)val)->defined, "freeing defined value") ;
  free(val) ;

  --value_count ;
} ;

static const symbol_funcs_t test_symbol_funcs =
{
  .hash   = symbol_hash_string,
  .equal  = test_symbol_cmp,
  .free   = test_symbol_free,
} ;


void
test_symbol_table_new(void)
{
  symbol_table table = NULL;
  char name[] = "name";
  struct test_value* value ;
  symbol sym = NULL;
  symbol sym2 = NULL;

  printf("test_symbol_table_init_new\n");
  table = symbol_table_new(NULL, 0, 0, &test_symbol_funcs);
  assert_true(table != NULL, "table == NULL");

  /* expect to not find */
  sym = symbol_lookup(table, name, no_add);
  assert_true(sym == NULL, "sym != NULL");

  /* add */
  sym = symbol_lookup(table, name, add);
  assert_true(sym != NULL, "sym == NULL");
  assert_true(symbol_get_body(sym) == NULL, "sym->value != NULL") ;

  value = test_symbol_make(name, 777) ;
  symbol_set_body(sym, value, true /* set */, free_it /* existing */) ;

  /* find */
  sym2 = symbol_lookup(table, name, no_add);
  assert_true(sym == sym2, "sym != sym2");
  assert_true(symbol_get_body(sym) == value, "symbol_get_body(sym) != value");

  value->defined = false ;
  symbol_delete(sym, free_it);

  assert_true(value_count == 0, "value_count != 0") ;

  sym = NULL ;
  while ((sym = symbol_table_ream(table, sym, free_it)) != NULL)
    assert_true(sym == NULL, "table not empty") ;
} ;

static int
test_symbol_sort(const symbol* a, const symbol* b)
{
  return strcmp_mixed(((struct test_value*)(*a)->body)->name,
                      ((struct test_value*)(*b)->body)->name ) ;
} ;

void
test_symbol_table_lookup(void)
{
  symbol_table table = NULL;
  char name[20];
  symbol sym = NULL;
  int i ;
  uint j ;
  struct test_value* value = NULL;
  const int len = 100000;
  struct symbol_walker itr;
  vector v = NULL;

  printf("test_symbol_table_lookup\n");
  table = symbol_table_new(NULL, 0, 200, &test_symbol_funcs);

  /* add */
  for (i = 0; i < len; ++i)
    {
      sprintf(name, "%d-name", i);
      sym = symbol_lookup(table, name, add);
      assert_true(sym != NULL, "add: sym == NULL");
      assert_true(symbol_get_body(sym) == NULL, "sym->body != NULL") ;

      value = test_symbol_make(name, i) ;
      symbol_set_body(sym, value, true /* set */, free_it /* existing */);
      assert_true(symbol_get_body(sym) == value,
                                            "symbol_get_body(sym) != value");
    }

  scan_symbol_table(table) ;

  /* find */
  for (i = 0; i < len; ++i)
    {
      sprintf(name, "%d-name", i);
      sym = symbol_lookup(table, name, no_add);
      assert_true(sym != NULL, "find: sym == NULL");
      value = symbol_get_body(sym) ;
      assert_true(value != NULL, "symbol_get_body(sym) == NULL");

      assert_true(strcmp(value->name, name) == 0,
                                             "strcmp(value->name, name) != 0");
      assert_true(value->val == i, "value->val != i");
    }

  /* walk with symbol_walker */
  symbol_walk_start(table, &itr);
  i = 0;
  while ((sym = symbol_walk_next(&itr)) != NULL)
    {
      value = symbol_get_body(sym) ;
      assert_true(!value->seen, "value seen already") ;
      value->seen = true ;
      ++i;
    } while (sym != NULL);
  assert_true(i == len, "i != len");

  /* extract vector */
  v = symbol_table_extract(table, NULL, NULL, 1, test_symbol_sort);
  assert_true(vector_end(v) == (unsigned)len, "vector_get_end(v) != len");

  i = 0 ;
  for (VECTOR_ITEMS(v, sym, j))
    {
      value = symbol_get_body(sym) ;
      assert_true(value->val == i, "value->val != i") ;
      ++i ;
    }
  assert_true(i == len, "i != len");

  vector_free(v);

  /* Ream out                                                   */
  sym = NULL ;
  i = 0 ;
  while ((sym = symbol_table_ream(table, sym, free_it)) != NULL)
    {
      value = symbol_get_body(sym) ;
      value->defined = false ;
      ++i ;
    } ;
  assert_true(i == len, "i != len");

  assert_true(value_count == 0, "value_count != 0") ;
}

#if 0
void
test_call_back(void)
{
  symbol_table table = NULL;
  char name[] = "name";
  char value[] = "value";
  char new_value[] = "new value";
  symbol sym = NULL;

  printf("test_call_back\n");
  table = symbol_table_init_new(table, NULL, 0, 0, NULL, NULL);
  assert_true(table != NULL, "table == NULL");

  /* add */
  symbol_table_set_call_back(table, call_back_function_set);
  sym = symbol_lookup(table, name, add);
  symbol_set_value(sym, value);

  /* change */
  symbol_table_set_call_back(table, call_back_function_change);
  sym = symbol_lookup(table, name, add);
  symbol_set_value(sym, new_value);

  /* delete */
  symbol_table_set_call_back(table, call_back_function_unset);
  symbol_unset_value(sym);

  while ((symbol_table_ream(table, 1)) != NULL)
    {
    }
}

void call_back_function_set(symbol sym, void* value)
{
  assert_true(symbol_get_body(sym) != NULL && value == NULL,
      "symbol_get_body(sym) == NULL || value != NULL");
}

void call_back_function_change(symbol sym, void* value)
{
  assert_true(symbol_get_body(sym) != NULL && value != NULL,
      "symbol_get_body(sym) == NULL || value == NULL");
}


void call_back_function_unset(symbol sym, void* value)
{
  assert_true(symbol_get_body(sym) == NULL && value != NULL,
      "symbol_get_body(sym) != NULL || value == NULL");
}

void
test_ref(void)
{
  symbol_table table = NULL;
  char name[] = "name";
  char value[] = "value";
  symbol sym = NULL;
  symbol_nref ref = NULL;
  symbol_nref ref1 = NULL;
  symbol_nref ref2 = NULL;
  struct symbol_nref walk;
  const int num_refs = 2;
  long int itag = 0;

  printf("test_ref\n");
  table = symbol_table_init_new(table, NULL, 0, 0, NULL, NULL);

  /* add */
  sym = symbol_lookup(table, name, add);
  symbol_set_value(sym, value);

  /* create references, in reverse order so that walk in order */
  ref2 = symbol_set_ref(NULL, sym);
  assert_true(ref2 != NULL, "ref2 == NULL");
  sym_ref_set_i_tag(ref2, 2);
  assert_true(sym_ref_i_tag(ref2) == 2, "sym_ref_i_tag(ref2) != 2");

  ref1 = symbol_set_ref(NULL, sym);
  assert_true(ref1 != NULL, "ref1 == NULL");
  sym_ref_set_i_tag(ref1, 1);
  assert_true(sym_ref_i_tag(ref1) == 1, "sym_ref_i_tag(ref1) != 1");

  /* walk references */
  itag = 1;
  symbol_nref_walk_start(sym, &walk) ;
  assert_true(sym->ref_list == &walk, "sym->ref_list != &walk");
  assert_true(walk.next == ref1, "walk.next != ref1");
  assert_true(ref1->next == ref2, "ref1->next != ref2");
  assert_true(ref2->next == NULL, "ref2->next != NULL");

  while ((ref = symbol_nref_walk_step(&walk)) != NULL)
    {
      assert_true(sym_ref_i_tag(ref) == itag, "sym_ref_i_tag(ref) != itag");
      ++itag;
    }
  assert_true(itag == num_refs + 1, "itag != num_refs + 1");

  symbol_nref_walk_end(&walk);

  /* clean up */
  symbol_unset_ref(ref1, 1);
  symbol_unset_ref(ref2, 1);

  while ((symbol_table_ream(table, 1)) != NULL)
    {
    }
}

void
test_ref_heavy(void)
{
  symbol_table table = NULL;
  char name[] = "name";
  char value[] = "value";
  symbol sym = NULL;
  symbol_nref ref = NULL;
  struct symbol_nref walk;
  const long int num_refs = 100000;
  long int itag = 0;

  printf("test_ref_heavy\n");
  table = symbol_table_init_new(table, NULL, 0, 0, NULL, NULL);

  /* add */
  sym = symbol_lookup(table, name, add);
  symbol_set_value(sym, value);

  /* create references, in reverse order so that walk in order */
  for (itag = num_refs; itag > 0; --itag)
    {
      ref = symbol_set_ref(NULL, sym);
      assert_true(ref != NULL, "ref == NULL");
      sym_ref_set_i_tag(ref, itag);
      assert_true(sym_ref_i_tag(ref) == itag, "sym_ref_i_tag(ref) != itag");
    }

  /* walk references */
  itag = 1;
  symbol_nref_walk_start(sym, &walk) ;
  assert_true(sym->ref_list == &walk, "sym->ref_list != &walk");

  while ((ref = symbol_nref_walk_step(&walk)) != NULL)
    {
      assert_true(sym_ref_i_tag(ref) == itag, "sym_ref_i_tag(ref) != itag");
      ++itag;
      symbol_unset_ref(ref, 1);
    }
  assert_true(itag == num_refs + 1, "itag != num_refs + 1");

  symbol_nref_walk_end(&walk);

  while ((symbol_table_ream(table, 1)) != NULL)
    {
    }
}

#endif


/*==============================================================================
 * Scanning symbol table and showing properties.
 */
static void show_histogram(uint length[], uint n, uint t) ;

static void
scan_symbol_table(symbol_table table)
{
  uint   n = 10 ;           /* 0..10 and >10        */
  uint   length[n+2] ;
  uint   i ;
  uint*  comp ;

  for (i = 0 ; i < (n + 2) ; ++i)
    length[i] = 0 ;

  fprintf(stderr, "Symbol Table %'d entries: %'d bases and %'d extend_thresh"
                                                         " @ density %0.2f\n",
                   table->entry_count, table->base_count,
                   table->extend_thresh, table->density) ;

  for (i = 0 ; i < table->base_count ; ++i)
    {
      symbol sym ;
      uint   l ;

      l = 0 ;
      sym = table->bases[i] ;

      while (sym != NULL)
        {
          ++l ;
          sym = sym->next ;
        } ;

      if (l <= n)
        ++length[l] ;
      else
        ++length[n + 1] ;
    } ;

  show_histogram(length, n, table->entry_count) ;

  for (i = 0 ; i < (n + 2) ; ++i)
    length[i] = 0 ;

  fprintf(stderr, "  RAND_MAX == 0x%x\n", RAND_MAX) ;

  comp = calloc(table->base_count, sizeof(uint)) ;
  for (i = 0 ; i < table->entry_count ; ++i)
    {
      uint q = rand() % table->base_count ;
      ++comp[q] ;
    } ;

  for (i = 0 ; i < table->base_count ; ++i)
    {
      uint   l ;

      l = comp[i] ;

      if (l <= n)
        ++length[l] ;
      else
        ++length[n + 1] ;
    } ;

  show_histogram(length, n, table->entry_count) ;
} ;



static void
show_histogram(uint length[], uint n, uint t)
{
  uint   i ;
  uint   m ;
  uint   c ;

  m = 0 ;
  for (i = 0 ; i < (n + 2) ; ++i)
    if (length[i] > m)
      m = length[i] ;

  c = 0 ;
  for (i = 0 ; i < (n + 2) ; ++i)
    {
      uint j ;
      uint s ;

      if (i <= n)
        fprintf(stderr, "   %2d: ", i) ;
      else
        fprintf(stderr, "  >%2d: ", n) ;

      s = (length[i] * 50) / m ;
      for (j = 0 ; j < 51 ; ++j)
        if (j < s)
          fprintf(stderr, "=") ;
        else
          fprintf(stderr, " ") ;

      j = i * length[i] ;
      c += j ;
      fprintf(stderr, "%'6d   %6d  %4.1f%%  %5.1f%% :%2d\n", length[i], j,
                                               ((double)j * 100.0)/(double)t,
                                               ((double)c * 100.0)/(double)t,
                                                                           i) ;
    } ;
} ;

/*
 *
 * TODO
 *

symbol_table_set_parent
symbol_table_get_parent
symbol_hash_string
symbol_hash_bytes
symbol_table_set_call_back
symbol_table_free
symbol_unset_value
symbol_select_cmp
symbol_sort_cmp
symbol_table_extract
symbol_sort_cmp
symbol_get_name_len
symbol_get_table
symbol_zero_ref
symbol_dec_ref
symbol_init_ref
symbol_set_ref
symbol_unset_ref
symbol_unset_ref_free
symbol_unset_ref_keep
sym_ref_symbol
sym_ref_value
sym_ref_name
sym_ref_name_len
sym_ref_parent
sym_ref_p_tag
sym_ref_u_tag
sym_ref_i_tag
sym_ref_set_parent
sym_ref_set_p_tag
sym_ref_set_i_tag
 */

/*==============================================================================
 * The symbol table stuff uses some simple minded hashes.
 *
 * The purpose of this test is to see how well that works against the more
 * sophisticated jhash function.
 *
 * The acid test is how many collisions the hash generates for a given
 * density of table, for a given representative selection of values to hash.
 * This makes things tricky, given the difficulty of identifying a
 * representative selection.
 *
 * The symbol table always uses an odd number of symbol bases, so part of the
 * hash is the division by that number.
 *
 * This tests against tables with 1, 2, and 5 entries per chain base, for
 * 11, 101, 1001 and 10001 chain bases.
 *
 * The tests for the "integer hash" are:
 *
 *   1) a "random" sequence -- generated by random().
 *
 *      The point here is that the result should preserve the randomness !
 *
 *   2) a sequence of small integers starting at zero, stepping 1 or 2 at
 *      random.
 *
 *      To see how well the hash spreads those out.
 *
 *   3) a sequence of large integers, starting at a value that looks like
 *      an address, and stepping by some multiple 1..16 of 32.
 *
 *      This is supposed to simulate addresses, and we hope the hash spreads
 *      them out.
 *
 * The tests for the "bytes hash" are:
 *
 *   1) a "random" sequence of bytes
 *
 *      for a number of string lengths ?
 *
 *   2) a sequence of short strings, where the difference between one and the
 *      next is small.
 *
 *   3) a sequence of longer strings, where the difference between one and the
 *      next is also small.
 */
typedef struct ht_bytes* ht_bytes ;
typedef struct ht_bytes  ht_bytes_t ;

enum { ht_max_bytes = 40 } ;

struct ht_bytes
{
  ushort  len ;
  uchar   bytes[ht_max_bytes] ;
} ;

typedef struct ht_value* ht_value ;
typedef struct ht_value  ht_value_t ;

struct ht_value
{
  ht_value      next ;

  uint32_t      jhash ;
  symbol_hash_t shash ;
  uint32_t      vhash ;

  union
  {
    uint        i ;
    ht_bytes_t  b ;
  } v ;
} ;

typedef struct ht_table* ht_table ;
typedef struct ht_table  ht_table_t ;

enum { ht_max_bases = 10001 } ;
enum { ht_max_hist  =   100 } ;

struct ht_table
{
  uint          bases ;
  uint          density ;

  uint          trials ;
  uint          total ;         /* total number of items in all trials  */

  ht_value      unique[ht_max_bases] ;

  ht_value      r_unique[ht_max_bases] ;

  uint          j_counts[ht_max_bases] ;
  uint          s_counts[ht_max_bases] ;
  uint          r_counts[ht_max_bases] ;
  uint          v_counts[ht_max_bases] ;

  uint          j_hist[ht_max_hist + 2] ;
  uint          s_hist[ht_max_hist + 2] ;
  uint          r_hist[ht_max_hist + 2] ;
  uint          v_hist[ht_max_hist + 2] ;

  ht_value_t    seed[1] ;
} ;

typedef struct ht_test_spec* ht_test_spec ;
typedef struct ht_test_spec  ht_test_spec_t ;

typedef void ht_test_init(ht_table table, ht_test_spec spec, uint n) ;
typedef void ht_test_gen(ht_table table, ht_test_spec spec, ht_value value);
typedef void ht_hash(ht_value v) ;
typedef int  ht_cmp(ht_value a, ht_value b) ;

struct ht_test_spec
{
  const char*   name ;

  uint          count ;

  ht_test_init* init ;

  ht_test_gen*  gen ;

  ht_hash*      jhash ;
  ht_hash*      shash ;
  ht_cmp*       cmp ;
} ;

static ht_value ht_free_values = NULL ;

static ht_table ht_table_new(void) ;
static void ht_table_reset(ht_table table, uint bases, uint density) ;
static void ht_table_clear(ht_table table) ;
static ht_table ht_table_free(ht_table table) ;
static ht_value ht_value_new(void) ;
static void ht_values_free(void) ;

static void ht_test_run(ht_table table, ht_test_spec spec) ;
static void ht_test_hist(uint* counts, uint* hist, uint bases) ;
static void ht_test_report(ht_table table) ;

static bool ht_table_add(ht_value unique[], ht_value value, uint32_t hash,
                                                                  ht_cmp* cmp) ;
static void ht_jhash_word(ht_value v) ;
static void ht_shash_word(ht_value v) ;
static void ht_jhash_bytes(ht_value v) ;
static void ht_shash_bytes(ht_value v) ;

static int  ht_cmp_word(ht_value a, ht_value b) ;
static int  ht_cmp_bytes(ht_value a, ht_value b) ;

static void ht_rand_i_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_rand_i_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;
static void ht_small_i_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_small_i_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;
static void ht_large_i_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_large_i_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;

static void ht_rand_b_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_rand_b_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;
static void ht_small_b_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_small_b_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;
static void ht_large_b_test_init(ht_table table, ht_test_spec spec, uint n) ;
static void ht_large_b_test_gen(ht_table table, ht_test_spec spec,
                                                               ht_value value) ;

/*------------------------------------------------------------------------------
 * The table of tests to run.
 */
static ht_test_spec_t ht_tests[] =
    {
        {
            .name   = "random integers",
            .count  = 20,

            .init   = &ht_rand_i_test_init,
            .gen    = &ht_rand_i_test_gen,

            .jhash  = &ht_jhash_word,
            .shash  = &ht_shash_word,
            .cmp    = &ht_cmp_word,
        },

        {
            .name   = "simple small integers",
            .count  = 20,

            .init   = &ht_small_i_test_init,
            .gen    = &ht_small_i_test_gen,

            .jhash  = &ht_jhash_word,
            .shash  = &ht_shash_word,
            .cmp    = &ht_cmp_word,
        },

        {
            .name   = "simple large integers",
            .count  = 20,

            .init   = &ht_large_i_test_init,
            .gen    = &ht_large_i_test_gen,

            .jhash  = &ht_jhash_word,
            .shash  = &ht_shash_word,
            .cmp    = &ht_cmp_word,
        },

        {
            .name   = "random bytes",
            .count  = 20,

            .init   = &ht_rand_b_test_init,
            .gen    = &ht_rand_b_test_gen,

            .jhash  = &ht_jhash_bytes,
            .shash  = &ht_shash_bytes,
            .cmp    = &ht_cmp_bytes,
        },

        {
            .name   = "simple small bytes",
            .count  = 20,

            .init   = &ht_small_b_test_init,
            .gen    = &ht_small_b_test_gen,

            .jhash  = &ht_jhash_bytes,
            .shash  = &ht_shash_bytes,
            .cmp    = &ht_cmp_bytes,
        },

        {
            .name   = "simple large bytes",
            .count  = 20,

            .init   = &ht_large_b_test_init,
            .gen    = &ht_large_b_test_gen,

            .jhash  = &ht_jhash_bytes,
            .shash  = &ht_shash_bytes,
            .cmp    = &ht_cmp_bytes,
        },

        {   .name = NULL        }
    } ;

static uint base_counts[] = { 11, 101, 1001, 10001, 0 } ;
static uint densities[]   = {  1, 2, 5, 0 } ;

/*------------------------------------------------------------------------------
 * Perform the tests !
 */
static void
test_hashes(void)
{
  ht_table table ;
  ht_test_spec spec ;

  table = ht_table_new() ;

  spec = ht_tests ;
  while (spec->name != NULL)
    {
      uint* bc ;

      bc = base_counts ;
      while (*bc != 0)
        {
          uint* d ;

          d = densities ;
          while (*d != 0)
            {
              uint n ;

              ht_table_reset(table, *bc, *d) ;

              fprintf(stdout, " %s: %5d bases, density %d * %d\n", spec->name,
                                                         *bc, *d, spec->count) ;
              for (n = 1 ; n <= spec->count ; ++n)
                {
                  ++table->trials ;             /* The trial number     */

                  ht_test_run(table, spec) ;

                  ht_table_clear(table) ;
                } ;

              ht_test_report(table) ;

              ++d ;
            } ;

          ++bc ;
        } ;

      ++spec ;
    } ;

  ht_table_free(table) ;
  ht_values_free() ;
} ;

/*------------------------------------------------------------------------------
 * Run the current test
 */
static void
ht_test_run(ht_table table, ht_test_spec spec)
{
  uint i, n ;

  n = table->bases * table->density ;

  spec->init(table, spec, table->trials) ;

  for (i = 1 ; i <= n ; ++i)
    {
      ht_value val ;

      val = ht_value_new() ;

      do
        {
          spec->gen(table, spec, val) ;
          spec->jhash(val) ;
          spec->shash(val) ;
        } while (!ht_table_add(table->unique, val, val->jhash, spec->cmp)) ;

      table->j_counts[val->jhash % table->bases] += 1;
      table->s_counts[val->shash % table->bases] += 1;
      table->v_counts[val->vhash % table->bases] += 1;

      val = ht_value_new() ;

      do
        {
          val->v.i = random() ;
        } while (!ht_table_add(table->r_unique, val, val->v.i, spec->cmp)) ;

      table->r_counts[val->v.i % table->bases] += 1;
    } ;

  table->total += n ;
  ht_test_hist(table->j_counts, table->j_hist, table->bases) ;
  ht_test_hist(table->s_counts, table->s_hist, table->bases) ;
  ht_test_hist(table->r_counts, table->r_hist, table->bases) ;
  ht_test_hist(table->v_counts, table->v_hist, table->bases) ;
} ;

/*------------------------------------------------------------------------------
 * Update the histograms from the counts
 */
static void
ht_test_hist(uint* counts, uint* hist, uint bases)
{
  uint i ;

  for (i = 0 ; i < bases ; ++i)
    {
      uint c ;

      c = counts[i] ;

      if (c > ht_max_hist)
        c = ht_max_hist + 1 ;

      hist[c] += 1 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Have built up a histogram on the basis of a number of trials
 */
static void
ht_test_report(ht_table table)
{
  uint i, m ;
  uint jc, sc, rc, vc ;
  uint ja, sa, ra, va ;
  double b_scale, t_scale, jt, st, rt, vt ;

  b_scale = (double)table->trials * table->bases / 100 ;
  t_scale = (double)table->total / 100 ;

  jc = sc = rc = vc = 0 ;
  ja = sa = ra = va = 0 ;
  jt = st = rt = vt = 0.0 ;

  m = 0 ;
  for (i = 0 ; i <= ht_max_hist + 1 ; ++i)
    {
      double j, s, r, v;

      /* % of bases which have "i" items hung off same
       */
      j = (double)table->j_hist[i] / b_scale ;
      s = (double)table->s_hist[i] / b_scale ;
      r = (double)table->r_hist[i] / b_scale ;
      v = (double)table->v_hist[i] / b_scale ;

      /* % of items on bases with "i" or fewer items hung off same
       */
      if (i <= ht_max_hist)
        {
          jc += table->j_hist[i] * i ;
          sc += table->s_hist[i] * i ;
          rc += table->r_hist[i] * i ;
          vc += table->v_hist[i] * i ;
        }
      else
        {
          jc += table->total ;
          sc += table->total ;
          rc += table->total ;
          vc += table->total ;
        } ;

      jt = (double)jc / t_scale ;
      st = (double)sc / t_scale ;
      rt = (double)rc / t_scale ;
      vt = (double)vc / t_scale ;

      if ((table->j_hist[i] != 0) || (table->s_hist[i] != 0))
        fprintf(stdout,
   "%5u: %5.2f%% %5.2f%% (%5.2f%% %5.2f%%) %6.2f%% %6.2f%% (%6.2f%% %6.2f%%)\n",
                                                i, j, s, r, v, jt, st, rt, vt) ;

      m += i ;
      ja += table->j_hist[i] * m ;
      sa += table->s_hist[i] * m ;
      ra += table->r_hist[i] * m ;
      va += table->v_hist[i] * m ;
    } ;

  /* Ratio of total amount of work to look up everything once
   */
  t_scale = (double)table->total ;

  jt = (double)ja / t_scale ;
  st = (double)sa / t_scale ;
  rt = (double)ra / t_scale ;
  vt = (double)va / t_scale ;

  fprintf(stdout,
    "   av: %5.2f  %5.2f  (%5.2f  %5.2f )\n", jt, st, rt, vt) ;
} ;

/*------------------------------------------------------------------------------
 * Create new, entirely empty ht_table
 */
static ht_table
ht_table_new(void)
{
  return XCALLOC(MTYPE_TMP, sizeof(ht_table_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Empty out the given ht_table and reset all counts etc.
 *
 * Set new count of bases and the density.
 *
 * This is for the start of a new test
 */
static void
ht_table_reset(ht_table table, uint bases, uint density)
{
  ht_table_clear(table) ;

  assert(bases <= ht_max_bases) ;

  memset(table, 0, sizeof(ht_table_t)) ;

  table->bases   = bases ;
  table->density = density ;
} ;

/*------------------------------------------------------------------------------
 * Empty out the given ht_table, clear the counts but keep the histogram.
 *
 * This is for between runs of the same test.
 */
static void
ht_table_clear(ht_table table)
{
  uint i ;

  for (i = 0 ; i < ht_max_bases ; ++i)
    {
      ht_value val ;
      ht_value free ;

      val = table->unique[i] ;

      if (val == NULL)
        continue ;

      free = ht_free_values ;
      ht_free_values = val ;

      while (val->next != NULL)
        val = val->next ;

      val->next = free ;
    } ;

  memset(table->unique,   0, sizeof(table->unique)) ;
  memset(table->r_unique, 0, sizeof(table->r_unique)) ;
  memset(table->j_counts, 0, sizeof(table->j_counts)) ;
  memset(table->s_counts, 0, sizeof(table->s_counts)) ;
  memset(table->r_counts, 0, sizeof(table->r_counts)) ;
  memset(table->v_counts, 0, sizeof(table->r_counts)) ;
} ;

/*------------------------------------------------------------------------------
 * Empty out the given ht_table and free it.
 *
 * NB: does not free the values.
 */
static ht_table
ht_table_free(ht_table table)
{
  ht_table_clear(table) ;
  XFREE(MTYPE_TMP, table) ;

  return NULL ;
}

/*------------------------------------------------------------------------------
 * Create new empty ht_value (or use an existing free one).
 */
static ht_value
ht_value_new(void)
{
  ht_value val ;

  val = ht_free_values ;
  if (val != NULL)
    ht_free_values = val->next ;
  else
    val = XMALLOC(MTYPE_TMP, sizeof(ht_value_t)) ;

  memset(val, 0, sizeof(ht_value_t)) ;

  return val ;
} ;

/*------------------------------------------------------------------------------
 * Free all the values on the ht_free_values list.
 */
static void
ht_values_free(void)
{
  ht_value next ;

  next = ht_free_values ;

  while (next != NULL)
    {
      ht_value val ;

      val  = next ;
      next = val->next ;

      XFREE(MTYPE_TMP, val) ;
    } ;

  ht_free_values = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Add given value to the given "unique" store, provided it is unique.
 *
 * Uses the given hash and the given comparison to do this.
 *
 * Returns: true <=> added (is unique)
 */
static bool
ht_table_add(ht_value unique[], ht_value value, uint32_t hash, ht_cmp* cmp)
{
  uint i ;
  ht_value buddy ;

  i = hash % ht_max_bases ;

  buddy = unique[i] ;
  while (buddy != NULL)
    {
      if (cmp(buddy, value) == 0)
        return false ;

      buddy = buddy->next ;
    } ;

  value->next = unique[i] ;
  unique[i] = value ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Set v->jhash for given integer value
 */
static void
ht_jhash_word(ht_value v)
{
  v->jhash = jhash_1word(v->v.i, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Set v->shash for given integer value
 */
static void
ht_shash_word(ht_value v)
{
  v->shash = symbol_hash_word(v->v.i) ;
} ;

/*------------------------------------------------------------------------------
 * Set v->jhash for given bytes value
 */
static void
ht_jhash_bytes(ht_value v)
{
  v->jhash = jhash(v->v.b.bytes, v->v.b.len, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Set v->shash for given bytes value
 */
static void
ht_shash_bytes(ht_value v)
{
  v->shash = symbol_hash_bytes(v->v.b.bytes, v->v.b.len) ;
} ;

/*------------------------------------------------------------------------------
 * Compare integer values
 */
static int
ht_cmp_word(ht_value a, ht_value b)
{
  if (a->v.i != b->v.i)
    return (a->v.i < b->v.i) ? -1 : +1 ;

  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Compare bytes values
 */
static int
ht_cmp_bytes(ht_value a, ht_value b)
{
  if (a->v.b.len != b->v.b.len)
    return (a->v.b.len < b->v.b.len) ? -1 : +1 ;

  return memcmp(a->v.b.bytes, b->v.b.bytes, a->v.b.len) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for random integer test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_rand_i_test_init(ht_table table, ht_test_spec spec, uint n)
{
  /* Nothing to do      */
} ;

/*------------------------------------------------------------------------------
 * Next value for random integer test.
 */
static void
ht_rand_i_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  value->v.i = random() ;
  value->vhash = value->v.i ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for small integer test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_small_i_test_init(ht_table table, ht_test_spec spec, uint n)
{
  table->seed->v.i = n ;
} ;

/*------------------------------------------------------------------------------
 * Next value for small integer test.
 */
static void
ht_small_i_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  value->v.i = table->seed->v.i ;
  value->vhash = value->v.i ;
  table->seed->v.i += (random() % 5) + 1 ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for large integer test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_large_i_test_init(ht_table table, ht_test_spec spec, uint n)
{
  table->seed->v.i = n * 0xA50000 ;
} ;

/*------------------------------------------------------------------------------
 * Next value for large integer test.
 */
static void
ht_large_i_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  value->v.i = table->seed->v.i ;
  value->vhash = value->v.i ;
  table->seed->v.i += ((random() % 8) + 1) * 0x20 ;
} ;

/*------------------------------------------------------------------------------
 * The gash vhash for bytes tests
 */
static void
ht_vhash_b_test(ht_value value)
{
  uint32_t v ;
  uchar* p, * e ;

  v = value->v.b.len ;
  p = value->v.b.bytes ;
  e = (v < 4) ? p + v : p + 4 ;

  while (p < e)
    v = (v << 8) + *p++ ;

  value->vhash = v ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for random bytes test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_rand_b_test_init(ht_table table, ht_test_spec spec, uint n)
{
  table->seed->v.b.len = 5 + (random() % ((n % 5) + 1)) ;
  assert(table->seed->v.b.len <= ht_max_bytes) ;
} ;

/*------------------------------------------------------------------------------
 * Next value for random bytes test.
 */
static void
ht_rand_b_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  uint l ;
  uchar* p, * e ;

  l = table->seed->v.b.len + (random() % 5) ;

  while (l > ht_max_bytes)
    l -= (random() % (ht_max_bytes / 2)) + 1 ;

  value->v.b.len = l ;
  p = value->v.b.bytes ;
  e = p + l ;
  while (p < e)
    *p++ = random() % 256 ;

  ht_vhash_b_test(value) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for small bytes test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_small_b_test_init(ht_table table, ht_test_spec spec, uint n)
{
  table->seed->v.b.len = 5 + (n % 4) ;
  assert(table->seed->v.b.len <= ht_max_bytes) ;

  memset(table->seed->v.b.bytes, 'a' + (n % 26), ht_max_bytes) ;
} ;

/*------------------------------------------------------------------------------
 * Next value for small bytes test.
 */
static void
ht_small_b_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  uint  l ;
  uchar ch, fch ;
  uchar* p ;

  value->v.b = table->seed->v.b ;

  l   = table->seed->v.b.len ;
  p   = table->seed->v.b.bytes ;
  fch = *p ;
  p += l - 1 ;

  while (1)
    {
      ch = *p + 2 ;             /* 26 / 2 = 13  */
      if (ch > (uchar)'z')
        ch -= ('z' - 'a') ;
      *p = ch ;

      if (ch != fch)
        break ;

      if (l == 2)
        {
          l = table->seed->v.b.len ;
          table->seed->v.b.bytes[l] = fch ;
          table->seed->v.b.len = l + 1 ;

          assert(table->seed->v.b.len <= ht_max_bytes) ;

          break ;
        } ;

      --p ;
      --l ;
    } ;

  ht_vhash_b_test(value) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise for large bytes test.
 *
 * The table->seed has been zeroised.
 */
static void
ht_large_b_test_init(ht_table table, ht_test_spec spec, uint n)
{
  table->seed->v.b.len = 10 + (random() % 5) ;

  assert(table->seed->v.b.len <= ht_max_bytes) ;

  memset(table->seed->v.b.bytes, 'a' + (n % 26), ht_max_bytes) ;
} ;

/*------------------------------------------------------------------------------
 * Next value for large bytes test.
 */
static void
ht_large_b_test_gen(ht_table table, ht_test_spec spec, ht_value value)
{
  uint  l ;
  uchar ch, fch ;
  uchar* p ;

  value->v.b = table->seed->v.b ;

  l   = table->seed->v.b.len ;
  p   = table->seed->v.b.bytes ;
  fch = *p ;
  p += l - 1 ;

  while (1)
    {
      ch = *p + 13 ;            /* 26 / 13 = 2          */
      if (ch > (uchar)'z')
        ch -= ('z' - 'a') ;
      *p = ch ;

      if (ch != fch)
        break ;

      if (l == 2)
        {
          l = table->seed->v.b.len ;
          table->seed->v.b.bytes[l] = fch ;
          table->seed->v.b.len = l + 1 ;

          assert(table->seed->v.b.len <= ht_max_bytes) ;

          break ;
        } ;

      --p ;
      --l ;
    } ;

  ht_vhash_b_test(value) ;
} ;


