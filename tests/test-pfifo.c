#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pfifo.h"


typedef struct
{
  struct dl_list_pair(struct datum*) list_pointers;//pfifo_pair_t list_pointers;
  const char* junk;
} datum;

static void
test_pfifo_item_head(void)
{
  /* Initialize pfifo. */
  uint max_periods;
  max_periods = 5;
  uint alloc_on_progression;
  alloc_on_progression = 1;

  pfifo p;
  p = pfifo_init_new(NULL, max_periods, alloc_on_progression, offsetof(datum, list_pointers));


  // [BEGIN] Single item && Single period
  //
  // Add an item to period ptime and remove from pfifo using
  // pfifo_item_head
  fprintf(stderr, "test_item_head_one_period... \t");
  pfifo_period_t ptime;
  ptime = 1;

  /* Add items to the first period in the pfifo. */
  datum new_stuff;
  new_stuff.junk = "Junk Data Here";
  pfifo_item_add(p, &new_stuff, ptime);

  /* Extract item from pfifo. */
  datum* old_item;
  old_item = pfifo_item_head(p);

  /* Ensure data was preserved. */
  if ( strcmp(new_stuff.junk, old_item->junk) != 0 ) {
    fprintf(stderr, "Failed single_item_single_period\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", new_stuff.junk, old_item->junk);
  }
  fprintf(stderr, "OK\n");
  //
  // [END] Single item && Single period


  // [BEGIN] Multiple items && Separate period
  //
  // Add two items to two separate periods. Ensure
  // pfifo_item_head removes both items from pfifo.
  fprintf(stderr, "test_item_head_many_periods... \t");
  ptime = 2;
  datum misp_a;
  misp_a.junk = "Item a";
  pfifo_item_add(p, &misp_a, ptime);

  ptime = 3;
  datum misp_b;
  misp_b.junk = "Item b";
  pfifo_item_add(p, &misp_b, ptime);

  datum* misp_a_out;
  misp_a_out = pfifo_item_head(p);
  if ( strcmp(new_stuff.junk, old_item->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", misp_a.junk, misp_a_out->junk);
  }

  datum* misp_b_out;
  misp_b_out = pfifo_item_head(p);
  if ( strcmp(new_stuff.junk, old_item->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", misp_b.junk, misp_b_out->junk);
  }
  fprintf(stderr, "OK\n");
  //
  // [END] Multiple items && Separate period

  /* Free up any lingering memory pieces. */
  pfifo_free(p);
  return;
}


// Add a single item to a single period. Delete the item, then
// call head to verify the pfifo is indeed empty.
static void
test_pfifo_item_del(void) {
  fprintf(stderr, "test_item_del... \t");

  /* Initialize pfifo. */
  uint max_periods;
  max_periods = 5;
  uint alloc_on_progression;
  alloc_on_progression = 1;

  pfifo p;
  p = pfifo_init_new(NULL, max_periods, alloc_on_progression, offsetof(datum, list_pointers));

  datum item;
  item.junk = "broken microwave";

  pfifo_period_t period;
  period = 10;

  pfifo_index_t loc;
  loc = pfifo_item_add(p, &item, period);

  // Why do I need both the item if I have the loc?
  pfifo_item_del(p, &item, loc);

  datum* unsafe;
  unsafe = pfifo_item_head(p);

  if (unsafe != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "[ERROR] Made a call to pfifo_item_head on an empty pfifo. Did not return NULL.\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


static void
test_pfifo_item_move(void) {
  return;
}


static void
test_pfifo_item_next(void) {
  return;
}


static void
test_pfifo_take(void) {
  return;
}


static void
test_pfifo_flush(void) {
  return;
}


static void
test_pfifo_flush_empty(void) {
  return;
}


static void
test_pfifo_first_period(void) {
  return;
}


static void
test_pfifo_first_not_ex_period(void) {
  return;
}


int
main(int argc, char* argv[]) {
  test_pfifo_item_head();
  test_pfifo_item_del();
  test_pfifo_item_move();
  test_pfifo_item_next();

  test_pfifo_take();
  test_pfifo_flush();
  test_pfifo_flush_empty();
  test_pfifo_first_period();
  test_pfifo_first_not_ex_period();
}
