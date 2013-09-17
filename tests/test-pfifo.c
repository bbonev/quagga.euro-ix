#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pfifo.h"


typedef struct
{
  struct dl_list_pair(struct datum*) list_pointers;//pfifo_pair_t list_pointers;
  const char* item;
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
  new_stuff.item = "Junk Data Here";
  pfifo_item_add(p, &new_stuff, ptime);

  /* Extract item from pfifo. */
  datum* old_item;
  old_item = pfifo_item_head(p);

  /* Ensure data was preserved. */
  if ( strcmp(new_stuff.item, old_item->item) != 0 ) {
    fprintf(stderr, "Failed single_item_single_period\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", new_stuff.item, old_item->item);
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
  misp_a.item = "Item a";
  pfifo_item_add(p, &misp_a, ptime);

  ptime = 3;
  datum misp_b;
  misp_b.item = "Item b";
  pfifo_item_add(p, &misp_b, ptime);

  datum* misp_a_out;
  misp_a_out = pfifo_item_head(p);
  if ( strcmp(new_stuff.item, old_item->item) != 0 ) {
    fprintf(stderr, "Failed multiple_item_separte_period\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", misp_a.item, misp_a_out->item);
  }

  datum* misp_b_out;
  misp_b_out = pfifo_item_head(p);
  if ( strcmp(new_stuff.item, old_item->item) != 0 ) {
    fprintf(stderr, "Failed multiple_item_separate_period\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", misp_b.item, misp_b_out->item);
  }
  fprintf(stderr, "OK\n");
  //
  // [END] Multiple items && Separate period

  /* Free up any lingering memory pieces. */
  pfifo_free(p);
  return;
}


int
main(int argc, char* argv[]) {
  fprintf(stderr, "Starting pfifo Tests\n");
  test_pfifo_item_head();
}
