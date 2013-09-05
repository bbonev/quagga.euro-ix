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
pfifo_next_item(void)
{
  fprintf(stderr, "pfifo_next_item...\t");
  /* Initialize pfifo. */
  uint max_periods;
  max_periods = 5;
  uint alloc_on_progression;
  alloc_on_progression = 1;

  pfifo p;
  p = pfifo_init_new(NULL, max_periods, alloc_on_progression, offsetof(datum, list_pointers));

  /* Get current period. */
  pfifo_period_t ptime;
  ptime = 1;
  fprintf(stderr, "Using period: %d.\n", (int)ptime);

  /* Add items to the first period in the pfifo. */
  datum new_stuff;
  //new_stuff = XCALLOC(1, sizeof(datum));//= {(pfifo_pair_t) NULL, NULL };
  new_stuff.item = "Junk Data Here";
  fprintf(stderr, "Expected: %s\n", new_stuff.item);

  pfifo_item_add( p, &new_stuff, ptime );
  fprintf(stderr, "Added item to period.\n");

  /* Grab the next item. */
  datum* old_item;
  old_item = pfifo_item_head(p);

  if ( strcmp(new_stuff.item, old_item->item) != 0 ) {
    /* Free up any lingering memory pieces. */
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", new_stuff.item, old_item->item);
    pfifo_free(p);
  }

  /* Free up any lingering memory pieces. */
  pfifo_free(p);
  fprintf(stderr, "OK\n");
  return;
}


int
main(int argc, char* argv[]) {
  fprintf(stderr, "Starting pfifo Tests\n");
  pfifo_next_item();
}
