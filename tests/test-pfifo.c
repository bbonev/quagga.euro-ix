#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pfifo.h"


static void
pfifo_next_item(void)
{
  fprintf(stderr, "pfifo_next_item...\t");
  /* Initialize pfifo. */
  uint max_periods;
  max_periods = 5;
  uint alloc_on_progression;
  alloc_on_progression = 1;
  uint pair_offset;
  pair_offset = 2;

  pfifo p;
  p = pfifo_init_new(NULL, max_periods, alloc_on_progression, pair_offset);

  /* Get current period. */
  pfifo_period_t ptime;
  ptime = pfifo_first_period(p);
  fprintf(stderr, "Got period: %d.\n", ptime);

  /* Add items to p. */
  char* new_stuff = "Junk Data Here";
  pfifo_item_add( p, (void*)new_stuff, pfifo_first_period(p) );
  fprintf(stderr, "Added item to period.\n");

  /* Grab the next item. */
  void* old_stuff;
  old_stuff = pfifo_item_next(p);
  fprintf(stderr, "Got item from pfifo.\n");

  if ( strcmp(new_stuff, (char*)old_stuff) != 0 ) {
    /* Free up any lingering memory pieces. */
    pfifo_free(p);
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", new_stuff, (char*)old_stuff);
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
