#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pfifo.h"
#include "qtime.h"

typedef struct
{
  struct dl_list_pair(struct datum*) list_pointers;//pfifo_pair_t list_pointers;
  const char* junk;
} datum;


static pfifo
new_pfifo(void) {
  /* Initialize pfifo. */
  uint max_periods;
  max_periods = 5;
  uint alloc_on_progression;
  alloc_on_progression = 1;

  pfifo p;
  p = pfifo_init_new(NULL, max_periods, alloc_on_progression, offsetof(datum, list_pointers));
  return p;
}


static void
test_pfifo_item_head_empty(void) {
  fprintf(stderr, "test_pfifo_item_head_empty... \t\t");
  pfifo p;
  p = new_pfifo();

  datum* unsafe;
  unsafe = pfifo_item_head(p);

  if (unsafe != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Made a call to pfifo_item_head on an empty pfifo. Did not return NULL.\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Add an item to period ptime and remove from pfifo using
// pfifo_item_head
static void
test_pfifo_item_head_single_period(void)
{
  fprintf(stderr, "test_pfifo_item_head_single_period... \t");
  pfifo p;
  p = new_pfifo();

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
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", new_stuff.junk, old_item->junk);
  } else {
    fprintf(stderr, "OK\n");
  }
  pfifo_free(p);
  return;
}


// Add two items to two separate periods. Ensure
// pfifo_item_head returns a pointer to the first item
// in the pfifo after n calls.
static void
test_pfifo_item_head_many_periods(void) {
  fprintf(stderr, "test_pfifo_item_head_many_periods... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
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
  if ( strcmp(misp_a.junk, misp_a_out->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "1. Expected: %s, Got: %s\n", misp_a.junk, misp_a_out->junk);
    pfifo_free(p);
    return;
  }

  datum* misp_b_out;
  misp_b_out = pfifo_item_head(p);
  if ( strcmp(misp_a.junk, misp_b_out->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "2. Expected: %s, Got: %s\n", misp_a.junk, misp_b_out->junk);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Add a single item to a single period. Delete the item, then
// call head to verify the pfifo is indeed empty.
static void
test_pfifo_item_del(void) {
  fprintf(stderr, "test_item_del... \t\t\t");
  pfifo p;
  p = new_pfifo();

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
    fprintf(stderr, "Made a call to pfifo_item_head on an empty pfifo. Did not return NULL.\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// + Basic Move
// period-1 <- item-a
// period-2 <- item-b
// move item-a to period-3
// check its period is 3
static void
test_pfifo_item_move_fwd(void) {
  fprintf(stderr, "test_pfifo_item_move_fwd... \t\t");
  pfifo p;
  p = new_pfifo();

  datum item_a;
  item_a.junk = "ie6";
  datum item_b;
  item_b.junk = "svn";

  pfifo_period_t period;
  period = 10;

  pfifo_item_add(p, &item_a, period);

  pfifo_index_t loc_b;
  loc_b = pfifo_item_add(p, &item_b, period + 1);

  loc_b = pfifo_item_move(p, &item_b, loc_b, period + 2);

  pfifo_period_t period_of_b;
  period_of_b = pfifo_period_get(p, loc_b);
  if (period_of_b != period + 2) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item was not moved to the correct period. Expected %d, but got %d\n", (int)(period + 2), (int)period_of_b);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// + Backwards Move
// period-1 <- item-a
// period-2 <- item-b
// move item-b to period 1
// check its period is 1
static void
test_pfifo_item_move_bwd(void) {
  fprintf(stderr, "test_pfifo_item_move_bwd... \t\t");
  pfifo p;
  p = new_pfifo();

  datum item_a;
  item_a.junk = "ie6";
  datum item_b;
  item_b.junk = "svn";

  pfifo_period_t period;
  period = 10;

  pfifo_index_t loc_a;
  loc_a = pfifo_item_add(p, &item_a, period);

  pfifo_index_t loc_b;
  loc_b = pfifo_item_add(p, &item_b, period + 1);

  loc_b = pfifo_item_move(p, &item_b, loc_b, period);

  pfifo_period_t period_of_b;
  period_of_b = pfifo_period_get(p, loc_b);
  if (period_of_b != period) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item was not moved to the correct period. Expected %d, but got %d\n", (int)period, (int)period_of_b);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// pull item from pfifo, ensure NULL
static void
test_pfifo_item_next_empty(void) {
  fprintf(stderr, "test_pfifo_item_next_empty... \t\t");
  pfifo p;
  p = new_pfifo();

  datum* unsafe;
  unsafe = pfifo_item_next(p);

  if (unsafe != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Made a call to pfifo_item_head on an empty pfifo. Did not return NULL.\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// pull item from pfifo
static void
test_pfifo_item_next_single_period(void) {
  fprintf(stderr, "test_pfifo_item_next_single_period... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 1;

  /* Add items to the first period in the pfifo. */
  datum item_a;
  item_a.junk = "pascal";
  pfifo_item_add(p, &item_a, ptime);

  /* Extract item from pfifo. */
  datum* item_ap;
  item_ap = pfifo_item_next(p);

  /* Ensure data was preserved. */
  if ( strcmp(item_a.junk, item_ap->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected: %s, Got: %s\n", item_a.junk, item_ap->junk);
  } else {
    fprintf(stderr, "OK\n");
  }
  pfifo_free(p);
  return;
}


// pull all added items from pfifo in order
static void
test_pfifo_item_next_many_periods(void) {
  fprintf(stderr, "test_pfifo_item_next_many_periods... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 2;

  datum item_a;
  item_a.junk = "Item a";
  pfifo_item_add(p, &item_a, ptime);

  ptime = 3;
  datum item_b;
  item_b.junk = "Item b";
  pfifo_item_add(p, &item_b, ptime);

  datum* item_a_out;
  item_a_out = pfifo_item_next(p);
  if ( strcmp(item_a.junk, item_a_out->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "1. Expected: %s, Got: %s\n", item_a.junk, item_a_out->junk);
    pfifo_free(p);
    return;
  }

  datum* item_b_out;
  item_b_out = pfifo_item_head(p);
  if ( strcmp(item_b.junk, item_b_out->junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "2. Expected: %s, Got: %s\n", item_b.junk, item_b_out->junk);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// p1 <- item_a
// p2 <- item_b
// p3 <- item_c
// item_p = take(p3)
// check that item_a.junk == (*item_p).junk
static void
test_pfifo_take(void) {
  fprintf(stderr, "test_pfifo_take... \t\t\t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  /* Add items to the first period in the pfifo. */
  datum item_a;
  item_a.junk = "cats";
  pfifo_item_add(p, &item_a, ptime);
  ptime += 1;

  datum item_b;
  item_b.junk = "salad";
  pfifo_item_add(p, &item_b, ptime);
  ptime += 1;

  datum item_c;
  item_c.junk = "bluray";
  pfifo_item_add(p, &item_c, ptime);

  // NOIDEA what third arg does???
  datum* item_p;
  item_p = pfifo_take(p, ptime, true);

  if ( strcmp(item_p->junk, item_a.junk) != 0 ) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "1. Expected: %s, Got: %s\n", item_a.junk, item_p->junk);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Move items to the 'ex' period. pfifo_flush should return the
// address of the first item in 'ex' period.
static void
test_pfifo_flush(void) {
  fprintf(stderr, "test_pfifo_flush... \t\t\t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  /* Add items to the first period in the pfifo. */
  datum item_a;
  item_a.junk = "tires";
  pfifo_item_add(p, &item_a, ptime);

  datum* res;
  res = pfifo_flush(p);
  if (&item_a != res) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected pointer returned by pfifo_flush to be equal to the address of item_a\n");
    pfifo_free(p);
    return;
  }

  datum* head;
  head = pfifo_item_head(p);
  if (&item_a != head) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected pointer returned by pfifo_head to be equal to the address of item_a\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


static void
test_pfifo_flush_zero(void) {
  fprintf(stderr, "test_pfifo_flush_zero... \t\t");
  pfifo p;
  p = new_pfifo();

  datum* res;
  res = pfifo_flush(p);
  if (res != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected pointer returned by pfifo_flush to be NULL\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


static void
test_pfifo_flush_empty(void) {
  fprintf(stderr, "test_pfifo_flush_empty... \t\t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  /* Add items to the first period in the pfifo. */
  datum item_a;
  item_a.junk = "tires";
  pfifo_item_add(p, &item_a, ptime);

  datum* res;
  res = pfifo_flush_empty(p);
  if (&item_a != res) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected pointer returned by pfifo_flush_empty to be equal to the address of item_a\n");
    pfifo_free(p);
    return;
  }

  datum* head;
  head = pfifo_item_head(p);
  if (head != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected pointer returned by pfifo_head to be NULL\n");
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Get period of the first item in the pfifo. If nothing in the
// 'ex' list expect pn.
static void
test_pfifo_first_period_pn(void) {
  fprintf(stderr, "test_pfifo_first_period_pn... \t\t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  datum item_a;
  item_a.junk = "tires";
  pfifo_item_add(p, &item_a, ptime);

  pfifo_period_t restime;
  restime = pfifo_first_period(p);

  if (restime != ptime) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected period %d, but received %d.\n", (int)ptime, (int)restime);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Get period of the first item in the pfifo. If item exists in
// the 'ex' list expect p0 - 1 .
static void
test_pfifo_first_period_pn_m_one(void) {
  fprintf(stderr, "test_pfifo_first_period_pn_m_one... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  datum item_a;
  item_a.junk = "tires";
  pfifo_item_add(p, &item_a, ptime);

  datum item_b;
  item_b.junk = "roller blades";
  pfifo_item_add(p, &item_b, ptime+10);

  pfifo_take(p, ptime+10, true);

  pfifo_period_t restime;
  restime = pfifo_first_period(p);

  if (restime != (ptime+10-1)) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected period %d, but received %d.\n", (int)ptime, (int)restime);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Get first__period of an empty pfifo. Expecting to
// receive PFIFO_PERIOD_MAX or QTIME_PERIOD_MAX.
static void
test_pfifo_first_period_nobody(void) {
  fprintf(stderr, "test_pfifo_first_period_nobody... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  pfifo_period_t restime;
  restime = pfifo_first_period(p);

  if (restime != QTIME_PERIOD_MAX) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected period %d, but received %d.\n", (int)ptime, (int)restime);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Get period of the first item in the pfifo. Items in the 'ex'
// list are not considered.
static void
test_pfifo_first_not_ex_period(void) {
  fprintf(stderr, "test_pfifo_first_not_ex_period... \t");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  datum item_a;
  item_a.junk = "tires";
  pfifo_item_add(p, &item_a, ptime);

  datum item_b;
  item_b.junk = "roller blades";
  pfifo_item_add(p, &item_b, ptime+10);

  pfifo_take(p, ptime+10, true);

  pfifo_period_t restime;
  restime = pfifo_first_not_ex_period(p);

  if (restime != ptime+10) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected period %d, but received %d.\n", (int)(ptime+10), (int)restime);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


// Get first_not_ex_period of an empty pfifo. Expecting to
// receive PFIFO_PERIOD_MAX or QTIME_PERIOD_MAX.
static void
test_pfifo_first_not_ex_period_nobody(void) {
  fprintf(stderr, "test_pfifo_first_not_ex_period_nobody...");
  pfifo p;
  p = new_pfifo();

  pfifo_period_t ptime;
  ptime = 10;

  pfifo_period_t restime;
  restime = pfifo_first_not_ex_period(p);

  if (restime != QTIME_PERIOD_MAX) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Expected period %d, but received %d.\n", (int)(QTIME_PERIOD_MAX), (int)restime);
  } else {
    fprintf(stderr, "OK\n");
  }

  pfifo_free(p);
  return;
}


int
main(int argc, char* argv[]) {
  test_pfifo_item_head_empty();
  test_pfifo_item_head_single_period();
  test_pfifo_item_head_many_periods();

  test_pfifo_item_del();

  test_pfifo_item_move_fwd();
  test_pfifo_item_move_bwd();

  test_pfifo_item_next_empty();
  test_pfifo_item_next_single_period();
  test_pfifo_item_next_many_periods();

  test_pfifo_take();

  test_pfifo_flush();
  test_pfifo_flush_zero();

  test_pfifo_flush_empty();

  test_pfifo_first_period_pn();
  test_pfifo_first_period_pn_m_one();
  test_pfifo_first_period_nobody();

  test_pfifo_first_not_ex_period();
  test_pfifo_first_not_ex_period_nobody();
}
