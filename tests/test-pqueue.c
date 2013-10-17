/* Priority Queue
 * in_order - Added elements in order, assert removed in order.
 * randoms_in_order - Added random elements, assert removed in
 *   in order.
 * over_dequeue - Remove items from an empty queue. Assert -1 as
 *   a return value.
 */

#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pqueue.h"


static int
cmp (void* a, void* b)
{
  int* ai;
  int* bi;
  ai = (int*)a;
  bi = (int*)b;

  if (*ai >= *bi)
    return 1;
  else
    return -1;
}


static void
in_order(int data_size)
{
  fprintf(stderr, "in_order...\t");
  struct pqueue* q;
  q = pqueue_create();
  q->cmp = &cmp;

  // Initalize test_data
  int test_data[data_size];
  int i;
  for (i = 0; i < data_size; i++)
    {
      test_data[i] = i;
      if (q->size != i) {
	fprintf(stderr, "failed\n");
	return;
      }
      pqueue_enqueue(&test_data[i], q);
    }
  
  // Remove data from queue and ensure removed in proper order.
  for (i = 0; i < data_size; i++)
    {
      int* r;
      r = (int*)pqueue_dequeue(q);
      if (test_data[i] != *r) {
	fprintf(stderr, "failed\n");
	return;
      }
    }
    fprintf(stderr, "ok\n");
}


static void
randoms_in_order(int data_size)
{
  fprintf(stderr, "randoms_in_order...\t");
  struct pqueue* q;
  q = pqueue_create();
  q->cmp = &cmp;

  // Initalize test_data with pseudo-random ints.
  int test_data[data_size];
  int i;
  for (i = 0; i < data_size; i++)
    {
      test_data[i] = rand() % 4096;
      pqueue_enqueue(&test_data[i], q);
    }

  // Remove data from queue and ensure removed in proper order.
  int prev;
  prev = -1;
  for (i = 0; i < data_size; i++)
    {
      int* v;
      v = (int*)pqueue_dequeue(q);
      if (prev > *v) {
	fprintf(stderr, "failed\n");
	return;
      }
      prev = *v;
    }
  fprintf(stderr, "ok\n");
}


static void
over_dequeue(void)
{
  fprintf(stderr, "over_dequeue...\t");
  struct pqueue* q;
  q = pqueue_create();
  q->cmp = &cmp;

  int result;
  result = pqueue_dequeue(q);
  if (result != -1) {
    fprintf(stderr, "failed\n");
    return;
  }
  fprintf(stderr, "ok\n");
}


int
main(int argc, char* argv[]) {
  fprintf(stderr, "Starting Priority Queue Tests\n");

  in_order(100);
  randoms_in_order(5);
  over_dequeue();
}
