#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "vhash.h"

vhash_hash_t hash_func(vhash_data_c hash_key);
int equal_func(vhash_item_c item, vhash_data_c data);
vhash_item new_func(vhash_table table, vhash_data_c data);
vhash_item free_func(vhash_item item, vhash_table table);
vhash_item orphan_func(vhash_item item, vhash_table table);

// Ideal Struct? maybe...
struct datum {
  vhash_node node;
  vhash_hash_t key;
  int val;
};


vhash_hash_t
hash_func(vhash_data_c hash_key) {
  vhash_hash_t hash;
  hash = vhash_hash_string( (const char*)hash_key );
  return hash;
}

int
equal_func(vhash_item_c item, vhash_data_c data) {
  const struct datum* i;
  i = (const struct datum*)item;
  if (i->key == hash_func(data)) {
    return 0;
  }
  return -1;
}

vhash_item
new_func(vhash_table table, vhash_data_c data) {
  struct datum* i = malloc( sizeof(struct datum) );
  i->key = hash_func(data);
  i->val = -1;
  return (vhash_item)i;
}

vhash_item
free_func(vhash_item item, vhash_table table) {
  return NULL;
}

vhash_item
orphan_func(vhash_item item, vhash_table table) {
  return NULL;
}


static vhash_table
new_table() {
  vhash_params_t params;
  params.hash = &hash_func;
  params.equal = &equal_func;
  params.new = &new_func;
  params.free = &free_func;
  params.orphan = &orphan_func;

  vhash_table table;
  table = vhash_table_new(NULL, 512, 0, &params);
  return table;
}


// test_vhash_lookup
// Add key and get item. Expect p_added to be true. Set value of
// item. Add duplicate key. Expect p_added to be true. Expect 
// value of item to be equal to first item.
static void
test_vhash_lookup() {
  fprintf(stderr, "test_vhash_lookup... \t\t\t");
  vhash_table table;
  table = new_table();

  const vhash_data* key;
  key = (const vhash_data*)"3pin";

  vhash_item item;
  bool ok;
  item = vhash_lookup(table, key, &ok);
  
  if (ok != true) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Value wasn't added to vhash.\n");
    return;
  }
  if (item == NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was NULL.\n");
    return;
  }

  const vhash_data* dup_key;
  dup_key = (const vhash_data*)"3pin";

  vhash_item item2;
  bool ok2;
  item2 = vhash_lookup(table, dup_key, &ok2);

  if (ok != true) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Value wasn't added to vhash.\n");
    return;
  }
  if (item != item2) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was not item the expected.\n");
    return;
  }

  table = vhash_table_reset(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be de-allocated.\n");
    return;
  }
  fprintf(stderr, "OK\n");
  return;
}


// test_vhash_table_set_parent
// Create a vhash_table and a random ponter. Set the parent of
// table_a to be the pointer. Expect that 
// vhash_get_parent( table_a ) returns pointer to that pointer.
static void
test_vhash_table_set_parent() {
  fprintf(stderr, "test_vhash_table_set_parent... \t\t\t");
  vhash_table table;
  table = new_table();

  int i;
  i = 10000;
  vhash_table_set_parent(table, &i);

  void* j;
  j = vhash_table_get_parent(table);
  
  if (&i != j) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to return pointer to parent.\n");
    return;
  }

  table = vhash_table_reset(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be de-allocated.\n");
    return;
  }

  fprintf(stderr, "OK\n");
  return;
}


// test_vhash_table_get_parent
// Create a vhash_table and a random ponter. Expect that
// vhash_get_parent( table_a ) returns NULL. Set the parent of
// table_a to be the pointer. Expect that 
// vhash_get_parent( table_a ) returns that random pointer.
static void
test_vhash_table_get_parent() {
  fprintf(stderr, "test_vhash_table_get_parent... \t\t\t");
  vhash_table table;
  table = new_table();

  void* j;
  j = vhash_table_get_parent(table);
  if (j != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to return NULL pointer of unset parent.\n");
    return;
  }

  int i;
  i = 10000;
  vhash_table_set_parent(table, &i);
  
  j = vhash_table_get_parent(table);
  if (&i != j) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to return pointer to parent.\n");
    return;
  }

  table = vhash_table_reset(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be de-allocated.\n");
    return;
  }

  fprintf(stderr, "OK\n");
  return;
}


// test_vhash_table_ream
// Create a table and add a value. Call vhash_table_ream. Expect
// vhash_table_lookup( value ) to be NULL. Ensure table is not
// NULL.
static void
test_vhash_table_ream() {
  fprintf(stderr, "test_vhash_table_ream... \t\t\t");
  vhash_table table;
  table = new_table();

  const vhash_data* key;
  key = (const vhash_data*)"3pin";

  vhash_item item;
  bool ok;
  item = vhash_lookup(table, key, &ok);
  
  if (ok != true) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Value wasn't added to vhash.\n");
    return;
  }
  if (item == NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was NULL.\n");
    return;
  }

  vhash_table_ream(table);
  if (table == NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table was incorrectly set to NULL.\n");
    return;
  }

  item = vhash_lookup(table, key, &ok);
  if (item != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was not NULL.\n");
    return;
  }

  table = vhash_table_reset(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be de-allocated.\n");
    return;
  }

  fprintf(stderr, "OK\n");
  return;
}


//
// What are the chain bases in vhash?
//
// Diff between ream and reset just the de-allocation of mem. Y.
// + table now points to NULL. Expect vhash_table_lookup( val )
// is NULL.
// test_vhash_table_reset
static void
test_vhash_table_reset(void) {
  fprintf(stderr, "test_vhash_table_reset... \t\t\t");
  vhash_table table;
  table = new_table();

  const vhash_data* key;
  key = (const vhash_data*)"3pin";

  vhash_item item;
  bool ok;
  item = vhash_lookup(table, key, &ok);
  
  if (ok != true) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Value wasn't added to vhash.\n");
    return;
  }
  if (item == NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was NULL.\n");
    return;
  }

  item = vhash_lookup(table, key, &ok);
  if (item != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Item returned from vhash_lookup was not NULL.\n");
    return;
  }

  table = vhash_table_reset(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be deallocated and set to NULL.\n");
    return;
  }

  fprintf(stderr, "OK\n");
  return;
}

// Create a table. Ensure table != NULL. Then free table. Ensure
// table == NULL.
static void
test_vhash_table_free(void) {
  fprintf(stderr, "test_vhash_table_free... \t\t\t");
  vhash_table table;
  table = new_table();
  if (table == NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be allocated.\n");
    return;
  }

  table = vhash_table_free(table);
  if (table != NULL) {
    fprintf(stderr, "Failed\n");
    fprintf(stderr, "Table failed to be deallocated and set to NULL.\n");
    return;
  }

  fprintf(stderr, "OK\n");
  return;
}

// test_vhash_table_reset_bases


// test_vhash_unset
//
// If ref count is zero, run vhash_remove, else
// return pointer to item.
//
// - test_vhash_unset_ref_zero. expect NULL


// test_vhash_unset_delete
//
//


// test_vhash_delete


// test_vhash_walk_start


// test_vhash_walk_next


// test_vhash_table_extract


int
main(int argc, char* argv[]) {
  //test_vhash_lookup();
  //test_vhash_table_set_parent();
  //test_vhash_table_get_parent();
  //test_vhash_table_ream();
  //test_vhash_table_reset();
  test_vhash_table_free();
}
