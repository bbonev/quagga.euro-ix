#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "vhash.h"


// Ideal Struct? maybe...
struct datum {
  vhash_node node;
  vhash_data_c key;
  int value;
};


vhash_hash_t
hash_func(vhash_data_c data) {
  uint32 val;
  val = (uint32)data;
  val += 7;
  return (vhash_hash_t)val;
}

int
equal_func(vhash_item_c item, vhash_data_c data) {
  datum* i;
  i = (datum*)item;
  if (hash_func(i.value) == hash_func(data)) {
    return 0;
  }
  return -1;
}

vhash_item
new_func(vhash_table table, vhash_data_c data) {
  datum* i;
  i.key = data;
  return (vhash_item)i;
}

vhash_item
free_func(vhash_item item, vhash_table table) {
  return NULL
}

vhash_item
orphan_func(vhash_item item, vhash_table table) {
  return NULL
}


vhash_table
new_table() {
  vhash_params_c params;
  params.vhash_hash_func = &hash_func;
  params.vhash_equal_func = &equal_func;
  params.vhash_new_func = &new_func;
  params.vhash_free_func = &free_func;
  params.vhash_orphan_func = &orphan_func;

  vhash_table table;
  table = vhash_table_new(NULL, 512, 0, params);
  return table;
}


// test_vhash_lookup
// Add key and get item. Expect p_added to be true. Set value of
// item. Add duplicate item. Expect p_added to be false. Expect 
// value of item to be equal to set value.


// test_vhash_table_set_parent
// Create two vhash_tables. Set the parent of table_a to be
// table_b. Expect that vhash_get_parent( table_a ) returns 
// table_b.


// test_vhash_table_get_parent
// Create two vhash_tables. Expected that 
// vhash_get_parent( table_a ) returns NULL. Set the parent of
// table_a to be table_b. Expect vhash_get_parent( table_a )
// returns table_b.


// test_vhash_table_ream
// Create a table and add a value. Call vhash_table_ream. Expect
// vhash_table_lookup( value ) to be NULL.


// test_vhash_table_reset


// test_vhash_table_reset_bases


// test_vhash_unset


// test_vhash_unset_delete


// test_vhash_delete


// test_vhash_walk_start


// test_vhash_walk_next


// test_vhash_table_extract


int
main(int argc, char* argv[]) {
  fprintf(stderr, "test_vhash... \t\t");
}
