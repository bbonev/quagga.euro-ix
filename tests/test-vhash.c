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
}


int
main(int argc, char* argv[]) {
  fprintf(stderr, "test_vhash... \t\t");
}
