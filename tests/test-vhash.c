#include "misc.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "vhash.h"


//
vhash_hash_t
hash_func(vhash_data_c data) {

}

int
equal_func(vhash_item_c item, vhash_data_c data) {

}

vhash_item
new_func(vhash_table table, vhash_data_c data) {

}

vhash_item
free_func(vhash_item item, vhash_table table) {

}

vhash_item
orphan_func(vhash_item item, vhash_table table) {

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
