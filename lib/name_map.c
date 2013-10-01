/* Map value to name -- functions
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "misc.h"

#include "name_map.h"

/*==============================================================================
 * Direct Map
 */

/*------------------------------------------------------------------------------
 * Map given value to name, using a map_direct_t.
 */
extern name_str_t
map_direct(const map_direct_t map, int val)
{
  const char* name ;
  int         index ;

  name = NULL ;
  if ((val >= map->min_val) && ((index = val - map->min_val) < map->count))
    name = map->body[index] ;

  if ((name == NULL) && (map->deflt != NULL))
    return map_name_str_val(map->deflt, val) ;

  return map_name_str(name) ;
} ;

/*------------------------------------------------------------------------------
 * Make a name_str from the given string -- NULL gives an empty string
 */
extern name_str_t
map_name_str(const char* name)
{
  name_str_t QFB_QFS(st, qfs) ;

  qfs_put_str(qfs, name) ;
  qfs_term(qfs) ;

  return st ;
} ;

/*------------------------------------------------------------------------------
 * Make a name_str from the given string
 */
extern name_str_t
map_name_str_val(const char* name, int val)
{
  name_str_t QFB_QFS(st, qfs) ;

  if (name == NULL)
    name = "%d" ;

  qfs_printf(qfs, name, val) ;
  qfs_term(qfs) ;

  return st ;
} ;

/*------------------------------------------------------------------------------
 * Map given value to "name(val)" or to the default.
 *
 * Returns:  address of known name
 *       or: NULL -- name not known
 */
extern name_str_t
map_direct_with_value(const map_direct_t map, int val)
{
  const char* name ;
  int         index ;

  name_str_t QFB_QFS(st, qfs) ;

  name = NULL ;
  if ((val >= map->min_val) && ((index = val - map->min_val) < map->count))
    name = map->body[index] ;

  if (name == NULL)
    qfs_printf(qfs, "%s(%d)", name, val) ;
  else if (map->deflt != NULL)
    qfs_printf(qfs, map->deflt, val) ;

  qfs_term(qfs) ;

  return st ;
} ;

/*------------------------------------------------------------------------------
 * Map given value to name, using a map_direct_t, for known values only.
 *
 * Returns:  address of known name
 *       or: NULL -- name not known
 */
extern const char*
map_direct_known(const map_direct_t map, int val)
{
  int index ;

  if ((val >= map->min_val) && ((index = val - map->min_val) < map->count))
    return map->body[index] ;
  else
    return NULL ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Tiny test of map_direct()
 */

#include "stdio.h"

extern void test_map_direct(void) ;

const char* test_map_body[] =
{
  [ 1]  = "one",
  [10]  = "ten",

  [ 2]  = "two",
  [ 7]  = "seven",
} ;

const map_direct_t test_map = map_direct_s(test_map_body, "DEFAULT[%d]") ;

enum { mm = -3 } ;

const char* test_map_body_m[] =
{
  [ -2 - mm]  = "m2",
  [ -1 - mm]  = "m1",

  [  3 - mm]  = "three",
  [  5 - mm]  = "five",
} ;

const map_direct_t test_map_m = map_direct_min_s(test_map_body_m, NULL, mm) ;

extern void
test_map_direct(void)
{
  int i ;

  for (i = -2 ; i <= 12 ; ++i)
    fprintf(stdout, "Val=%3d  name='%s'\n", i, map_direct(test_map, i).str) ;

  for (i = -5 ; i <= 9 ; ++i)
    fprintf(stdout, "Val=%3d  name='%s'\n", i, map_direct(test_map_m, i).str) ;
} ;

#endif

/*==============================================================================
 * Bits map.
 *
 * The map is scanned from the start, looking for entries all of whose bits
 * match the given value.
 */

/*------------------------------------------------------------------------------
 * Scans the given map looking for the first entry all of whose bits are set
 * in the given value.
 *
 * If finds one, returns the string and unsets those bits.
 *
 * Otherwise, returns NULL.
 */
extern const char*
map_bits_first(const map_bit_names_s* map, uint64_t* p_bits)
{
  if (*p_bits != 0)
    {
      while (map->bits != 0)
        {
          if ((*p_bits & map->bits) == map->bits)
            {
              *p_bits ^= map->bits ;
              return map->str ;
            } ;

          map += 1 ;
        } ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Scans the given map looking for entries all of whose bits are set in the
 * given value.  When finds that, appends the name to the result, separated
 * from any previous name by " ", and removes the bits from the set being
 * considered.
 *
 * If ends up with unknown bits, appends a hex rendering of the remaining bits.
 */
extern bits_str_t
map_bits_all(const map_bit_names_s* map, uint64_t bits)
{
  bits_str_t QFB_QFS(st, qfs) ;

  while ((bits != 0) && (map->bits != 0))
    {
      if ((bits & map->bits) == map->bits)
        {
          bits ^= map->bits ;

          if (qfs->cp != 0)
            qfs_put_str(qfs, " ") ;

          qfs_put_str(qfs, map->str) ;
        } ;

      map += 1 ;
    } ;

  if (bits != 0)
    qfs_printf(qfs, "%s*unknown=0x%lx*", (qfs->cp != 0 ? " " : ""), bits) ;

  qfs_term(qfs) ;

  return st ;
}

/*------------------------------------------------------------------------------
 * Scans the given map looking for the first entry all of whose bits are set
 * in the given value.
 *
 * If finds one, returns the ordinal and unsets those bits.
 *
 * Otherwise, returns 0.
 */
extern uint
map_bit_ord_first(const map_bit_ords_s* map, uint64_t* p_bits)
{
  if (*p_bits != 0)
    {
      while (map->bits != 0)
        {
          if ((*p_bits & map->bits) == map->bits)
            {
              *p_bits ^= map->bits ;
              return map->ord ;
            } ;

          map += 1 ;
        } ;
    } ;

  return 0 ;
} ;
