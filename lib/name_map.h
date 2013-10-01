/* Map value to name -- header
 * Copyright (C) 2011 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_NAME_MAP_H
#define _ZEBRA_NAME_MAP_H

#include "misc.h"
#include "qfstring.h"

/*==============================================================================
 * Name table definitions
 *
 * A name table maps an integer value to a name, with an option default for
 * unknown values.
 *
 * Three forms of name table are supported:
 *
 *   * direct   -- where the names are in an array indexed directly by value
 *
 *   * indirect -- where the name has to be searched for
 *
 *   * bits     -- where a bit significant value specifies a number of
 *                 names.
 *
 * Obviously, direct is more efficient, except where the value range is large,
 * or very sparse.
 */
QFB_T( 60) name_str_t ;         /* Reasonable size "name"               */
QFB_T(120) bits_str_t ;         /* Reasonable size "set of names"       */

/*------------------------------------------------------------------------------
 * Direct name table
 *
 * This comes in two parts, the "body", which is an array of pointers, and the
 * "map", which points at the body and also contains the default (if any) and
 * the number of entries in the body.
 *
 * The body may be constructed as any other array, for example:
 *
 *   const char* bgp_message_types_body[] =
 *   {
 *     [BGP_MT_OPEN]   = "OPEN",
 *     [BGP_MT_UPDATE] = "UPDATE",
 *     ...
 *   } ;
 *
 * NB: this means that any unspecified values will map to NULL.  Which implies
 *     that it is not possible to map to NULL, because that will map to the
 *     default !
 *
 * The map is most easily constructed using the direct_map macro, for example:
 *
 *   const map_direct_t bgp_message_types_map direct_map =
 *                         map_direct_s(bgp_message_types_body, "UNKNOWN(%d)") ;
 *
 * The map_direct function returns a name_str_t struct, with a .str entry,
 * so can be used:
 *
 *   fprintf("...BGP %s message...", ...,
 *                     map_direct(bgp_message_types_map, val).str, ...) ;
 *
 * If the val is not known, map_direct() will return the default which is
 * assumed to be a format string for sprintf(), with val as the only value
 * parameter.  If the map has no explicit default (NULL is given to the
 * direct_map() macro) then an empty string is returned !
 *
 * To allow for value ranges that include -ve numbers or start with large
 * values, a "min-value" may be specified.  So that:
 *
 *   const char* const foo_body[] =
 *   {
 *     [foo_val_a - foo_min]   = "A",
 *     [foo_val_b - foo_min]   = "B",
 *     ...
 *   } ;
 *
 *   const map_direct_t foo_map direct_map =
 *                          map_direct_min_s(foo_body, "UNKNOWN(%d)", foo_min) ;
 *
 * will work.
 */
typedef const struct map_direct
{
  const char* const* body ;
  const char* const deflt ;

  int   min_val ;
  int   count ;
} map_direct_t[] ;

typedef const struct map_direct* map_direct_p ;

#define map_direct_min_s(_body, _default, _min_val) \
  {{.body    = _body, \
    .deflt   = _default, \
    .min_val = _min_val, \
    .count   = sizeof(_body) / sizeof(char*), \
  }}

#define map_direct_s(_body, _default) map_direct_min_s(_body, _default, 0)

/*------------------------------------------------------------------------------
 * Indirect Map -- TBA
 */

/*------------------------------------------------------------------------------
 * Bits name table -- for sets of up to 64 bits.
 *
 * This is an array of map_bit_names_s structures:
 *
 *   uint64_t bits ; const char* "string" ;
 *
 * terminated by an entry with a 0 bits value.
 *
 * So can construct such a table:
 *
 * static const map_bit_names_s[] =
 * {
 *   { .bits = 0x55555, .str = "Ahha" },
 *   ....
 *   { 0 }
 * } ;
 */
typedef const struct map_bit_names map_bit_names_s ;

struct map_bit_names
{
  uint64_t    bits ;
  const char* str ;
} ;

/*------------------------------------------------------------------------------
 * Bits ordinal table -- for sets of up to 64 bits.
 *
 * This is an array of map_bit_ords_s structures:
 *
 *   uint64_t bits ; uint ord ;
 *
 * terminated by an entry with a 0 bits value.
 *
 * So can construct such a table:
 *
 * static const map_bit_ords_s[] =
 * {
 *   { .bits = 0x55555, .ord = 1 },
 *   ....
 *   { 0 }
 * } ;
 */
typedef const struct map_bit_ords map_bit_ords_s ;

struct map_bit_ords
{
  uint64_t  bits ;
  uint      ord ;
} ;

/*==============================================================================
 * Functions
 */
extern name_str_t map_direct(const map_direct_t map, int val) ;
extern name_str_t map_name_str(const char* name) ;
extern name_str_t map_name_str_val(const char* name, int val) ;

extern name_str_t map_direct_with_value(const map_direct_t map, int val) ;
extern const char* map_direct_known(const map_direct_t map, int val) ;

extern const char* map_bits_first(const map_bit_names_s* map, uint64_t* p_bits) ;
extern bits_str_t map_bits_all(const map_bit_names_s* map, uint64_t bits) ;

extern uint map_bit_ord_first(const map_bit_ords_s* map, uint64_t* p_bits) ;

#endif /* _ZEBRA_NAME_MAP_H */
