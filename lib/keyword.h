/* Keyword Tables -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_KEYWORD_H
#define _ZEBRA_KEYWORD_H

#include "misc.h"
#include "vector.h"
#include "qlump.h"

/*==============================================================================
 * This is some very simple support for tables of keywords.
 *
 * A list of keywords can be compiled into an indexed form for moderately
 * rapid lookup.
 *
 * A keyword object is a structure which points to the null terminated string
 * which is the keyword, and has an unspecified value part.
 *
 * A compiled keyword table comprises:
 *
 *   * a vector of pointers to keyword objects, held in sorted order, so that
 *     can binary chop within it.
 *
 *   * a table mapping the first two characters of each keyword to a range
 *     of indexes unto the vector.
 *
 *   * a pointer to an original list of keywords (if any)
 *
 *   * other red-tape for the management of keyword tables.
 *
 *     In particular, state indicating whether need to compile the table,
 *     or not.
 *
 * The keyword table is designed to support:
 *
 *   * lookup of *partial* keywords -- which is why it is not implemented
 *     as a hash.
 *
 *   * the ability to return a pointer to a list of keywords which are
 *     partly matched to.
 *
 *   * building of keyword tables dynamically and statically (or a mixture).
 *
 *   * automatic compiling of a table when it is first used, or next used
 *     after a keyword has been added.
 *
 *   * sharing of keywords between tables -- so that can have tables with
 *     different subsets of some common pool of keywords.
 *
 * In general, the keyword objects will be const.
 */
typedef const struct keyword  keyword_t ;
typedef const struct keyword* keyword ;

typedef struct keyword keyword_s ;      /* in case want to build one    */

struct keyword
{
  const char*   word ;

  union
    {
      void*      v ;
      uintptr_t  u ;
      intptr_t   i ;
    } val ;
} ;

/* A keyword list is an array of keyword pointers, terminated by a NULL
 *
 * A list will usually be declared as:
 *
 *   static const keyword_list foo =
 *   {
 *     &kw1,
 *     &kw2,
 *     NULL
 *   } ;
 *
 * Where each keyword is declared as:
 *
 *   static keyword_t kw1 = { .word = "help", .val.u = 99 } ;
 */
typedef const keyword  keyword_list[] ;
typedef const keyword* keyword_list_p ;

/* A keyword table is the working structure
 */
typedef struct keyword_table  keyword_table_t ;
typedef struct keyword_table* keyword_table ;

/* The state of a Keyword Table
 */
enum keyword_table_state
{
  /* A keyword table is initialised "unset".
   *
   * Keywords may be added to the table, in which case it will change to
   * kwts_partial, and if there is a keyword list that is automatically added.
   *
   * The table may be used to look-up a keyword, in which case any keyword
   * list is automatically added to the table, and the table will be compiled.
   */
  kwts_unset    = 0,

  /* If a keyword is added to the table, it enters kwts_partial state.
   *
   * If the table was kwts_unset, any keyword_list will be added to the table
   * when it becomes kwts_partial.
   *
   * The table may be used to look-up a keyword, in which case the table is
   * compiled.
   */
  kwts_partial,

  /* Trying to look-up a keyword will cause it to be compiled, if it is not
   * already kwts_compiled.
   */
  kwts_compiled,
} ;

typedef enum keyword_table_state keyword_table_state_t ;

struct keyword_table
{
  /* Pointer to an (initial) list of keywords to be included in this table.
   *
   * A keyword table may be statically initialised to just this, and when the
   * table is first used, the working form will be compiled.
   *
   * May be NULL.
   */
  keyword_list_p  list ;

  /* State of the table.
   */
  keyword_table_state_t state ;

  /* Pointer to other compiled tables -- for shut-down
   */
  keyword_table   next ;

  /* The initial index -- first two characters of the keyword are the index
   * for this.
   */
  qlump_t         index ;

  /* The vector of pointers to all keywords
   */
  vector_t        words[1] ;
} ;

/*------------------------------------------------------------------------------
 * To construct a keyword table for use, typically need to:
 *
 *   * construct the keyword objects
 *
 *   * construct a list of keyword objects
 *
 *   * construct a keyword table to include that list
 *
 * eg:
 *
 *    static keyword_t kw_comm_internet =
 *                  { .word = "internet",     .val.u = 0          } ;
 *    static keyword_t kw_comm_no_export =
 *                  { .word = "no-export",    .val.u = 0xFFFFFF01 } ;
 *    static keyword_t kw_comm_no_advertise =
 *                  { .word = "no-advertise", .val.u = 0xFFFFFF02 } ;
 *    static keyword_t kw_comm_local_as =
 *                  { .word = "local-as",     .val.u = 0xFFFFFF03 } ;
 *
 *    static const keyword_list kw_comm_list =
 *    {
 *      &kw_comm_internet,
 *      &kw_comm_no_export,
 *      &kw_comm_no_advertise,
 *      &kw_comm_local_as,
 *      NULL
 *    } ;
 *
 *    static keyword_table_t kw_comm =
 *    {
 *      .list = kw_comm_list,
 *    } ;
 */

/*------------------------------------------------------------------------------
 * The keyword lookup assumes that keywords have been identified in some
 * way -- so that the lookup is given a complete word to find.
 *
 * To support a minimum of parsing, the keyword_scan() function can scan for
 * various termination conditions, to find the length of a keyword to be
 * looked up.
 */
enum keyword_term_type
{
  kwtt_ws,                      /* white-space                          */

  kwtt_punct,                   /* white-space + everything 0x21..0x7F
                                 * except 0..9, A..Z, a..z and '_'      */

  kwtt_punct_nh,                /* As kwtt_punct less '-'               */
} ;

typedef enum keyword_term_type keyword_term_type_t ;

/*==============================================================================
 * Functions
 */
extern keyword keyword_lookup(keyword_table table, const char* str, ulen len,
                                                                 uint* result) ;
extern ulen keyword_scan(const char* str, keyword_term_type_t term) ;

#endif /* _ZEBRA_KEYWORD_H */
