/* BGP Extended Communities Attribute -- Header
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman (substantially rewritten)
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
#ifndef _QUAGGA_BGP_ECOMMUNITY_H
#define _QUAGGA_BGP_ECOMMUNITY_H

#include "misc.h"
#include "vhash.h"
#include "qlump.h"
#include "qstring.h"

#include "bgpd/bgp.h"

/*==============================================================================
 * Extended Community attributes comprise:
 *
 *   * a set of 8 byte "ecommunity" values
 *
 * The order of communities is not material, repeated communities are redundant.
 * So the canonical form of a ecommunity attribute has the attributes in order
 * and duplicates are dropped.
 *
 * The communities are held as a qlump of 8 byte entries, with an embedded body
 * of 10 entries, which is a bit of a guess.
 *
 * The 8 byte entry is kept in HOST order, as uint64_t -- so that comparisons
 * are as straightforward as possible.
 *
 * The qlump length is the length of the CLUSTER_LIST.
 */
typedef uint64_t ecommunity_t ;

enum { ecommunity_list_embedded_size = 6 } ;

enum attr_ecommunity_state
{
  ecms_null          = 0,        /* no string, nothing known     */

  ecms_string        = BIT(0),

  ecms_encoded       = BIT(4),

  ecms_limit,
} ;
CONFIRM(ecms_limit <= 256) ;

typedef byte attr_ecommunity_state_t ;

typedef       struct attr_ecommunity  attr_ecommunity_t ;
typedef       struct attr_ecommunity* attr_ecommunity ;
typedef const struct attr_ecommunity* attr_ecommunity_c ;

struct attr_ecommunity
{
  /* Red tape for storing ecommunity attributes
   */
  vhash_node_t vhash ;

  bool      stored ;

  /* State of attr_ecommunity
   */
  attr_ecommunity_state_t  state ;

  /* String form of communities
   */
  qstring_t str ;               /* embedded qstring     */

  /* Encoded form of communities -- everything and transitive only.
   */
  qlump_t enc ;                 /* embedded qlump       */
  qlump_t enc_trans ;           /* embedded qlump       */

  /* list qlump and embedded body
   *
   * The items in the list are ecommunity_t (uint32_t).  The list is held
   * in sorted order, with no duplicates.
   */
  qlump_t   list ;

  ecommunity_t  embedded_list[ecommunity_list_embedded_size] ;
} ;

CONFIRM(offsetof(attr_ecommunity_t, vhash) == 0) ;      /* see vhash.h  */

/*------------------------------------------------------------------------------
 * When converting to string form, output in one of three forms.
 *
 * See attr_ecommunity_to_str()
 */
enum ecommunity_format
{
  ECOMMUNITY_FORMAT_ROUTE_MAP,          /* no prefixes          */
  ECOMMUNITY_FORMAT_COMMUNITY_LIST,     /* "rt " and "soo "     */
  ECOMMUNITY_FORMAT_DISPLAY,            /* "RT:" and "SoO:"     */
} ;

typedef enum ecommunity_format ecommunity_format_t ;

/*==============================================================================
 * Functions
 */
extern void attr_ecommunity_start(void) ;
extern void attr_ecommunity_finish(void) ;

extern attr_ecommunity attr_ecommunity_new(uint n) ;
extern attr_ecommunity attr_ecommunity_free(attr_ecommunity ecomm) ;
extern attr_ecommunity attr_ecommunity_store(attr_ecommunity new) ;
Inline void attr_ecommunity_lock(attr_ecommunity ecomm) ;
Inline attr_ecommunity attr_ecommunity_release(attr_ecommunity ecomm) ;

extern attr_ecommunity attr_ecommunity_set (const byte* p, uint count) ;
extern byte* attr_ecommunity_out_prepare(attr_ecommunity ecomm, bool trans,
                                                                  uint* p_len) ;
extern attr_ecommunity attr_ecommunity_add_list (attr_ecommunity ecomm_a,
                                                      attr_ecommunity ecomm_b) ;
extern attr_ecommunity attr_ecommunity_replace_list (attr_ecommunity ecomm_a,
                                                      attr_ecommunity ecomm_b) ;
extern attr_ecommunity attr_ecommunity_del_list (attr_ecommunity ecomm_a,
                                                      attr_ecommunity ecomm_b) ;
extern attr_ecommunity attr_ecommunity_del_value(attr_ecommunity ecomm,
                                                             ecommunity_t val) ;
extern attr_ecommunity attr_ecommunity_drop_value(attr_ecommunity ecomm,
                                                                      uint ic) ;
extern attr_ecommunity attr_ecommunity_clear (attr_ecommunity ecomm) ;
extern bool attr_ecommunity_match(attr_ecommunity_c ecomm_a,
                                                    attr_ecommunity_c ecomm_b) ;
extern bool attr_ecommunity_equal(attr_ecommunity_c ecomm_a,
                                                    attr_ecommunity_c ecomm_b) ;
extern const char* attr_ecommunity_str (attr_ecommunity ecomm) ;
extern qstring attr_ecommunity_str_form(qstring qs, attr_ecommunity ecomm,
                                                   ecommunity_format_t format) ;
extern attr_ecommunity attr_ecommunity_from_str(const char *str,
                                               bool with_prefix, uint subtype) ;

extern void attr_ecommunity_print_all_vty (struct vty *vty) ;

/*------------------------------------------------------------------------------
 * Functions to increase the reference count and to release an attr_ecommunity.
 */
Private vhash_table attr_ecommunity_vhash ;

/*------------------------------------------------------------------------------
 * Increase the reference count on the given attr_ecommunity
 *
 * NB: ecomm may NOT be NULL and MUST be stored
 */
Inline void
attr_ecommunity_lock(attr_ecommunity ecomm)
{
  qassert((ecomm != NULL) && (ecomm->stored)) ;

  vhash_inc_ref(ecomm) ;
} ;

/*------------------------------------------------------------------------------
 * Release the given attr_ecommunity (if any):
 *
 *   * do nothing if NULL
 *
 *   * if is stored, reduce the reference count.
 *
 *   * if is not stored, free it.
 *
 * Returns:  NULL
 */
Inline attr_ecommunity
attr_ecommunity_release(attr_ecommunity ecomm)
{
  if (ecomm != NULL)
    {
      if (ecomm->stored)
        vhash_dec_ref(ecomm, attr_ecommunity_vhash) ;
      else
        attr_ecommunity_free(ecomm) ;
    } ;

  return NULL ;
} ;

#endif /* _QUAGGA_BGP_ECOMMUNITY_H */
