/* Community attribute related functions. -- header
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
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
#ifndef _QUAGGA_BGP_COMMUNITY_H
#define _QUAGGA_BGP_COMMUNITY_H

#include "vhash.h"
#include "qlump.h"
#include "qstring.h"
#include "vty.h"

#include "bgpd/bgp_common.h"

/*==============================================================================
 * Community attributes comprise:
 *
 *   * a set of 32-bit "community" values
 *
 * The order of communities is not material, repeated communities are redundant.
 * So the canonical form of a community attribute has the attributes in order
 * and duplicates are dropped.
 *
 *
 * Operations on community attributes are:
 *

 *
 * The communities are held as a qlump of 4 byte entries, with an embedded body
 * of 10 entries, which is a bit of a guess.
 *
 * The qlump length is the length of the CLUSTER_LIST.
 */
typedef uint32_t community_t ;

enum { community_list_embedded_size = 6 } ;

enum attr_community_state
{
  cms_null           = 0,       /* no string, nothing known             */

  cms_no_export     = BIT(0),   /* if cms_known: BGP_ATT_COM_NO_EXPORT     */
  cms_no_advertise  = BIT(1),   /* if cms_known: BGP_ATT_COM_NO_ADVERTISE  */
  cms_local_as      = BIT(2),   /* if cms_known: BGP_ATT_COM_LOCAL_AS
                                 *    aka BGP_ATT_COM_NO_EXPORT_SUBCONFED  */

  cms_known         = BIT(4),

  cms_string        = BIT(5),   /* have 'str'                           */
  cms_text          = BIT(6),   /* have 'text_v' and 'text_form'        */
  cms_encoded       = BIT(7),   /* have 'enc'                           */

  cms_limit,
} ;
CONFIRM(cms_limit <= 256) ;

typedef byte attr_community_state_t ;

typedef       struct attr_community  attr_community_t ;
typedef       struct attr_community* attr_community ;
typedef const struct attr_community* attr_community_c ;

struct attr_community
{
  /* Red tape for storing community attributes
   */
  vhash_node_t vhash ;

  bool      stored ;

  /* State of attr_community
   */
  attr_community_state_t state ;

  /* String form of communities
   */
  qstring_t str ;               /* embedded qstring     */

  /* Encoded form of communities
   */
  qlump_t   enc ;               /* embedded qlump       */

  /* list qlump and embedded body
   *
   * The items in the list are community_t (uint32_t).  The list is held
   * in sorted order, with no duplicates.
   */
  qlump_t   list ;

  community_t  embedded_list[community_list_embedded_size] ;

  /* Text form of each community -- if required.
   *
   * Used when which to regex match to each community in turn.
   */
  vector    text_v ;
  qstring_t text_form ;         /* embedded qstring     */
} ;

CONFIRM(offsetof(attr_community_t, vhash) == 0) ;       /* see vhash.h  */

/*------------------------------------------------------------------------------
 * When parsing a list of communities, can accept the keywords 'none' and
 * 'additive' iff they appear at the end of the string, and this return value
 * signals the result.
 *
 * Can also accept 'any' and 'internet' iff they appear as the only item in
 * some strings.
 *
 * Can even accept a completely empty string !
 */
enum attr_community_type
{
  act_simple,           /* nothing special, not empty           */

  act_additive,         /* 'additive'                           */

  act_none,             /* 'none'                               */

  act_any,              /* 'any'                                */
  act_internet,         /* 'internet'                           */
  act_empty,            /* completely empty string              */

  act_invalid,          /* invalid string                       */
} ;

typedef enum attr_community_type attr_community_type_t ;

/*==============================================================================
 * Functions
 */
extern void attr_community_start(void) ;
extern void attr_community_finish(void) ;

extern attr_community attr_community_new(uint n) ;
extern attr_community attr_community_store(attr_community new) ;
extern attr_community attr_community_free(attr_community comm) ;
Inline void attr_community_lock(attr_community comm) ;
Inline attr_community attr_community_release(attr_community comm) ;

extern attr_community attr_community_set (const byte* p, uint count) ;
extern byte* attr_community_out_prepare(attr_community comm, uint* p_len) ;
extern attr_community attr_community_add_list (attr_community comm_a,
                                                        attr_community comm_b) ;
extern attr_community attr_community_replace_list (attr_community comm_a,
                                                        attr_community comm_b) ;
extern attr_community attr_community_del_value (attr_community comm,
                                                              community_t val) ;
extern attr_community attr_community_del_list (attr_community comm_a,
                                                        attr_community comm_b) ;
extern attr_community attr_community_drop_value (attr_community comm, uint ic) ;
extern attr_community attr_community_clear (attr_community comm) ;
extern attr_community_state_t attr_community_known (attr_community comm) ;
extern bool attr_community_match(attr_community_c comm_a,
                                                      attr_community_c comm_b) ;
extern bool attr_community_equal(attr_community_c comm_a,
                                                      attr_community_c comm_b) ;
extern const char* attr_community_str (attr_community comm) ;
extern attr_community attr_community_from_str (const char *str,
                                                   attr_community_type_t* act) ;
extern vector attr_community_text_vector(attr_community comm) ;

extern void attr_community_print_all_vty (struct vty *vty) ;

/*------------------------------------------------------------------------------
 * Functions to increase the reference count and to release an attr_community.
 */
Private vhash_table attr_community_vhash ;

/*------------------------------------------------------------------------------
 * Increase the reference count on the given attr_community
 *
 * NB: comm may NOT be NULL and MUST be stored
 */
Inline void
attr_community_lock(attr_community comm)
{
  qassert((comm != NULL) && (comm->stored)) ;

  vhash_inc_ref(comm) ;
} ;

/*------------------------------------------------------------------------------
 * Release the given attr_community (if any):
 *
 *   * do nothing if NULL
 *
 *   * if is stored, reduce the reference count.
 *
 *   * if is not stored, free it.
 *
 * Returns:  NULL
 */
Inline attr_community
attr_community_release(attr_community comm)
{
  if (comm != NULL)
    {
      if (comm->stored)
        vhash_dec_ref(comm, attr_community_vhash) ;
      else
        attr_community_free(comm) ;
    } ;

  return NULL ;
} ;

#endif /* _QUAGGA_BGP_COMMUNITY_H */
