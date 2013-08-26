/* BGP ROUTE-REFRESH and ORF handling -- header
 * Copyright (C) Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_ROUTE_REFRESH_H
#define _QUAGGA_BGP_ROUTE_REFRESH_H

#include "lib/misc.h"
#include "bgpd/bgp_common.h"

#include "lib/prefix.h"
#include "lib/plist.h"

/*==============================================================================
 * Structures to hold ROUTE-REFRESH and ORF
 */
typedef struct bgp_orf_unknown_entry  bgp_orf_unknown_entry_t ;
typedef struct bgp_orf_unknown_entry* bgp_orf_unknown_entry ;

struct bgp_orf_unknown_entry
{
  bgp_size_t    length ;
  uint8_t       data[] ;
} ;

typedef struct bgp_orf_entry  bgp_orf_entry_t ;
typedef struct bgp_orf_entry* bgp_orf_entry ;

struct bgp_orf_entry
{
  uint8_t       orf_type ;      /* BGP_ORF_T_xxx -- _rfc version !      */

  bool          unknown ;       /* ignore everything other than the     */
                                /* unknown data part                    */

  bool          remove_all ;    /* rest is ignored if this is set       */

  bool          remove ;        /* otherwise: add                       */
  bool          deny ;          /* otherwise: permit                    */

  union {                       /* must be last...                      */
    orf_prefix_value_t       orfpv ;
    bgp_orf_unknown_entry_t  orf_unknown ;      /*... flexible array.   */
  } body ;
} ;

/* (The typedef is required to stop Eclipse (3.4.2 with CDT 5.0) whining
 *  about first argument of offsetof().)
 */
typedef struct bgp_orf_entry bgp_orf_entry_t ;
enum
{
  bgp_orf_unknown_min_l =   sizeof(bgp_orf_entry_t)
                          - offsetof(bgp_orf_entry_t, body.orf_unknown.data)
} ;

typedef struct bgp_route_refresh  bgp_route_refresh_t ;
typedef struct bgp_route_refresh* bgp_route_refresh ;

struct bgp_route_refresh
{
  bgp_route_refresh next ;      /* list of same                         */

  /* The address family -- both qafx and the Internet AFI/SAFI.
   *
   * May have any AFI/SAFI, so qafx may be qafx_other (or qafx_undef).
   */
  qafx_t        qafx ;

  iAFI_t        i_afi ;
  iSAFI_t       i_safi ;

  /* Any ORF required are stored here.
   */
  vector_t      entries[1] ;    /* empty => simple ROUTE-REFRESH        */

  bool          defer ;         /* otherwise: immediate                 */

  /* These support the output of ROUTE-REFRESH messages with ORF.
   *
   * These are zeroised when the bgp_route_refresh structure is created.
   */
  uint          next_index ;    /* next entry to process                */
  uint8_t       last_orf_type ; /* type of last ORF entry processed     */
} ;

/*==============================================================================
 * Prototypes
 */

extern bgp_route_refresh bgp_route_refresh_new(iAFI_t afi, iSAFI_t safi,
                                                                   uint count) ;
extern bgp_route_refresh bgp_route_refresh_free(bgp_route_refresh rr) ;
extern void bgp_route_refresh_set_orf_defer(bgp_route_refresh rr, bool defer) ;
extern bgp_orf_entry bgp_orf_add(bgp_route_refresh rr, uint8_t orf_type,
                                                       bool remove, bool deny) ;
extern void bgp_orf_add_remove_all(bgp_route_refresh rr, uint8_t orf_type);
extern void bgp_orf_add_unknown(bgp_route_refresh rr, uint8_t orf_type,
                                       bgp_size_t length, const void* entries) ;

Inline unsigned
bgp_orf_get_count(bgp_route_refresh rr)
{
  return vector_end(rr->entries) ;
} ;

Inline bgp_orf_entry
bgp_orf_get_entry(bgp_route_refresh rr, uint index)
{
  return vector_get_item(rr->entries, index) ;
} ;

#endif /* _QUAGGA_BGP_ROUTE_REFRESH_H */
