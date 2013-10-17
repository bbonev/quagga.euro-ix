/* AS path related definitions.
   Copyright (C) 1997, 98, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_ASPATH_H
#define _QUAGGA_BGP_ASPATH_H

#include "misc.h"

#include "bgpd/bgp_common.h"

#include "qlump.h"
#include "vty.h"
#include "vhash.h"

/*==============================================================================
 * as_path Structure and asp_item_t
 */
typedef       struct as_path  as_path_t ;
typedef       struct as_path* as_path ;
typedef const struct as_path* as_path_c ;

enum
{
  /* Co-opt the last BGP_AS_xxx type value as an invalid value
   */
  BGP_AS_SEG_INVALID = BGP_AS_SEG_MAX,

  /* The maximum supported count -- ludicrously large.
   */
  as_max_count      = 4000,

  /* A path length of 8 is quite a long path !  Especially as we squash
   * repeats to the equivalent of 2 ASN.  So we save a little malloc() effort
   * by embedding short (the vast majority) of as paths in the as_path
   * structure.
   */
  as_path_size_min   = 8,
} ;

CONFIRM((uint)BGP_AS_SET             != BGP_AS_SEG_INVALID) ;
CONFIRM((uint)BGP_AS_SEQUENCE        != BGP_AS_SEG_INVALID) ;
CONFIRM((uint)BGP_AS_CONFED_SEQUENCE != BGP_AS_SEG_INVALID) ;
CONFIRM((uint)BGP_AS_CONFED_SET      != BGP_AS_SEG_INVALID) ;

typedef byte as_seg_t ;

CONFIRM(BGP_AS_SEG_MAX <= 255) ;

enum qas_seg
{
  qAS_SEG_NULL   = 0,

  qAS_SET        = BIT(0),
  qAS_SEQUENCE   = BIT(1),

  qAS_CONFED     = BIT(2),

  qAS_CONFED_SEQUENCE = qAS_CONFED | qAS_SEQUENCE,
  qAS_CONFED_SET      = qAS_CONFED | qAS_SET,

  qAS_SET_START  = BIT(3),

  qAS_SEG_MAX    = BIT(4) - 1,
} ;

typedef uint16_t qas_seg_t ;
typedef uint16_t as_count_t ;

CONFIRM(qAS_SEG_MAX  <= UINT16_MAX) ;
CONFIRM(as_max_count <= UINT16_MAX) ;

/* Each asp_item_t
 *
 */
typedef struct asp_item  asp_item_t ;
typedef struct asp_item* asp_item ;

typedef uint64_t  asp_item_raw_t ;

struct asp_item
{
  as_t       asn ;
  as_count_t count ;            /* 0 <=> drop           */
  qas_seg_t  qseg ;
} ;

/* It is important that the asp_item_t structure has no holes in it,
 * because we create the hash for an as_path byte-wise.
 */
CONFIRM(sizeof(asp_item_t) == 8) ;
CONFIRM(sizeof(asp_item_t) == (sizeof(as_t) + sizeof(as_count_t)
                                            + sizeof(qas_seg_t))) ;

/* When an as_path is first created, it is in a "raw" state.  Changing an
 * as_path puts it back to its "raw" state.  In "raw" state:
 *
 *   * stored MUST be false -- cannot be stored in raw state, and cannot
 *                             be changed once has been stored.
 *
 *   * last_seg  -- always up to date
 *
 *   * everything other than end, size and path are indeterminate.
 *
 * In as_path_post_process() the state is changed to "processed", and all
 * values are filled in, except for:
 *
 *   * string
 *   * as_attr
 *   * as2_attr
 *   * as4_attr
 *
 * all of which are now invalid -- but memory may be present that may be
 * reused.
 *
 * In as_path_make_string(), as_path_make_as2() and as_path_make_as4() will
 * fill in the appropriate form, and update the state.
 */
enum asp_state
{
  asps_raw       = 0,

  asps_processed = BIT(0),

  asps_string    = BIT(1),      /* ignore if !asp_processed             */
  asps_as4_path  = BIT(3),      /* ditto                                */
  asps_as2_path  = BIT(2),      /* ditto                                */
  asps_as4_req   = BIT(4),      /* need to send an AS4_PATH
                                 * valid only if asps_as2_path is set   */
  asps_max,
} ;
CONFIRM(asps_max < 256) ;       /* fits in a byte               */

typedef enum asp_state asp_state_t ;

/*------------------------------------------------------------------------------
 * Properties as established in post-processing -- see as_path_post_process()
 */
typedef struct as_path_seg_properties as_path_seg_properties_t ;

struct as_path_seg_properties
{
  uint     length ;             /* contribution to AS Path Length       */

  uint     seq_count ;          /* number of sequences                  */
  uint     set_count ;          /* number of sets                       */

  as_seg_t first_seg ;          /* type of segment
                                 *     -- BGP_AS_SEG_NULL <=> none      */

  /* The 'first' offset points at the segment marker of the first segment
   * of this kind -- except where the first segment is BGP_AS_SEQUENCE and
   * the offset is zero, in which case there is no segment marker.
   *
   * The 'last' offset points at the first item (if there is one) after the
   * last item in the last segment of this kind.  So 'last' is zero if
   * first_seg == BGP_AS_SEG_NULL.
   */
  uint     first ;              /* start of first segment -- 0 if none  */
  uint     last ;               /* end + 1 of last segment-- 0 if none  */

  /* The 'first_asn' is the first ASN in the first AS_SEQUENCE/_CONFED_SEQUENCE
   * PROVIDED that is *not* preceded by an AS_SET/_CONFED_SET.
   *
   * This is used, for example, when checking for application of MED.
   *
   * NB: for simple stuff, if the first segment is an AS_SET, or there are no
   *     simple segments, then 'first_asn' is BGP_ASN_NULL.
   *
   *     If there are any Confed segments, then those are ignored as far as the
   *     'first_asn' of the simple segments is concerned.
   *
   * NB: for confed stuff, iff the first segment in the AS_PATH is
   *     AS_CONFED_SEQUENCE, then 'first_asn' is the first ASN in that segment.
   *     Otherwise the first_asn is BGP_ASN_NULL,
   *
   *     It is clear that Confed segments MUST be at the start of the AS_PATH.
   *     So, we do not set a 'first_asn' for confed stuff if the first confed
   *     segment comes after any simple segment(s).
   */
  as_t     first_asn ;
} ;

/* The 'left_most_asn' of an AS_PATH is:
 *
 *   first ASN in the first AS_SEQUENCE/_CONFED_SEQUENCE, PROVIDED that is the
 *   *first* segment.
 *
 * This is used, for example, when checking an AS_PATH for MED purposes.  For
 * MED purposes, any Confed stuff is ignored by default, but there is an
 * option to compare MEDs from Confed neighbors, which this supports.
 */
typedef struct as_path_properties as_path_properties_t ;

struct as_path_properties
{
  bool     simple_sequence ;    /* BGP_AS_SEQUENCE *only*, or empty     */

  uint     total_length ;       /* simple.length + confed.length        */
  as_t     left_most_asn ;      /* if have confed: confed.left_most_asn
                                 *           else: simple.left_most_asn */

  as_path_seg_properties_t simple ;     /* BGP_AS_SEQUENCE/_SET         */
  as_path_seg_properties_t confed ;     /* BGP_AS_CONFED_SEQUENCE/_SET  */
} ;

/*------------------------------------------------------------------------------
 * The structure itself
 */
struct as_path
{
  /* Red tape for storing as_path
   */
  vhash_node_t vhash ;

  bool      stored ;

  /* State of the as_path -- see above.
   */
  byte      state ;

  /* The type of the last segment in the path -- always up to date.
   *
   * An empty path is BGP_AS_SEG_NULL.
   */
//as_seg_t  last_seg ;

  /* Properties of the path, established by as_path_post_process()
   */
  as_path_properties_t  p ;

  /* String equivalent of the current path -- valid if asps_string
   */
  qstring_t   str ;             /* embedded qstring             */

  /* Encoded body of as_path, in two forms:
   *
   *   * as4  -- four octet AS_PATH, with confed (if any)
   *
   *             as4_off_simple gives offset of the first AS_SEQUENCE or
   *             AS_SET segment (if any)
   *
   *   * as2  -- two octet AS_PATH, with confed (if any)
   *
   *             as2_off_simple gives offset of the first AS_SEQUENCE or
   *             AS_SET segment (if any)
   */
  qlump_t     as4_form ;
  qlump_t     as2_form ;

  uint        as4_off_simple ;
  uint        as2_off_simple ;

  /* The mechanics for the body of the path
   */
  qlump_t     path ;

  asp_item_t  embedded_path[as_path_size_min] ;
} ;

CONFIRM(offsetof(as_path_t, vhash) == 0) ;      /* see vhash.h  */

/*------------------------------------------------------------------------------
 * A set of ASNs.
 *
 * Kept as a qlump of as_t values, sorted so can be searched by binary chop.
 */
typedef struct asn_set  asn_set_t ;

struct asn_set
{
  qlump_t     set ;

  bool        searchable ;

  asp_item_t  embedded_set[as_path_size_min] ;
} ;

/*------------------------------------------------------------------------------
 * Structure for constructing an AS_PATH or AS4_PATH
 */
typedef struct as_path_out  as_path_out_t ;
typedef struct as_path_out* as_path_out ;

struct as_path_out
{
  as_seg_t   seg ;

  uint       prepend_count ;
  as_t       prepend_asn[2] ;

  byte*      part[2] ;
  uint       len[2] ;

  /* buffer large enough for 3/4 bytes of attribute red tape, one segment
   * header followed by up to 2 ASN, and a further segment header.
   */
  byte       buf[4 + 2 + 4 + 4 + 2] ;
} ;

/*==============================================================================
 */
extern void as_path_start(void) ;
extern void as_path_finish(void) ;

extern as_path as_path_new(uint n) ;
extern as_path as_path_store(as_path asp) ;
extern as_path as_path_free(as_path asp) ;
Inline void as_path_lock(as_path asp) ;
Inline as_path as_path_release(as_path asp) ;

extern as_path as_path_parse(const byte* p, uint length, bool as4) ;
extern bool as_path_out_prepare(as_path_out out, as_path asp, bool as4) ;

extern uint as_path_count(void) ;
extern uint as_path_simple_path_length (as_path asp) ;
extern uint as_path_confed_path_length (as_path asp) ;
extern uint as_path_total_path_length (as_path asp) ;
extern as_t as_path_highest (as_path asp) ;
extern uint as_path_size (as_path asp) ;
extern bool as_path_loop_check (as_path asp, asn_t asn, uint threshold) ;
extern bool as_path_loop_check_not_confed (as_path asp, asn_t asn,
                                                               uint threshold) ;
extern bool as_path_private_as_check (as_path asp) ;
extern bool as_path_is_empty(as_path asp) ;
extern bool as_path_confed_ok(as_path asp) ;
extern as_t as_path_first_simple_asn(as_path asp) ;
extern as_t as_path_first_confed_asn(as_path asp) ;
extern as_t as_path_left_most_asn (as_path asp) ;
extern as_path as_path_confed_delete(as_path asp) ;
extern as_path as_path_confed_sweep(as_path asp) ;
extern as_path as_path_prepend_path (as_path a, as_path b) ;
extern as_path as_path_add_seq (as_path asp, as_t asn) ;
extern as_path as_path_add_confed_seq (as_path asp, asn_t asn) ;
extern as_path as_path_append_path (as_path a, as_path b) ;
extern as_path as_path_reconcile_as4 (as_path asp2, as_path asp4) ;
extern as_path as_path_aggregate (as_path a, as_path b) ;
extern as_path as_path_exclude_asns (as_path asp, asn_set asns) ;

extern as_path as_path_from_str(const char *str) ;
extern const char* as_path_str(as_path asp) ;

extern void as_path_print_all_vty (struct vty *vty) ;

extern asn_set asn_set_free(asn_set asns) ;
extern asn_set asn_set_add(asn_set asns, as_t asn) ;
extern bool asn_set_del(asn_set asns, as_t asn) ;
extern uint asn_set_get_len(asn_set asns) ;
extern as_t asn_set_get_asn(asn_set asns, uint index) ;
extern bool asn_set_contains(asn_set asns, as_t asn) ;
extern asn_set asn_set_from_str(const char* str) ;

extern as_path as_path_empty_asp ;

/* For SNMP BGP4PATHATTRASPATHSEGMENT
 */
#if 0
extern byte* as_path_snmp_pathseg (as_path asp, size_t* p_size);
#endif

/*------------------------------------------------------------------------------
 * Functions to increase the reference count and to release an as_path.
 */
Private vhash_table as_path_vhash ;

/*------------------------------------------------------------------------------
 * Increase the reference count on the given as_path
 *
 * NB: asp may NOT be NULL and MUST be stored
 */
Inline void
as_path_lock(as_path asp)
{
  qassert((asp != NULL) && (asp->stored)) ;

  vhash_inc_ref(asp) ;
} ;

/*------------------------------------------------------------------------------
 * Release the given as_path:
 *
 *   * if is stored, reduce the reference count.
 *
 *   * if is not stored, free it.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  NULL
 */
Inline as_path
as_path_release(as_path asp)
{
  qassert(asp != NULL) ;

  if (asp->stored)
    vhash_dec_ref(asp, as_path_vhash) ;
  else
    as_path_free(asp) ;

  return NULL ;
} ;

/*==============================================================================
 * Interfaces for test purposes only.
 */
extern void as_path_post_process_tx(as_path asp) ;
extern as_path as_path_prepend_tx(as_path asp, as_seg_t seg, as_t asn,
                                                                   uint count) ;
extern const char* as_path_check_valid_tx(as_path asp, bool set_last_seg,
                                                                   bool valid) ;

#endif /* _QUAGGA_BGP_ASPATH_H */
