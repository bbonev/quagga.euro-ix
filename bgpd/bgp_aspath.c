/* AS path management routines.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2005 Sun Microsystems, Inc.
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

#include "misc.h"
#include "miyagi.h"
#include "memory.h"
#include "vhash.h"
#include "qlump.h"
#include "vector.h"

#include "log.h"
#include "stream.h"

#include "bgpd/bgp.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_debug.h"

/*==============================================================================
 * The basic AS_PATH is a (possibly empty) list of AS_PATH segments.  Most
 * AS_PATHS contain one, generally short, AS_SEQUENCE type segment.
 *
 * The as_path object contains an AS_PATH, plus:
 *
 *   * some properties of the path -- for quick reference
 *
 *   * encoded versions of the path -- so do not have to recreate for
 *     every UPDATE message.
 *
 *   * string version of the path -- for regex use etc.
 *
 * The body of the as_path object is intended for rapid scanning for ASN
 * and to provide a concise, canonical form of an AS_PATH:
 *
 *   * repeated ASN are compressed to a repeat count + ASN
 *
 *   * segment starts are embedded markers in the body of the as path, which
 *     is a simple vector of 32-bit values
 *
 *   * short AS_PATHs (after compression of repeats) are held inside the
 *     as_path object -- requiring no further memory to be allocated.
 *
 * A key operation on an as_path is the "post-processing", which (a) ensures
 * that the body of the path is in its canonical form, and (b) fills in the
 * properties of the path for future use.
 *
 * The encoded versions of the as_path and the string form are generated on
 * demand, and stored with the as_path.
 *
 * Confederation Segments
 * ----------------------
 *
 * If an AS_PATH contains Confederation segments, they can really only be
 * at the front of the AS_PATH.  RFC 5065 is quite strict:
 *
 *   a) MUST treat as invalid an AS_PATH containing Confed segments if the
 *      peer in not a member of the local confederation.
 *
 *      And, MUST NOT send Confed segments to a peer outside the local
 *      confederation.
 *
 *   b) MUST treat as invalid an AS_PATH received from a member of the local
 *      confederation in a different Member-AS, if that AS_PATH does NOT
 *      start with an AS_CONFED_SEQUENCE.
 *
 *      And, when sending UPDATE to a member of the local confederation in
 *      a different Member-AS, MUST send an AS_CONFED_SEQUENCE.
 *
 * This all implies that:
 *
 *   c) an AS_PATH starting AS_CONFED_SET can only come from a peer in the
 *      same Member-AS.
 *
 *      Actually, AS_CONFED_SET is pretty much an optional item... but we need
 *      to cope.
 *
 *   d) an AS_PATH with Confederation segments anywhere other than at the
 *      beginning is a big mistake.
 *
 * The as_path code generally assumes these rules, and where it copes with
 * misplaced Confed stuff, it may either discard it or treat it as an error.
 *
 * Empty as_path
 * -------------
 *
 * For some attributes, a NULL is equivalent to an empty or absent attribute.
 *
 * For the as_path attribute, an empty as_path object is created, stored and
 * set "owned" early in the morning, and is used when an empty as_path is
 * required (available as the extern as_path_empty_asp).
 */

/*------------------------------------------------------------------------------
 * The body of an as_path is a qlump -- which is an array of asp_item_t values
 */
static const qlump_type_t as_path_body_qt[1] =
{
  { .alloc        = qlump_alloc,
    .free         = qlump_free,

    .unit         = sizeof(asp_item_t),

    .size_add     = 8,
    .size_unit_m1 = 4 - 1,              /* 16 byte boundaries   */

    .size_min     = 20,                 /* if have to allocate  */

    .size_min_unit_m1 = 1 - 1,          /*  4 byte boundaries   */

    .embedded_size   = as_path_size_min,
    .embedded_offset = qlump_embedded_offset(as_path_t, path, embedded_path),

    .size_term    = 0,
  }
} ;

/*------------------------------------------------------------------------------
 * Map BGP_AS_XXX value to qAS_SEG_XXXX -- for start of set if is set.
 */
inline static qas_seg_t
qas_seg_start(as_seg_t seg)
{
  switch (seg)
    {
      case BGP_AS_SEQUENCE:
        return qAS_SEQUENCE ;

      case BGP_AS_SET:
        return qAS_SET | qAS_SET_START ;

      case BGP_AS_CONFED_SEQUENCE:
        return qAS_CONFED_SEQUENCE ;

      case BGP_AS_CONFED_SET:
        return qAS_CONFED_SET | qAS_SET_START ;

      default:
        return qAS_SEG_NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Map qAS_SEG_XXXX to BGP_AS_XXXX
 */
inline static as_seg_t
as_seg_type(qas_seg_t qseg)
{
  switch (qseg)
    {
      case qAS_SEQUENCE:
        return BGP_AS_SEQUENCE ;

      case qAS_SET:
      case qAS_SET | qAS_SET_START:
        return BGP_AS_SET ;

      case qAS_CONFED_SEQUENCE:
        return BGP_AS_CONFED_SEQUENCE ;

      case qAS_CONFED_SET:
      case qAS_CONFED_SET | qAS_SET_START:
        return BGP_AS_CONFED_SET ;

      default:
        return BGP_AS_SEG_NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return:  n * sizeof(asp_item_t)
 */
inline static size_t
sizeof_asp_items(uint n)
{
  return n * sizeof(asp_item_t) ;
} ;

/*------------------------------------------------------------------------------
 * Storing an as_path
 *
 * Note that an "orphan" function is not required because there is only one
 * as_path_vhash, which we set to NULL if/when the table is reset and freed.
 */
vhash_table as_path_vhash ;             /* Private in bgp_aspath.h      */

as_path as_path_empty_asp ;             /* the shared empty as_path     */

static vhash_hash_t as_path_hash(vhash_data_c data) ;
static int          as_path_equal(vhash_item_c item, vhash_data_c data) ;
static vhash_item   as_path_vhash_new(vhash_table table, vhash_data_c data) ;
static vhash_item   as_path_vhash_free(vhash_item item, vhash_table table) ;

static const vhash_params_t as_path_vhash_params =
{
    .hash   = as_path_hash,
    .equal  = as_path_equal,
    .new    = as_path_vhash_new,
    .free   = as_path_vhash_free,
    .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * The pre formed AS_PATH attributes are held as qlumps
 */
static const qlump_type_t as_path_enc_qt[1] =
{
  { .alloc       = qlump_alloc,
    .free        = qlump_free,

    .unit         = 1,                  /* bytes                */

    .size_add     = 16,
    .size_unit_m1 = 4 - 1,              /* 16 byte boundaries   */

    .size_min     = 16,

    .size_min_unit_m1 = 1 - 1,          /*  4 byte boundaries   */

    .embedded_size   = 0,
    .embedded_offset = 0,

    .size_term    = 0,
  }
} ;

/*------------------------------------------------------------------------------
 * Sets of ASN are held as qlumps.
 */
static const qlump_type_t asn_set_body_qt[1] =
{
  { .alloc       = qlump_alloc,
    .free        = qlump_free,

    .unit         = sizeof(as_t),

    .size_add     = 8,
    .size_unit_m1 = 4 - 1,              /* 16 byte boundaries   */

    .size_min     = 20,                 /* if have to allocate  */

    .size_min_unit_m1 = 1 - 1,          /*  4 byte boundaries   */

    .embedded_size   = as_path_size_min,
    .embedded_offset = qlump_embedded_offset(asn_set_t, set, embedded_set),

    .size_term    = 0,
  }
} ;

/*------------------------------------------------------------------------------
 * Creates and uses this stream structure in as_path_snmp_pathseg().
 * Frees it in as_path_finish().
 */
struct stream* snmp_stream = NULL ;

/*==============================================================================
 * The stored as_path functions.
 */
inline static asp_item_t* as_path_get_processed(as_path asp) ;

/*------------------------------------------------------------------------------
 * Start-up initialisation of the as_path handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 */
extern void
as_path_start(void)
{
  as_path_vhash = vhash_table_new(NULL, 1000 /* chain bases */,
                                         200 /* % density   */,
                                                        &as_path_vhash_params) ;
  qlump_register_type(MTYPE_AS_PATH_BODY, as_path_body_qt,
                                                       false /* not a test */) ;
  qlump_register_type(MTYPE_AS_PATH_ENC, as_path_enc_qt,
                                                       false /* not a test */) ;
  qlump_register_type(MTYPE_ASN_SET_BODY, asn_set_body_qt,
                                                       false /* not a test */) ;

  as_path_empty_asp = as_path_store(as_path_new(0)) ;

  vhash_set(as_path_empty_asp) ;
  vhash_dec_ref(as_path_empty_asp, as_path_vhash) ;
} ;

/*------------------------------------------------------------------------------
 * Close down the as_path handling
 *
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored as_paths.  That should be achieved naturally when all routes are
 * dismantled -- which should have been done before this is called.
 *
 * If any stored as_paths remain, they may be unlocked, but will not be freed.
 */
extern void
as_path_finish(void)
{
  snmp_stream = stream_free(snmp_stream) ;

  as_path_empty_asp = vhash_unset_delete(as_path_empty_asp, as_path_vhash) ;

  as_path_vhash = vhash_table_reset(as_path_vhash, free_it) ;
} ;

/*------------------------------------------------------------------------------
 * Get -- from the vhash table -- the number of known AS_PATHs
 */
extern uint
as_path_count(void)
{
  return as_path_vhash->entry_count ;
} ;

/*------------------------------------------------------------------------------
 * Either store the given as_path, or free it and return existing stored value.
 *
 * Increment reference count.
 *
 * NB: storing may discard the given as_path altogether, which will discard
 *     the string form and all other cached stuff.
 *
 *     Even if the given as_path does not exist, and so is the one to be
 *     stored, the string form and other cached stuff may be moved to new
 *     memory -- so no pointers to that cached stuff can be depended on.
 *
 *     Once an as_path is stored, the cached stuff is stable (once created),
 *     so pointers to it are dependable, while there is a lock on the stored
 *     value.
 */
extern as_path
as_path_store(as_path new)
{
  as_path asp ;
  bool added ;

  qassert(!new->stored && (new->vhash.ref_count == 0)) ;

  as_path_get_processed(new) ;          /* ensure canonical     */

  added = false ;
  asp = vhash_lookup(as_path_vhash, new, &added) ;

  if (added)
    {
      qassert(asp == new) ;

      asp->stored = true ;

      qlump_store(&asp->path) ;
      qs_store(asp->str) ;

      qlump_store(&asp->as4_form) ;
      qlump_store(&asp->as2_form) ;
    }
  else
    {
      /* Found the same as_path -- so discard the current "new" one.
       */
      qassert(asp->stored) ;

      as_path_free(new) ;
    } ;

  vhash_inc_ref(asp) ;

  return asp ;
} ;

/*------------------------------------------------------------------------------
 * Generate hash for given as_path 'data' -- vhash call-back
 *
 * For the as_path vhash the 'data' is a new (not-stored) as_path
 */
static vhash_hash_t
as_path_hash(vhash_data_c data)
{
  as_path_c new = data ;

  qassert(!new->stored) ;

  return vhash_hash_bytes(new->path.body.b, sizeof_asp_items(new->path.len)) ;
} ;

/*------------------------------------------------------------------------------
 * Is the 'item's 'data' the same as the given 'data' -- vhash call-back
 *
 * For the as_path vhash: the 'item' is an as_path, stored in the vhash
 *
 *                        the 'data' is a new (not-stored) as_path
 */
static int
as_path_equal(vhash_item_c item, vhash_data_c data)
{
  as_path_c asp = item ;
  as_path_c new = data ;

  qassert(asp->stored && !new->stored) ;

  if (asp->path.len != new->path.len)
    return 1 ;

  return memcmp(asp->path.body.b, new->path.body.v,
                                              sizeof_asp_items(new->path.len)) ;
} ;

/*------------------------------------------------------------------------------
 * "Create" new item for as_path vhash -- vhash call-back
 *
 * For the as_path vhash: the 'data' is a new (not-stored) as_path, so this
 * is trivial.
 */
static vhash_item
as_path_vhash_new(vhash_table table, vhash_data_c data)
{
  as_path  new = miyagi(data) ;

  qassert(!new->stored) ;

  return (vhash_item)new ;
} ;

/*------------------------------------------------------------------------------
 * Free item which is being removed from the vhash -- vhash call-back
 *
 * For the as_path vhash: the 'item' is a stored as_path
 *
 * Returns:  NULL <=> the item has been freed
 */
static vhash_item
as_path_vhash_free(vhash_item item, vhash_table table)
{
  as_path asp = item ;

  qassert(asp->stored) ;

  asp->stored = false ;                 /* no longer stored     */

  return as_path_free(asp) ;
} ;

/*==============================================================================
 * The basic as_path object functions
 */

/*------------------------------------------------------------------------------
 * Need a total of 'n' items in the as_path -- extend if required.
 *
 * Return (new) address of body.
 */
inline static asp_item_t*
as_path_need(as_path asp, ulen n)
{
  if (n > asp->path.size)
    return qlump_extend(&asp->path, n, MTYPE_AS_PATH_BODY) ;

  return asp->path.body.v ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, and empty as_path.
 *
 * If have an idea of how many ASN there will be -- then will allocate for that.
 */
extern as_path
as_path_new(uint n)
{
  as_path new ;

  new = XCALLOC(MTYPE_AS_PATH, sizeof(as_path_t)) ;

  /* Zeroizing has set:
   *
   *    * vhash           -- initialised
   *
   *    * stored          -- false
   *
   *    * state           -- asps_raw
   *
   *    * last_seg        -- BGP_AS_SEG_NULL
   *
   *    * p               -- X     -- not valid until asps_processed
   *
   *    * str             -- X     -- initialised below
   *
   *    * as4_form        -- X     -- initialised below
   *    * as2_form        -- X     -- initialised below
   *
   *    * path            -- X     -- initialised below
   *
   *    * embedded_path   -- all zeros - not that this matters
   */
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  confirm(asps_raw == 0) ;
  confirm(BGP_AS_SEG_NULL == 0) ;

  qs_init_new(new->str, 0) ;

  qlump_init(&new->as4_form,  0, MTYPE_AS_PATH_ENC) ;
  qlump_init(&new->as2_form,  0, MTYPE_AS_PATH_ENC) ;

  qlump_init(&new->path, n, MTYPE_AS_PATH_BODY) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Create a new as_path, which is a copy of an existing one.
 *
 * The new path will have enough room for the given number of extra items,
 * and that extra space can come before or after the original content.
 *
 * The 'before' argument true <=> place non-zero extra space before the
 * existing content.
 *
 * Sets the length of the new path to be the length of the src + any 'extra'.
 *
 * If 'extra' == 0, copies the properties of the path, ie:
 *
 *   * src->state   -- but only the asps_processed state
 *
 *   * src->p       -- if asps_processed
 *
 * Otherwise, sets src->state = asps_raw.
 *
 * Returns: address of new as_path.
 */
static as_path
as_path_copy(as_path_c src, uint extra, bool before)
{
  as_path  dst ;
  uint     slen ;

  slen = src->path.len ;

  dst = as_path_new(slen + extra) ;
  dst->path.len = slen + extra ;

  if (extra == 0)
    if ((dst->state = src->state & asps_processed))
      dst->p = src->p ;

  if (slen != 0)
    {
      asp_item_t* dst_ptr ;

      dst_ptr = dst->path.body.v ;

      if (before)
        dst_ptr += extra ;      /* extra (if any) at the front  */

      memcpy(dst_ptr, src->path.body.v, sizeof_asp_items(slen)) ;
    } ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Free given as_path and any allocated body and other dependent data.
 */
extern as_path
as_path_free(as_path asp)
{
  if (asp != NULL)
    {
      qassert(asp->vhash.ref_count == 0) ;      /* always               */
      qassert(!asp->stored) ;                   /* always               */

      qs_reset(asp->str, keep_it) ;             /* embedded qstring     */

      qlump_free_body(&asp->as4_form) ;
      qlump_free_body(&asp->as2_form) ;
      qlump_free_body(&asp->path) ;

      XFREE(MTYPE_AS_PATH, asp) ;
    } ;

  return NULL ;
} ;

/*==============================================================================
 * The main attribute in and out functions
 */
static bool as_path_encode(qlump enc, as_path asp, bool as4,
                                                           uint* p_off_simple) ;
inline static uint as_path_encode_prepend(byte* pp, uint lp, as_seg_t seg,
                      uint len, bool as4, as_t* pre, uint n, bool* p_as_trans) ;
inline static uint as_path_encode_segment(qlump enc, uint eseg, uint elen,
                                                 uint seg_count, uint asn_len) ;
static uint as_path_encode_fixup(qlump enc, uint eseg, uint elen,
                                              uint* p_seg_count, uint asn_len) ;

/*------------------------------------------------------------------------------
 * AS path parse function -- parses AS_PATH and AS4_PATH attributes
 *
 * Requires: p      -- byte pointer, currently positioned before first segment
 *                     of AS_PATH or AS4_PATH (ie after attribute header)
 *           length -- length of the value of the AS_PATH or AS4_PATH
 *           as4    -- true <=> 4Byte ASN, otherwise 2Byte ASN
 *
 * Returns: if valid: address of a new as_path
 *              else: NULL
 *
 * NB: empty AS path (length == 0) is valid, and an empty as_path is returned.
 *
 * Rejects stuff which is badly formed at the "lexical" level:
 *
 *   * rejects zero length segments
 *
 *   * rejects segments which over-run the end of the attribute
 *
 *   * rejects an attribute with an incomplete segment at the end
 *
 *   * rejects ASN == 0 (per draft-ietf-idr-as0)
 *
 *   * rejects any segment types we don't recognise.  Assume that any new
 *     segment types will be the subject of a capability !
 *
 * Does not check any semantic things -- such as the validity of Confed
 * segments.
 *
 * Will combine contiguous BGP_AS_SEQUENCE segments with each other without
 * worrying about their lengths.  Similarly BGP_AS_CONFED_SEQUENCE segments.
 *
 * Will NOT combine contiguous BGP_AS_SET segments.  Nor BGP_AS_CONFED_SET
 * segments.  This is because each set makes a contribution to the AS_PATH
 * length.
 */
extern as_path
as_path_parse(const byte* p, uint length, bool as4)
{
  as_path     asp ;
  as_t        prev_asn ;
  qas_seg_t   prev_qseg ;
  uint        plen ;
  uint        left ;
  asp_item_t* path ;

  /* Create a new path -- the guess of number of ASN will be almost exact if
   * the path is a simple BGP_AS_SEQUENCE.
   */
  asp = as_path_new(length / (as4 ? 4 : 2)) ;

  /* Crunch the segments.
   *
   * At the top of the loop, the length is the number of bytes of attribute
   * left, and the stream is positioned at the start of a segment.
   */
  prev_asn  = BGP_ASN_NULL ;
  prev_qseg = qAS_SEG_NULL ;

  path = asp->path.body.v ;
  plen = 0 ;

  left = length ;
  while (left >= BGP_ATT_ASPS_MIN_L)
    {
      uint seg_length, seg_size ;
      qas_seg_t   qseg ;

      /* softly softly, get the header first on its own
       */
      qseg       = qas_seg_start(*p++) ;
      seg_length = *p++ ;

      confirm(BGP_ATT_ASPS_MIN_L >= 2) ;

      /* Check that the segment type and length is valid
       *
       * RFC4271 4.3, Path Attributes, b) AS_PATH:
       *
       *   "path segment value field contains one or more AS numbers"
       */
      if (qseg == qAS_SEG_NULL)
        break ;

      if (seg_length == 0)
        break ;

      seg_size = BGP_ATT_ASPS_MIN_L + (seg_length * (as4 ? 4 : 2)) ;
                            /* includes the segment type and length red tape  */

      if (seg_size > left)
        break ;

      /* Can now eat what we have.
       *
       * Note that although all the checking of plen against psize looks like
       * hard work, for most simple AS_PATHs -- which we expect will fit into
       * the embedded path -- plen is always < psize.  For slightly longer
       * AS_PATHS, the first allocation should do the job.
       *
       * The loop works the way it does, so that spots repeats and only
       * allocates space for the compressed path.
       */
      left -= seg_size ;

      if (qseg != prev_qseg)
        {
          /* We keep the prev_qseg as the qseg less the qAS_SET_START,
           * so each time we get a set segment we reset prev_asn.
           */
          prev_asn = BGP_ASN_NULL ;

          prev_qseg = qseg & ~qAS_SET_START ;
        } ;

      while (seg_length--)
        {
          /* Proceed to fetch the asn from the attribute and insert into the
           * path, compressing out repeated ASN and deal with escaping ASN
           * if required.
           *
           * Also, per draft-ietf-idr-as0, reject path with an ASN == 0 in it !
           */
          as_t asn ;

          if (as4)
            {
              asn = load_nl(p) ;
              p  += 4 ;
            }
          else
            {
              asn = load_ns(p) ;
              p  += 2 ;
            } ;

          if (asn == BGP_ASN_NULL)
            return as_path_free(asp) ;

          confirm(BGP_ASN_NULL == 0) ;

          if (asn == prev_asn)
            {
              /* We have a repeat -- ignore if in set, or repeat at maximum !
               */
              if (!(qseg & qAS_SET) && (path[plen - 1].count < as_max_count))
                path[plen - 1].count += 1 ;
            }
          else
            {
              /* Not a repeat
               */
              prev_asn = asn ;

              if (plen >= asp->path.size)
                path = as_path_need(asp, plen + 1) ;

              path[plen].asn   = asn ;
              path[plen].count = 1 ;
              path[plen].qseg  = qseg ;

              plen += 1 ;
            } ;

          qseg &= ~qAS_SET_START ;
        } ;
    } ;

  asp->path.len = plen ;

  /* If we appear here with left != 0, we have a broken attribute
   */
  if (left == 0)
    return asp ;
  else
    return as_path_free(asp) ;
} ;

/*------------------------------------------------------------------------------
 * Prepare as_path_out -- in 2 or 4 octet form, with given prepend, if any.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * The out->seg value specifies what to with the front of the
 * AS_PATH/AS4_PATH:
 *
 *   * BGP_AS_SEG_NULL        => preserve any leading CONFED stuff.
 *                            => no prepend (ignores out->prepend_count)
 *
 *   * BGP_AS_SEQUENCE        => strip any leading CONFED stuff.
 *                            => prepend 0, 1 or 2 ASN, per out->prepend_count,
 *                               as a BGP_AS_SEQUENCE.
 *
 *   * BGP_AS_CONFED_SEQUENCE => preserve any leading CONFED stuff.
 *                            => prepend 0, 1 or 2 ASN, per out->prepend_count,
 *                               as a BGP_AS_CONFED_SEQUENCE.
 *
 * Returns:  true <=> was AS2 form and needs an AS4_PATH
 *                    ie. had to substitute ASN_TRANS at least once in
 *                        an AS_SEQUENCE or AS_SET.
 */
extern bool
as_path_out_prepare(as_path_out out, as_path asp, bool as4)
{
  qlump enc ;
  uint  len, lp, lb, off_simple, pc, ss ;
  as_t* pre ;
  byte* pp, * pb ;

  bool as_trans ;

  /* First, construct the AS4 or AS2 encoded form of the as_path, if required.
   */
  as_path_get_processed(asp) ;

  if (as4)
    {
      enc = &asp->as4_form ;

      if (!(asp->state & asps_as4_path))
        {
          as_path_encode(enc, asp, true /* as4 */, &asp->as4_off_simple) ;
          asp->state |= asps_as4_path ;

          if (asp->stored)
            qlump_store(enc) ;
        } ;

      off_simple = asp->as4_off_simple ;
      as_trans = false ;
    }
  else
    {
      enc = &asp->as2_form ;

      if (!(asp->state & asps_as2_path))
        {
          as_trans = as_path_encode(enc, asp, false /* as2 */,
                                                    &asp->as2_off_simple) ;
          asp->state |= asps_as2_path ;

          if (asp->stored)
            qlump_store(enc) ;

          if (as_trans)
            asp->state |= asps_as4_req ;
        } ;

      off_simple = asp->as2_off_simple ;
      as_trans = (asp->state & asps_as4_req) ;
    } ;

  /* Now construct the red-tape for the attribute, and prepend up to two ASN,
   * stripping any confed stuff if required.
   *
   * We have:  pp = pointer to "prepend" -- the attribute red tape and
   *                                        any prepended stuff
   *           lp = length of that
   *
   *           pb = pointer to body of encoded as_path -- this is stuff which
   *                is prepared and stored in the as_path.
   *
   *           lb = length of that
   */
  pp  = out->buf + 4 ;
  lp  = 0 ;

  pb  = enc->body.v ;
  lb  = enc->len ;

  switch (out->seg)
    {
      default:
        qassert(false) ;
        fall_through ;

      /* Prepending nothing => sending the as_path as is.
       */
      case BGP_AS_SEG_NULL:
        break ;

      /* Prepending an AS_SEQUENCE => stripping any confed stuff, first.
       *
       * Steps the pb and lb past to the start of the "simple" stuff.
       */
      case BGP_AS_SEQUENCE:
        pb  += off_simple ;
        lb  -= off_simple ;

        fall_through ;

      /* Prepending an AS_SEQUENCE or AS_CONFED_SEQUENCE, most likely by
       * extending the first segment (replacing its red tape), but by inserting
       * a new segment if possible.
       *
       * This does not touch the *read-only* pre-encoded body, but adjusts
       * pb/lb and adds stuff to pp/lp.
       *
       * Note that we end up doing nothing at all if the prepend_count == 0.
       *
       * So: pc = count of ASN (left) to prepend
       *     ss = spare space at the front of the current first segment, if any
       *          and if is of the required type.
       */
      case BGP_AS_CONFED_SEQUENCE:
        pc = out->prepend_count ;

        if (pc == 0)
          break ;

        pre = out->prepend_asn ;

        if ((lb == 0) || (pb[0] != out->seg))
          ss = 0 ;
        else
          ss = (uint)255 - pb[1] ;

        if (ss < pc)
          {
            /* Does not all fit at the front of the current first segment.
             */
            uint sc ;                   /* count of ASN in new segment  */

            sc = pc - ss ;
            lp = as_path_encode_prepend(pp, lp, out->seg, sc, as4, pre, sc,
                                                                    &as_trans) ;
            if (pc == sc)
              break ;

            pc  -= sc ;                 /* account for what we prepended
                                         * as a new segment.            */
            pre += sc ;
          } ;

        /* Fit (what remains of) prepend at front of current first segment,
         * stepping past the pre-built segment prefix, and inserting a new
         * one in the prepend buffer.
         */
        qassert(pb[0] == out->seg) ;
        qassert((pb[1] + pc) <= 255) ;

        lp = as_path_encode_prepend(pp, lp, out->seg, pb[1] + pc, as4, pre, pc,
                                                                    &as_trans) ;

        pb += 2 ;               /* Discard segment prefix       */
        lb -= 2 ;

        break ;
    } ;

  qassert((pp + lp) <= (out->buf + sizeof(out->buf))) ;

  /* Add the Attribute Red-Tape to the front of the buffer and set the
   * pointers/lengths of the two parts.
   */
  len = lp + lb ;

  if (len <= 255)
    {
      pp -= 3 ;
      lp += 3 ;

      pp[0] = BGP_ATF_TRANSITIVE ;
      pp[2] = len ;
    }
  else
    {
      pp -= 4 ;
      lp += 4 ;

      pp[0] = BGP_ATF_TRANSITIVE | BGP_ATF_EXTENDED;
      store_ns(&pp[2], len) ;
    } ;

  pp[1] = BGP_ATT_AS_PATH ;

  out->part[0] = pp ;
  out->len[0]  = lp ;
  out->part[1] = pb ;
  out->len[1]  = lb ;

  return as_trans ;
} ;

/*------------------------------------------------------------------------------
 * Construct the given encoded form of the given as_path.
 *
 * If is 'as4', produces encoded AS_PATH with 4 octet ASN -- returns false.
 *
 * Otherwise, produces encoded AS_PATH with 2 octet ASN -- returns true iff
 * has to render an ASN as AS_TRANS, ie there is an ASN > 65535 in the path.
 *
 * If the as_path is empty, sets the given enc empty.
 *
 * NB: requires the given as_Path to have been processed.
 *
 * NB: although Confed stuff which is not at the start of the AS_PATH is not
 *     really valid, this function encodes the as_path as given.
 *
 * NB: in the unlikely event of having more than 255 ASN in a segment of a
 *     given type, creates physical segments with the short one (if any)
 *     *first* -- so that can prepend most simply at the physical encoding
 *     level.
 *
 * NB: when preparing an AS2 encoded path, does NOT sort and dedup BGP_AS_SET
 *     or BGP_AS_CONFED_SET when an ASN is replaced by BGP_ASN_TRANS.
 *
 *     This is not simply laziness -- though it does save a little extra code.
 *
 *     Sorting and dedupping a set in these circumstances is to throw away a
 *     small amount of information.  The receiver may (well) do do in any case,
 *     but that's their decision, not ours.
 */
static bool
as_path_encode(qlump enc, as_path asp, bool as4, uint* p_off_simple)
{
  asp_item_t* path ;
  uint        ptr, len ;
  ulen        elen, eseg, asn_len, off_simple ;
  uint        seg_count ;
  qas_seg_t   qseg ;
  bool        as4_trans ;
  bool        done_simple ;
  byte*       ebuf ;

  qassert(asp->state & asps_processed) ;

  as4_trans = false ;
  asn_len  = as4 ? 4 : 2 ;

  /* Start with a guess as to the encoded length, which is going to be OK
   * for confed sequence (if any) followed by simple sequence.
   *
   * The guess will be zero if the asp is empty.
   */
  elen = (asp->p.confed.length * asn_len) + 2
       + (asp->p.simple.length * asn_len) + 2 ;

  if (elen >= enc->size)
    qlump_extend(enc, elen, MTYPE_AS_PATH_ENC) ;

  elen  = 0 ;
  ebuf = enc->body.v ;

  /* Process the path into encoded form
   */
  path = asp->path.body.v ;
  len  = asp->path.len ;

  qseg        = qAS_SEG_NULL ;
  seg_count   = 0 ;             /* nothing in the segment, yet          */
  done_simple = false ;         /* no simple segments, yet              */
  eseg        = 0 ;             /* start of first segment               */
  off_simple  = 0 ;

  for (ptr = 0 ; ptr < len ; ptr++)
    {
      as_t        asn ;
      uint        count ;

      count = path[ptr].count ;
      asn   = path[ptr].asn ;

      if ((count == 0) || (asn == BGP_ASN_NULL))
        {
          /* A count of zero means the item has been dropped.  BGP_ASN_NULL
           * is meaningless.  Do not expect to find these, but do not want to
           * be tripped up !
           *
           * The only tricky bit is that if this is the start of set segment,
           * and we are currently in a set segment, then we need to terminate
           * the current set.
           */
          if ((qseg & qAS_SET) && (qseg != path[ptr].qseg))
            qseg = qAS_SEG_NULL ;

          continue ;
        } ;

      if (path[ptr].qseg != qseg)
        {
          /* We have a new segment type, so finish off any existing segment,
           * and prepare for the next type.
           *
           * NB: the as_Path is in canonical form, so all segment starts
           *     should be converted to encoded segments.
           */
          uint need ;

          if (seg_count != 0)
            {
              elen = as_path_encode_segment(enc, eseg, elen, seg_count,
                                                                      asn_len) ;
              ebuf = enc->body.v ;
            } ;

          /* qseg_prev is set to the aAS_SEG_XXX value, less the start of
           * segment bit -- so all items in the same set end up in the same
           * segment, but the next set value with the start bit set will start
           * another segment.
           */
          qseg = path[ptr].qseg & ~qAS_SET_START ;

          /* Start new segment
           */
          eseg = elen ;

          if (!done_simple && !(qseg & qAS_CONFED))
            {
              done_simple = true ;
              off_simple  = eseg ;
            } ;

          need = elen + 2 + (asn_len * count) ;

          if (need > enc->size)
             ebuf = qlump_extend(enc, need, MTYPE_AS_PATH_ENC) ;

          ebuf[eseg + 0] = as_seg_type(qseg) ;
          ebuf[eseg + 1] = 0 ;

          elen = eseg + 2 ;

          seg_count = count ;
        }
      else
        {
          uint need ;

          need = elen + (asn_len * count) ;

          if (need > enc->size)
            ebuf = qlump_extend(enc, need, MTYPE_AS_PATH_ENC) ;

          seg_count += count ;
        } ;

      /* We have an ASN, which may be repeated.
       */
      if (as4)
        {
          do
            {
              store_nl(&ebuf[elen], asn) ;
              elen += 4 ;
            }
          while (--count) ;
        }
      else
        {
          if (asn > BGP_AS2_MAX)
            {
              if (done_simple)
                as4_trans = true ;              /* in non-confed part   */

              asn = BGP_ASN_TRANS ;
            } ;

          do
            {
              store_ns(&ebuf[elen], asn) ;
              elen += 2 ;
            }
          while (--count) ;
        } ;
    } ;

  /* Finish off the last segment -- will be one, unless path is empty
   */
  if (seg_count != 0)
    elen = as_path_encode_segment(enc, eseg, elen, seg_count, asn_len) ;

  assert(elen <= enc->size) ;

  enc->len = elen ;

  *p_off_simple = done_simple ? off_simple : elen ;
  return as4_trans ;
} ;

/*------------------------------------------------------------------------------
 * Add segment to the prepend buffer.
 *
 *   * pp is address of buffer and lp is the current length/pointer in that
 *
 *     returns updated lp.
 *
 *   * as4 true <=> 4 byte ASN
 *
 *   * seg and len are the segment types length (including the stuff is
 *     about to prepend)
 *
 *   * pre is address of first ASN to prepend and n is the number to process
 *
 *   * if is not as4, and seg is BGP_AS_SEQUENCE, set *p_as_trans if have to
 *     translate any ASN.
 */
inline static uint
as_path_encode_prepend(byte* pp, uint lp, as_seg_t seg, uint len, bool as4,
                                            as_t* pre, uint n, bool* p_as_trans)
{
  uint i ;

  pp[lp++] = seg ;              /* new segment red tape */
  pp[lp++] = len ;

  for (i = 0 ; i < n ; ++i)
    {
      as_t asn ;

      asn = pre[i] ;

      if (as4)
        {
          store_nl(&pp[lp], asn) ;
          lp += 4 ;
        }
      else
        {
          if (asn > BGP_AS2_MAX)
            {
              if (seg == BGP_AS_SEQUENCE)
                *p_as_trans = true ;
              asn = BGP_ASN_TRANS ;
            } ;
          store_ns(&pp[lp], asn) ;
          lp += 2 ;
        } ;
    } ;

  return lp ;
} ;

/*------------------------------------------------------------------------------
 * Finish off current segment by writing away the segment length.
 *
 * If the segment length is > 255, fix-up the encoding so that we have the
 * (minimum) number of segments required, arranging for the first segment to
 * be the short one (if they are not all 255 ASN long).
 *
 * Returns:  the (new) length of the encoding
 *
 * NB: If the length of the encoding changes, then the enc->body may *also*
 *     change.
 *
 *     The length of the encoding only changes if the segment is > 255 ASN.
 */
inline static uint
as_path_encode_segment(qlump enc, uint eseg, uint elen,
                                                   uint seg_count, uint asn_len)
{
  byte* ebuf ;

  qassert((eseg + 2) < elen) ;
  qassert((elen - eseg - 2) == (seg_count * asn_len)) ;
  qassert(elen <= enc->size) ;

  if (seg_count > 255)
    elen = as_path_encode_fixup(enc, eseg, elen, &seg_count, asn_len) ;

  qassert(seg_count != 0) ;

  ebuf = enc->body.v ;
  ebuf[eseg + 1] = seg_count ;

  return elen ;
} ;

/*------------------------------------------------------------------------------
 * Fix-up encoding of a segment with more than 255 items in it.
 *
 * This is a largely theoretical possibility, which is why we assume the simple
 * case and fix-up afterwards.
 *
 * We want the minimum number of physical segments.  At least for the leading
 * AS_SEQUENCE or AS_CONFED_SEQUENCE, we want the *first* segment to contain
 * all the "spare space".
 *
 * Updates the elen to reflect the extra segment starts required.
 *
 * Returns:  (new) address of the buffer
 */
static uint
as_path_encode_fixup(qlump enc, uint eseg, uint elen,
                                                uint* p_seg_count, uint asn_len)
{
  byte*  ebuf ;
  uint   extra_segs ;
  uint   ep, eq ;

  extra_segs = (*p_seg_count - 1) / 255 ;

  eq    = elen ;                        /* current end          */
  elen += (extra_segs * 2) ;            /* new end              */

  *p_seg_count -= (extra_segs * 255) ;  /* remaining count      */

  if (elen > enc->size)
    ebuf = qlump_extend(enc, elen, MTYPE_AS_PATH_ENC) ;
  else
    ebuf = enc->body.v ;

  ep = elen ;
  while (extra_segs--)
    {
      /* Step back one tranche of 255 ASN, and move them up into place.
       */
      eq -= 255 * asn_len ;
      ep -= 255 * asn_len ;

      memmove(ebuf + ep, ebuf + eq, 255 * asn_len) ;

      /* Insert start of full physical segment
       */
      ep -= 2 ;

      ebuf[ep + 0] = ebuf[eseg] ;
      ebuf[ep + 1] = 255 ;
    } ;

  qassert(ep == eq) ;
  qassert(eseg == (ep - (*p_seg_count * asn_len) - 2)) ;
  qassert(*p_seg_count <= 255) ;

  return elen ;
} ;

/*==============================================================================
 * Functions to get information about a given as_path
 */

/*------------------------------------------------------------------------------
 * Get AS_PATH length of any simple segments
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * ie: count of all ASN's in all BGP_AS_SEQUENCE segments (including any
 *     repeats) plus the number of BGP_AS_SET segments.
 *
 *     So... ignores any Confed stuff.
 */
extern uint
as_path_simple_path_length (as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.simple.length ;
} ;

/*------------------------------------------------------------------------------
 * Get AS_PATH length of any confed segments
 *
 * This may be used to check for the presence of any Confed stuff in the
 * as_path.  This does not check that all the Confed segments are leading
 * segments.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * ie: count of all ASN's in all BGP_AS_CONFED_SEQUENCE segments (including any
 *     repeats) plus the number of BGP_AS_CONFED_SET segments.
 *
 *     So... ignores any "simple" stuff.
 */
extern uint
as_path_confed_path_length (as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.confed.length ;
} ;

/*------------------------------------------------------------------------------
 * Get AS_PATH length, including segments of all types.
 *
 * NB: NULL asp is invalid -- will crash !
 */
extern uint
as_path_total_path_length (as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.total_length ;
} ;

/*------------------------------------------------------------------------------
 * Return highest public ASN in path
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * This is a rare operation -- so we don't keep track of this.
 */
extern as_t
as_path_highest (as_path asp)
{
  asp_item_t* path ;
  uint ptr, len ;
  as_t highest ;

  path = asp->path.body.v ;
  len  = asp->path.len ;

  highest = 0 ;
  for (ptr = 0 ; ptr < len ; ++ptr)
    {
      if (path[ptr].asn > highest)
        highest = path[ptr].asn ;
    } ;

  return highest ;
} ;

/*------------------------------------------------------------------------------
 * Return encoded size of as_path -- assuming AS4
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Not actually required to provide an exact answer, but may as well encode
 * in AS4 form.
 */
extern uint
as_path_size (as_path asp)
{
  as_path_get_processed(asp) ;

  if (!(asp->state & asps_as4_path))
    {
      as_path_encode(&asp->as4_form, asp, true /* as4 */,
                                                        &asp->as4_off_simple) ;
      asp->state |= asps_as4_path ;
    } ;

  return asp->as4_form.len ;
} ;

/*------------------------------------------------------------------------------
 * AS path loop check.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Count number of times given ASN appears in the AS_PATH, and return false
 * if that count exceeds the given threshold.
 *
 * Returns:  true <=> given ASN does NOT appear in the AS_PATH
 *                    or appears <= threshold times
 *
 * IE: returns true <=> path is OK.
 *
 * NB: will not find BGP_ASN_NULL -- not even if there are asp_drop items in
 *     the as_path !
 */
extern bool
as_path_loop_check (as_path asp, asn_t asn, uint threshold)
{
  asp_item_t* path ;
  uint ptr, len ;

  /* We don't need the AS_PATH to be post-processed for this.
   */
  path = asp->path.body.v ;
  len  = asp->path.len ;

  for (ptr = 0 ; ptr < len ; ++ptr)
    {
      if (path[ptr].asn == asn)
        {
          /* The count is the number of times the ASN should appear.  A
           * zero count means that the ASN has been dropped, and the item
           * will be ignored !
           *
           * Threshold == 0 means that if the ASN appears 1 or more times,
           * the check must return false.
           *
           * So... threshold < count should return false, and will that unless
           *                                           the asn is BGP_ASN_NULL.
           */
          if (threshold < path[ptr].count)
            return (asn == BGP_ASN_NULL) ;

          threshold -= path[ptr].count ;        /* update threshold     */
        } ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * AS path loop check -- ignoring any Confed Stuff.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Count number of times given ASN appears in the AS_PATH, ignoring Confed
 * segments, and return false if that count exceeds the given threshold.
 *
 * Returns:  true <=> given ASN does NOT appear in the AS_PATH
 *                    or appears <= threshold times
 *
 * IE: returns true <=> path is OK.
 *
 * NB: will not find BGP_ASN_NULL -- not even if there are asp_drop items in
 *     the as_path !
 */
extern bool
as_path_loop_check_not_confed (as_path asp, asn_t asn, uint threshold)
{
  asp_item_t* path ;
  uint ptr, len ;

  /* We don't need the AS_PATH to be post-processed for this.
   */
  path = asp->path.body.v ;
  len  = asp->path.len ;

  for (ptr = 0 ; ptr < len ; ++ptr)
    {
      if ((path[ptr].asn == asn) && !(path[ptr].qseg & qAS_CONFED))
        {
          /* The count is the number of times the ASN should appear.  A
           * zero count means that the ASN has been dropped, and the item
           * will be ignored !
           *
           * Threshold == 0 means that if the ASN appears 1 or more times,
           * the check must return false.
           *
           * So... threshold < count should return false, and will that unless
           *                                           the asn is BGP_ASN_NULL.
           */
          if (threshold < path[ptr].count)
            return (asn == BGP_ASN_NULL) ;

          threshold -= path[ptr].count ;        /* update threshold     */
        } ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Return:  true <=> as_path is not empty, and all the ASN in it are private ASN
 *
 * NB: NULL asp is invalid -- will crash !
 */
extern bool
as_path_private_as_check (as_path asp)
{
  asp_item_t* path ;
  uint ptr, len ;

  as_path_get_processed(asp) ;

  path = asp->path.body.v ;
  len  = asp->path.len ;

  for (ptr = 0 ; ptr < len ; ++ptr)
    {
      as_t asn ;

      asn = path[ptr].asn ;

      if (asn < BGP_ASN_PRIV_MIN)
        return false ;

      if (asn > BGP_ASN_PRIV_MAX)
        return false ;
    } ;

  return (len != 0) ;
} ;

/*------------------------------------------------------------------------------
 * Is given as_path completely empty ?
 *
 * NB: NULL asp is invalid -- will crash !
 */
extern bool
as_path_is_empty(as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->path.len == 0 ;
} ;

/*------------------------------------------------------------------------------
 * Is the given as_path OK from a Confed Stuff perspective ?
 *
 * Returns:  true <=> there is no Confed Stuff
 *                    or there is and it is all at the front of the as_path.
 *           false => there is Confed stuff, and some part of it is after
 *                    some other sort of segment.
 *
 * NB: NULL asp is invalid -- will crash !
 */
inline static bool
as_path_confed_ok_test(as_path asp)
{
  qassert(asp->state & asps_processed) ;

  return (asp->p.confed.last <= asp->p.simple.first)
                                                 || (asp->p.simple.last == 0) ;
} ;

/*------------------------------------------------------------------------------
 * Is the given as_path OK from a Confed Stuff perspective ?
 *
 * Returns:  true <=> there is no Confed Stuff
 *                    or there is and it is all at the front of the as_path.
 *           false => there is Confed stuff, and some part of it is after
 *                    some other sort of segment.
 *
 * NB: NULL asp is invalid -- will crash !
 */
extern bool
as_path_confed_ok(as_path asp)
{
  as_path_get_processed(asp) ;

  if (qdebug)
    {
      if (asp->p.confed.first_seg == BGP_AS_SEG_NULL)
        qassert((asp->p.confed.last == 0) && (asp->p.confed.first == 0)) ;
      else
        qassert(asp->p.confed.last != 0) ;

      if (asp->p.simple.first_seg == BGP_AS_SEG_NULL)
        qassert((asp->p.simple.last == 0) && (asp->p.simple.first == 0)) ;
      else
        qassert(asp->p.simple.last != 0) ;
    } ;

  return as_path_confed_ok_test(asp) ;
} ;

/*------------------------------------------------------------------------------
 * Return first simple ASN -- ignoring any leading Confed segments.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  iff the first segment is BGP_AS_SEQUENCE (ignoring any Confed),
 *           returns the first ASN of that segment.
 *
 *           otherwise: returns BGP_ASN_NULL
 *
 *           (so, if the AS_PATH is empty, or if the first segment is
 *            BGP_AS_SET (ignoring any Confed), returns BGP_ASN_NULL)
 */
extern as_t
as_path_first_simple_asn(as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.simple.first_asn ;
} ;

/*------------------------------------------------------------------------------
 * Return first confed ASN -- of any leading confed segments.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  iff the first segment is BGP_AS_CONFED_SEQUENCE,
 *           returns the first ASN of that segment.
 *
 *           otherwise: returns BGP_ASN_NULL.
 *
 *           (so, if the first segment is BGP_AS_CONFED_SET,
 *            returns BGP_ASN_NULL)
 *
 * NB: confed stuff should only appear at the front of an AS_PATH.  If the
 *     first Confed segment is a BGP_AS_CONFED_SEQUENCE, but it comes after
 *     a BGP_AS_SEQUENCE/_SET, then it is ignored for these purposes.
 */
extern as_t as_path_first_confed_asn(as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.confed.first_asn ;
} ;

/*------------------------------------------------------------------------------
 * Return left_most ASN -- the first of either BGP_AS_SEQUENCE or
 *                                             BGP_AS_CONFED_SEQUENCE, if any.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  if the first segment is BGP_AS_CONFED_SEQUENCE,
 *           returns the first ASN of that segment.
 *
 *           if the first segment is BGP_AS_SEQUENCE,
 *           returns the first ASN of that segment.
 *
 *           otherwise: returns BGP_ASN_NULL
 *
 *           (so, if the AS_PATH is empty, or if the first segment is
 *            BGP_AS_SET or BGP_AS_CONFED_SET, returns BGP_ASN_NULL)
 */
extern as_t
as_path_left_most_asn (as_path asp)
{
  as_path_get_processed(asp) ;

  return asp->p.left_most_asn ;
} ;

/*==============================================================================
 * Operations on as_paths
 */
static as_path as_path_prepend(as_path src, as_seg_t seg, as_t asn,
                                                                   uint count) ;
static as_path as_path_confed_fixup(as_path asp) ;
static void as_path_aggregate_segs(as_path dst, as_path a, as_path b,
                                                          qas_seg_t qsort) ;
static uint as_path_add_as_set(asp_item_t* dst_path, uint len,
                               asp_item_t* src_path, uint ptr, uint end,
                                                               qas_seg_t qset) ;
static void as_path_post_process(as_path asp) ;
static ulen as_path_sweep(as_path asp, ulen start) ;

/*------------------------------------------------------------------------------
 * Prepend as_path 'b' onto the front of as_path 'a'.
 *
 * NB: NULL asp is invalid -- will crash !  Except for 'b', where NULL => empty.
 *
 * If Confed stuff exists in either path, then the result may, in fact, be
 * invalid -- with some Confed segment(s) after some Simple one(s).  It is the
 * caller's responsibility to worry about those semantic issues, as required,
 * see as_path_confed_sweep().
 *
 * Returns:  if 'b' is empty (or NULL) return 'a'.
 *           if 'a' is empty AND 'b' is *stored*, return 'b'
 *           otherwise: if 'a' is stored, return new path with 'b' prepended
 *                             otherwise, return 'a' with 'b' prepended.
 *
 * So... creates a new as_path only if absolutely necessary.  And if can
 *       replace an empty 'a' with a stored, not-empty 'b', then does so.
 *
 * NB: it is the caller's responsibility to deal with the original 'a' if the
 *     return is different.
 *
 * NB: does not bother to check for path 'b' ending with a sequence, and 'a'
 *     starting with the same sort of sequence, and there being the same ASN at
 *     the join.
 *
 *     Such cases are rare, and swept up by post-processing.
 */
extern as_path
as_path_prepend_path (as_path a, as_path b)
{
  as_path  dst ;
  ulen     alen, blen ;

  if (b == NULL)
    return a ;                  /* easy for 'b' absent                  */

  blen = b->path.len ;

  if (blen == 0)
    return a ;                  /* easy for 'b' empty                   */

  alen = a->path.len ;

  if ((alen == 0) && b->stored)
    return b ;                  /* easy for 'a' empty & 'b' stored      */

  /* Worry about whether we are creating a new as_path, or adjusting an
   * existing one.
   *
   * Sets the dst->path.len = a->path.len + blen
   */
  if (a->stored)
    {
      /* Create a new as_path -- cannot change a stored one !
       *
       * This allocates "need" extra items, and places them before the existing
       * contents of the path.
       */
      dst = as_path_copy(a, blen, true /* extra before existing */) ;
    }
  else
    {
      /* Can insert at the front of the existing as_path.
       */
      dst = a ;
      qlump_add_space(&dst->path, 0, blen) ;
    } ;

  dst->state = asps_raw ;               /* needs post-processing        */

  /* Copy from 'b' to front of 'a'.
   */
  memcpy(dst->path.body.v, b->path.body.v, sizeof_asp_items(blen)) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Add specified AS to the leftmost of aspath.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  new asp if existing asp is 'stored'
 *           otherwise: the given asp, updated
 */
extern as_path
as_path_add_seq (as_path asp, as_t asno)
{
  return as_path_prepend(asp, BGP_AS_SEQUENCE, asno, 1);
}

/*------------------------------------------------------------------------------
 * Add new AS number to the leftmost part of the aspath as AS_CONFED_SEQUENCE.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Returns:  new asp if existing asp is 'stored'
 *           otherwise: the given asp, updated
 */
extern as_path
as_path_add_confed_seq (as_path asp, as_t asno)
{
  return as_path_prepend(asp, BGP_AS_CONFED_SEQUENCE, asno, 1);
} ;

/*------------------------------------------------------------------------------
 * Append as_path 'b' onto the end of as_path 'a'.
 *
 * NB: NULL asp is invalid -- will crash !  Except for 'b', where NULL => empty.
 *
 * If Confed stuff exists in either path, then the result may, in fact, be
 * invalid -- with some Confed segment(s) after some Simple one(s).  It is the
 * caller's responsibility to worry about those semantic issues, as required,
 * see as_path_confed_sweep().
 *
 * Returns:  if 'b' is empty (or NULL) return 'a'.
 *           if 'a' is empty AND 'b' is *stored*, return 'b'
 *           otherwise: if 'a' is stored, return new path with 'b' appended
 *                             otherwise, return 'a' with 'b' appended.
 *
 * So... creates a new as_path only if absolutely necessary.  And if can
 *       replace an empty 'a' with a stored, not-empty 'b', then does so.
 *
 * NB: it is the caller's responsibility to deal with the original 'a' if the
 *     return is different.
 *
 * NB: does not bother to check for path 'a' ending with a sequence, and 'b'
 *     starting with the same sort of sequence, and there being the same ASN at
 *     the join.
 *
 *     Such cases are rare, and swept up by post-processing.
 */
extern as_path
as_path_append_path (as_path a, as_path b)
{
  as_path     dst ;
  asp_item_t* path ;
  ulen        alen, blen ;

  if (b == NULL)
    return a ;                  /* easy for 'b' absent                  */

  blen = b->path.len ;

  if (blen == 0)
    return a ;                  /* easy for 'b' empty                   */

  alen = a->path.len ;

  if ((alen == 0) && b->stored)
    return b ;                  /* easy for 'a' empty & 'b' stored      */

  /* Worry about whether we are creating a new as_path, or adjusting an
   * existing one.
   *
   * Sets the dst->path.len = a->path.len + blen
   */
  if (a->stored)
    {
      /* Create a new as_path -- cannot change a stored one !
       *
       * This allocates "need" extra items, and places them after the existing
       * contents of the path.
       */
      dst = as_path_copy(a, blen, false /* space after existing items */) ;
    }
  else
    {
      /* Can insert at the end of the existing as_path.
       */
      dst = a ;
      qlump_add_space(&dst->path, alen, blen) ;
    } ;

  dst->state = asps_raw ;               /* needs post-processing        */

  /* Copy from 'b' to end of 'a'.
   */
  path = dst->path.body.v ;

  memcpy(&path[alen], b->path.body.v, sizeof_asp_items(blen)) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * If there is any misplaced Confed stuff, sweep it to the front.
 *
 * After, for example, as_path_prepend_path(), it is possible to end up with
 * an as_path which is invalid because there are one or more Confed segments
 * after one or more simple segments.  This function checks for that and
 * fixes up the as_path by moving any such Confed segments to the front (but
 * not past any Confed segments already at the front).
 *
 * Returns:  new asp if any change was made and the existing asp is 'stored'
 *           otherwise: the given asp, updated as required
 *            *
 * NB: in any case, returns the path post-processed.
 */
extern as_path
as_path_confed_sweep(as_path asp)
{
  as_path_get_processed(asp) ;

  if (as_path_confed_ok_test(asp))
    return asp ;

  return as_path_confed_fixup(asp) ;
} ;

/*------------------------------------------------------------------------------
 * Delete all BGP_AS_CONFED_SEQUENCE/_SET segments from aspath.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * See RFC5065, 4.1 c) 1)
 *
 *   "...if any path segments of the AS_PATH are of the type AS_CONFED_SEQUENCE
 *    or AS_CONFED_SET, those segments MUST be removed..."
 *
 *     If does create a new as_path, it needs to be post-processed.
 *
 * Returns:  if there is no Confed stuff, returns the original asp
 *           otherwise, if the asp is stored, returns a new asp
 *           otherwise, returns the asp (updated)
 */
extern as_path
as_path_confed_delete(as_path asp)
{
  as_path     dst ;
  ulen        dlen ;
  asp_item_t* keep ;

  /* Decide whether there is anything to do here, and if there is, make sure
   * all confed stuff is at the front of the path
   */
  as_path_get_processed(asp) ;

  if (asp->p.confed.first_seg == BGP_AS_SEG_NULL)
    {
      qassert((asp->p.confed.first == 0) && ((asp->p.confed.last == 0))) ;

      return asp ;                      /* Nothing to do                */
    } ;

  if (!as_path_confed_ok_test(asp))
    dst = as_path_confed_fixup(asp) ;   /* post-processes the path if it
                                         * makes any changes            */
  else
    dst = asp ;

  /* Need to hack off one or more confed segments -- creating a new as_path
   * if current one is stored.
   */
  qassert((dst->p.confed.last != 0) &&
                 ( (dst->p.simple.first_seg == BGP_AS_SEG_NULL) ||
                   (dst->p.simple.first == dst->p.confed.last) )) ;

  dlen = dst->path.len - dst->p.confed.last ;

  keep = ((asp_item_t*)dst->path.body.v) + dst->p.confed.last ;

  if (dst->stored)
    dst = as_path_new(dlen) ;

  if (dlen != 0)
    memcpy(dst->path.body.v, keep, sizeof_asp_items(dlen)) ;

  /* Done -- set new length and return updated original or new as_path.
   */
  dst->state    = asps_raw ;
  dst->path.len = dlen ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Reconcile the given AS2 form AS_PATH with the given AS4_PATH.
 *
 * NB: NULL asp2 is invalid -- will crash !  asp4 may be NULL (deemed empty).
 *
 * For the most part, this drops stuff from the end of the AS2, and then
 * appends the AS4_PATH -- where the amount of stuff dropped is the same as
 * the amount of stuff in the AS4_PATH.  So this function operates in much
 * the same was as as_path_append_path().
 *
 * If the asp2 is empty or contains only confed stuff, then this degenerates
 * to an as_path_append_path(asp2, asp4).
 *
 * NB: result is (largely) undefined if the asp4 contains confed stuff,
 *     anywhere.
 *
 * Returns:  if 'b' is empty (or NULL) return 'a'.
 *           if 'a' is the same as 'b' AND 'b' is *stored*, return 'b'
 *           otherwise: if 'a' is stored, return new path reconciled with 'b'
 *                             otherwise, return 'a' reconciled with 'b'
 *
 * So... creates a new as_path only if absolutely necessary.  And if can
 *       replace 'a' with a stored, not-empty 'b', then does so.
 *
 * NB: it is the caller's responsibility to deal with the original 'a' if the
 *     return is different.
 *
 * RFC4893 and the -bis-07 simply count the ASN in sequences and the number
 * of sets.  If the asp2 is longer or the same length, then take 'n' ASNs/sets,
 * and append the asp4 to create a path of the same length as the asp2.  If
 * the asp2 is shorter, discard the asp4.
 *
 * This code more or less does that.  Except, since the asp4 is not allowed to
 * carry any confed stuff, it seems easier to treat any leading confed stuff on
 * the asp2 separately:
 *
 *   * if the asp2 including the confed stuff is shorter than the asp4,
 *     then treating the confed stuff separately makes no difference.
 *
 *   * if the asp2 less the confed stuff is shorter than the asp4, then the
 *     replacing parts of the confed stuff by leading ASN in the asp4 makes
 *     no sense.  Indeed -bis-07 has a note which suggests that leading
 *     confed stuff should be retained intact.
 *
 * It was tempting to treat repeated ASN as single items, but the asp2 may
 * well have repeated AS_TRANS... and after that it is all down-hill.
 *
 * ALSO, Quagga bgpd ignores the RFC's, and if the asp2 is shorter than the
 * asp4, it simply jams the two together !
 */
extern as_path
as_path_reconcile_as4 (as_path asp2, as_path asp4)
{
  as_path  dst ;
  uint     len ;

  /* If the as2 path has any confed part *after* any simple stuff, fixup up the
   * path so that all confed precedes all simple.
   *
   * There should not be any confed stuff after the first simple segment, but
   * if there is, it will get in the way of the replacement of the tail of
   * the asp2 path with the asp4 path.  So, moving all confed stuff to the
   * front is a strategy for avoiding a bad situation from getting worse.
   */
  as_path_get_processed(asp2) ;

  if (!as_path_confed_ok_test(asp2))
    asp2 = as_path_confed_fixup(asp2) ;

  /* Worry about empty/absent asp4 and make sure we have that post-processed
   */
  if (asp4 == NULL)
    return asp2 ;               /* easy for 'asp4' absent               */

  if (asp4->path.len == 0)
    return asp2 ;               /* easy for 'asp4' empty                */

  as_path_get_processed(asp4) ;

  /* We now have an asp2 with at least one simple segment, so we do need to
   * reconcile that with the given asp4, which is not empty.
   *
   * There is a final edge case to deal with here.  If 'b' is stored, and the
   * reconciliation is, in fact, replacing 'a' by 'b', then we do so.
   *
   * If asp2 is stored, then we now need a copy of it, preserving its
   * properties (not adding any extra space at this stage).
   */
  if (asp4->stored && (asp4->p.simple.length == asp2->p.simple.length)
                   && (asp4->p.confed.length == 0)
                   && (asp2->p.confed.length == 0))
    return asp4 ;

  if (asp2->stored)
    dst = as_path_copy(asp2, 0 /* no extra space */, false) ;
  else
    dst = asp2 ;

  /* Decide how much of the as2 path we are going to keep, after any confed
   * stuff.
   *
   * Note that we do not expect the asp4 to contain any confed stuff, but if
   * it does, we treat it as if the asp4 was longer than the asp2, and stick
   * the entire asp4 on the end as an AS_SET !
   */
  if ((dst->p.simple.length >= asp4->p.simple.length) &&
                              (asp4->p.confed.length == 0))
    {
      /* Simple stuff -- keep the leading part of dst (as2), and replace the
       * trailing part by as4.
       *
       * Note: RFC4893 and the -bis-07 effectively replace the as2 by the as4
       *       if they are the same length.
       *
       *       This allows for a mix of NEW and OLD BGP speakers in iBGP.
       *
       * NB: by the time we get to here we have:
       *
       *       asp4->p.simple.length == asp4->p.total_length
       *       asp4->p.simple.length >  0
       */
      asp_item_t* path ;
      ulen        keep, ptr, last ;

      qassert(asp4->p.simple.length == asp4->p.total_length) ;
      qassert(asp4->p.simple.length > 0) ;

      keep = dst->p.simple.length - asp4->p.simple.length ;

      path = dst->path.body.v ;
      ptr  = dst->p.simple.first ;      /* start with first simple      */
      last = dst->p.simple.last ;       /* cannot go further than this  */

      while ((keep > 0) && (ptr < last))
        {
          uint count ;

          count = path[ptr].count ;

          switch (path[ptr].qseg)
            {
              case qAS_SEQUENCE:
                /* If the item count > number of items to keep, reduce the
                 * item count.
                 */
                if (keep >= count)
                  keep -= count ;
                else
                  {
                    path[ptr].count = keep ;
                    keep = 0 ;
                  } ;

                ++ptr ;         /* copy the sequence item       */
                break ;

              case qAS_SET:
                qassert(false) ;        /* should not be        */
                fall_through ;

              case qAS_SET | qAS_SET_START:
                do
                  ++ptr ;       /* copy the set                 */
                while ((ptr < last) && (path[ptr].qseg == qAS_SET)) ;

                keep -= 1 ;     /* entire set counts as 1       */
                break ;

              default:
                qassert(false) ;
                ++ptr ;         /* step, anyway                 */
                break ;
            } ;
        } ;

      /* Chop the new path at the current position, and then insert the asp4.
       *
       * With luck the original size of the dst will suffice.
       */
      qassert(asp4->path.len != 0) ;

      len = ptr + asp4->path.len ;
      if (len > dst->path.size)
        path = as_path_need(dst, len) ;

      memcpy(&path[ptr], asp4->path.body.v, sizeof_asp_items(asp4->path.len)) ;
    }
  else if (asp4->path.len > 0)
    {
      /* The as2 path is shorter than the as4 path, and the as4 path is not
       * empty.
       *
       * What Quagga used to do is jam the as4 onto the end of the as2.
       *
       * This code jams a BGP_AS_SET onto the back of the as2, which contains
       * all the ASN in the as4, dropping any ASN which are already present in
       * the as2 path.
       */
      asp_item_t* path ;
      asp_item_t* as4_path ;
      uint        start, ptr ;
      qas_seg_t   qseg ;

      /* Need enough space to copy the entire as4 path, plus a BGP_AS_SET
       * marker.
       *
       * Note that the as4 path has been post-processed, so is not empty at
       * this point -- since asp4->path.len > 0.
       */
      len  = dst->path.len ;
      path = as_path_need(dst, len + asp4->path.len) ;

      /* Put the entire as4 path onto the end of the as2 path, as a BGP_AS_SET,
       * but do not include any ASN which already appear in the as2.
       */
      start = len ;
      as4_path = asp4->path.body.v ;
      qseg = qAS_SET | qAS_SET_START ;

      for (ptr = 0 ; ptr < asp4->path.len ; ++ptr)
        {
          as_t asn ;
          uint scan ;

          asn = as4_path[ptr].asn ;

          for (scan = 0 ; scan < start ; ++scan)
            {
              if (path[scan].asn == asn)
                break ;
            } ;

          if (scan == start)
            {
              path[len].asn   = asn ;
              path[len].count = 1 ;
              path[len].qseg  = qseg ;

              len += 1 ;
              qseg = qAS_SET ;
            } ;
        } ;
    } ;

  /* Set the new length, then post process to sweep up repeats, sort any
   * appended set etc.
   */
  qassert(len <= dst->path.size) ;
  dst->path.len = len ;

  as_path_post_process(dst) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Merge as_path 'b' into aggregate as_path 'b'.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * Treats simple and confed segments as disjoint.  If there are confed segments,
 * they should be the leading segments.  Should reject as paths which have
 * misplaced confed segments -- but this code simply moves any misplaced stuff
 * to the front of the path.
 *
 * If one path has leading confed stuff and the other doesn't, then will
 * create a confed set at the start of the aggregated path.
 *
 * The aggregation process considers confed stuff first (moving all such to
 * the start of the result path), and simple stuff second.  As per RFC5065,
 * Appendix A, confed stuff and simple stuff is treated entirely separately.
 *
 * The principal objective is to retain as much as possible of the AS_PATH
 * sequences.  Anything that cannot be preserved has to go into a set or
 * sets.  Where there are sets in the paths being aggregated, a little
 * effort is spent to preserve some set boundaries.
 *
 * As the process moves along the two AS_PATHs it is in one of 3 states:
 *
 *   (A) the last thing copied to the result was a matching sequence ASN.
 *
 *   (B) the last thing(s) copied to the result was two "matching" sets, merged
 *       together.
 *
 *   (C) the last thing(s) copied to the result were appended to the current
 *       set which is at the end of the result.
 *
 * The process starts in state (A) with an empty result path.
 *
 * In the following, all lower-case letters denote sequence ASNs and all
 * upper-case '{X}' denotes a set.  Any set will match another set, but a set
 * and a sequence ASN do not match.  '|' is where the process has reached in
 * the two paths, and '...' is an arbitrary amount of stuff already or to be
 * processed.
 *
 * There are then 8 cases:
 *
 *   (1) have reached the end of one or both paths:
 *
 *       (A) copy what remains to a new set.
 *
 *           eg:  ...p | x {X} y z  -> ...p {x,X,y,z}
 *                ...p |
 *
 *       (B) copy what remains to the current set
 *
 *           eg:  ...{S} | x {X} y z  -> ...{S,T,x,X,y,z}
 *                ...{T} |
 *
 *           Note that this associates all the trailing stuff with the last
 *           set in the respective path.
 *
 *       (C) copy what remains to the current set -- same as (B), but the
 *           current set may have been created in a number of ways.
 *
 *           eg:  ...p | x {X} y z  -> ...{...p,q,x,X,y,z}
 *                ...q |
 *
 *   (2) have a matching ASN:
 *
 *       (A) copy the ASN to the result, remain in state (A)
 *
 *           eg:  ...p | a...  -> ...p a |
 *                ...p | a...
 *
 *       (B) copy the ASN to the result, change to state (A)
 *
 *           eg:  ...{S} | a...  -> ...{S,T} a |
 *                ...{T} | a...
 *
 *       (C) copy the ASN to the result, change to state (A) -- same as (B),
 *           but the current set may have been created in a number of ways.
 *
 *           eg:  ...p | a...  -> ...{...,p,q} a |
 *                ...q | a...
 *
 *   (3) have mis-matching ASN, and no match further along either path:
 *
 *       NB: when have two sequence ASNs which do not match,  scans forward
 *           along the paths to see if there is a match further along.
 *
 *           In this case there is no such match.
 *
 *           The scan ignores ASN in sets -- only interested in "synchronising"
 *           sequence ASNs.
 *
 *       (A) copy the mismatched ASN to the result as a new set, change to
 *           state (C)
 *
 *           eg:  ...p | a...  -> ...p {a,b} |
 *                ...p | b...
 *
 *       (B) copy the mismatched ASN to the result, change to state (C)
 *
 *           eg:  ...{S} | a...  -> ...{S,T} {a,b} |
 *                ...{T} | b...
 *
 *           Note that in this case we start a new set following the previously
 *           existing, and now merged, sets.
 *
 *       (C) copy the mismatched ASN to the result in the existing set, stay in
 *            state (C).
 *
 *           eg:  ...p | a...  -> ...{...,p,q,a,b} |
 *                ...q | b...
 *
 *   (4) have mis-matching but cross-matched ASN:
 *
 *       NB: in this case the scan forward along the paths has found a match
 *           for both ASNs further down the other path.
 *
 *       This behaves in the same way as (3) above, ignoring the matches
 *       further down the path.  This is so that will find something like:
 *
 *          ... | a...x ...b
 *          ... | b...x ...a
 *
 *       later on.  (The alternative would be to stick 'a ... b' and 'b ... a'
 *       into a set and step past -- which would miss the matching 'x'.)
 *
 *       The other possible approach would be to chose the closer... but then,
 *       what to do if both are equally close ?  And what do we mean, close ?
 *       This case is covered so that something well defined happens, not
 *       necessarily the optimal thing !
 *
 *   (5) have matching ASN further down one path (but not both):
 *
 *       (A) copy the stuff up to the matched ASN to the result as a new set,
 *           then copy the matched ASN, and change to state (A)
 *
 *           eg:  ...p | a...  ->  ...p {x...y} a |
 *                ...p | x...y a...
 *
 *           This creates a new set -- inevitable in this case.
 *
 *       (B) copy the stuff up to the matched ASN to the result appending to
 *           the existing set, then copy the matched ASN, and change to
 *           state (A)
 *
 *           eg:  ...{S} | x...y b...  -> ...{S,T,x...y} b |
 *                ...{T} | b ...
 *
 *           In this case we do not start a new set after the merged sets.
 *           Instead it treats not-matched stuff after {S} as being absorbed
 *           by {S}.
 *
 *       (C) copy the stuff up to the matched ASN to the result appending to
 *           the existing set, then copy the matched ASN, and change to
 *           state (A)
 *
 *           eg:  ...p | x...y b...  -> ...{...p,q,x...y} b |
 *                ...q | b...
 *
 *      Note that it does not matter what is in 'x...y', there may be
 *      any combination of sequence ASN and sets.
 *
 *   (6) have a set (in one path) and a sequence ASN (in the other), and no
 *       match for the ASN in the first path:
 *
 *       This is essentially the same as case (3), except one of the items
 *       is a set, not an ASN.
 *
 *       (A) copy the mismatched ASN and set to the result as a new set, change
 *           to state (C)
 *
 *           eg:  ...p | a...   -> ...p {a,X} |
 *                ...p | {X}...
 *
 *       (B) copy the mismatched ASN and set to the result as a new set, change
 *           to state (C)
 *
 *           eg:  ...{S} | {X}...  -> ...{S,T} {X,b} |
 *                ...{T} | b...
 *
 *           Note that in this case we start a new set following the previously
 *           existing, and now merged, sets -- since we can happily merge 'b'
 *           into '{X}' we can leave the original set boundaries.
 *
 *       (C) copy the mismatched ASN to the result in the existing set, stay in
 *           state (C).
 *
 *           eg:  ...p | a...  -> ...{...,p,q,a,X} |
 *                ...q | {X}...
 *
 *   (7) have a set (in one path) and a sequence ASN (in the other), and a
 *       match for the ASN in the first path:
 *
 *       This is essentially the same as case (5), except one of the items
 *       is a set, not an ASN.
 *
 *       (A) copy the stuff up to the matched ASN to the result as a new set,
 *           then copy the matched ASN, and change to state (A)
 *
 *           eg:  ...p | a...  -> ...   p {X...y} a |
 *                ...p | {X}...y a...
 *
 *
 *       (B) copy the stuff up to the matched ASN to the result creating a new
 *           set, then copy the matched ASN, and change to state (A)
 *
 *           eg:  ...{S} | {X}...y b...  -> ...{S,T} {X...y} b |
 *                ...{T} | b...
 *
 *           In this case we can merge everything before the matched ASN into
 *           the existing set {X}.
 *
 *       (C) copy the stuff up to the matched ASN to the result appending to
 *           the existing set, then copy the matched ASN, and change to
 *           state (A)
 *
 *           eg:  ...p | {X}...y b...  -> ...{...p,q,X...y} b |
 *                ...q | b...
 *
 *           In this case we merge all the set stuff up to the 'b' into
 *           one set.
 *
 *      Note that it does not matter what is in '{X}...y', there may be
 *      any combination of sequence ASN and sets.
 *
 *   (8) have a set in both paths:
 *
 *       (A) merge the sets as a new set in the result, and change to state (B)
 *
 *           eg:  ...p | {X}... -> ...   p {X,Y} |
 *                ...p | {Y}...
 *
 *       (B) merge the sets as a new set in the result, and change to state (B)
 *
 *           eg:  ...{S} | {X}...  -> ...{S,T} {X,Y} |
 *                ...{T} | {Y}...
 *
 *           In this case we can merge everything before the matched ASN into
 *           the existing set {X}.
 *
 *       (C) merge the sets as a new set in the result, and change to state (B)
 *
 *           eg:  ...p | {X}...  -> ...{...p,q,X,Y} |
 *                ...q | {Y}...
 *
 * Once the new AS_PATH has been created:
 *
 *   i) will remove ASN 'x' from every set it appears in, if it appears in a
 *      sequence, and from all but the first sequence, if it appears in more
 *      than one sequence.
 *
 *  ii) will remove ASN 'x' from all but the first set it appears in (if it
 *      appears in any set after (i) above).
 *
 * The procedure here is thought to be RFC4271 compliant, not that the RFC
 * requires very much.  Except that:
 *
 *   * preserves some set boundaries -- which Quagga likes to do, in general.
 *
 *   * where ASN 'x' is matched in the two AS_PATHs in a sequence, and 'x'
 *     appears in either path or both paths as a run of repeated 'x's, then
 *     the longer of the runs appears in the result.  (The RFC is silent on
 *     this matter, AFAICS.)
 *
 *   * merges sets together irrespective of content, where the RFC matches
 *     ASNs, irrespective of the "tuple" type.
 *
 * Also, there appears to be a bug in RFC4271.  It calls for:
 *
 *   - for any tuple X of type AS_SEQUENCE in the aggregated AS_PATH, which
 *     precedes tuple Y in the aggregated AS_PATH, X precedes Y in each AS_PATH
 *     in the initial set, which contains Y, regardless of the type of Y.
 *
 * which is not consistent with the recommendation:
 *
 *   - if the aggregated AS_PATH has more than one tuple with the same value
 *     (regardless of tuple's type), eliminate all but one such tuple by
 *     deleting tuples of the type AS_SET from the aggregated AS_PATH.
 *
 * ... where the first tuple X is an AS_SET tuple and there are AS_SEQUENCE
 * tuples for Y and X (in that order) later in the AS_PATH !!
 *
 * The procedure used is along the lines of that given in F.6 of the RFC,
 * except that it (the procedure used) ignores set tuples when attempting
 * to re-synchronise.
 */
extern as_path
as_path_aggregate (as_path a, as_path b)
{
  as_path     dst ;

  /* Start with everything canonical, ship shape, Bristol fashion
   */
  as_path_get_processed(b) ;
  as_path_get_processed(a) ;

  /* Start with a brand new path, with room for the two paths stuck together,
   * which is definitely the worst case -- nothing at all matches, and all
   * ASNs are different.
   */
  dst = as_path_new(a->path.len + b->path.len) ;

  if ( (a->p.confed.first_seg != BGP_AS_SEG_NULL)
    || (b->p.confed.first_seg != BGP_AS_SEG_NULL) )
    as_path_aggregate_segs(dst, a, b, qAS_CONFED) ;

  as_path_aggregate_segs(dst, a, b, 0 /* simple */);

  as_path_post_process(dst) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Iterate over AS_PATH segments and wipe all occurrences of any member of the
 * given asn_set.  Some segments may lose some or even all data on the way.
 *
 * NB: NULL asp is invalid -- will crash !  A NULL asn_set is an empty asn_set.
 *
 * Creates a new as_path if src is 'stored', otherwise operates on the current
 * src.
 *
 * Returns:  if no change is made, returns the given as_path
 *           if the given as_path is not stored, returns the given as_path,
 *                                                         updated as required.
 *           if some change was made, and the as_path was stored, returns
 *           a new as_path.
 *
 * NB: the src need not have been post-processed.
 */
extern as_path
as_path_exclude_asns (as_path asp, asn_set asns)
{
  as_path     dst ;
  asp_item_t* path ;
  ulen        len, ptr, drop ;

  /* Make sure we are not wasting time.
   */
  if ((asns == NULL) || (asns->set.len == 0))
    return asp ;

  path = asp->path.body.v ;
  len  = asp->path.len ;

  ptr = 0 ;
  while (1)
    {
      if (ptr == len)
        return asp ;            /* nothing to drop      */

      if (asn_set_contains(asns, path[ptr].asn))
        break ;

      ++ptr ;
    } ;

  /* Prepare to drop one or more ASN
   */
  if (asp->stored)
    {
      dst = as_path_copy(asp, 0 /* nothing extra */, false) ;
      path = dst->path.body.v ;
    }
  else
    dst = asp ;

  dst->state = asps_raw ;       /* result needs post-processing !       */

  /* Mark this and any further items to be dropped.
   */
  drop = ptr ;                  /* first drop                           */
  path[ptr].count = 0 ;

  for (ptr = ptr + 1 ; ptr < len ; ++ptr)
    {
      if (asn_set_contains(asns, path[ptr].asn))
        path[ptr].count = 0 ;
    } ;

  as_path_sweep(dst, drop) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Prepend the given ASN one or more times.
 *
 * If the given as_path is stored, create a new as_path.
 *
 * For BGP_AS_SEQUENCE or BGP_AS_CONFED_SEQUENCE, the count may be
 * 1..asp_count_max (and is clamped to be in that range).
 *
 * For BGP_AS_SET or BGP_AS_CONFED_SET, the count is ignored.  A new set is
 * created at the start of the as_path.
 *
 * The result as_path needs to be post-processed.
 *
 * Returns:  new or existing as_path, with stuff prepended.
 *
 * NB: does not bother to check for prepending an ASN in some sort of sequence,
 *     to a path which starts with the same sort of sequence and the same ASN.
 *
 *     This will be swept up by post-processing.
 */
static as_path
as_path_prepend(as_path asp, as_seg_t seg, as_t asn, uint count)
{
  as_path     dst ;
  asp_item_t* path ;
  qas_seg_t   qseg ;

  /* Worry about whether we are creating a new as_path, or adjusting an
   * existing one.
   */
  if (asp->stored)
    {
      /* Create a new as_path -- cannot change a stored one !
       *
       * This allocates 1 extra item, and places them before the existing
       * contents of the path.
       *
       * Sets the dst->path.len = asp->path.len + 1
       */
      dst = as_path_copy(asp, 1, true /* extra before existing */) ;
    }
  else
    {
      /* Can insert at the front of the existing as_path.
       *
       * Updates dst->path.len
       */
      dst = asp ;
      qlump_add_space(&dst->path, 0, 1) ;
    } ;

  dst->state = asps_raw ;       /* needs post-processing        */

  /* Now insert what we need to insert at the front of the dst.
   */
  path = dst->path.body.v ;

  qseg = qas_seg_start(seg) ;

  path[0].asn = asn ;

  if ((count <= 1) || (qseg & qAS_SET))
    path[0].count = 1 ;
  else
    {
      if (count > as_max_count)
        count = as_max_count ;
      path[0].count = count ;
    }

  path[0].qseg = qseg ;

  /* Return new or original as_path
   */
  return dst ;
} ;

/*------------------------------------------------------------------------------
 * If required, fixup confed stuff.
 *
 * If the path has any confed, and any confed segment comes after any
 * simple segment(s), move the confed stuff to in front of the simple stuff.
 *
 * Returns:  new as_path if any fixup required and the given one is stored
 *           otherwise, the given as_path
 *
 * NB: in any case, returns the path post-processed.
 */
static as_path
as_path_confed_fixup(as_path asp)
{
  asp_item_t* path ;
  uint scan, len, simple_start ;

  as_path_get_processed(asp) ;

  /* Nothing to do if last confed segment precedes the first simple segment,
   * or there are no simple segments, or there are no confed segments.
   */
  if (as_path_confed_ok_test(asp))
    return asp ;

  /* So we do need to fix this.
   *
   * Make new path if the given path is stored.
   */
  if (asp->stored)
    asp  = as_path_copy(asp, 0 /* no extra entries */, false) ;

  path = asp->path.body.v ;
  len  = asp->path.len ;                /* cannot be zero !     */

  qassert(len > 0) ;

  /* Step past any leading confed stuff.
   *
   * Then at top of loop the scan is pointing at the start of a simple
   * segment.  Steps to any following confed stuff, then steps past that, and
   * swaps the simple stuff with the confed stuff.
   */
  scan = 0 ;
  while ((scan < len) && (path[scan].qseg & qAS_CONFED))
    ++scan ;

  simple_start = scan ;

  while (1)
    {
      uint confed_start, confed_len, simple_len ;

      while ((scan < len) && !(path[scan].qseg & qAS_CONFED))
        ++scan ;

      simple_len   = scan - simple_start ;

      if (simple_len == 0)
        break ;

      confed_start = scan ;
      while ((scan < len) && (path[scan].qseg & qAS_CONFED))
        ++scan ;

      confed_len   = scan - confed_start ;

      if (confed_len == 0)
        break ;

      qlump_swap_items(&asp->path, simple_start, simple_len,
                                   confed_start, confed_len) ;

      simple_start += confed_len ;
    } ;

  as_path_post_process(asp) ;

  return asp ;
} ;

/*------------------------------------------------------------------------------
 * Aggregate either simple or confed segments.
 *
 * See as_path_aggregate().
 */
static void
as_path_aggregate_segs(as_path dst, as_path a, as_path b, qas_seg_t qsort)
{
  asp_item_t* path,* path_a, * path_b ;
  uint        ptr_a, ptr_b, end_a, end_b ;
  qas_seg_t   qset, qseq, qset_start ;
  uint        start, ptr, len, drop ;
  bool        set_match ;

  as_path_seg_properties_t* p_sp_a, *p_sp_b ;

  qassert((a->state & asps_processed) && (b->state & asps_processed)) ;

  path  = dst->path.body.v ;
  len   = dst->path.len ;

  start = len ;                 /* for removal of redundant ASN */

  /* Want to start with the first confed/simple segment in each path, and
   * process all such segments.
   *
   * The post-processing has captured:
   *
   *   p.confed.first_seg   -- segment type for the first confed segment
   *   p.confed.first       -- offset of the first confed segment -- 0 if none
   *   p.confed.last        -- offset of last item +1 in the last confed
   *                           segment -- 0 if none
   *
   * And similarly for simple segments.
   */
  if (qsort & qAS_CONFED)
    {
      p_sp_a = &a->p.confed ;
      p_sp_b = &b->p.confed ;
    }
  else
    {
      p_sp_a = &a->p.simple ;
      p_sp_b = &b->p.simple ;
    } ;

  path_a = a->path.body.v ;
  ptr_a  = p_sp_a->first ;
  end_a  = p_sp_a->last ;

  path_b = b->path.body.v ;
  ptr_b  = p_sp_b->first ;
  end_b  = p_sp_b->last ;

  /* Step past the items common to the two paths, and copy to the destination.
   *
   * NB: both paths have been post-processed, so are in the canonical form.
   */
  qset = qsort | qAS_SET ;
  qseq = qsort | qAS_SEQUENCE ;

  qset_start = qAS_SET_START ;
  set_match  = false ;

  while ((ptr_a < end_a) && (ptr_b < end_b))
    {
      qas_seg_t qseg_a, qseg_b ;
      uint set_a, set_b ;
      bool match ;

      /* Step past any items which are not the required sort of item.
       *
       * This is a royal pain,
       */
      qseg_a = path_a[ptr_a].qseg ;
      if ((qseg_a & qAS_CONFED) != qsort)
        {
          ++ptr_a ;
          continue ;
        } ;

      qseg_b = path_b[ptr_b].qseg ;
      if ((qseg_b & qAS_CONFED) != qsort)
        {
          ++ptr_b ;
          continue ;
        } ;

      /* Now we have two items of the required sort:
       *
       *   * both sets
       *
       *     Copy both sets to the result, sets:
       *
       *       - qset_start = qAS_SET_START -- copying original sets
       *
       *                                       qset_start will be cleared once
       *                                       the sets have been copied.
       *
       *       - set_match  = true          -- have "matching" sets, so next
       *                                       set may be a new set, but by
       *                                       default will not be.
       *
       *   * 'a' set, 'b' sequence
       *
       *     If the ASN 'b' matches downstream in path 'a', then copy
       *     everything from 'a' up to the match, as set items, and then copy
       *     the matched ASN.
       *
       *       - qset_start -- untouched    -- so if last thing was a sequence,
       *                                       then will start new set,
       *                                       otherwise will append to the
       *                                       existing one.
       *
       *                                       qset_start will be set to
       *                                       qAS_SET_START once the matching
       *                                       ASN have been copied.
       *
       *     Otherwise, copy the set 'a' and the ASN 'b' to the result as
       *     set items.
       *
       *       - qset_start = qAS_SET_START *iff* set_match
       *          otherwise -- untouched
       *                                    -- so if last thing was a sequence,
       *                                       or if the last thing was a
       *                                       matching pair of sets, then will
       *                                       start new set, otherwise will
       *                                       append to the existing one.
       *
       *                                       qset_start will be cleared once
       *                                       the set stuff has been copied.
       *
       *     In both cases:
       *
       *       - set_match  = false         -- not "matching" sets.
       *
       *   * 'a' sequence, 'b' set
       *
       *     As above, but vice versa.
       *
       *   * both sequence items
       *
       *     If the ASN match, copy to the result (using the larger count),
       *     and continue.
       *
       *       - qset_start untouched     --
       *
       *     If they do not match, scan in 'b' looking for the 'a' ASN in a
       *     sequence, and scan in 'a' looking for the 'b' ASN likewise.
       *     Then:
       *
       *       - if neither are found or both are found, then copy the
       *         mismatched ASN as set items and continue.
       *
       *         Note: where we have two paths thus:
       *
       *            path a:  .... a ..... b
       *            path b:  .... b ..... a
       *
       *         we find 'a' in path 'b', and 'b' in path 'a', but it really
       *         isn't clear which one we should synchronise on.  So, we
       *         choose to synchronise on neither -- perhaps we will find
       *         something between a .... b and b ..... a ?  But if not, the
       *         everything in those parts will end up in a set.
       *
       *       - if one is found, put everything up to the match into the
       *         current or new set, and then copy the matching sequence
       *         (using the larger count), and continue.
       *
       *     If matching ASNs are found:
       *
       *       - qset_start -- untouched    -- used if have set stuff before
       *                                       the match in one of the paths.
       *
       *                                       So if last thing was a sequence,
       *                                       then will start new set,
       *                                       otherwise will append to the
       *                                       existing one.
       *
       *                                       qset_start will be set to
       *                                       qAS_SET_START once the matching
       *                                       ASN have been copied.
       *
       *     If matching ASNs are not found:
       *
       *       - qset_start = qAS_SET_START *iff* set_match
       *          otherwise -- untouched
       *                                    -- so if last thing was a sequence,
       *                                       or if the last thing was a
       *                                       matching pair of sets, then will
       *                                       start new set, otherwise will
       *                                       append to the existing one.
       *
       *                                       qset_start will be cleared once
       *                                       the set stuff has been copied.
       *
       *     In all cases:
       *
       *       - set_match  = false       -- not "matching" sets.
       *
       * Note that in the event of a match found by scanning forwards,
       * everything which is stepped across in the scan is bundled together
       * into the current set (or a new one, if there is no current set).
       */
      set_a = ptr_a ;
      set_b = ptr_b ;

      if ((qseg_a | qseg_b) & qAS_SET)
        {
          /* One or the other or both is a set -- so start a new set.
           */
          if (qseg_a & qseg_b & qAS_SET)
            {
              /* Both are a set, so we copy both to the result -- no match.
               *
               * Sets qAS_SET_START to preserve the "matching" set boundary.
               * (This is mostly for the leading "common" part of two AS_PATHs.)
               *
               * Sets set_match, so that what follows may also start a new
               * set, if that is reasonable.
               */
              qset_start = qAS_SET_START ;
              set_match  = true ;
              match = false ;
            }
          else if (qseg_a & qAS_SET)
            {
              /* 'a' is a set, but 'b' is *not*.
               *
               * Scan forwards to see if we can get an ASN match.  If we can,
               * that will take precedence.
               *
               * If do not get an ASN match, add the set and the ASN to the
               * result -- appending to the current set, if any.
               */
              as_t asn_b ;
              bool match_b ;

              qassert(!(qseg_b & qAS_SET)) ;        /* 'b' *not* a set  */
              asn_b = path_b[ptr_b].asn ;

              while (1)
                {
                  ++ptr_a ;

                  if (ptr_a >= end_a)
                    {
                      match_b = false ;
                      break ;
                    } ;

                  if ( (path_a[ptr_a].asn == asn_b)
                                            && (path_a[ptr_a].qseg == qseq) )
                    {
                      match_b = true ;
                      break ;
                    } ;
                } ;

              if (match_b)
                {
                  /* Found ASN 'b' in 'a' -- eat everything in 'a' upto,
                   * but excluding the match, then eat the matching ASN.
                   *
                   * We have:  set_b == ptr_b  -- pointing at ASN 'b' in 'b'
                   *           set_a <  ptr_a  -- pointing at ASN 'b' in 'a'
                   */
                  qseg_a = qAS_SEG_NULL ;       /* stepped past the set */
                  match = true ;
                }
              else
                {
                  /* Did not find ASN 'b' in 'a' -- no match.
                   *
                   * Eat ASN 'b' and set 'a', together, starting a new set if
                   * the previous items were matching set items (or, by
                   * default, if they were matching sequence items).
                   */
                  ptr_a = set_a ;       /* backtrack, will scan for
                                         * the end of set 'a', below    */
                  ++ptr_b ;             /* Take the ASN from 'b'        */
                  match = false ;

                  if (set_match)
                    qset_start = qAS_SET_START ;
                } ;

              set_match = false ;
            }
          else
            {
              /* 'a' is *not* a set, but 'b' is.
               *
               * Proceed as above, but vice versa.
               */
              as_t asn_a ;
              bool match_a ;

              qassert(qseg_b & qAS_SET) ;           /* 'b' must be a set */
              asn_a = path_a[ptr_a].asn ;

              while (1)
                {
                  ++ptr_b ;

                  if (ptr_b >= end_b)
                    {
                      match_a = false ;
                      break ;
                    } ;

                  if ( (path_b[ptr_b].asn == asn_a)
                                            && (path_b[ptr_b].qseg == qseq) )
                    {
                      match_a = true ;
                      break ;
                    } ;
                } ;

              if (match_a)
                {
                  /* Found ASN 'a' in 'b' -- eat everything in 'b' upto,
                   * but excluding the match, then eat the matching ASN.
                   *
                   * We have:  set_a == ptr_a  -- pointing at ASN 'a' in 'a'
                   *           set_b <  ptr_b  -- pointing at ASN 'a' in 'b'
                   */
                  qseg_b = qAS_SEG_NULL ;       /* stepped past the set */
                  match = true ;
                }
              else
                {
                  /* Did not find ASN 'a' in 'b' -- no match.
                   *
                   * Eat ASN 'a' and set 'b', together, starting a new set if
                   * the previous items were matching set items (or, by
                   * default, if they were matching sequence items).
                   */
                  ptr_b = set_b ;       /* backtrack, will scan for
                                         * the end of set 'b', below    */
                  ++ptr_a ;             /* Take the ASN from 'a'        */
                  match = false ;

                  if (set_match)
                    qset_start = qAS_SET_START ;
                } ;

              set_match = false ;
            } ;

          if (qseg_a & qAS_SET)
            {
              /* Scan for end of set 'a'
               */
              do
                ++ptr_a ;
              while ((ptr_a < end_a) && (path_a[ptr_a].qseg == qset)) ;
            } ;

          if (qseg_b & qAS_SET)
            {
              /* Scan for end of set 'b'
               */
              do
                ++ptr_b ;
              while ((ptr_b < end_b) && (path_b[ptr_b].qseg == qset)) ;
            } ;
        }
      else
        {
          /* Neither 'a' nor 'b' is a set
           */
          as_t asn_a, asn_b ;

          asn_a = path_a[ptr_a].asn ;
          asn_b = path_b[ptr_b].asn ;

          match = (asn_a == asn_b) ;

          if (!match)
            {
              /* Scan forwards along path 'a' looking for ASN 'b', and
               * similarly along 'b'.
               *
               * Note that this scan steps over all types of segment, so steps
               * over segments of the wrong sort, and over sets of same sort.
               */
              bool match_a, match_b ;

              while (1)
                {
                  ++ptr_b ;

                  if (ptr_b >= end_b)
                    {
                      match_a = false ;
                      break ;
                    } ;

                  if ( (path_b[ptr_b].asn == asn_a)
                                            && (path_b[ptr_b].qseg == qseq) )
                    {
                      match_a = true ;
                      break ;
                    } ;
                } ;

              while (1)
                {
                  ++ptr_a ;

                  if (ptr_a >= end_a)
                    {
                      match_b = false ;
                      break ;
                    } ;

                  if ( (path_a[ptr_a].asn == asn_b)
                                            && (path_a[ptr_a].qseg == qseq) )
                    {
                      match_b = true ;
                      break ;
                    } ;
                } ;

              /* Now decide what to do with the result !
               */
              if (match_a == match_b)
                {
                  /* We found both or neither.
                   *
                   * Back-track and take just the mismatch ASN -- there
                   * may be a better match to find later.
                   *
                   * Copies the ASNs to into  into the current or a new set
                   * (depending on qset_next), then.  We clear qset_next so
                   * that any further set stuff will be appended to the set
                   * (until that is changed).
                   */
                   ptr_a = set_a + 1 ;
                   ptr_b = set_b + 1 ;

                   if (set_match)
                     qset_start = qAS_SET_START ;
                }
              else
                {
                  /* We found ASN 'a' in path 'b' or ASN 'b' in path 'a'
                   * (but not both).
                   *
                   * Arrange for ptr_a and ptr_b to point at the matching ASN.
                   * Result will be to copy everything up to the match into
                   * the current or a new set (depending on qset_next), then
                   * copy the matching ASN.  We set qset_next so that the next
                   * set created will be a new set.
                   */
                  if (match_a)
                    ptr_a = set_a ;     /* found ASN 'a' in path 'b'    */
                  else
                    ptr_b = set_b ;     /* found ASN 'b' in path 'a'    */

                  match     = true ;
                } ;
            } ;

          set_match = false ;           /* obviously            */
        } ;

      /* Having carefully studied the matter above, we now have:
       *
       *   * set_a and ptr_a -- start and end+1 of any items which
       *                        need to be put in the current or a new set.
       *
       *   * set_b and ptr_b -- start and end+1 of any items which
       *                        need to be put in the current or a new set.
       *
       *   * match           -- true <=> the ASN at ptr_a and ptr_b match
       *                        and are in a sequence (of the right sort).
       *
       *                        The ASN is copied to the result, using the
       *                        larger of the two counts.
       *
       *   * qset_start      --
       */
      if (set_a < ptr_a)
        {
          len = as_path_add_as_set(path, len, path_a, set_a, ptr_a,
                                                            qset | qset_start) ;
          qset_start = 0 ;
        } ;

      if (set_b < ptr_b)
        len = as_path_add_as_set(path, len, path_b, set_b, ptr_b,
                                                            qset | qset_start) ;

      if (match)
        {
          /* Hurrah !  A simple match.
           *
           * Since we are starting, or continuing a sequence, any set that
           * follows will be a new one.
           */
          path[len].asn   = path_a[ptr_a].asn ;
          path[len].qseg  = qseq ;
          path[len].count = (path_a[ptr_a].count >= path_b[ptr_b].count)
                           ? path_a[ptr_a].count :  path_b[ptr_b].count ;
          ++len ;
          ++ptr_a ;
          ++ptr_b ;

          qset_start = qAS_SET_START ;
        } ;
    } ;

  /* Run out of either path_a or path_b, or both
   *
   * Append what remains as set items, set the final length and post process to
   * tidy up.
   */
  if (ptr_a < end_a)
    {
      len = as_path_add_as_set(path, len, path_a, ptr_a, end_a,
                                                            qset | qset_start) ;
      qset_start = 0 ;
    } ;

  if (ptr_b < end_b)
    len = as_path_add_as_set(path, len, path_b, ptr_b, end_b,
                                                            qset | qset_start) ;

  qassert(len <= dst->path.size) ;

  dst->path.len = len ;

  as_path_post_process(dst) ;

  /* Sadly, that is not the end of it...
   *
   * ...we are now required to eliminate ASNs from sets, if the ASN appears
   * in a sequence or more than one set, and must eliminate ASNs from
   * sequences if they appear more than once -- except where they appear
   * in a group together.
   *
   * We scan from the beginning, and for each ASN, see if it appears later
   * in the path.  If the first appearance:
   *
   *   * is in a sequence, drop the later appearance, and continue.
   *
   *   * is in a set:
   *
   *       - drop the later appearance if it is also in a set, and continue.
   *
   *       - drop the first appearance if the later is in a sequence, and stop.
   *         (Will come across the later ASN again, later.)
   *
   * If we drop anything -- which we do by setting the asn to BGP_ASN_NULL,
   * then we sweep up afterwards and set the state back to asps_raw.
   *
   * NB: the procedure for aggregation does any Confed stuff entirely
   *     separately from the simple stuff.  It's not clear why the Confed
   *     part should mention something which appears in the simple part,
   *     or vice versa.  But, the presence of a given ASN in the Confed part
   *     may be considered separately from its presence in the simple part
   *     (for MEDs, for example).  Further, the Confed stuff may well be
   *     stripped -- so it would seem wrong to remove ASNs from the simple
   *     part on the strength of their appearance in the Confed part, at
   *     least.  So treating the two parts separately is not only simpler,
   *     but probably correct (!) -- but in any case unlikely to make the
   *     slightest difference in the real world.
   */
  drop = len ;

  for (ptr = start ; ptr < len ; ++ptr)
    {
      as_t  asn ;
      uint  scan ;

      asn = path[ptr].asn ;

      for (scan = ptr + 1 ; scan < len ; ++scan)
        {
          if (path[scan].asn == asn)
            {
              /* We have a match
               *
               * If the ptr item is a set, and the scan item is a sequence,
               * drop the ptr item, and exit the scan -- will re-process the
               * scan item later, to deal with anything downstream.
               *
               * Otherwise, drop the scan item and continue.
               */
              if ((path[ptr].qseg & qAS_SET)
                                            && !(path[scan].qseg & qAS_SET))
                {
                  /* Drop the earlier (set) appearance
                   */
                  path[ptr].asn = BGP_ASN_NULL ;
                  if (ptr < drop)
                    drop = ptr ;

                  break ;
                }
              else
                {
                  /* Drop the later appearance
                   */
                  path[scan].asn = BGP_ASN_NULL ;
                  if (scan < drop)
                    drop = scan ;
                } ;
            } ;
        } ;
    } ;

  if (drop < len)
    as_path_sweep(dst, drop) ;
} ;

/*------------------------------------------------------------------------------
 * Copy items from src_path from ptr..end-1, skipping any which are of the
 * wrong sort, and make those set items in the dst_path -- advancing its len.
 *
 * The incoming qset specifies the sort of segments to be copied.
 *
 * The incoming qset may also specify that the first item be qAS_SET_START.
 *
 * Returns:  new dst_path len.
 *
 * NB: assumes there is room for all this !
 */
static uint
as_path_add_as_set(asp_item_t* dst_path, uint len, asp_item_t* src_path,
                                         uint ptr, uint end, qas_seg_t qset)
{
  qas_seg_t qsort ;

  qsort = qset & qAS_CONFED ;

  for (; ptr < end ; ++ptr)
    {
      if ((src_path[ptr].qseg & qAS_CONFED) == qsort)
        {
          dst_path[len].asn   = src_path[ptr].asn ;
          dst_path[len].qseg  = qset ;
          dst_path[len].count = 1 ;

          ++len ;
          qset &= ~ qAS_SET_START ;
        } ;
    } ;

  return len ;
} ;

/*==============================================================================
 * Converting as_path to/from strings.
 *
 * Form is: string   is: item
 *                   or: item " " string
 *
 *          item     is: asn                     -- BGP_AS_SEQUENCE
 *                   or: "{" set_list "}"        -- BGP_AS_SET
 *                   or: "(" seq_list ")"        -- BGP_AS_CONFED_SEQUENCE
 *                   or: "[" set_list "]"        -- BGP_AS_CONFED_SET
 *
 *          set_list is: asn
 *                   or: asn "," set_list
 *
 *          seq_list is: asn
 *                   or: asn " " seq_list
 *
 *          asn      is: 1..((2^32)-1)         -- rejects 0, accepts hex
 *                   or: 0..65535 "." 0..65535 -- rejects 0, accpets hex
 *
 * where: " " is any combination of isspace() characters
 *
 *        "," is a comma or (in fact) " " -- so does not insist on ","
 *            separators in a set, but will not accept a trailing ",".
 *
 *        any number of isspace() characters may appear around and between
 *        items -- except for ".", which is deemed to be part of an ASN.
 *
 * NB: RFC5396 comes down in favour of "asplain" as the only notation.
 *
 *     This allows asdot+ and asdot -- but does not endorse it (!).
 */
static void as_path_make_str(as_path asp) ;

/*------------------------------------------------------------------------------
 * Create a new as_path from the given string.
 *
 * Accepts a NULL or an empty (apart from white-space) string, and returns
 * a new, empty (post-processed) as_path (not as_path_empty_asp).
 *
 * NB: rejects ASN == 0 (per draft-ietf-idr-as0).
 *
 * Returns:  new, post-processed, as_path
 *           NULL if the given string is not valid
 */
extern as_path
as_path_from_str(const char *str)
{
  as_path     asp ;
  asp_item_t* path ;
  qas_seg_t   qseg ;
  as_t        prev_asn ;
  uint        len ;
  char        sep ;
  char        ket ;
  char        ch ;
  bool        ok ;

  asp  = as_path_new(1) ;       /* set up to use embedded       */
  path = asp->path.body.v ;
  len  = 0 ;

  if (str == NULL)
    str = "" ;                  /* for completeness             */

  /* We start default type as AS_SEQUENCE.
   */
  qseg     = qAS_SEQUENCE;
  prev_asn = BGP_ASN_NULL ;

  sep  = ' ' ;          /* space separates items in sequences   */
  ket  = '\0' ;         /* not expecting a closing bracket      */
  ok   = true ;

  do
    {
      as_t        asn ;
      const char* end ;
      strtox_t    tox ;

      do
        ch = *str++ ;
      while (isspace((int)ch)) ;

      switch (ch)
        {
          case '0':
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9':
            asn = strtoul_xr(str - 1, &tox, &end, 0, BGP_AS4_MAX) ;

            if (tox != strtox_ok)
              {
                ok = false ;
                break ;
              } ;

            if (*end == '.')
              {
                if (asn > 0xFFFF)
                  {
                    ok = false ;
                    break ;
                  } ;

                asn = (asn << 16) + strtoul_xr(end + 1, &tox, &end, 0, 0xFFFF) ;

                if ((tox != strtox_ok) || (asn > BGP_AS4_MAX))
                  {
                    ok = false ;
                    break ;
                  } ;
              } ;

            if (asn == BGP_ASN_NULL)
              {
                ok = false ;
                break ;
              } ;

            str = end ;
            while (isspace((int)*str))
              ++str ;

            if (*str == sep)            /* NB: *str != ' '      */
              {
                /* If find a "separator" (ie ',') that may be followed by
                 * whitespace, and must then be followed by a digit.
                 */
                do
                  ch = *(++str) ;
                while (isspace((int)ch)) ;

                if ((ch < '0') || (ch > '9'))
                  {
                    ok = false ;
                    break ;
                  }
              } ;

            if (asn == prev_asn)
              {
                if (!(qseg & qAS_SET) && (path[len - 1].count
                                                             < as_max_count))
                  path[len - 1].count += 1 ;
              }
            else
              {
                prev_asn = asn ;

                if (len >= asp->path.size)
                  path = as_path_need(asp, len + 1) ;

                path[len].asn   = asn ;
                path[len].count = 1 ;
                path[len].qseg  = qseg ;

                len += 1 ;
                qseg &= ~qAS_SET_START ;
              } ;

            break ;

          case '{':
            ok = (ket == '\0') ;

            qseg     = qAS_SET | qAS_SET_START ;
            prev_asn = BGP_ASN_NULL ;
            sep      = ',' ;
            ket      = '}' ;
            break ;

          case '(':
            ok = (ket == '\0') ;

            qseg     = qAS_CONFED_SEQUENCE ;
            prev_asn = BGP_ASN_NULL ;
            sep      = ' ' ;
            ket      = ')' ;
            break ;

          case '[':
            ok = (ket == '\0') ;

            qseg     = qAS_CONFED_SET | qAS_SET_START ;
            prev_asn = BGP_ASN_NULL ;
            sep      = ',' ;
            ket      = ']' ;
            break ;

          case '}':
          case ')':
          case ']':
          case '\0':
            ok = (ket == ch) ;

            /* Note that we unset the prev_asn.  If we get two confed
             * sequences in a row we ought really to have preserved the
             * prev_asn state between the two... but if the last ASN of one
             * is the same as the first ASN of the next, the post-processing
             * will pick that up... so cannot be bothered with it here.
             */
            qseg     = qAS_SEQUENCE ;
            prev_asn = BGP_ASN_NULL ;
            sep      = ' ' ;
            ket      = '\0' ;
            break ;

          default:
            ok = false ;
            break ;
        } ;
    }
  while (ok && (ch != '\0')) ;

  qassert(len <= asp->path.size) ;
  asp->path.len = len ;

  if (ok)
    as_path_post_process(asp) ;
  else
    asp = as_path_free(asp) ;

  return asp ;
} ;

/*------------------------------------------------------------------------------
 * Get string version of given as_path.
 *
 * NB: NULL asp is invalid -- will crash !
 *
 * If required, construct it.
 *
 * Returns:  address of string -- an empty string if the path is empty.
 */
extern const char*
as_path_str(as_path asp)
{
  const char* str ;

  if ( (asp->state & (asps_string | asps_processed)) !=
                     (asps_string | asps_processed) )
    as_path_make_str(asp) ;

  str = qs_char_nn(asp->str) ;

  return (str != NULL) ? str : "" ;
} ;

/*------------------------------------------------------------------------------
 * Make string version of given as_path.
 *
 * NB: NULL asp is invalid -- will crash !
 */
static void
as_path_make_str(as_path asp)
{
  asp_item_t* path ;
  uint        ptr ;
  qas_seg_t   qseg ;
  char*       sp ;
  uint        len, size, need ;
  char        post, sep ;

  path = as_path_get_processed(asp) ;

  /* Have to generate a new string.
   *
   * Start by clearing the asp->str and with a guess as to the likely length.
   *
   * Vast majority of paths are simple BGP_AS_SEQUENCE, dominated by small
   * AS numbers -- so this guess is probably a little on the high side.
   */
  qs_new_size(asp->str, (asp->p.total_length * 8) + 1) ;

  /* Create string.
   *
   * The state to drive this is:
   *
   *    pre   -- character to precede the next asn
   *
   *             is '\0' at the start of a BGP_AS_SEQUENCE, and not at any
   *                     other time.
   *
   *             is '{' at the start of a BGP_AS_SET segment
   *
   *             is '(' at the start of a BGP_AS_CONFED_SEQUENCE segment
   *
   *             is '[' at the start of a BGP_AS_CONFED_SET segment
   *
   *             is ' ' or ',' after the start of a segment == sep
   *
   *    sep   -- is ' ' or ',', depending on the type of segment
   *
   *    post  -- character to terminate the current segment
   *
   *             '\0', '}', ')' or ']', depending on the type of segment.
   *
   * NB: a post-processed as_path does not contain any empty sequences or
   *     sets -- so no need to "debounce" the start/end of a segment.
   */
  sp   = qs_char_nn(asp->str) ;
  len  = 0 ;
  size = qs_size_nn(asp->str) ;

  sep  = post = '\0' ;
  qseg = qAS_SEG_NULL ;

  for (ptr = 0 ; ptr < asp->path.len ; ++ptr)
    {
      uint       count ;
      as_t       asn ;
      u32_buf_t  buf ;
      uint       l_asn ;
      char*      p_asn, *e_asn ;

      count = path[ptr].count ;
      asn   = path[ptr].asn ;

      if ((count == 0) || (asn == BGP_ASN_NULL))
        {
          /* A count of zero means the item has been dropped.  BGP_ASN_NULL
           * is meaningless.  Do not expect to find these, but do not want to
           * be tripped up !
           *
           * The only tricky bit is that if this is the start of set segment,
           * and we are currently in a set segment, then we need to terminate
           * the current set.
           */
          if ((qseg & qAS_SET) && (qseg != path[ptr].qseg))
            qseg = qAS_SEG_NULL ;

          continue ;
        } ;

      if (path[ptr].qseg == qseg)
        {
          /* No change of segment type (and no qAS_SET_START),
           * so put down separator.
           */
          qassert((len + 1) <= size) ;  /* We have space for 'sep'      */
          sp[len++] = sep ;
        }
      else
        {
          /* Change of segment type.
           *
           * Terminate previous segment (if any) and start a new one.
           *
           * Between end of one segment and start of the next we have a ' '.
           */
          need = len + 3 ;      /* Worst case: '>' ' ' '<' */

          if (need > size)
            {
              sp   = qs_extend(asp->str, need) ;
              size = qs_size_nn(asp->str) ;
            } ;

          if (post != '\0')
            sp[len++] = post ;          /* closing bracket      */

          if (len != 0)
            sp[len++] = ' ' ;

          qseg = path[ptr].qseg & ~qAS_SET_START ;

          switch(qseg)
            {
              case qAS_SEQUENCE:
                sep       = ' ' ;
                post      = '\0' ;
                break ;

              case qAS_SET:
                sp[len++] = '{' ;
                sep       = ',' ;
                post      = '}' ;
                break ;

              case qAS_CONFED_SEQUENCE:
                sp[len++] = '(' ;
                sep       = ' ' ;
                post      = ')' ;
                break ;

              case qAS_CONFED_SET:
                sp[len++] = '[' ;
                sep       = ',' ;
                post      = ']' ;
                break ;

              default:
                sp[len++] = '<' ;
                sep       = '?' ;
                post      = '>' ;
                break ;
            } ;
        } ;

      /* Construct decimal form of the ASN
       */
      e_asn = buf + sizeof(buf) ;
      p_asn = u32tostr(e_asn, asn, 10, false /* not uc */) ;
      l_asn = e_asn - p_asn ;

      /* Now work out space required in the buffer, and make sure we have that.
       *
       * NB: allocates space for a separator after each copy of the ASN,
       *     including the last one -- this is used at the top of the loop
       *     when separating the next ASN in the same segment.
       */
      need = len + ((l_asn + 1) * count) ;

      if (need > size)
        {
          sp   = qs_extend(asp->str, need) ;
          size = qs_size_nn(asp->str) ;
        } ;

      while (1)
        {
          memcpy(&sp[len], p_asn, l_asn) ;
          len += l_asn ;

          count -= 1 ;
          if (count == 0)
            break ;

          sp[len++] = sep ;
        } ;
    } ;

  need = len + ((post != '\0') ? 1 : 0) ;

  if (need >= size)             /* ensuring space for '\0'      */
    sp = qs_extend(asp->str, need) ;

  if (post != '\0')
    sp[len++] = post ;          /* closing bracket              */

  sp[len] = '\0' ;

  qs_set_len_nn(asp->str, len) ;

  /* Return result -- storing it first if is a stored as_path.
   */
  if (asp->stored)
    qs_store(asp->str) ;

  asp->state |= asps_string ;
} ;

/*==============================================================================
 * Printing functions
 */

/*------------------------------------------------------------------------------
 * Function to compare as_path objects by comparison of their string forms.
 */
static int
as_path_extract_cmp(const vhash_item_c* a, const vhash_item_c* b)
{
  as_path  asp_a = miyagi(*a) ;
  as_path  asp_b = miyagi(*b) ;

  const char* str_a ;
  const char* str_b ;

  str_a = as_path_str(asp_a) ;
  str_b = as_path_str(asp_b) ;

  return strcmp(str_a, str_b) ;
} ;

/*------------------------------------------------------------------------------
 * Print all aspath and hash information.
 */
extern void
as_path_print_all_vty (struct vty *vty)
{
  vector extract ;
  uint i ;

  extract = vhash_table_extract(as_path_vhash, NULL, NULL, true /* most */,
                                                          as_path_extract_cmp) ;

              /* 1234567890_12345678_12........*/
  vty_out (vty, "Hash       Refcnt   Path\n");

  for (i = 0 ; i < vector_length(extract) ; ++i)
    {
      as_path  asp ;

      asp = vector_get_item(extract, i) ;

      vty_out (vty, "[%8x] (%6u) %s\n", asp->vhash.hash, asp->vhash.ref_count,
                                                             as_path_str(asp)) ;
    } ;

  vector_free(extract) ;
} ;

/*==============================================================================
 * Post-processing and related functions
 */
static uint as_path_set_process(asp_item_t* path, uint ptr, uint next) ; ;

static const char* as_path_check_valid(as_path asp) ;

/*------------------------------------------------------------------------------
 * Get address of path, ensuring it has been post-processed.
 *
 * Returns:  address of post-processed body of path.
 *           can be NULL iff asp->path.size == 0 => asp->oath.len == 0
 */
inline static asp_item_t*
as_path_get_processed(as_path asp)
{
  asp_item_t* path ;

  if (!(asp->state & asps_processed))
    as_path_post_process(asp) ;

  path = asp->path.body.v ;

  if (asp->path.size != 0)
    qassert(path != NULL) ;
  qassert(asp->path.len <= asp->path.size) ;

  return path ;
} ;

/*------------------------------------------------------------------------------
 * Post process the given as_path
 *
 *   * sort and remove duplicates from any BGP_AS_SET and BGP_AS_CONFED_SET
 *
 *     Maintains the rule that adjoining sets cannot be joined, but will
 *     discard sets which are (now) empty.
 *
 *   * merge repeated ASN
 *
 *   * drop any ASN with count == 0 and any BGP_ASN_NULL
 *
 *   * count things and set:
 *
 *       asp->state     = asps_processed (all other state is cleared)
 *
 *       asp->p.simple_sequence  = true iff the as_path is a single
 *                                 BGP_AS_SEQUENCE, or is empty.
 *
 *       asp->p.total_length     = asp->p.simple.length + asp->p.confed.length
 *
 *       asp->p.left_most_asn    = if have confed: asp->p.confed.left_most_asn
 *                                           else: asp->p.simple.left_most_asn
 *
 *       asp->p.simple:
 *
 *         .length       = number of ASN (including repeats) in any
 *                         BGP_AS_SEQUENCE segments plus the the number
 *                         of BGP_AS_SET segments.
 *
 *                         ie: the AS_PATH length for selection purposes,
 *                             not counting any Confed stuff.
 *
 *         .seq_count    = number of BGP_AS_SEQUENCE segments
 *
 *         .set_count    = number of BGP_AS_SET segments
 *
 *         .first_seg    = type of first simple segment, if any
 *                         BGP_AS_SEG_NULL <=> none
 *
 *         .first        = offset in the path of the first simple segment.
 *
 *         .last         = offset in the path of the end + 1 of the last
 *                         simple segment.
 *
 *                         0 <=> there are no simple segments
 *
 *         .first_asn    = if the first simple segment is BGP_AS_SEQUENCE, then
 *                         this is the first ASN in that segment.
 *
 *                         Is BGP_ASN_NULL otherwise.
 *
 *       asp->p.confed:
 *
 *         .length       = number of ASN (including repeats) in any
 *                         BGP_AS_CONFED_SEQUENCE segments plus the the number
 *                         of BGP_AS_CONFED_SET segments.
 *
 *                         ie: the extra AS_PATH length for selection purposes,
 *                             if Confed stuff is counted.
 *
 *         .seq_count    = number of BGP_AS_CONFED_SEQUENCE segments
 *
 *         .set_count    = number of BGP_AS_CONFED_SET segments
 *
 *         .first_seg    = type of first confed segment, if any
 *                         BGP_AS_SEG_NULL <=> none
 *
 *         .first        = offset in the path of the first confed segment.
 *
 *         .last         = offset in the path of the end + 1 of the last
 *                         confed segment.
 *
 *                         0 <=> there are no confed segments
 *
 *         .first_asn    = if the first segment is BGP_AS_CONFED_SEQUENCE, then
 *                         this is the first ASN in that segment.
 *
 *                         Is BGP_ASN_NULL otherwise.
 *
 *                         NB: confed stuff should only appear at the front
 *                             of an AS_PATH -- so confed.first_asn is set
 *                             *only* if the absolutely first segment is a
 *                             BGP_AS_CONFED_SEQUENCE.  This is unlike
 *                             simple.first_asn, which is set if the first
 *                             simple segment is a BGP_AS_SEQUENCE.
 *
 * Operations which change an as_path must clear the asps_processed state.
 * The changes do not have to worry about maintaining the as_path in canonical
 * form, or about the various counts, where it is required the as_path will be
 * post_processed here.  Changes to an as_path must take into consideration:
 *
 *   * adding a sequence item is straightforward.
 *
 *     If it is next to or between items of the same sequence type it will be
 *     included in that segment, and if the ASN is, in fact, a repeat the
 *     post-processing will amalgamate the items.
 *
 *     If it is between items of set type then it splits the set, and post-
 *     processing will add the required qAS_SET_START.
 *
 *     If the objective is to permanently split a set, then it would be best
 *     to set the qAS_SET_START explicitly -- because adding and then
 *     removing a sequence item would return the set to its old state.
 *
 *   * adding a set item is pretty straightforward.
 *
 *     However, need to be careful about the qAS_SET_START state, and
 *     to be clear about when a set item is to be the start of a new set, or
 *     part of an existing one.
 *
 *   * setting a count of 0 (or setting the ASN to BGP_ASN_NULL) renders the
 *     item invisible, except for its qseg and qAS_SET_START.
 *
 *     When post-processing or sweeping an as_path, any qAS_SET_START
 *     on a "dropped" item is moved forward to the first not-dropped item of
 *     the same type -- but discarded if finds an item of a different type.
 *
 * In other words, where an as_path function is prepared to operate on as_path
 * which has not been post-processed, it may see:
 *
 *   * dropped items (count == 0)
 *
 *   * possibly BGP_ASN_NULL asn
 *
 *   * repeated ASN
 *
 *   * "missing" qAS_SET_START
 *
 * Confederation stuff should only appear at the front of an AS_PATH.  The
 * first item in a confederation AS_PATH should only be a BGP_CONFED_SEQUENCE,
 * and that should not be empty.  However, checking for all that is left to
 * a higher level of (semantic) checking.
 *
 * FWIW, if you thought BGP_AS_SETs were rare... BGP_AS_CONFED_SETs are
 * probably only seen in test suites.
 *
 * Returns:  true <=> all OK.
 *           false => the as_path is broken, and should not be used.
 */
static void
as_path_post_process(as_path asp)
{
  asp_item_t* path ;
  uint        ptr, len, prev_ptr, drop ;
  as_t        prev_asn ;
  qas_seg_t   qseg ;

  /* Re-initialise all the state that the post_processor creates
   *
   * Zeroizing the as_path_properties sets:
   *
   *   * simple_sequence          -- X       -- initialised true, below
   *
   *   * total_length             -- 0
   *
   *   * left_most_asn            -- BGP_ASN_NULL    <=> none
   *
   *   * simple.length            -- 0
   *     simple.seq_count         -- 0
   *     simple.set_count         -- 0
   *     simple.first_seg         -- BGP_AS_SEG_NULL <=> none
   *     simple.first             -- 0
   *     simple.last              -- 0
   *     simple.first_asn         -- BGP_ASN_NULL    <=> none
   *
   *   * confed stuff             -- as above
   */
  confirm(BGP_AS_SEG_NULL == 0) ;
  confirm(BGP_ASN_NULL    == 0) ;

  memset(&asp->p, 0, sizeof(as_path_properties_t)) ;

  asp->p.simple_sequence = true ;       /* so far, so good              */

  /* Crunch through the path
   *
   * Note that the processing loop expects the as_path to be in good shape
   * most of the time -- so where the as_path has to be changed, it is
   * adjusted in place, using the drop mechanism.
   *
   * This loop counts up the asp->p.total_length, and clears
   * asp->p.simple_sequence if we get anything other than qAS_SEQUENCE.
   */
  prev_asn   = BGP_ASN_NULL ;           /* no previous                  */
  prev_ptr   = 0 ;                      /* tidy                         */

  qseg       = qAS_SEQUENCE ;           /* hope for simple path         */

  path = asp->path.body.v ;
  len  = asp->path.len ;
  drop = len ;                          /* nothing dropped, yet         */
  ptr  = 0 ;

  while (ptr < len)
    {
      uint count ;
      as_t asn ;

      asn   = path[ptr].asn ;
      count = path[ptr].count ;

      if ((count == 0) || (asn == BGP_ASN_NULL))
        {
          /* Ignore dropped or invalid ASN items -- swept up later.
           *
           * Note that when we process sets, we eat all items up to the start
           * of the next segment, so do not need to worry about the set start
           * bit here.
           */
          if (drop > ptr)
            drop = ptr ;

          ++ptr ;
          continue ;
        } ;

      if (path[ptr].qseg != qseg)
        {
          /* Start of a new segment -- change of segment type, or start of set
           *
           * Can no longer be a simple_sequence !
           *
           * NB: does not require the first item in a set to have the start
           *     bit set, but does set the bit.
           */
          uint next ;

          asp->p.simple_sequence = false ;

          qseg = path[ptr].qseg & ~qAS_SET_START ;
          prev_asn = BGP_ASN_NULL ;

          switch (qseg)
            {
              case qAS_SEQUENCE:
              case qAS_CONFED_SEQUENCE:
                break ;

              case qAS_SET:
              case qAS_CONFED_SET:
                /* Eat the entire set here, sorting and de-dupping in the
                 * process.
                 *
                 * We have 'ptr' pointing at the first (and possibly only) ASN
                 * in the set.
                 *
                 * We have 'qseg' set to the qAS_SEG_SET_XXXX value for the
                 * set, less the qAS_SET_START.  So, all the items
                 * which live with the first in the set will match the current
                 * 'qseg'.
                 *
                 * We skim forward to the first item which is not part of the
                 * set, then hand the set to as_path_set_process().  That
                 * returns the ptr to the first item which is to be dropped as
                 * a result, if any.
                 *
                 * May eat stuff which has been dropped here, too and that will
                 * be discarded as the set is sorted and dedupped.
                 *
                 * Note that as_path_set_process() sets qAS_SET_START
                 * on the result first item in the set.
                 */
                 asp->p.total_length += 1 ;

                 next = ptr + 1 ;
                 while ((next < len) && (path[next].qseg == qseg))
                   ++next ;

                 ptr = as_path_set_process(path, ptr, next) ;

                 if ((ptr != next) && (drop > ptr))
                   drop = ptr ;

                 ptr  = next ;
                 qseg = qAS_SEQUENCE ;

                 /* NB: this is a bit dirty -- we crash out of the switch and
                  *     out of the enclosing 'if', to return to the outside
                  *     enclosing 'while'.
                  *
                  * We continue with qseg = qAS_SEQUENCE, because if the
                  * next item is such there is no further work to do, and if
                  * the next item is not, we get to see it here.
                  */
                 continue ;

              default:
                /* Really should not be here... this means we have an invalid
                 * qseg value in an as_path item.
                 *
                 * NB: this is also dirty -- crashes out to the enclosing
                 *    'while'.
                 */
                qassert(false) ;

                path[ptr].count = 0 ;           /* arrange to drop      */
                drop = 0 ;                      /* signal drop          */

                qseg = qAS_SEQUENCE ;       /* default              */

                ++ptr ;                         /* step past broken     */

                continue ;
            } ;
        } ;

      /* Continuing in the current segment -- must be a sequence.
       */
      qassert( (qseg = qAS_SEQUENCE) ||
               (qseg = qAS_CONFED_SEQUENCE) ) ;

      if (asn != prev_asn)
        {
          /* Not a repeat of the previous ASN, so add to the count
           * (looking out for invalid same), and continue.
           */
          if (count > as_max_count)
            count = path[ptr].count = as_max_count ;

          asp->p.total_length += count ;

          prev_asn = asn ;          /* in case next ASN is a repeat */
          prev_ptr = ptr ;          /* ditto                        */
        }
      else
        {
          /* We have a repeat of the previous ASN.
           *
           * We don't expect this to happen much -- the parsing of
           * AS_PATH attributes and the reading of strings will spot most
           * repeats.  So this is really to trap repeats created by
           * prepending/appending paths or other such path operations.
           */
          uint  prev_count ;

          prev_count = path[prev_ptr].count ;

          count += prev_count ;

          if (count > as_max_count)
            count = as_max_count ;

          asp->p.total_length += (count - prev_count) ;
          path[prev_ptr].count = count ;

          path[ptr].count = 0 ;

          if (drop > ptr)
            drop = ptr ;
        } ;

      ++ptr ;                       /* step past item               */
    } ;

  /* Sweep up if we dropped anything.
   */
  if (drop < len)
    len = as_path_sweep(asp, drop) ;

  /* We now have a post-processed as_path in canonical form.
   *
   * Worry about the properties of the as_path.
   */
  if (asp->p.simple_sequence)
    {
      /* For a not-empty simple_sequence:
       *
       *  * the simple.length is the same as the total_length
       *
       *  * the simple.first_asn and the left_most_asn are the same, and are
       *    the first ASN in the (not empty) as_path.
       *
       *  * there are no confed things to worry about, so that is left all
       *    zeros.
       */
      if (len != 0)
        {
          asp->p.simple.length    = asp->p.total_length ;
          asp->p.simple.seq_count = 1 ;
          asp->p.simple.first_seg = BGP_AS_SEQUENCE ;
          asp->p.simple.last      = len ;
          asp->p.simple.first_asn = asp->p.left_most_asn = path[0].asn ;
        } ;
    }
  else
    {
      /* For a not-simple sequence we need to rescan the now canonical form,
       * and extract the properties.
       */
      uint* p_last ;

      p_last = &asp->p.simple.last ;
      qseg = qAS_SEG_NULL ;

      for (ptr = 0 ; ptr < len ; ++ptr)
        {
          switch (path[ptr].qseg)
            {
              case qAS_SEQUENCE:
                if (qseg != qAS_SEQUENCE)
                  {
                    *p_last = ptr ;

                    if (asp->p.simple.first_seg == BGP_AS_SEG_NULL)
                      {
                        asp->p.simple.first     = ptr ;
                        asp->p.simple.first_seg = BGP_AS_SEQUENCE ;

                        asp->p.simple.first_asn = path[ptr].asn ;

                        if (asp->p.confed.first_seg == BGP_AS_SEG_NULL)
                          asp->p.left_most_asn = path[ptr].asn  ;
                      } ;

                    asp->p.simple.seq_count += 1 ;

                    p_last = &asp->p.simple.last ;
                    qseg = qAS_SEQUENCE ;
                  } ;

                asp->p.simple.length += path[ptr].count ;
                break ;

              case qAS_CONFED_SEQUENCE:
                if (qseg != qAS_CONFED_SEQUENCE)
                  {
                    *p_last = ptr ;

                    if (asp->p.confed.first_seg == BGP_AS_SEG_NULL)
                      {
                        asp->p.confed.first     = ptr ;
                        asp->p.confed.first_seg = BGP_AS_CONFED_SEQUENCE ;

                        if (asp->p.simple.first_seg == BGP_AS_SEG_NULL)
                          {
                            asp->p.confed.first_asn = path[ptr].asn ;
                            asp->p.left_most_asn    = path[ptr].asn ;
                          } ;
                      } ;

                    asp->p.confed.seq_count += 1 ;

                    p_last = &asp->p.confed.last ;
                    qseg = qAS_CONFED_SEQUENCE ;
                  } ;

                asp->p.confed.length += path[ptr].count ;
                break ;

              case qAS_SET | qAS_SET_START:
                *p_last = ptr ;

                if (asp->p.simple.first_seg == BGP_AS_SEG_NULL)
                  {
                    asp->p.simple.first     = ptr ;
                    asp->p.simple.first_seg = BGP_AS_SET ;
                  } ;

                 asp->p.simple.set_count += 1 ;
                 asp->p.simple.length    += 1 ;

                 p_last = &asp->p.simple.last ;
                 qseg = qAS_SET ;
                 break ;

              case qAS_SET:
                qassert(qseg == qAS_SET) ;
                break ;

              case qAS_CONFED_SET | qAS_SET_START:
                *p_last = ptr ;

                if (asp->p.confed.first_seg == BGP_AS_SEG_NULL)
                  {
                    asp->p.confed.first     = ptr ;
                    asp->p.confed.first_seg = BGP_AS_CONFED_SET ;
                  } ;

                asp->p.confed.set_count += 1 ;
                asp->p.confed.length    += 1 ;

                p_last = &asp->p.confed.last ;
                qseg = qAS_CONFED_SET ;
                break ;

              case qAS_CONFED_SET:
                qassert(qseg == qAS_CONFED_SET) ;
                break ;

              default:
                qassert(false) ;
                continue ;
            } ;
        } ;

      *p_last = len ;
    } ;

  if (qdebug)
    {
      const char* msg ;

      msg = as_path_check_valid(asp) ;

      if (msg != NULL)
        zabort(msg) ;
    } ;

  asp->state = asps_processed ;
} ;

/*------------------------------------------------------------------------------
 * Sweep given path, removing any items with asn == BGP_ASN_NULL.
 *
 * The only tricky thing about this is dealing with dropping of the start
 * of a set segment -- where that start needs to be propagated forward.
 *
 * Starts scanning from the given start position -- can simply start at the
 * beginning, but may wish to start at the known first "dropped" item.
 *
 * There does not have to be anything to drop, but if there is, clears the
 * state down to asps_raw.
 *
 * Requires that the asp->path.len is up to date.
 *
 * Returns:  new length of path
 *
 * NB: address of path body does NOT change.
 *
 * NB: MUST NOT be stored !
 */
static ulen
as_path_sweep(as_path asp, ulen start)
{
  asp_item_t* path ;
  uint len, scan, old_len ;

  qassert(!asp->stored) ;

  path = asp->path.body.v ;

  len     = start ;
  old_len = asp->path.len ;

  scan = start ;
  while (scan < old_len)
    {
      if ((path[scan].count != 0) && (path[scan].asn != BGP_ASN_NULL))
        path[len++] = path[scan++] ;
      else
        {
          asp->state = asps_raw ;

          if (!(path[scan].qseg & qAS_SET_START))
            scan++ ;                    /* step past the dropped item   */
          else
            {
              /* Special case of dropping a set start.
               *
               * Need to scan forwards to find an item which is in this set
               * and not about to be dropped, or another segment, or the end
               * of the path.
               */
              qas_seg_t  qseg ;

              qseg = path[scan].qseg & ~qAS_SET_START ;
              scan++ ;                    /* step past the dropped item   */

              while (scan < old_len)
                {
                  /* Will not propagate a set start past a different segment,
                   * or another start for the same type of segment
                   */
                  if (path[scan].qseg != qseg)
                    break ;

                  if ((path[scan].count != 0) &&
                                               (path[scan].asn != BGP_ASN_NULL))
                    {
                      /* We have a significant item, of the same type as the
                       * item that used to have the qAS_SET_START bit, so we
                       * can move it here.
                       *
                       * We can move the significant item before returning
                       * to the main loop.
                       */
                      path[scan].qseg = qseg | qAS_SET_START ;

                      path[len++] = path[scan++] ;
                      break ;
                    } ;

                  /* Found another item to drop, in the same set.
                   */
                  scan++ ;              /* step past the dropped item   */
                } ;
            } ;
        } ;
    } ;

  return asp->path.len = len ;
} ;

/*------------------------------------------------------------------------------
 * Sort the ASN in the given set, and then drop any duplicates.
 *
 * Entered with start = first item to consider, and next = last + 1.
 *
 * The stuff between start and last may contain items which should be dropped.
 *
 * Returns:  index of end of set -- which may be less than original last,
 *           if stuff was and/or is now to be dropped.
 */
static int
as_item_cmp(const void* pa, const void* pb)
{
  as_t a = ((const asp_item_t*)pa)->asn ;
  as_t b = ((const asp_item_t*)pb)->asn ;

  if (a != b)
    return (a < b) ? -1 : +1 ;

  return 0 ;
} ;

static uint
as_path_set_process(asp_item_t* path, uint start, uint next)
{
  uint ptr ;
  as_t prev_asn ;
  qas_seg_t qseg ;

  qseg = path[start].qseg & ~qAS_SET_START ;

  /* We scan to see if is all in order already.
   *
   * Each item must not be BGP_ASN_NULL and must be greater than the previous
   * one and the count must not be zero.  By starting with BGP_ASN_NULL the
   * scan naturally eliminates that.
   *
   * In the process we discard any repeats.
   */
  prev_asn = BGP_ASN_NULL ;
  confirm(BGP_ASN_NULL == 0) ;

  for (ptr = start ; ptr < next ; ++ptr)
    {
      if (path[ptr].count != 1)
        {
          if (path[ptr].count == 0)
            break ;
          else
            path[ptr].count = 1 ;
        } ;

      if (path[ptr].asn <= prev_asn)
        break ;

      prev_asn = path[ptr].asn ;

      if (ptr != start)
        qassert(path[ptr].qseg == qseg) ;
    } ;

  /* If the scan did not complete, we need to do something with the set.
   */
  if (ptr != next)
    {
      uint      scan ;

      path[start].qseg = qseg ;         /* clear start mark before sort */

      /* We start by making sure that the set is in ascending order of ASN.
       */
      qsort(&path[start], next - start, sizeof(asp_item_t), as_item_cmp) ;

      /* Now scan to eliminate BGP_ASN_NULL, counts of zero, and any repeated
       * ASN.  In the process, make sure all counts that remain are 1.
       */
      prev_asn = BGP_ASN_NULL ;
      ptr = start ;
      for (scan = start ; scan < next ; ++scan)
        {
          as_t asn ;

          asn = path[scan].asn ;

          if ((asn > prev_asn) && (path[scan].count != 0))
            {
              qassert(path[scan].qseg == qseg) ;

              path[ptr].asn   = asn ;
              path[ptr].count = 1 ;
              path[ptr].qseg  = qseg ;

              prev_asn = asn ;
              ptr += 1 ;
            } ;
        } ;

      /* If we have dropped one or more items, clear out those items.
       */
      if (ptr < next)
        memset(&path[ptr], 0, sizeof_asp_items(next - ptr)) ;
    } ;

  /* The set is already all in order.
   *
   * 'ptr' points to the last item in the set + 1
   *
   * Make sure that the qAS_SET_START is set, and we are done.
   */
  path[start].qseg = qseg | qAS_SET_START ;

  return ptr ;
} ;

/*------------------------------------------------------------------------------
 * Check that the given as_path is valid.
 *
 * If is not "processed", then will check for:
 *
 *   * all path[i].qseg valid
 *
 * and nothing else.
 *
 * If is "processed", then will check for:
 *
 *   * no BGP_ASN_NULL
 *
 *   * count == 1 on every set item
 *
 *   * count >= 1 and <= as_count_max on every sequence item
 *
 *   * sets in ascending ASN order and all ASN unique.
 *
 *   * all path[i].qseg valid -- including qAS_SET_START if a set
 *                               item is preceded by a sequence, or is the
 *                               first item.
 *
 *   * all properties valid
 *
 * Returns:  NULL <=> OK
 *           Otherwise is address of short message.
 */
static const char*
as_path_check_valid(as_path asp)
{
  asp_item_t* path ;
  uint        ptr, len ;
  bool        processed, seen_simple, seen_confed ;
  as_path_properties_t p ;

  const char* err_msg = NULL ;

  memset(&p, 0, sizeof(as_path_properties_t)) ;

  path = asp->path.body.v ;
  len  = asp->path.len ;

  if (asp->path.size != 0)
    qassert(asp->path.body.v != NULL) ;
  qassert(asp->path.len <= asp->path.size) ;    /* always       */

  processed = (asp->state & asps_processed) ;
  seen_simple = seen_confed = false ;

  ptr = 0 ;
  while (ptr < len)
    {
      as_t prev_asn ;

      switch (path[ptr].qseg)
        {
          case qAS_SEQUENCE:
            if (!seen_simple)
              {
                p.simple.first     = ptr ;
                p.simple.first_seg = BGP_AS_SEQUENCE ;

                p.simple.first_asn = path[ptr].asn ;
                if (!seen_confed)
                  p.left_most_asn  = path[ptr].asn ;

                seen_simple = true ;
              } ;

            p.simple.seq_count += 1 ;

            do
              {
                if (processed)
                  {
                    if (path[ptr].count == 0)
                      return "found count == 0 in qAS_SEG_SEQUENCE" ;
                    if (path[ptr].count > as_max_count)
                      return "found count > max in qAS_SEG_SEQUENCE" ;
                    if (path[ptr].asn == BGP_ASN_NULL)
                      return "found BGP_ASN_NULL in qAS_SEG_SEQUENCE" ;
                  }
                p.simple.length += path[ptr].count ;

                ++ptr ;
              }
            while ((ptr < len) && (path[ptr].qseg == qAS_SEQUENCE)) ;

            p.simple.last = ptr ;
            break ;

          case qAS_SET | qAS_SET_START:
            if (!seen_simple)
              {
                p.simple.first     = ptr ;
                seen_simple = true ;
              } ;

            p.simple.set_count += 1 ;
            p.simple.length    += 1 ;

            prev_asn = BGP_ASN_NULL ;
            do
              {
                if (processed)
                  {
                    if (path[ptr].count == 0)
                      return "found count == 0 in qAS_SEG_SET" ;
                    if (path[ptr].count > 1)
                      return "found count > 1 in qAS_SEG_SET" ;
                    if (path[ptr].asn <= BGP_ASN_NULL)
                      return "found BGP_ASN_NULL in qAS_SEG_SET" ;
                    if (path[ptr].asn <= prev_asn)
                      return "found out of order ASN in qAS_SEG_SET" ;
                  }

                ++ptr ;
              }
            while ((ptr < len) && (path[ptr].qseg == qAS_SET)) ;

            p.simple.last = ptr ;
            break ;

          case qAS_SET:
            if (processed)
              return "found out of place qAS_SEG_SET" ;

            ++ptr ;
            break ;

          case qAS_CONFED_SEQUENCE:
            if (!seen_confed)
              {
                p.confed.first     = ptr ;
                p.confed.first_seg = BGP_AS_CONFED_SEQUENCE ;

                if (!seen_simple)
                  {
                    p.confed.first_asn = path[ptr].asn ;
                    p.left_most_asn    = path[ptr].asn ;
                  } ;

                seen_confed = true ;
              } ;

            p.confed.seq_count += 1 ;

            do
              {
                if (processed)
                  {
                    if (path[ptr].count == 0)
                      return "found count == 0 in qAS_SEG_CONFED_SEQUENCE" ;
                    if (path[ptr].count > as_max_count)
                      return "found count > max in qAS_SEG_CONFED_SEQUENCE" ;
                    if (path[ptr].asn == BGP_ASN_NULL)
                      return "found BGP_ASN_NULL in qAS_SEG_CONFED_SEQUENCE" ;
                  }
                p.confed.length += path[ptr].count ;

                ++ptr ;
              }
            while ((ptr < len) && (path[ptr].qseg == qAS_CONFED_SEQUENCE)) ;

            p.confed.last = ptr ;
            break ;

          case qAS_CONFED_SET | qAS_SET_START:
            if (!seen_confed)
              {
                p.confed.first     = ptr ;
                seen_confed = true ;
              } ;

            p.confed.set_count += 1 ;
            p.confed.length    += 1 ;

            prev_asn = BGP_ASN_NULL ;
            do
              {
                if (processed)
                  {
                    if (path[ptr].count == 0)
                      return "found count == 0 in qAS_SEG_CONFED_SET" ;
                    if (path[ptr].count > 1)
                      return "found count > 1 in qAS_SEG_CONFED_SET" ;
                    if (path[ptr].asn <= BGP_ASN_NULL)
                      return "found BGP_ASN_NULL in qAS_SEG_CONFED_SET" ;
                    if (path[ptr].asn <= prev_asn)
                      return "found out of order ASN in qAS_SEG_CONFED_SET" ;
                  }

                ++ptr ;
              }
            while ((ptr < len) && (path[ptr].qseg == qAS_CONFED_SET)) ;

            p.confed.last = ptr ;
            break ;

          case qAS_CONFED_SET:
            if (processed)
              return "found out of place qAS_SEG_CONFED_SET" ;

            ++ptr ;
            break ;

          default:
            return "found invalid qseg value" ;
        } ;
    } ;

  if ((err_msg == NULL) && processed)
    {
      p.simple_sequence = (p.simple.set_count + p.confed.set_count
                                              + p.confed.seq_count) == 0 ;

      p.total_length  = p.confed.length + p.simple.length ;

      if (err_msg == NULL)
        {
          if      (p.total_length  != asp->p.total_length)
            err_msg = "total_length incorrect" ;
          else if (p.simple.length != asp->p.simple.length)
            err_msg = "simple.length incorrect" ;
          else if (p.confed.length != asp->p.confed.length)
            err_msg = "confed.length incorrect" ;
          else if (p.simple.seq_count != asp->p.simple.seq_count)
            err_msg = "simple.seq_count incorrect" ;
          else if (p.simple.set_count != asp->p.simple.set_count)
            err_msg = "simple.set_count incorrect" ;
          else if (p.confed.seq_count != asp->p.confed.seq_count)
            err_msg = "confed.seq_count incorrect" ;
          else if (p.confed.set_count != asp->p.confed.set_count)
            err_msg = "confed.set_count incorrect" ;
          else if (p.simple_sequence  != asp->p.simple_sequence)
            err_msg = "disagree about whether simple" ;
        } ;
    } ;

  return err_msg ;
} ;

/*==============================================================================
 * The asn_set structure handling
 *
 * Kept as a qlump of as_t values, sorted so can be searched by binary chop.
 *
 * The body of an asn_set is a qlump.
 */

/*------------------------------------------------------------------------------
 * Create a new, empty asn_set.
 *
 * If have an idea of how many ASN there will be -- then will allocate for that.
 */
static asn_set
asn_set_new(uint n)
{
  asn_set new ;

  new = XCALLOC(MTYPE_ASN_SET, sizeof(asn_set_t)) ;

  /* Zeroizing has set:
   *
   *    * set            -- X     -- initialised below
   *
   *    * searchable     -- false
   *
   *    * embedded_set   -- X     -- initialised below
   */
  qlump_init(&new->set, n, MTYPE_ASN_SET_BODY) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Free given asn_set and any allocated body and other dependent data.
 *
 * Returns:  NULL
 */
extern asn_set
asn_set_free(asn_set asns)
{
  if (asns != NULL)
    {
      qlump_free_body(&asns->set) ;

      XFREE(MTYPE_ASN_SET, asns) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Add given ASN to the given asn_set -- create asn_set if required.
 *
 * Simply appends the given ASN to the set.  When the set is searched, it will
 * be resorted and de-dupped.
 *
 * Returns:  address of (possibly new) asn_set
 */
extern asn_set
asn_set_add(asn_set asns, as_t asn)
{
  as_t* set ;

  if (asns == NULL)
    asns = asn_set_new(1) ;
  else
    asns->searchable = false ;

  if (asns->set.len >= asns->set.size)
    qlump_extend(&asns->set, asns->set.len + 1, MTYPE_ASN_SET_BODY) ;

  set = asns->set.body.v ;
  set[asns->set.len++] = asn ;

  return asns ;
} ;

/*------------------------------------------------------------------------------
 * Comparison for asn_set items
 */
static int
asn_cmp(const void* pa, const void* pb)
{
  as_t a = *(const as_t*)pa ;
  as_t b = *(const as_t*)pb ;

  if (a != b)
    return (a < b) ? -1 : +1 ;
  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Sort and dedup the given asn_set -- and set searchable.
 */
static void
asn_set_sort_dedup(asn_set asns)
{
  qlump_sort_dedup(&asns->set, asn_cmp) ;
  asns->searchable = true ;
} ;


/*------------------------------------------------------------------------------
 * Delete given ASN from the given asn_set.
 *
 * Does nothing if the asn_set is NULL or otherwise empty, and does nothing
 * if the ASN is not present in the asn_set.
 *
 * Returns:  true <=> asn was in the asn_set.
 */
extern bool
asn_set_del(asn_set asns, as_t asn)
{
  int  result ;
  uint index ;

  if (asns == NULL)
    return false ;

  if (!asns->searchable)
    asn_set_sort_dedup(asns) ;

  index = qlump_bsearch(&asns->set, asn_cmp, &asn, &result) ;

  if (result != 0)
    return false ;              /* not there    */

  qlump_drop_items(&asns->set, index, 1) ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Is given ASN a member of the given asn_set (if any)
 *
 * Returns:  true <=> given ASN is a member of the asn_set
 */
extern bool
asn_set_contains(asn_set asns, as_t asn)
{
  int  result ;

  if ((asns == NULL) || (asns->set.len == 0))
    return false ;

  if (!asns->searchable)
    asn_set_sort_dedup(asns) ;

  qlump_bsearch(&asns->set, asn_cmp, &asn, &result) ;

  return result == 0 ;
} ;

/*------------------------------------------------------------------------------
 * Sort and dedup given asn set (if any) and return length
 *
 * Returns:  number of unique asns in the set (0 if asns NULL or empty)
 */
extern uint
asn_set_get_len(asn_set asns)
{
  if (asns == NULL)
    return 0 ;

  if (!asns->searchable)
    asn_set_sort_dedup(asns) ;

  return asns->set.len ;
} ;

/*------------------------------------------------------------------------------
 * Get 'ith' ASN from the given set.
 *
 * Returns:  ASN -- BGP_ASN_NULL if asns NULL or index >= set length
 */
extern as_t
asn_set_get_asn(asn_set asns, uint index)
{
  if ((asns == NULL) || (asns->set.len <= index))
    return BGP_ASN_NULL ;

  return ((as_t*)asns->set.body.v)[index] ;
} ;

/*------------------------------------------------------------------------------
 * Construct asn_set from the given string
 */
extern asn_set
asn_set_from_str(const char* str)
{
  as_path     asp ;
  asn_set     asns ;
  asp_item_t* path ;
  uint        ptr ;

  /* Start by converting the string into an as_path, but we only accept a
   * simple list of ASN -- which is a simple_sequence as far as the as_path
   * is concerned.
   */
  asp = as_path_from_str(str) ;

  if (asp == NULL)
    return NULL ;

  if (!asp->p.simple_sequence && (asp->p.total_length != 0))
    {
      as_path_free(asp) ;
      return NULL ;
    } ;

  /* Create the asn_set, copy the ASN across.
   *
   * Note that we assume the as path doesn't have duplicates or other nonsense,
   * so we create an asn_set using the length of the as_path.
   */
  asns = asn_set_new(asp->p.simple.length) ;

  path = asp->path.body.v ;
  for (ptr = 0 ; ptr < asp->path.len ; ++ptr)
    asn_set_add(asns, path[ptr].asn) ;

  as_path_free(asp) ;

  return asns ;
}

/*==============================================================================
 * Support for snmp.
 */

/*------------------------------------------------------------------------------
 * This is for SNMP BGP4PATHATTRASPATHSEGMENT
 * Creates a new as_path if src is "stored", otherwise operates on the current
 * src.
 *
 * We have no way to manage the storage, so we use a static stream
 * wrapper around aspath_put.
 */
extern byte*
as_path_snmp_pathseg (as_path asp, size_t* p_size)
{
  as_path_out_t out[1] ;

  if (asp == NULL)
    {
      *p_size = 0;
      return NULL;
    }

  out->seg   = BGP_AS_SEG_NULL ;
  out->prepend_count = 0 ;
  as_path_out_prepare(out, asp, false /* AS2 pro tem */) ;

  if (snmp_stream == NULL)
    snmp_stream = stream_new(1000);
  else
    stream_reset (snmp_stream);

  stream_put(snmp_stream, out->part[0], out->len[0]) ;
  stream_put(snmp_stream, out->part[1], out->len[1]) ;

  *p_size = stream_get_endp (snmp_stream);

  return stream_get_pnt(snmp_stream);
} ;

/*==============================================================================
 * Interfaces for test purposes only.
 */
extern void
as_path_post_process_tx(as_path asp)
{
  as_path_post_process(asp) ;
} ;

extern as_path
as_path_prepend_tx(as_path asp, as_seg_t seg, as_t asn, uint count)
{
  return as_path_prepend(asp, seg, asn, count) ;
} ;

extern const char*
as_path_check_valid_tx(as_path asp, bool set_last_seg, bool valid)
{
  return as_path_check_valid_tx(asp, set_last_seg, valid) ;
} ;
