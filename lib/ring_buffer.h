/* Ring Buffer -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_RING_BUFFER_H
#define _ZEBRA_RING_BUFFER_H

#include "misc.h"
#include "memory.h"

/*------------------------------------------------------------------------------
 * Sort out RING_BUFFER_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if RING_BUFFER_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set RING_BUFFER_DEBUG    == 0 to turn off debug
 *       *  or set RING_BUFFER_DEBUG    != 0 to turn on debug
 *       *  or set RING_BUFFER_NO_DEBUG != 0 to force debug off
 */

#ifdef RING_BUFFER_DEBUG          /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(RING_BUFFER_DEBUG)
#  undef  RING_BUFFER_DEBUG
#  define RING_BUFFER_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define RING_BUFFER_DEBUG QDEBUG
#endif

#ifdef RING_BUFFER_NO_DEBUG       /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(RING_BUFFER_NO_DEBUG)
#  undef  RING_BUFFER_DEBUG
#  define RING_BUFFER_DEBUG 0
# endif
#endif

enum { ring_buffer_debug = RING_BUFFER_DEBUG } ;

/*==============================================================================
 * Ring Buffer -- contains a number of contiguous segments.
 *
 * Also suck and blow primitives
 */
typedef struct ring_buffer* ring_buffer ;

/* In the ring buffer we make sure that there is at least "ring_buffer_slack"
 * bytes between the current end of a segment, and the physical limit.  This
 * slack means that it is permissible to suck up to the slack before checking
 * for over-run, and blow that much, likewise.
 *
 * NB: where there is more than one segment in the ring buffer, over-running
 *     the end of the current segment may read part of the next, or complete
 *     garbage.
 *
 * The suck/blow operations assume either that the caller will ensure that
 * there is no overrun, or will ensure that there is some amount of slack.
 * When overrun is detected, the 'ptr' is forced back to the 'end' + 1,
 * so that overrun is still detectable straightforwardly... so, assuming that
 * suck_buffer_slack/blow_buffer_slack is present after 'end', then after an
 * overrun check, the actual safe amount to suck/blow is one less than the
 * slack !!
 */
enum
{
  ring_buffer_slack        = 65,

  suck_buffer_slack        = ring_buffer_slack,
  blow_buffer_slack        = ring_buffer_slack,

  suck_buffer_safe         = ring_buffer_slack - 1,
  blow_buffer_safe         = ring_buffer_slack - 1,

  ring_buffer_seg_len_max  = UINT16_MAX,
  ring_buffer_seg_type_max = UINT8_MAX,
} ;

typedef struct sucker* sucker ;         /* forward reference    */
typedef struct blower* blower ;         /* forward reference    */

/*------------------------------------------------------------------------------
 * Red tape at the front of a ring-buffer segment
 */
enum ring_buffer_red_tape
{
  rbrt_off_len    = 0,
  rbrt_len_len    = 2,          /* 2 bytes of length    */

  rbrt_off_type   = rbrt_off_len + rbrt_len_len,
  rbrt_len_type   = 1,          /* 1 byte of type       */

  rbrt_off_body   = rbrt_off_type + rbrt_len_type
};

/*==============================================================================
 * Functions:
 */
extern ring_buffer rb_create(mtype_t mtype, uint size, bool shared) ;
extern void rb_reset(ring_buffer rb) ;
extern bool rb_is_shared(ring_buffer rb) ;
extern ring_buffer rb_destroy(ring_buffer rb) ;

extern ptr_t rb_get_first(ring_buffer rb, bool set_waiting) ;
extern ptr_t rb_get_step_first(ring_buffer rb, bool set_waiting) ;
extern ptr_t rb_get_next(ring_buffer rb) ;
extern void rb_get_step_last(ring_buffer rb) ;
extern void rb_get_step(ring_buffer rb) ;
extern void rb_get_drop(ring_buffer rb) ;
extern void rb_get_discard(ring_buffer rb) ;
extern bool rb_get_copy(ring_buffer dst, ring_buffer src) ;
Inline ptr_t rb_get_body(ptr_t seg, uint* length, uint* type) ;
extern uint rb_set_sucker(sucker sr, ring_buffer rb) ;

extern ptr_t rb_put_open(ring_buffer rb, uint len, bool set_waiting) ;
extern ptr_t rb_put_ptr(ring_buffer rb) ;
extern ptr_t rb_put_close(ring_buffer rb, uint final_len, uint type) ;
extern void rb_put_drop(ring_buffer rb) ;
extern bool rb_put_copy(ring_buffer dst, ring_buffer src) ;
extern void rb_set_blower(blower br, ring_buffer rb) ;

extern bool rb_get_kick(ring_buffer rb) ;
extern bool rb_get_prompt(ring_buffer rb, bool anyway) ;
extern void rb_get_prompt_clear(ring_buffer rb) ;
extern bool rb_put_kick(ring_buffer rb) ;
extern bool rb_put_prompt(ring_buffer rb, uint threshold) ;
extern void rb_put_prompt_clear(ring_buffer rb) ;

/*------------------------------------------------------------------------------
 * From address of segment, get address of body, length of same and type.
 *
 * Note that returns non-NULL body even if length == 0.
 */
Inline ptr_t
rb_get_body(ptr_t seg, uint* length, uint* type)
{
  if (seg == NULL)
    {
      *length = 0 ;
      *type   = 0 ;

      return NULL ;
    } ;

  *length = load_s(&seg[rbrt_off_len]) ;    confirm(rbrt_len_len  == 2) ;
  *type   = load_b(&seg[rbrt_off_type]) ;   confirm(rbrt_len_type == 1) ;

  return &seg[rbrt_off_body] ;
}

/*==============================================================================
 * Buffer sucking -- lightweight extraction of things from protocol buffer.
 *
 * Does NOTHING in the way of bound-checking.  The ring-buffer allows for
 * the pointer to overrun the end by 'suck_buffer_slack' bytes.  The
 * suck_left() function will pull the sr->ptr back to the sr->end, and keep
 * track of the overrun.
 *
 * Buffer sucker structure...
 */
typedef struct sucker  sucker_t ;

struct sucker
{
  ptr_t  start ;        /* current known start                  */
  ptr_t  ptr ;          /* current read pointer                 */
  ptr_t  end ;          /* current known end                    */

  uint   overrun ;      /* total overrun                        */
  bool   failed ;       /* overrun here or in sub-section       */
} ;

/* Sucker Functions.
 */
Inline void suck_init(sucker sr, void* start, uint length) ;
Inline int suck_left(sucker sr) ;
Inline bool suck_check_read(sucker sr, uint n) ;
Inline bool suck_overrun_check(sucker sr) ;
Inline bool suck_check_complete(sucker sr) ;
Inline int suck_total(sucker sr) ;
Inline ptr_t suck_start(sucker sr) ;
Inline ptr_t suck_ptr(sucker sr) ;
Inline ptr_t suck_step(sucker sr, int n) ;

Inline void suck_sub_init(sucker ssr, sucker sr, uint n) ;

Inline void suck_n(void* p, sucker sr, uint n) ;
Inline void suck_x(sucker sr) ;
Inline void suck_nx(sucker sr, uint n) ;
Inline uint8_t   suck_b(sucker sr) ;
Inline uint16_t  suck_w(sucker sr) ;
Inline uint32_t  suck_l(sucker sr) ;
Inline in_addr_t suck_ipv4(sucker sr) ;
Inline uint64_t  suck_q(sucker sr) ;

Private uint suck_overrun(sucker sr) ;
Private int suck_P_left_overrun(sucker sr) ;

/*------------------------------------------------------------------------------
 * Set sucker to given address and length
 */
Inline void
suck_init(sucker sr, void* start, uint length)
{
  sr->start   = (ptr_t)start ;
  sr->ptr     = (ptr_t)start ;
  sr->end     = (ptr_t)start + length ;
  sr->overrun = 0 ;
  sr->failed  = false ;
} ;

/*------------------------------------------------------------------------------
 * Get sucker number of bytes between ptr and end (could be negative !)
 *
 * NB: if is -ve that implies that has overrun the current end, in which
 *     case will have reset the sr->end and updated the sr->overrun.
 *
 *     When overrun is reset, sr->ptr is clamped to sr->end + 1, and the
 *     sr->overrun is updated.
 */
Inline int
suck_left(sucker sr)
{
  int left ;

  left = (sr->end - sr->ptr) ;

  return (left >= 0) ? left : suck_P_left_overrun(sr) ;
} ;

/*------------------------------------------------------------------------------
 * Check that we have read 'n' bytes.
 */
Inline bool
suck_check_read(sucker sr, uint n)
{
  return (sr->ptr == (sr->start + n)) ;
} ;

/*------------------------------------------------------------------------------
 * Check we have not overrun, but if have: pull ptr back to end + 1.
 *
 * Returns:  true <=> OK, not overrun
 *           false => has overrun, and ptr pulled back to end + 1
 */
Inline bool
suck_overrun_check(sucker sr)
{
  if (sr->ptr <= sr->end)
    return true ;

  suck_overrun(sr) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Check that we have read to the sr->end AND not overrun.
 */
Inline bool
suck_check_complete(sucker sr)
{
  return (sr->ptr == sr->end) ;
} ;

/*------------------------------------------------------------------------------
 * Get number of bytes between start and end
 */
Inline int
suck_total(sucker sr)
{
  return sr->end - sr->start ;
} ;

/*------------------------------------------------------------------------------
 * Get current start
 */
Inline ptr_t
suck_start(sucker sr)
{
  return sr->start ;
} ;

/*------------------------------------------------------------------------------
 * Get current ptr
 */
Inline ptr_t
suck_ptr(sucker sr)
{
  return sr->ptr ;
} ;

/*------------------------------------------------------------------------------
 * Get current ptr and step past 'n' bytes -- which may be -ve
 *
 * Returns:  pointer before step.
 *
 * NB: does NOT check if 'n' is reasonable !
 */
Inline ptr_t
suck_step(sucker sr, int n)
{
  ptr_t ptr ;

  ptr = sr->ptr ;
  sr->ptr = ptr + (intptr_t)n ;
  return ptr ;
} ;

/*------------------------------------------------------------------------------
 * Start a sub-section sucker.
 *
 * Sub-section starts at the current sr->ptr and ends at sr->ptr + n
 *
 * Advances the sr->ptr by the given 'n'.
 *
 * When is finished with the sub-section can check suck_left() for underrun
 * (and overrun).
 */
Inline void
suck_sub_init(sucker ssr, sucker sr, uint n)
{
  ssr->start = ssr->ptr = sr->ptr ;
  ssr->end   = sr->ptr  = sr->ptr + n ;
} ;

/*------------------------------------------------------------------------------
 * Suck 'n' bytes -- assumes 'n' != 0
 *
 * NB: does not check for over-run.
 */
Inline void
suck_n(void* p, sucker sr, uint n)
{
  memcpy(p, sr->ptr, n) ;
  sr->ptr += n ;
} ;

/*------------------------------------------------------------------------------
 * Suck and discard a byte
 *
 * NB: does not check for over-run.
 */
Inline void
suck_x(sucker sr)
{
  ++sr->ptr ;
} ;

/*------------------------------------------------------------------------------
 * Suck and discard 'n' bytes
 *
 * NB: does not check for over-run.
 */
Inline void
suck_nx(sucker sr, uint n)
{
  sr->ptr += n ;
} ;

/*------------------------------------------------------------------------------
 * Suck 1 byte
 *
 * NB: does not check for over-run.
 */
Inline uint8_t
suck_b(sucker sr)
{
  return *sr->ptr++ ;
} ;

/*------------------------------------------------------------------------------
 * Suck 2 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline uint16_t
suck_w(sucker sr)
{
  ptr_t ptr ;

  ptr = sr->ptr ;
  sr->ptr = ptr + sizeof(uint16_t) ;

  return load_ns(ptr) ;
} ;

/*------------------------------------------------------------------------------
 * Suck 4 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline uint32_t
suck_l(sucker sr)
{
  ptr_t ptr ;

  ptr = sr->ptr ;
  sr->ptr = ptr + sizeof(uint32_t) ;

  return load_nl(ptr) ;
} ;

/*------------------------------------------------------------------------------
 * Suck ipv4 address -- 4 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline in_addr_t                /* Network Order        */
suck_ipv4(sucker sr)
{
  ptr_t ptr ;

  ptr = sr->ptr ;
  sr->ptr = ptr + sizeof(uint32_t) ;

  return load_l(ptr) ;
} ;

/*------------------------------------------------------------------------------
 * Suck 8 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline uint64_t
suck_q(sucker sr)
{
  ptr_t ptr ;

  ptr = sr->ptr ;
  sr->ptr = ptr + sizeof(uint64_t) ;

  return load_nq(ptr) ;
} ;

/*==============================================================================
 * Buffer blowing -- lightweight writing of things to a protocol buffer.
 *
 * Does VERY LITTLE in the way of bound-checking.  The ring-buffer allows for
 * the pointer to overrun the end by 'blow_buffer_slack' bytes, so for many
 * things can write object(s) using a blower, and check for overrun afterwards.
 * The following check for overrun:
 *
 *   * blow_left()
 *   * blow_want()
 *   * blow_overrun_check()
 *   * blow_ptr_inc_overrun()
 *   * blow_n_check()
 *
 *   * blow_sub_init()
 *   * blow_sub_end_b()
 *   * blow_sub_end_w()
 *
 *   * blow_overrun()
 *
 * Buffer blower structure.
 */
typedef struct blower  blower_t ;

struct blower
{
  ptr_t  start ;        /* current known start                          */
  ptr_t  ptr ;          /* current read pointer                         */
  ptr_t  end ;          /* current known end                            */

  uint   overrun ;      /* total overrun                                */
  bool   failed ;       /* set on overrun, copied from sub-section      */

  ptr_t  p_len ;        /* pointer to sub-section length field          */
} ;

/* Blower Functions.
 */
extern void blow_init(blower br, void* start, uint length) ;
Inline int blow_left(blower br) ;
Inline int blow_length(blower br) ;
Inline bool blow_has_written(blower br, uint n) ;
Inline bool blow_overrun_check(blower br) ;
Inline bool blow_is_complete(blower br) ;
Inline bool blow_is_ok(blower br) ;
Inline int blow_total(blower br) ;
Inline ptr_t blow_start(blower br) ;
Inline ptr_t blow_ptr(blower br) ;
Inline ptr_t blow_ptr_inc_overrun(blower br) ;
Inline ptr_t blow_set_ptr(blower br, ptr_t ptr) ;

Inline ptr_t blow_step(blower br, int n) ;
Inline ptr_t blow_want(blower br, uint n) ;

Inline void blow_n_check(blower br, const void* p, uint n) ;
Inline void blow_n(blower br, const void* p, uint n) ;
Inline void blow_b(blower br, uint8_t b) ;
Inline void blow_b_n(blower br, uint8_t b, uint n) ;
Inline void blow_w(blower br, uint16_t w) ;
Inline void blow_l(blower br, uint32_t l) ;
Inline void blow_ipv4(blower br, in_addr_t ip) ;
Inline void blow_q(blower br, uint64_t q) ;

extern bool blow_sub_init(blower sbr, blower br, uint ll, int off, uint max) ;
extern uint blow_sub_end(blower br, blower sbr) ;
extern uint blow_sub_end_b(blower br, blower sbr) ;
extern uint blow_sub_end_w(blower br, blower sbr) ;

Private uint blow_overrun(blower br) ;
Private int blow_P_left_overrun(blower br) ;
Private ptr_t blow_P_ptr_inc_overrun(blower br) ;
Private void blow_P_n_overrun(blower br, const void* p, uint n, ptr_t over_end);

/*------------------------------------------------------------------------------
 * Get blower number of bytes between ptr and end (could be negative !)
 *
 * NB: if is -ve that implies that has overrun the current end, in which
 *     case will have reset the br->ptr and updated the br->overrun.
 *
 *     When reset, br->ptr is clamped to br->end + 1, so the full
 *     blow_buffer_safe space is available.
 */
Inline int
blow_left(blower br)
{
  int left ;

  left = (br->end - br->ptr) ;

  return (left >= 0) ? left : blow_P_left_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Get number of bytes between start and ptr
 */
Inline int
blow_length(blower br)
{
  return br->ptr - br->start ;
} ;

/*------------------------------------------------------------------------------
 * Check that we have written 'n' bytes.
 *
 * NB: this ignores the possibility of overrun(s) having messed things up !
 */
Inline bool
blow_has_written(blower br, uint n)
{
  return (br->ptr == (br->start + n)) ;
} ;

/*------------------------------------------------------------------------------
 * Check whether have overrun, and deal with same.
 *
 * NB: this does not check for overruns in sub-sections -- for which
 *     blow_is_ok() should be used.
 *
 * Returns:  true <=> has NOT overrun -- so far, so good :-)
 */
Inline bool
blow_overrun_check(blower br)
{
  if (br->ptr <= br->end)
    return true ;

  blow_overrun(br) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Check that we have written to the br->end, exactly.
 */
Inline bool
blow_is_complete(blower br)
{
  return (br->ptr == br->end) ;
} ;

/*------------------------------------------------------------------------------
 * Check that we are OK.
 */
Inline bool
blow_is_ok(blower br)
{
  return !br->failed ;
}

/*------------------------------------------------------------------------------
 * Get number of bytes between start and end
 */
Inline int
blow_total(blower br)
{
  return br->end - br->start ;
} ;

/*------------------------------------------------------------------------------
 * Get current start
 */
Inline ptr_t
blow_start(blower br)
{
  return br->start ;
} ;

/*------------------------------------------------------------------------------
 * Get current ptr
 */
Inline ptr_t
blow_ptr(blower br)
{
  return br->ptr ;
} ;

/*------------------------------------------------------------------------------
 * Get current ptr, but if has overrun add on the total known overrun.
 *
 * This is provided so that (under normal circumstances) can calculate how
 * much would have written, had the buffer been bigger !
 *
 * NB: this is completely foxed if the pointer has been moved backwards at
 *     any time.
 *
 * NB: if a sub-section overruns...
 */
Inline ptr_t
blow_ptr_inc_overrun(blower br)
{
  if (br->ptr <= br->end)
    return br->ptr ;
  else
    return blow_P_ptr_inc_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Set the given ptr.
 *
 * NB: does NOT check the new ptr -- may overrun etc !
 *
 * NB: if the blower has overrun, confusion may result.
 *
 * Returns:  the new ptr.
 */
Inline ptr_t
blow_set_ptr(blower br, ptr_t ptr)
{
  return br->ptr = ptr ;
} ;

/*------------------------------------------------------------------------------
 * Get current ptr and step past 'n' bytes -- which may be -ve
 *
 * NB: does NOT check if 'n' is reasonable -- may overrun etc !
 *
 * NB: if 'n' is -ve, and the blower has overrun, confusion may result.
 *
 * Returns: ptr *before* the step.
 */
Inline ptr_t
blow_step(blower br, int n)
{
  ptr_t ptr ;

  ptr = br->ptr ;
  br->ptr = ptr + (intptr_t)n ;
  return ptr ;
} ;

/*------------------------------------------------------------------------------
 * Want 'n' bytes at the current ptr: get address and step pointer.
 *
 * Checks for overrun *before*, but not after.
 *
 * NB: qasserts that 'n' <= blow_buffer_safe.
 *
 * Returns: ptr *before* the step.
 */
Inline ptr_t
blow_want(blower br, uint n)
{
  ptr_t ptr ;

  qassert(n <= blow_buffer_safe) ;

  if (br->ptr > br->end)
    blow_overrun(br) ;

  ptr = br->ptr ;
  br->ptr = ptr + n ;
  return ptr ;
} ;

/*------------------------------------------------------------------------------
 * Blow 'n' bytes, checking for overrun (before and after)
 */
Inline void
blow_n_check(blower br, const void* p, uint n)
{
  ptr_t end ; ;

  if (n == 0)
    return ;

  end = (br->ptr + n) ;
  if (br->end < end)
    blow_P_n_overrun(br, p, n, end) ;
  else
    {
      memcpy(br->ptr, p, n) ;
      br->ptr = end ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Blow 'n' bytes
 *
 * NB: does not check for over-run.
 */
Inline void
blow_n(blower br, const void* p, uint n)
{
  if (n != 0)
    {
      memcpy(br->ptr, p, n) ;
      br->ptr += n ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Blow 1 byte
 *
 * NB: does not check for over-run.
 */
Inline void
blow_b(blower br, uint8_t b)
{
  *br->ptr++ = b ;
} ;

/*------------------------------------------------------------------------------
 * Blow 1 byte 'n' times
 *
 * NB: does not check for over-run.
 */
Inline void
blow_b_n(blower br, uint8_t b, uint n)
{
  if (n != 0)
    {
      memset(br->ptr, b, n) ;
      br->ptr += n ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Blow 2 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline void
blow_w(blower br, uint16_t w)
{
  ptr_t ptr ;

  ptr = br->ptr ;
  br->ptr = ptr + sizeof(uint16_t) ;

  store_ns(ptr, w) ;
} ;

/*------------------------------------------------------------------------------
 * Blow 4 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline void
blow_l(blower br, uint32_t l)
{
  ptr_t ptr ;

  ptr = br->ptr ;
  br->ptr = ptr + sizeof(uint32_t) ;

  store_nl(ptr, l) ;
} ;

/*------------------------------------------------------------------------------
 * Blow ipv4 address -- 4 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline void
blow_ipv4(blower br, in_addr_t ip)
{
  ptr_t ptr ;

  confirm(sizeof(in_addr_t) == sizeof(uint32_t)) ;

  ptr = br->ptr ;
  br->ptr = ptr + sizeof(uint32_t) ;

  return store_l(ptr, ip) ;
} ;

/*------------------------------------------------------------------------------
 * Blow 8 bytes -- Network Order
 *
 * NB: does not check for over-run.
 */
Inline void
blow_q(blower br, uint64_t q)
{
  ptr_t ptr ;

  ptr = br->ptr ;
  br->ptr = ptr + sizeof(uint64_t) ;

  store_nq(ptr, q) ;
} ;

#endif /* _ZEBRA_RING_BUFFER_H */
