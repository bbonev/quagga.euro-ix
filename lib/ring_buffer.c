/* ring-buffer
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

#include "misc.h"

#include "ring_buffer.h"
#include "qlib_init.h"
#include "qpthreads.h"
#include "memory.h"

/*==============================================================================
 * ring-buffer
 *
 * A ring-buffer is a buffer containing a number of contiguous segments, where
 * those are read from the buffer in the order written.
 *
 * A ring-buffer may be shared by two pthreads -- one putting stuff in and
 * another getting it out.  A ring-buffer CANNOT be put to by more than one
 * pthread at any one time, and it CANNOT be got from by more than one pthread
 * at any one time.
 *
 * When putting stuff to a ring-buffer rb_put_open() gives the caller a pointer
 * to a suitable space beyond the current nominal end of the buffer.  Until
 * rb_put_close() or rb_put_drop(), no other pthread can rb_put_open().
 *
 * When getting stuff from a ring-buffer rb_get_first() gives the caller a
 * pointer to the first segment in the buffer, leaving it in the buffer.  It
 * is possible to the rb_get_next() to move forward, still retaining the (new)
 * current and all previous segments.  Until rb_get_step() has stepped past
 * all segments got by rb_get_first() and any rb_get_next(), or until
 * rb_get_drop(), no other pthread can rb_get_first() or rb_get_next().
 */
typedef struct ring_buffer  ring_buffer_t ;

struct ring_buffer
{
  /* If the ring-buffer is shared between pthreads -- then a spinlock is
   * used.
   *
   * When a pthread attempts to get a segment, and none are available, it
   * may set the get_waiting flag.  Similarly, when a pthread attempts to
   * put a segment and there is no space, it may set the put_waiting flag.
   */
  qpt_spin_t  slock ;

  bool    shared ;      /* set at creation time and NEVER changed       */

  /* In rb_get_first() and rb_get_step(), the get_waiting flag can be set
   * if the ring-buffer is empty.  When something has been put to the ring-
   * buffer the putter can see if (a) there is a waiter and (b) that the
   * buffer is not empty, and if so send some sort of prompt.  To ensure that
   * at most one prompt is in flight at any time, the prompted flag is used.
   *
   * Similarly for rb_put_open(), if there is not enough room.
   *
   * This is all under the spinlock if this is a shared pthread.
   */
  bool    get_waiting ;
  bool    get_prompted ;
  bool    put_waiting ;
  bool    put_prompted ;

  /* The following are shared between the get and put -- protected by the
   * slock if shared.
   */
  ptr_t   start ;               /* first segment for get        */
  ptr_t   end ;                 /* end of last segment...       */
  ptr_t   wrap_end ;            /* ...unless this is            */

  /* The get state is private to the current getting pthread -- if shared.
   */
  ptr_t   get_last ;            /* for rb_get_next()            */

  /* The put state is private to the current putting pthread -- if shared.
   */
  ptr_t   put_ptr ;             /* for rb_put_open()_close()    */
  uint    put_len ;             /* ditto                        */

  /* Properties of this ring-buffer -- set once at creation time
   */
  mtype_t mtype ;
  uint    full_size ;

  /* The actual ring-buffer -- set once at creation time
   */
  ptr_t   limit ;               /* pointer to last byte + 1     */
  ptr_t   buffer ;
} ;

/*------------------------------------------------------------------------------
 * Debug self-check functions
 */
static void rb_check_pointers(ring_buffer rb) ;
static void rb_check_contents(ring_buffer rb) ;

/*==============================================================================
 * Lock functions -- for visibility
 */
inline static void
RB_SPIN_LOCK(ring_buffer rb)
{
  if (rb->shared)
    qpt_spin_lock(rb->slock) ;
} ;

inline static void
RB_SPIN_UNLOCK(ring_buffer rb)
{
  if (rb->shared)
    qpt_spin_unlock(rb->slock) ;
} ;

/*==============================================================================
 * Creation and destruction of ring_buffer
 */
static bool rb_get_copy_section(ring_buffer dst, ptr_t src_start,
                                                       ptr_t src_end, bool ok) ;

/*------------------------------------------------------------------------------
 * Create ring-buffer of the given size.
 *
 * NB: creating a shared ring-buffer will freeze qpthreads_enabled !
 */
extern ring_buffer
rb_create(mtype_t mtype, uint size, bool shared)
{
  ring_buffer rb ;
  ptr_t       buffer ;
  uint        full_size ;

  rb = XCALLOC(mtype, sizeof(ring_buffer_t)) ;

  full_size = uround_up(size + suck_buffer_slack, qlib->pagesize) ;
  buffer = XMALLOC(mtype, full_size) ;

  /* Zeroizing the start of the ring_buffer sets:
   *
   *   * slock                -- X     -- set below, if required
   *   * shared               -- X     -- set below
   *
   *   * get_waiting          -- false )
   *   * get_prompted         -- false )  not yet
   *   * put_waiting          -- false )
   *   * put_prompted         -- false )
   *
   *   * start                -- X     -- set below
   *   * end                  -- X     -- set below
   *   * wrap_end             -- NULL  -- no wrap
   *
   *   * get_last             -- NULL  -- none
   *
   *   * put_ptr              -- NULL  -- none
   *   * put_len              -- 0     -- relevant only if put_ptr != NULL
   *
   *   * mtype                -- X     )
   *   * full_size            -- X     )  set below
   *   * buffer               -- X     )
   *   * limit                -- X     )
   */
  if (shared)
    qpt_spin_init(rb->slock) ;
  rb->shared    = shared ;

  rb->mtype     = mtype ;
  rb->full_size = full_size ;
  rb->buffer    = buffer ;
  rb->limit     = buffer + (full_size - suck_buffer_slack) ;

  rb_reset(rb) ;                /* do full reset, for consistency       */

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  return rb ;
} ;

/*------------------------------------------------------------------------------
 * Reset given ring-buffer to completely empty.
 *
 * It is the caller's responsibility to ensure that there are no outstanding
 * user of the rb->get_last, and that there is no open put segment.
 *
 * NB: assumes caller has dealt with any locking that may be required.
 */
extern void
rb_reset(ring_buffer rb)
{
  /* Sets:
   *
   *   * get_waiting          -- false )
   *   * get_prompted         -- false )  not yet
   *   * put_waiting          -- false )
   *   * put_prompted         -- false )
   *
   *   * start                -- X     -- set below
   *   * end                  -- X     -- set below
   *   * wrap_end             -- NULL  -- no wrap
   *
   *   * get_last             -- NULL  -- none
   *
   *   * put_ptr              -- NULL  -- none
   *   * put_len              -- 0     -- relevant only if put_ptr != NULL
   */
  rb->get_waiting  = false ;
  rb->get_prompted = false ;
  rb->put_waiting  = false ;
  rb->put_prompted = false ;

  rb->start        = rb->buffer ;
  rb->end          = rb->buffer ;
  rb->wrap_end     = NULL ;

  rb->get_last     = NULL ;

  rb->put_ptr      = NULL ;
  rb->put_len      = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Is the ring-buffer shared ?
 */
extern bool
rb_is_shared(ring_buffer rb)
{
  return rb->shared ;
} ;

/*------------------------------------------------------------------------------
 * Destroy given ring-buffer (if any).
 *
 * Where a ring-buffer is shared between pthreads it is the caller's
 * responsibility to deal with that.
 *
 * Returns:  NULL
 */
extern ring_buffer
rb_destroy(ring_buffer rb)
{
  if (rb != NULL)
    {
      if (rb->shared)
        qpt_spin_destroy(rb->slock) ;

      XFREE(rb->mtype, rb->buffer) ;
      XFREE(rb->mtype, rb) ;
    } ;

  return NULL ;
} ;

/*==============================================================================
 * Getting segments from ring-buffer
 *
 * This is designed to allow processing of one or more segments directly from
 * the ring-buffer.
 *
 *   * rb_get_first()     -- gets the first segment (if any) leaving it in the
 *                           ring-buffer.
 *
 *   * rb_get_step()      -- step past the current first segment, discarding it
 *                           from the ring-buffer.
 *
 *   * rb_get_next()      -- after rb_get_first() can step forward along
 *                           segments leaving each one in the ring-buffer.
 */
inline static ptr_t rb_do_get_first(ring_buffer rb, ptr_t start,
                                                             bool set_waiting) ;
inline static ptr_t rb_do_get_step_last(ring_buffer rb, ptr_t start);
inline static ptr_t rb_do_get_step(ring_buffer rb, ptr_t start, ptr_t end) ;

/*------------------------------------------------------------------------------
 * Get first segment (if any)
 *
 * If gets something, clears rb->get_waiting.  If does not get anything,
 * sets rb->get_waiting to the given set_waiting.
 *
 * Returns:  rb->get_last = address of segment -- points at red-tape
 *           rb->get_last = NULL <=> buffer is empty
 */
extern ptr_t
rb_get_first(ring_buffer rb, bool set_waiting)
{
  ptr_t start ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  start = rb_do_get_first(rb, rb->start, set_waiting) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return start ;
} ;

/*------------------------------------------------------------------------------
 * Step up to and past any current get_last, then get first segment (if any).
 *
 * If gets something, clears rb->get_waiting.  If does not get anything,
 * sets rb->get_waiting to the given set_waiting.
 *
 * Returns:  rb->get_last = address of segment -- points at red-tape
 *           rb->get_last = NULL <=> buffer is empty
 */
extern ptr_t
rb_get_step_first(ring_buffer rb, bool set_waiting)
{
  ptr_t start ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  start = rb_do_get_step_last(rb, rb->start) ;
  start = rb_do_get_first(rb, start, set_waiting) ;

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return start ;
} ;

/*------------------------------------------------------------------------------
 * Get next segment (if any) from the ring-buffer.
 *
 * If never done an rb_get_first(), or have rb_get_step() past the last segment
 * we got... treat as rb_get_first() -- BUT note that clears rb->get_waiting.
 *
 * Returns:  rb->get_last = address of segment -- points at red-tape
 *        or              = NULL  => nothing (more) available
 *                          if buffer is empty: rb->get_last = NULL
 *                                   otherwise: rb->get_last is unchanged.
 *
 * NB: In general rb_get_next() moves to the next segment after the last
 *     rb_get_first() or the last rb_get_next().
 *
 *     If there have been none of either rb_get_first() or rb_get_next(), then
 *     returns as if rb_get_first().
 *
 *     rb_get_step() steps past the first segment, and resets things if the
 *     that is also the last segment returned by rb_get_next().
 */
extern ptr_t
rb_get_next(ring_buffer rb)
{
  ptr_t last, next, end ;

  /* NB: rb->get_last belongs to the getter -- so no lock is required.
   */
  last = rb->get_last ;
  if (last == NULL)
    return rb_get_first(rb, false) ;    /* No last... get first */

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  qassert(rb->start < rb->end) ;        /* not empty            */

  next = last + load_s(&last[rbrt_off_len]) + rbrt_off_body ;

  if (next > rb->start)
    {
      qassert(last >= rb->start) ;

      /* Is after rb->start... so should be: rb->start..rb->end !
       */
      end = rb->end ;

      if (next >= end)
        {
          /* At end of buffer or time to wrap
           *
           * CANNOT have next > end !! But if is, treat as if is equal to end,
           * which will wrap around or, if already wrapped, return NULL.
           *
           * CANNOT have rb->wrap_end == rb->buffer, but treat as empty.
           */
          qassert(next == end) ;

          next = rb->buffer ;           /* wrap                 */
          end  = rb->wrap_end ;         /* need not have one    */

          if (next >= end)
            {
              qassert((end == NULL) || (next == end)) ;
              next = NULL ;             /* no more or no wrap   */
            } ;
        } ;
    }
  else
    {
      /* Has already wrapped... so should be: rb->buffer..rb->wrap_end
       */
      end  = rb->wrap_end ;             /* must have a wrap !   */

      if (next >= end)
        {
          qassert(next == end) ;
          next = NULL ;                 /* no more (or no wrap) */
        } ;
    } ;

  if (next != NULL)
    {
      qassert((next + rbrt_off_body) <= end) ;
      rb->get_last = next ;
    } ;

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return next ;
} ;

/*------------------------------------------------------------------------------
 * Step to and past the last segment got, if any -- clearing rb->get_last.
 */
extern void
rb_get_step_last(ring_buffer rb)
{
  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  rb_do_get_step_last(rb, rb->start) ;
  rb->get_last = NULL ;

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Step past the first segment, if any.
 *
 * Clears rb->get_last if this is rb->get_last.
 */
extern void
rb_get_step(ring_buffer rb)
{
  ptr_t start, end ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  start = rb->start ;
  end   = rb->end ;

  if (start >= end)
    {
      /* Buffer is already empty.
       *
       * CANNOT have start > end !! But if is, treat as if is equal to end.
       */
      qassert((start == end) && (rb->wrap_end == NULL)) ;
    }
  else
    {
      /* Buffer is not already empty, but may become so after step.
       *
       * Clear the get_last if this is it.
       */
      if (start == rb->get_last)
        rb->get_last = NULL ;

      /* Step past the current, and look out for wrap.
       */
      rb_do_get_step(rb, start, end) ;
    } ;

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Drop the rb->get_last -- if any.
 *
 * NB: rb->get_last belongs to the getter -- so no lock is required.
 */
extern void
rb_get_drop(ring_buffer rb)
{
  rb->get_last = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Discard the contents of the ring-buffer -- excluding any open rb_put segment
 */
extern void
rb_get_discard(ring_buffer rb)
{
  ptr_t end ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  end = rb->end ;

  if (rb->start >= end)
    {
      /* Buffer is already empty.
       *
       * CANNOT have start > end !! But if is, treat as if is equal to end.
       */
      qassert((rb->start == end) && (rb->wrap_end == NULL)) ;
    }
  else if (rb->wrap_end != NULL)
    {
      /* Crash the end to the wrap_end and clear same.
       */
      rb->end = end = rb->wrap_end ;
      rb->wrap_end  = NULL ;
    } ;

  rb->start    = end ;
  rb->get_last = NULL ;

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Copy the get side of one ring-buffer to another.
 *
 * If going to copy both get and put, must copy the get side first.
 *
 * If there is a src->get_last, then copies from that point forward, and the
 * dst->get_last is set NULL.
 *
 * NB: destroys contents of the destination... which is assumed to be recently
 *     initialised.
 *
 * NB: locks both source and destination, and for the duration of any memcpy()
 *     operations.
 *
 * Returns:  true <=> succeeded
 *           false => not enough room in the dst -- will now be full, but
 *                    contents are truncated.
 */
extern bool
rb_get_copy(ring_buffer dst, ring_buffer src)
{
  ptr_t start, end, last ;
  bool  ok ;

  RB_SPIN_LOCK(src) ;           /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/
  RB_SPIN_LOCK(dst) ;           /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_contents(src) ;

  start = src->start ;
  end   = src->end ;
  last  = src->get_last ;

  rb_reset(dst) ;
  ok = true ;

  if (start < end)
    {
      ptr_t wrap_start, wrap_end ;

      wrap_start = src->buffer ;
      wrap_end   = src->wrap_end ;      /* may be NULL !        */

      /* Worry about the get_last.
       *
       * If that is NULL, cannot be greater than or equal to either start or
       * wrap_start.
       *
       * If wrap_end is NULL there is no wrap section, and either last is
       * NULL or will be greater than wrap_end.
       */
      if      ((start <= last) && (last <= end))
        {
          /* The get_last is in the start..end section, so advance the
           * effective start to that -- NB: may end up with empty section.
           */
          start      = last ;
        }
      else if ((wrap_start <= last) && (last <= wrap_end))
        {
          /* The get_last is in the wrap_start..wrap_end section, so advance
           * the effective wrap_start to that, and empty out the first
           * section -- NB: may end up with two empty sections.
           */
          wrap_start = last ;
          start      = end ;
        } ;

      /* Copy section start..end, if any -- noting start may be the get_last.
       */
      ok = rb_get_copy_section(dst, wrap_start, wrap_end, ok) ;

      /* Copy section wrap_start..wrap_end, if any -- noting wrap_start may be
       * the get_last.
       *
       * If wrap_end == NULL then the section is deemed empty
       */
      ok = rb_get_copy_section(dst, wrap_start, wrap_end, ok) ;
    }
  else
    {
      /* The src buffer is empty -- and the dst buffer is reset, so we are
       * all set.
       *
       * CANNOT have start > end !! But if is, treat as if is equal to end.
       */
      qassert(start == end) ;
      qassert(last  == NULL) ;
      qassert(src->wrap_end == NULL) ;
    } ;

  if (ring_buffer_debug)
    rb_check_contents(dst) ;

  RB_SPIN_UNLOCK(dst) ;         /*->->->->->->->->->->->->->->->->->->->*/
  RB_SPIN_UNLOCK(src) ;         /*->->->->->->->->->->->->->->->->->->->*/

  return ok ;
} ;

/*------------------------------------------------------------------------------
 * Copy section of src to dst -- for rb_get_copy().
 *
 * NB: copes with src_end == NULL.
 *
 *     Indeed treats all src_end <= src_start as an empty section.
 *
 * Returns:  original ok or false iff unable to copy the section.
 */
static bool
rb_get_copy_section(ring_buffer dst, ptr_t src_start, ptr_t src_end, bool ok)
{
  if (src_start < src_end)
    {
      ptr_t dst_end ;
      uint  length ;

      dst_end = dst->end ;

      length  = src_end - src_start ;
      if ((dst_end + length) > dst->limit)
        {
          length = dst->limit - dst_end ;
          ok = false ;
        } ;

      if (length > 0)
        {
          memcpy(dst_end, src_start, length) ;
          dst->end = dst_end + length ;
        } ;
    } ;

  return ok ;
} ;

/*------------------------------------------------------------------------------
 * Mechanics for get_first...
 *
 * ...assumes all wrapping etc has been taken care of, so really only
 * interested in whether the buffer is now empty.
 *
 * Returns:  rb->get_last = address of segment -- points at red-tape
 *           rb->get_last = NULL <=> buffer is empty
 *
 * NB: assumes ring-buffer is locked.
 */
inline static ptr_t
rb_do_get_first(ring_buffer rb, ptr_t start, bool set_waiting)
{
  ptr_t end ;

  end = rb->end ;

  if (start < end)
    {
      qassert((start + load_s(&start[rbrt_off_len]) + rbrt_off_body) <= end) ;

      set_waiting = false ;             /* we have something    */
    }
  else
    {
      /* Buffer is empty.
       *
       * When start reaches end in rb_get_step(), it will wrap around if
       * there is an rb->wrap_end -- otherwise will remain where they are.
       *
       * CANNOT have start > end !! But if is, treat as if is equal to end.
       */
      qassert((start == end) && (rb->wrap_end == NULL)) ;

      start = NULL ;                    /* we have nothing      */
    } ;

  rb->get_waiting = set_waiting ;

  return rb->get_last = start ;
} ;

/*------------------------------------------------------------------------------
 * Step up to and then past any current rb->get_last.
 *
 * Returns:  address of (new) start -- existing start if no rb->get_last.
 *
 * NB: does NOT clear rb->get_last.
 *
 * NB: assumes ring-buffer is not empty and is locked.
 */
inline static ptr_t
rb_do_get_step_last(ring_buffer rb, ptr_t start)
{
  ptr_t last, end ;

  last = rb->get_last;          /* rb->get_last belongs to the getter   */

  if (last == NULL)
    return start ;

  end = rb->end ;

  qassert(start < end) ;        /* get_last != NULL <=> not empty       */

  if (last < start)
    {
      end = rb->wrap_end ;

      qassert((end != NULL) && (end < start)) ;

      rb->end      = end;
      rb->wrap_end = NULL ;
    } ;

  return rb_do_get_step(rb, start, end) ;
} ;

/*------------------------------------------------------------------------------
 * Do one step forwards from the given start, with the given end.
 *
 * NB: assumes ring-buffer (currently) NOT empty and is locked.
 */
inline static ptr_t
rb_do_get_step(ring_buffer rb, ptr_t start, ptr_t end)
{
  qassert(start < end) ;

  /* Step past the current, and look out for wrap.
   */
  start += load_s(&start[rbrt_off_len]) + rbrt_off_body ;

  if (start >= end)
    {
      /* At end of buffer or time to wrap
       *
       * CANNOT have new start > end !! But if is, treat as if is equal to
       * end, and wrap around if there is one.
       */
      qassert(start == end) ;

      end = rb->wrap_end ;              /* if any               */
      if (end != NULL)
        {
          /* Time to wrap -- clearing the wrap point.
           */
          start        = rb->buffer ;   /* wrap round           */
          rb->end      = end ;          /* update to wrap point */
          rb->wrap_end = NULL ;         /* clear                */
        } ;
    } ;

  qassert(((start + rbrt_off_body) <= end) || (start == end)) ;

  return rb->start = start ;
} ;

/*==============================================================================
 * Sucker support
 */

/*------------------------------------------------------------------------------
 * Set up the given sucker according to the last segment got.
 *
 * Returns:  type of segment
 *
 * NB: rb->get_last belongs to the getter -- so no lock is required.
 */
extern uint
rb_set_sucker(sucker sr, ring_buffer rb)
{
  ptr_t body ;
  uint  length, type ;

  memset(sr, 0, sizeof(*sr)) ;

  sr->start = sr->ptr = body = rb_get_body(rb->get_last, &length, &type) ;
  if (body != NULL)
    sr->end = body + length ;

  return type ;
} ;

/*------------------------------------------------------------------------------
 * Update overrun, if required, forcing sr->ptr to sr->end + 1.
 * If has overrun, sets sr->failed.
 *
 * Returns:   0 <=> not overrun
 *          > 0 <=> extent of overrun, beyond sr->end.
 */
Private uint
suck_overrun(sucker sr)
{
  int over ;

  over = sr->ptr - sr->end ;
  if (over <= 0)
    return 0 ;                  /* no overrun   */

  /* Sum the "over"s in br->overrun.
   *
   * After overrun we leave sr->ptr = sr->end + 1, so even though we've pulled
   * the sr->ptr back, it is still overrun.
   *
   * So after the first overrun, the extra amount we have gone over is one less
   * than it appears.
   */
  sr->ptr      = sr->end + 1 ;      /* NB: remains over by 1        */
  sr->failed   = true ;

  if (sr->overrun != 0)
    over = sr->overrun + (over - 1) ;

  return sr->overrun = over ;
} ;

/*------------------------------------------------------------------------------
 * Has overrun: reset ptr, update overrun, set failed and return -overrun.
 *
 * Returns:    0 <=> not overrun
 *           < 0 <=> -(extent of overrun)
 */
Private int
suck_P_left_overrun(sucker sr)
{
  return -suck_overrun(sr) ;
} ;

/*==============================================================================
 * Blower support
 */

/*------------------------------------------------------------------------------
 * Set up the given blower according to the last segment rb_put_open().
 *
 * NB: rb->put_ptr and put_len belong to the putter -- so no lock is required.
 */
extern void
rb_set_blower(blower br, ring_buffer rb)
{
  memset(br, 0, sizeof(*br)) ;          /* see below    */

  if (rb->put_ptr != NULL)
    {
      br->start = br->ptr = rb->put_ptr + rbrt_off_body ;
      br->end   = br->ptr + rb->put_len ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set blower to given address and length
 */
extern void
blow_init(blower br, void* start, uint length)
{
  /* Zeroizing sets:
   *
   *   * p_len          -- NULL     -- none, yet
   *   * overrun        -- 0        -- none, yet
   *   * failed         -- false    -- so far, so good
   */
  memset(br, 0, sizeof(*br)) ;

  br->start   = (ptr_t)start ;
  br->ptr     = (ptr_t)start ;
  br->end     = (ptr_t)start + length ;
} ;

/*------------------------------------------------------------------------------
 * Start a sub-section blower.
 *
 * sets:  sbr->p_len  = br->ptr
 *        br->ptr     = br->ptr + ll -- and plants zeros
 *
 *        check for parent overrun.
 *
 *        sbr->start  = br->ptr + off           ) using the br->ptr after
 *        sbr->ptr    = br->ptr                 ) planting ll length bytes and
 *        sbr->end    = br->ptr + off + max     ) checking overrun.
 *
 * NB: it is the *callers* responsibility to ensure that 'll' bytes can be
 *     written at the current br->ptr -- that may already have overrun,
 *     but if even so there MUST be 'll' bytes of slack left.
 *
 * Assumes that the sr->ptr points to where the length of the sub-section will
 * be written, when it is known.  ll is the length of that length, so we step
 * past that immediately.  May set ll = 0 if there is no length for this
 * subsection.
 *
 * It is assumed that the length will count bytes from immediately *after* the
 * length entry -- but if not, then 'off' may be used to adjust that...
 * so for a sub-section sbr->start is the origin for counting the length.
 * (Generally 'off' == 0.  Could be -ve, if the length to be planted includes
 * some or all of the preceding "red-tape".)
 *
 * The 'max' length is used to set the sbr->end, so we can detect overrun.
 * Note that the 'off' is included in this.
 *
 * The sbr->end is clamped at the br->end -- so an overrun of the parent
 * is definitely an overrun of the sub-section !
 *
 * NB: the check for parent overrun *after* planting any ll length bytes, and
 *     *before* setting it up.  So at the start of a sub-section, have the full
 *     slack.  Also, if the parent has already overrun, the sub-section stuff
 *     is still set so that can calculate the length of the sub-section.
 *
 * Returns: true <=> ok, so far.
 *
 */
extern bool
blow_sub_init(blower sbr, blower br, uint ll, int off, uint max)
{
  ptr_t ptr, start, end ;
  bool  ok ;

  memset(sbr, 0, sizeof(*sbr)) ;

  sbr->p_len   = br->ptr ;
  blow_b_n(br, 0, ll) ;

  ok = blow_overrun_check(br) ;

  ptr   = br->ptr ;
  start = ptr   + off ;
  end   = start + max ;

  if (end > br->end)
    end = br->end ;

  sbr->start = start ;
  sbr->ptr   = ptr ;
  sbr->end   = end ;

  return ok ;
} ;

/*------------------------------------------------------------------------------
 * End a sub-section blower -- with NO length setting
 *
 * If the sub-section has not overrun:
 *
 *   * cannot have overrun the parent, since: sbr->end <= br->end
 *
 *   * the length returned is: sbr->ptr - sbr->start -- see blow_sub_init()
 *
 * If the sub-section has overrun:
 *
 *   * the br->ptr is set to:
 *
 *       a) the sbr->end iff that is less than br->end.
 *
 *          In this case, had the sub-section behaved, it would not have
 *          overrun the parent, so we clamp to the sub-section end.
 *
 *       b) the "true" br->ptr and then blow_overrun().
 *
 *          In this case the sub-section has overrun both itself and the
 *          parent, so the parent also overflows.
 *
 *   * the br->failed flag is set, in any event.
 *
 *     So, when finishing off a section comprising one or more sub-sections,
 *     should check blow_ok() to check for any sub-section overruns.
 *
 *   * the length returned is what would have been if the sub-section had been
 *     of indefinite size.
 *
 *     This assumes that the ptr has not been moved backwards, explicitly or
 *     implicitly by sub-sub-section overruns.
 *
 * Returns:  sub-section length
 */
extern uint
blow_sub_end(blower br, blower sbr)
{
  ptr_t ptr, end ;

  ptr = sbr->ptr ;
  end = sbr->end ;

  qassert(end <= br->end) ;     /* sub-section ends within parent       */

  if (ptr <= end)
    {
      /* Looks like success -- but if a sub-sub-section failed, could have
       * sbr->failed... so we will copy that up.
       */
      br->ptr = ptr ;
    }
  else
    {
      /* We are closing the given sub-section, but that has overrun :-(
       *
       * Sets the br->ptr to the sbr->end
       *
       * NB: does NOT transfer the overrun count from the sub-section to the
       *     parent -- except where that also would have overrun the parent.
       *
       *     But *does* set the 'failed' flag on parent, whether or not *that* has
       *     overrun.
       */
      ptr = end + blow_overrun(sbr) ;   /* "true" sbr->ptr      */

      if (br->end > end)
        {
          /* The limit on the sub-section is within the limit of the parent,
           * so... had the sub-section behaved, would not have overrun the
           * parent... so we can clamp to the sub-section limit.
           *
           * NB: the length returned for the sub-section does not take this
           *     clamping into account -- so will exceed the maximum !
           */
          br->ptr = end ;                   /* clamp                */
        }
      else
        {
          /* The sub-section has overrun itself and the parent.  So, force
           * a parent overrun.
           */
          br->ptr = ptr ;
          blow_overrun(br) ;
        } ;
    } ;

  if (sbr->failed)
    br->failed = true ;

  return ptr - sbr->start ;
} ;

/*------------------------------------------------------------------------------
 * End a sub-section blower -- for a byte length, which can now be set
 *
 * See blow_sub_end() above
 *
 * NB: the length stored takes no notice of overruns... and under most
 *     conditions will be the length of stuff actually written.
 */
extern uint
blow_sub_end_b(blower br, blower sbr)
{
  uint len ;

  len = blow_sub_end(br, sbr) ;
  store_b(sbr->p_len, len) ;

  return len ;
} ;

/*------------------------------------------------------------------------------
 * End a sub-section blower -- for a word length, which can now be set
 *
 * See blow_sub_end() above
 *
 * NB: the length stored takes no notice of overruns... and under most
 *     conditions will be the length of stuff actually written.
 */
extern uint
blow_sub_end_w(blower br, blower sbr)
{
  uint len ;

  len = blow_sub_end(br, sbr) ;
  store_ns(sbr->p_len, len) ;

  return len ;
} ;

/*------------------------------------------------------------------------------
 * Has overrun: reset ptr, update overrun, set failed and return -overrun.
 *
 * Returns:    0 <=> not overrun
 *           < 0 <=> -(extent of overrun)
 */
Private int
blow_P_left_overrun(blower br)
{
  return -blow_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Has overrun: reset ptr, update overrun, set failed and return end + overrun.
 *
 * NB: this is completely foxed if the pointer has been moved backwards at
 *     any time.
 *
 *     If a sub-section has overrun, but did not overrun the end of the parent,
 *     then that implicitly moves the pointer backwards -- the effect is to
 *     truncate the sub-section to its maximum size.
 */
Private ptr_t
blow_P_ptr_inc_overrun(blower br)
{
  return br->end + blow_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * If has overrun: reset ptr, update overrun, set failed and return overrun.
 *
 * The br->overrun keeps track of the number of bytes simple writing would
 * have exceeded br->end by.
 *
 * If has overrun, sets br->failed.
 *
 * Returns:   0 <=> not overrun
 *          > 0 <=> extent of overrun, beyond br->end.
 */
Private uint
blow_overrun(blower br)
{
  int over ;

  over = br->ptr - br->end ;
  if (over <= 0)
    return 0 ;                  /* no overrun   */

  /* Sum the "over"s in br->overrun.
   *
   * After overrun we leave br->ptr = br->end + 1, so even though we've pulled
   * the br->ptr back, it is still overrun.
   *
   * So after the first overrun, the extra amount we have gone over is one less
   * than it appears.
   */
  br->ptr      = br->end + 1 ;      /* NB: remains over by 1        */
  br->failed   = true ;

  if (br->overrun != 0)
    over = br->overrun + (over - 1) ;

  return br->overrun = over ;
} ;

/*------------------------------------------------------------------------------
 * Trying to put 'n' bytes, but that overruns.
 */
Private void
blow_P_n_overrun(blower br, const void* p, uint n, ptr_t over_end)
{
  qassert(n != 0) ;

  if (br->ptr < br->end)
    {
      qassert((br->end - br->ptr) < n) ;
      memcpy(br->ptr, p, (br->end - br->ptr)) ;
    } ;

  br->ptr = over_end ;
  blow_overrun(br) ;
} ;

/*==============================================================================
 * Putting segments to ring-buffer
 */

/*------------------------------------------------------------------------------
 * Get space to write into the ring-buffer.
 *
 * If there is insufficient space after rb->end, then wrap round to the start
 * of the buffer -- if possible.
 *
 * If there is a current reservation, then it may be changed by this operation:
 *
 *   * if the new len is greater than the previous one, then the buffer may
 *     wrap to accommodate the new requirement.
 *
 *     But, if the new len cannot be accommodated, then the current reservation
 *     is unchanged -- but this function returns NULL.
 *
 *   * if the new len is less than the previous one, then the buffer may
 *     *unwrap* if the new len allows it.
 *
 * NB: it is the callers responsibility to detect whether the new and old
 *     segment addresses are different, and to do a memmove() from one to the
 *     other as required.
 *
 * If succeeds, clears the rb->put_waiting.  If not enough room, sets
 * rb->put_waiting to the given set_waiting.
 *
 * Returns:  address of segment body == rb->put_ptr + rbrt_off_body
 *                                      rb->put_len = the given length
 *
 *           NULL => not enough room  -- rb->put_ptr  *unchanged*
 *                                       rb->put_len  *unchanged*
 *
 * NB: does not set rb->wrap_end -- that is done when rb_put_close() is called.
 *
 *   rb->put_ptr is: rb->end       && rb->wrap_end == NULL
 *               or: rb->buffer    && rb->wrap_end == NULL
 *               or: rb->wrap_end  && rb->wrap_end > rb->buffer
 *
 *   rb->wrap_end may NOT be rb->buffer.
 *
 *   If not NULL, rb->wrap_end < rb->start.
 *
 * NB: does not actually write anything to the buffer.
 *
 * NB: where the space to write into is at the end of the buffer, there is
 *     always ring_buffer_slack bytes to over-run into.
 *
 *     where the space to write into is above the start of the buffer, we
 *     ensure there are ring_buffer_slack bytes spare bytes between the end
 *     of that space and the start of the buffer.
 */
extern ptr_t
rb_put_open(ring_buffer rb, uint len, bool set_waiting)
{
  ptr_t  put ;
  bool   can_do ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  qassert(len <= ring_buffer_seg_len_max) ;
  if (len > ring_buffer_seg_len_max)
    len = ring_buffer_seg_len_max ;

  /* Deal with the buffer empty case.
   *
   * The buffer is empty if rb->start == rb->end.
   *
   * The getter does not reset rb->start and rb->end to the top of the buffer
   * because there might be a put_ptr at rb->end at the time.
   *
   * Here we own the put_ptr and we may move it, so this is a mighty good
   * moment to reset to the top.
   *
   * We also trap the invalid case of rb->start > rb->end -- treating it as
   * buffer empty !!  And we unset rb->wrap_end, because we can.  It is also
   * impossible for there to be a put_ptr and nobody can own it, so we unset
   * that too.
   */
  if (rb->start >= rb->end)
    {
      qassert(rb->start    == rb->end) ;
      qassert(rb->wrap_end == NULL) ;
      qassert(rb->put_ptr  == NULL) ;

      put = rb->start = rb->end = rb->buffer ;
      rb->wrap_end = rb->put_ptr = NULL ;

      can_do = (len + rbrt_off_body) < (rb->limit - put) ;
    }
  else
    {
      /* So now we know that rb->start < rb->end, so there is something in the
       * buffer.
       *
       * We should not have wrap_end == rb->buffer, but if we do this forces
       * any new segment to be put at the top of the buffer.
       */
      put = rb->wrap_end ;

      if (put != NULL)
        can_do = false ;                /* not yet, anyway      */
      else
        {
          /* Has not already wrapped around, so we work from end forwards,
           * if at all possible.
           */
          put = rb->end ;

          qassert(put <= rb->limit) ;

          can_do = (len + rbrt_off_body) < (rb->limit - put) ;

          if (!can_do)
            {
              /* We do not have the required space beyond the rb->end, so
               * must now wrap around to the start.
               */
              put = rb->buffer ;        /* wrap around          */
            } ;
        } ;

      /* We now need to, or was already, wrapped round
       *
       *   put == rb->wrap_end or rb->buffer
       *
       * NB: the buffer is not empty... so rb->start < rb_end.  So, whatever
       *     lies between rb->buffer and rb->start is the next available space.
       *
       * NB: there may be no space available at all !
       */
      if (!can_do)
        {
          qassert(put <= rb->start) ;
          qassert(rb->start < rb->end) ;

          can_do = (len + rbrt_off_body + suck_buffer_slack)
                                                           < (rb->start - put) ;
        } ;
    } ;

  /* Now do we have the required space ?
   */
  if (can_do)
    {
      /* Success
       */
      rb->put_ptr = put ;
      rb->put_len = len ;

      put += rbrt_off_body ;

      set_waiting = false ;
    }
  else
    {
      /* Failure -- not enough space (pro tem)
       */
      put = NULL ;
    } ;

  rb->put_waiting = set_waiting ;

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return put ;
} ;

/*------------------------------------------------------------------------------
 * Get address of current putting segment (if any).
 *
 * Returns:  address of body of segment -- pointing *after* the red-tape
 *           NULL <=> no segment actually open !
 *
 * NB: rb->put_ptr and put_len belong to the putter -- so no lock is required.
 */
extern ptr_t
rb_put_ptr(ring_buffer rb)
{
  ptr_t put ;

  return ((put = rb->put_ptr) != NULL) ? put + rbrt_off_body : put ;
} ;

/*------------------------------------------------------------------------------
 * Complete putting segment (if any).
 *
 * Sets the length and type as given, clears the rb->put_ptr and updates the
 * rb->end or rb->wrap_end to step past the segment.
 *
 * Returns:  address of segment -- pointing at its red-tape
 *           NULL <=> no segment actually open !
 *
 * NB: it is a (VERY) sad mistake to set a length greater than the last
 *     length given to rb_put_open() -- so much so that will truncate to that
 *     length.
 *
 * NB: if the length given is less than the last length given to rb_put_open()
 *     that's fine, but will NOT unwrap, even if it could.
 */
extern ptr_t
rb_put_close(ring_buffer rb, uint final_len, uint type)
{
  ptr_t  put ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (ring_buffer_debug)
    rb_check_pointers(rb) ;

  qassert(type <= ring_buffer_seg_type_max) ;
  if (type > ring_buffer_seg_type_max)
    type = ring_buffer_seg_type_max ;

  put = rb->put_ptr ;

  if (put != NULL)
    {
      ptr_t  end ;

      qassert(final_len <= rb->put_len) ;
      if (final_len > rb->put_len)
        final_len = rb->put_len ;

      store_s(&put[rbrt_off_len], final_len) ;
      put[rbrt_off_type] = type ;

      end = rb->end ;
      if (put >= end)
        {
          /* At the end
           */
          qassert(put == end) ;

          rb->end = end + final_len + rbrt_off_body ;
        }
      else
        {
          /* Wrapped, so must be at the wrap_end or at the start
           */
          end = rb->wrap_end ;
          if (end == NULL)
            end = rb->buffer ;

          qassert(put == end) ;

          rb->wrap_end = end + final_len + rbrt_off_body ;
        } ;

      put += rbrt_off_body ;    /* return address of body       */
    } ;

  rb->put_ptr = NULL ;
  rb->put_len = 0 ;

  if (ring_buffer_debug)
    rb_check_contents(rb) ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return put ;
} ;

/*------------------------------------------------------------------------------
 * Drop putting segment (if any) -- clears put_waiting !
 *
 * NB: rb->put_ptr and put_len belong to the putter -- so no lock is required.
 */
extern void
rb_put_drop(ring_buffer rb)
{
  rb->put_ptr     = NULL ;
  rb->put_len     = 0 ;
  rb->put_waiting = false ;
} ;

/*------------------------------------------------------------------------------
 * Copy the put side of one ring-buffer to another.
 *
 * If going to copy both get and put, must copy the get side first.
 *
 * If there is a src->put_ptr, then copies that to a new dst->put_ptr, if
 * possible.  If succeeds, drops the src put segment.
 *
 * NB: destroys contents of any existing destination put_ptr... which is
 *     assumed to be empty, after recent initialisation of the dst.
 *
 * NB: caller must be the designated putter for *both* ring-buffers,
 *
 * Returns:  true <=> succeeded -- dropped any src put segment
 *           false => not enough room in the dst -- will have dropped any
 *                    existing dst put segment, but clears put_waiting.
 *
 *           Caller can get the new put_ptr (if any) by rb_put_ptr().
 */
extern bool
rb_put_copy(ring_buffer dst, ring_buffer src)
{
  ptr_t src_put ;
  bool  ok ;

  if (ring_buffer_debug)
    {
      RB_SPIN_LOCK(src) ;       /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/
      rb_check_pointers(src) ;
      RB_SPIN_UNLOCK(src) ;     /*->->->->->->->->->->->->->->->->->->->*/
    } ;

  ok = true ;

  src_put = rb_put_ptr(src) ;
  if (src_put == NULL)
    rb_put_drop(dst) ;
  else
    {
      ptr_t dst_put ;

      dst_put = rb_put_open(dst, src->put_len, false /* no set_waiting */) ;

      if (dst_put == NULL)
        {
          ok = false ;

          rb_put_drop(dst) ;
        }
      else
        {
          if (src->put_len > 0)
            memcpy(dst_put, src_put, src->put_len) ;

          rb_put_drop(src) ;
        } ;
    } ;

  if (ring_buffer_debug)
    {
      RB_SPIN_LOCK(dst) ;       /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/
      rb_check_pointers(dst) ;
      RB_SPIN_UNLOCK(dst) ;     /*->->->->->->->->->->->->->->->->->->->*/
    } ;

  return ok ;
} ;

/*------------------------------------------------------------------------------
 * How much space is available for putter.
 *
 * NB: MUST be locked
 */
inline static uint
rb_put_available(ring_buffer rb)
{
  if (rb->wrap_end == NULL)
    {
      /* No wrap... so everything above 'start' and below 'end'
       */
      return (rb->start - rb->buffer) + (rb->limit - rb->end) ;
    }
  else
    {
      /* Wrapped... so everything between 'wrap_end' and 'start'
       *
       * NB: we ignore the issue of ring_buffer_slack here !
       */
      return (rb->start - rb->wrap_end) ;
    } ;
} ;

/*==============================================================================
 * Prompting support.
 */

/*------------------------------------------------------------------------------
 * Wish to prompt the getter unless there is a prompt in flight already.
 *
 * If rb == NULL, clearly not !
 *
 * Return:  true <=> a prompt MUST now be sent.
 */
extern bool
rb_get_kick(ring_buffer rb)
{
  bool prompt ;

  if (rb == NULL)
    return false ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  prompt = !rb->get_prompted ;

  if (prompt)
    rb->get_prompted = true ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return prompt ;
} ;

/*------------------------------------------------------------------------------
 * Does the getter need a prompt ?
 *
 * If rb == NULL, clearly not !
 *
 * If the getter has signalled that it is waiting AND a prompt is not
 * "in-flight" AND either the buffer is not empty or we want to prompt anyway
 *
 * ...then a prompt is required, and we assume that one will be sent (so sets
 *    set "in-flight" here and now).
 *
 * Note that rb->get_waiting flag is set iff the last time the getter attempted
 * to get a segment the ring-buffer was empty.
 *
 * It is assumed that the caller is prepared to prompt because they have just
 * put something in the buffer.  It is possible for the decision to prompt
 * to be rendered out of date as soon as it is made -- if the getter starts
 * up of their own accord -- so the prompt is no more than a prompt, it is
 * not a guarantee there is something available.  Further, the caller can send
 * a prompt even if the buffer is empty !
 *
 * Return:  true <=> a prompt MUST now be sent.
 */
extern bool
rb_get_prompt(ring_buffer rb, bool anyway)
{
  bool prompt ;

  if (rb == NULL)
    return false ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  prompt = rb->get_waiting && !rb->get_prompted
                           && ((rb->start < rb->end) || anyway) ;

  if (prompt)
    rb->get_prompted = true ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return prompt ;
} ;

/*------------------------------------------------------------------------------
 * Clear the rb->get_prompted and rb->get_waiting flags.
 *
 * Does nothing if rb == NULL (!)
 *
 * This must be used ONLY when a prompt is collected by the getter.
 *
 * The purpose of the rb->get_prompted flag is to ensure that only one
 * prompt is "in-flight" at any time.  If the flag is cleared at any time
 * OTHER then when the prompt arrives, then the purpose is thwarted !
 */
extern void
rb_get_prompt_clear(ring_buffer rb)
{
  if (rb == NULL)
    return ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  rb->get_waiting = rb->get_prompted = false ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Wish to prompt the putter unless there is a prompt in flight already.
 *
 * If rb == NULL, clearly not !
 *
 * Return:  true <=> a prompt MUST now be sent.
 */
extern bool
rb_put_kick(ring_buffer rb)
{
  bool prompt ;

  if (rb == NULL)
    return false ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  prompt = !rb->put_prompted ;

  if (prompt)
    rb->put_prompted = true ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return prompt ;
} ;

/*------------------------------------------------------------------------------
 * Does the putter need a prompt ?
 *
 * If rb == NULL, clearly not !
 *
 * If the putter has signalled that it is waiting AND a prompt is not
 * "in-flight" AND there is at least threshold bytes available
 *
 * ...then a prompt is required, and we assume that one will be sent (so sets
 *    set "in-flight" here and now).
 *
 * Note that rb->put_waiting flag is set iff the last time the putter attempted
 * to put a segment the ring-buffer did not have sufficient space.
 *
 * It is assumed that the caller is prepared to prompt because they have just
 * made some space in the buffer.  It is possible for the decision to prompt
 * to be rendered out of date as soon as it is made -- if the putter starts
 * up of their own accord -- so the prompt is no more than a prompt, it is
 * not a guarantee there is something available.  Further, the caller can send
 * a prompt even if the buffer is still too full !
 *
 * Return:  true <=> a prompt MUST now be sent.
 */
extern bool
rb_put_prompt(ring_buffer rb, uint threshold)
{
  bool prompt ;

  if (rb == NULL)
    return false ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  prompt = rb->put_waiting && !rb->put_prompted
                           && (rb_put_available(rb) >= threshold) ;
  if (prompt)
    rb->put_prompted = true ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/

  return prompt ;
} ;

/*------------------------------------------------------------------------------
 * Clear the rb->put_prompted and rb->put_waiting flags.
 *
 * Does nothing if rb == NULL (!)
 *
 * This must be used ONLY when a prompt is collected by the putter.
 *
 * The purpose of the rb->put_prompted flag is to ensure that only one
 * prompt is "in-flight" at any time.  If the flag is cleared at any time
 * OTHER then when the prompt arrives, then the purpose is thwarted !
 */
extern void
rb_put_prompt_clear(ring_buffer rb)
{
  if (rb == NULL)
    return ;

  RB_SPIN_LOCK(rb) ;            /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  rb->put_waiting = rb->put_prompted = false ;

  RB_SPIN_UNLOCK(rb) ;          /*->->->->->->->->->->->->->->->->->->->*/
} ;

/*==============================================================================
 * Ring-buffer validity checking -- for debug !
 */

/*------------------------------------------------------------------------------
 * Check ring-buffer pointers -- assumes Spin-Locked as required
 */
static void
rb_check_pointers(ring_buffer rb)
{
  assert(rb != NULL) ;                  /* first things, first  */

  assert(rb->limit == ((ptr_t)rb) + rb->full_size - suck_buffer_slack) ;

  assert(rb->start >= rb->buffer) ;     /* start never NULL     */
  if (rb->start != rb->end)             /* end never NULL       */
    assert((rb->start + rbrt_off_body) <= rb->end) ;
  assert(rb->end   <= rb->limit) ;

  if (rb->wrap_end != NULL)
    {
      /* We may not have wrap round point at the start of the buffer.
       *
       * The rb->start (and hence rb->end) must be below the wrap_end, and
       * what's more, there must be ring_buffer_slack in there.
       */
      assert(rb->wrap_end >= (rb->buffer + rbrt_off_body)) ;
      assert((rb->wrap_end + suck_buffer_slack) <= rb->start) ;
    } ;

  if (rb->get_last != NULL)
    {
      /* If we have one of these, it must be between rb->start and rb->end or
       * between rb->buffer and rb->wrap_end.  And the buffer cannot be empty.
       */
      assert(rb->start != rb->end) ;

      if (rb->get_last >= rb->start)
        assert((rb->get_last + rbrt_off_body) <= rb->end) ;
      else
        {
          /* Must be in the wrap area, and there must be one
           */
          assert(rb->wrap_end != NULL) ;
          assert(rb->get_last >= rb->buffer) ;
          assert((rb->get_last + rbrt_off_body) <= rb->wrap_end) ;
        } ;
    } ;

  if (rb->put_ptr != NULL)
    {
      /* If we have one of these, it must be at rb->end or rb->wrap_end and the
       * length must be within rb->limit or rb->start - slack
       */
      if (rb->put_ptr == rb->end)
        assert((rb->put_ptr + rb->put_len + rbrt_off_body) <= rb->limit) ;
      else
        {
          if (rb->wrap_end != NULL)
            assert(rb->put_ptr == rb->wrap_end) ;
          else
            assert(rb->put_ptr == rb->buffer) ;

          assert((rb->put_ptr + rb->put_len + rbrt_off_body) <=
                                              (rb->start - suck_buffer_slack)) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Check ring-buffer pointers and content -- assumes Spin-Locked as required
 */
static void
rb_check_contents(ring_buffer rb)
{
  ptr_t seg, end ;
  bool  seen_get_last, seen_wrap ;

  rb_check_pointers(rb) ;

  seg = rb->start ;
  end = rb->end ;

  if (seg == end)
    return ;                    /* nothing else if is empty     */

  seen_get_last = false ;
  seen_wrap     = false ;

  while (1)
    {
      assert((seg + rbrt_off_body) <= end) ;

      if (seg == rb->get_last)
        {
          assert(!seen_get_last) ;
          seen_get_last = true ;
        } ;

      seg += load_s(&seg[rbrt_off_len]) + rbrt_off_body ;

      if (seg >= end)
        {
          assert(seg == end) ;

          if (seen_wrap || (rb->wrap_end == NULL))
            break ;

          seen_wrap = true ;

          seg = rb->buffer ;            /* wrap to top          */
          end = rb->wrap_end ;          /* new end point        */
        } ;
    } ;

  assert(seen_get_last == (rb->get_last != NULL)) ;
  assert(seen_wrap     == (rb->wrap_end != NULL)) ;
} ;
