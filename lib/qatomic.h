/* Quagga Atomic Operations support -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_QATOMIC_H
#define _ZEBRA_QATOMIC_H

#include "misc.h"
#include "time.h"
#include "qpthreads.h"
#include "list_util.h"

/*==============================================================================
 * Quagga Atomic Operations -- atomic wrt pthreads (not signals).
 *
 * Here are captured all the Atomic operations used in Quagga.
 */

/*------------------------------------------------------------------------------
 * Sort out QATOMIC_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if QATOMIC_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set QATOMIC_DEBUG    == 0 to turn off debug
 *       *  or set QATOMIC_DEBUG    != 0 to turn on debug
 *       *  or set QATOMIC_NO_DEBUG != 0 to force debug off
 */

#ifdef QATOMIC_DEBUG          /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(QATOMIC_DEBUG)
#  undef  QATOMIC_DEBUG
#  define QATOMIC_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define QATOMIC_DEBUG QDEBUG
#endif

#ifdef QATOMIC_NO_DEBUG       /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(QATOMIC_NO_DEBUG)
#  undef  QATOMIC_DEBUG
#  define QATOMIC_DEBUG 0
# endif
#endif

enum { qatomic_debug = QATOMIC_DEBUG } ;

/*==============================================================================
 * Functions
 */
extern void qatomic_start_up(void) ;
extern void qatomic_second_stage(void) ;
extern void qatomic_finish(void) ;

#define qa_wrap(qa) { LOCK_QATOMIC() ; qa ; UNLOCK_QATOMIC() ; }

/*==============================================================================
 * All atomic operations are (currently) implemented using a (single) spin-lock.
 */

Private qpt_spin_t qatomic_lock ;

/*------------------------------------------------------------------------------
 * Lock and unlock the qpt_mutex.
 */
inline static void
LOCK_QATOMIC(void)
{
  qpt_spin_lock(qatomic_lock) ;
} ;

inline static void
UNLOCK_QATOMIC(void)
{
  qpt_spin_unlock(qatomic_lock) ;
} ;

/*==============================================================================
 * Atomic get operations
 */

/*------------------------------------------------------------------------------
 * Get pointer
 */
Inline void*
qa_get_pointer(void** p_ptr)
{
  void* out ;
  qa_wrap(out = *p_ptr) ;
  return out ;
} ;

/*------------------------------------------------------------------------------
 * Get pointer const
 */
Inline const void*
qa_get_pointer_c(void* const* p_ptr_c)
{
  void* out_c ;
  qa_wrap(out_c = *p_ptr_c) ;
  return out_c ;
} ;

/*------------------------------------------------------------------------------
 * Get uint
 */
Inline uint
qa_get_uint(uint* p_uint)
{
  uint val ;
  qa_wrap(val = *p_uint) ;
  return val ;
} ;

/*==============================================================================
 * Atomic set operations
 */

/*------------------------------------------------------------------------------
 * Set pointer
 */
Inline void
qa_set_pointer(void** p_ptr, void* ptr)
{
  qa_wrap(*p_ptr = ptr) ;
} ;

/*------------------------------------------------------------------------------
 * Set uint
 */
Inline void
qa_set_uint(uint* p_uint, uint val)
{
  qa_wrap(*p_uint = val) ;
} ;

/*------------------------------------------------------------------------------
 * Set time_t
 */
Inline void
qa_set_time_t(time_t* p_time_t, time_t val)
{
  qa_wrap(*p_time_t = val) ;
} ;

/*==============================================================================
 * Atomic swap (get and set) operations
 */

/*------------------------------------------------------------------------------
 * Swap pointer -- sets given pointer to "in" value and returns original.
 */
Inline void*
qa_swap_pointers(void** p_ptr, void* in)
{
  void* out ;
  qa_wrap(out = *p_ptr ; *p_ptr = in) ;
  return out ;
} ;

/*------------------------------------------------------------------------------
 * Swap pointer const -- sets given pointer to "in" value and returns original.
 */
Inline const void*
qa_swap_pointers_c(const void** p_ptr_c, const void* in_c)
{
  const void* out_c ;
  qa_wrap(out_c = *p_ptr_c ; *p_ptr_c = in_c) ;
  return out_c ;
} ;

/*==============================================================================
 * Atomic add to integer operations
 */

/*------------------------------------------------------------------------------
 * Add to uint
 */
Inline uint
qa_add_to_uint(uint* p_uint, uint val)
{
  uint r_uint ;
  qa_wrap(r_uint = *p_uint += val) ;
  return r_uint ;
} ;

/*------------------------------------------------------------------------------
 * Add to ulong
 */
Inline ulong
qa_add_to_ulong(ulong* p_ulong, ulong val)
{
  ulong r_ulong ;
  qa_wrap(r_ulong = *p_ulong += val) ;
  return r_ulong ;
} ;

/*------------------------------------------------------------------------------
 * Add to urlong
 */
Inline urlong
qa_add_to_urlong(urlong* p_urlong, urlong val)
{
  uint r_urlong ;
  qa_wrap(r_urlong = *p_urlong += val) ;
  return r_urlong ;
} ;

/*==============================================================================
 * Atomic memcpy() and memset()
 */

/*------------------------------------------------------------------------------
 * memcpy
 */
Inline void
qa_memcpy(void* restrict dst, void* restrict src, size_t size)
{
  if (size != 0)
    qa_wrap(memcpy(dst, src, size)) ;
} ;

/*------------------------------------------------------------------------------
 * memset
 */
Inline void
qa_memset(void* dst, byte val, size_t size)
{
  if (size != 0)
    qa_wrap(memset(dst, val, size)) ;
} ;

/*==============================================================================
 * Atomic List Operations
 */

#endif /* _ZEBRA_QATOMIC_H */
