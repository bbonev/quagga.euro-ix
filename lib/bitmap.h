/* Simple Bitmap handling -- Header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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
#ifndef _ZEBRA_BITMAP_H
#define _ZEBRA_BITMAP_H

#include "misc.h"

/*==============================================================================
 * Bitmap is simple vector of bits.
 *
 * Each bitmap is a struct containing an array of bitmap words.  So that
 * operations on the complete bitmap operate on larger units.
 *
 * Bits are addressed in units (currently bytes): bits 0..n-1 are stored in
 * unit 0, bits n..(n*2)-1 are stored in unit 1, and so on -- where n is the
 * number of bits per unit (bitmap_unit_bits).  Bit 0 within a unit is the LS
 * bit of the unit.
 *
 * The following captures the organisation of the bitmap.
 */
typedef byte         bitmap_unit ;
typedef bitmap_unit* bitmap ;

typedef uint64_t     bitmap_word ;

enum
{
  bitmap_unit_bits   = sizeof(bitmap_unit) * CHAR_BIT,
  bitmap_word_bits   = sizeof(bitmap_word) * CHAR_BIT,

  bitmap_alloc_units = bitmap_word_bits / bitmap_unit_bits,

  bitmap_shift       = 3,
  bitmap_mask        = bitmap_unit_bits - 1,
} ;

CONFIRM((1 << bitmap_shift) == bitmap_unit_bits) ;
CONFIRM( (bitmap_word_bits >= bitmap_unit_bits) &&
        ((bitmap_word_bits %  bitmap_unit_bits) == 0)) ;

#define bitmap_bit(bit) ((bitmap_unit)1 << (bit & bitmap_mask))
#define bitmap_off(bit) (bit >> bitmap_shift)

#define bm_size_units(n) \
      ((((n) + bitmap_word_bits - 1) / bitmap_word_bits) * bitmap_alloc_units)

#define bm_bytes(p_bm) (sizeof(*(p_bm)))
#define bm_bits(p_bm)  (bm_bytes(p_bm) * 8)
#define bm_units(p_bm) (bm_bytes(p_bm) / sizeof(bitmap_unit))
#define bm_words(p_bm) (bm_bytes(p_bm) / sizeof(bitmap_word))

/*------------------------------------------------------------------------------
 * Working macros.
 *
 * The operations on bitmaps are mostly macros, which invoke working function,
 * which are inline functions for the simple set/clear/test.
 *
 * To declare a static bitmap for 29 bits, 0..28:
 *
 *   static bitmap_s(29) foo ;
 *
 * Can declare a bitmap type:
 *
 *   typedef bitmap_s(45) foo_t ;
 *
 * Or a 76 bit bitmap inside another structure:
 *
 *   struct zzz
 *     {
 *        ...
 *        bitmap_s(77)  bar ;
 *        ...
 *     }
 *
 *   static struct zzz q ;
 *
 *   struct zzz* pq = &q ;
 *
 * These declare fixed size bitmaps which can then be used with the bm_xxx
 * operations.  Note that the effective length of the bitmap is rounded up to
 * the number bits in the bitmap word.
 *
 *   bm_test(&foo, 5)          -- returns bool
 *
 *                                qasserts that the bit is within the effective
 *                                length -- returns false in this case.
 *
 *   bm_set(&q.bar, 6) ;       -- void function
 *
 *                                qasserts that the bit is within the effective
 *                                length -- does nothing in this case.
 *
 *   bm_test_set(&foo, 9)      -- returns bool -- bm_test() + bm_set()
 *
 *   bm_clear(&pq->bar, 24) ;  -- void function
 *
 *                                qasserts that the bit is within the effective
 *                                length -- does nothing in this case.
 *
 *   bm_test_set(&foo, 9)      -- returns bool -- bm_test() + bm_clear()
 *
 *   bm_reset(&pq->bar) ;      -- void function, sets all bits to 0
 *   bm_fill(&pq->bar) ;       -- void function, sets all bits to 1
 *
 *   bm_not(&pq->bar) ;        -- void function, inverts all bits
 *
 *   bm_copy(&a, &b) ;         -- void function, copies from b to a.
 *
 *                                If a is longer, zero fills.
 *                                If b is longer, drops the excess.
 */
#define bitmap_s(n) struct { bitmap_unit bm[bm_size_units(n)] ; }

#define bm_test(p_bm, bit)       _bm_test       ((p_bm)->bm, bit, bm_bits(p_bm))
#define bm_set(p_bm, bit)        _bm_set        ((p_bm)->bm, bit, bm_bits(p_bm))
#define bm_test_set(p_bm, bit)   _bm_test_set   ((p_bm)->bm, bit, bm_bits(p_bm))
#define bm_clear(p_bm, bit)      _bm_clear      ((p_bm)->bm, bit, bm_bits(p_bm))
#define bm_test_clear(p_bm, bit) _bm_test_clear ((p_bm)->bm, bit, bm_bits(p_bm))
#define bm_init(p_bm)            _bm_init((p_bm)->bm, bm_bytes(p_bm))
#define bm_fill(p_bm)            _bm_fill((p_bm)->bm, bm_bytes(p_bm))

#define bm_not(p_bm) _bm_not((p_bm)->bm, bm_words(p_bm))

#define bm_copy(p_a, p_b) _bm_copy((p_a)->bm, bm_bytes(p_a), \
                                   (p_b)->bm, bm_bytes(p_b))

#define bm_add(p_a, p_b) _bm_add((p_a)->bm, bm_words(p_a), \
                                 (p_b)->bm, bm_words(p_b))
#define bm_sub(p_a, p_b) _bm_sub((p_a)->bm, bm_words(p_a), \
                                 (p_b)->bm, bm_words(p_b))
#define bm_and(p_a, p_b) _bm_and((p_a)->bm, bm_words(p_a), \
                                 (p_b)->bm, bm_words(p_b))
#define bm_xor(p_a, p_b) _bm_xor((p_a)->bm, bm_words(p_a), \
                                 (p_b)->bm, bm_words(p_b))

/*------------------------------------------------------------------------------
 * The work functions
 */
Inline bool _bm_test      (bitmap bm, uint bit, uint bits) Always_Inline ;
Inline void _bm_set       (bitmap bm, uint bit, uint bits) Always_Inline ;
Inline bool _bm_test_set  (bitmap bm, uint bit, uint bits) Always_Inline ;
Inline void _bm_clear     (bitmap bm, uint bit, uint bits) Always_Inline ;
Inline bool _bm_test_clear(bitmap bm, uint bit, uint bits) Always_Inline ;

Inline void _bm_init(bitmap bm, uint bytes) Always_Inline ;
Inline void _bm_fill(bitmap bm, uint bytes) Always_Inline ;

extern void _bm_copy(bitmap a, uint abytes, bitmap b, uint bbytes) ;

extern void _bm_not(bitmap bm, uint words) ;
extern void _bm_add(bitmap a, uint awords, bitmap b, uint bwords) ;
extern void _bm_sub(bitmap a, uint awords, bitmap b, uint bwords) ;
extern void _bm_and(bitmap a, uint awords, bitmap b, uint bwords) ;
extern void _bm_xor(bitmap a, uint awords, bitmap b, uint bwords) ;

/*------------------------------------------------------------------------------
 * The Inline functions
 */
Inline bool
_bm_test(bitmap bm, uint bit, uint bits)
{
  if (bit < bits)
    return (bm[bitmap_off(bit)] & bitmap_bit(bit)) != 0 ;

  qassert(false) ;
  return false ;
} ;

Inline void
_bm_set(bitmap bm, uint bit, uint bits)
{
  if (bit < bits)
    bm[bitmap_off(bit)] |= bitmap_bit(bit) ;
  else
    qassert(false) ;
} ;

Inline bool
_bm_test_set(bitmap bm, uint bit, uint bits)
{
  if (bit < bits)
    {
      bitmap_unit* pu ;
      bitmap_unit was, bitm ;

      bitm = bitmap_bit(bit) ;
      pu   = &bm[bitmap_off(bit)] ;
      was  = *pu ;

      if (was & bitm)
        return true ;

      *pu = was | bitm ;
    }
  else
    qassert(false) ;

  return false ;
} ;

Inline void
_bm_clear(bitmap bm, uint bit, uint bits)
{
  if (bit < bits)
    bm[bitmap_off(bit)] &= ~bitmap_bit(bit) ;
  else
    qassert(false) ;
} ;

Inline bool
_bm_test_clear(bitmap bm, uint bit, uint bits)
{
  if (bit < bits)
    {
      bitmap_unit* pu ;
      bitmap_unit was, bitm ;

      bitm = bitmap_bit(bit) ;
      pu   = &bm[bitmap_off(bit)] ;
      was  = *pu ;

      if ((was & bitm) == 0)
        return false ;

      *pu = was ^ bitm ;
    }
  else
    qassert(false) ;

  return true ;
} ;

Inline void
_bm_init(bitmap bm, uint bytes)
{
  memset(&(bm), 0, sizeof(bm)) ;
} ;

Inline void
_bm_fill(bitmap bm, uint bytes)
{
  memset(&(bm), 0xFF, sizeof(bm)) ;
} ;

#endif /* _ZEBRA_BITMAP_H */
