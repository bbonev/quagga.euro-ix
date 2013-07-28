/* Simple Bitmap handling
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

#include "misc.h"

#include "bitmap.h"

/*==============================================================================
 * Bitmap operations -- working in bitmap_words across the bitmap(s)
 */

/*------------------------------------------------------------------------------
 * copy bitmap b to a -- truncate b or extend with zeros, as required
 */
extern void
_bm_copy(bitmap a, uint abytes, bitmap b, uint bbytes)
{
  byte* pa, * pb ;

  pa = (byte*)a ;
  pb = (byte*)b ;

  if (abytes <= bbytes)
    memcpy(pa, pb, abytes) ;
  else
    {
      memcpy(pa, pb, bbytes) ;
      memset(pa + bbytes, 0, abytes - bbytes) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * not bitmap
 */
extern void
_bm_not(bitmap bm, uint words)
{
  bitmap_word* pw ;
  uint i ;

  pw = (bitmap_word*)bm ;
  for (i = 0 ; i < words ; ++i)
    pw[i] = ~pw[i] ;
} ;

/*------------------------------------------------------------------------------
 * add bitmap b to a -- truncate b or extend with zeros, as required
 *
 * aka 'or' or 'union'
 */
extern void
_bm_add(bitmap a, uint awords, bitmap b, uint bwords)
{
  bitmap_word* pa, * pb ;
  uint i, cwords ;

  pa = (bitmap_word*)a ;
  pb = (bitmap_word*)b ;

  cwords = (awords <= bwords) ? awords : bwords ;
  for (i = 0 ; i < cwords ; ++i)
    pa[i] |= pb[i] ;
} ;

/*------------------------------------------------------------------------------
 * subtract bitmap b from a -- truncate b or extend with zeros, as required
 *
 * aka 'and-not'
 */
extern void
_bm_sub(bitmap a, uint awords, bitmap b, uint bwords)
{
  bitmap_word* pa, * pb ;
  uint i, cwords ;

  pa = (bitmap_word*)a ;
  pb = (bitmap_word*)b ;

  cwords = (awords <= bwords) ? awords : bwords ;
  for (i = 0 ; i < cwords ; ++i)
    pa[i] &= ~pb[i] ;
} ;

/*------------------------------------------------------------------------------
 * and bitmap b into a -- truncate b or extend with zeros, as required
 *
 * aka 'intersection'
 */
extern void
_bm_and(bitmap a, uint awords, bitmap b, uint bwords)
{
  bitmap_word* pa, * pb ;
  uint i, cwords ;

  pa = (bitmap_word*)a ;
  pb = (bitmap_word*)b ;

  if (awords <= bwords)
    cwords = awords ;
  else
    {
      uint abytes, bbytes ;

      abytes = awords * sizeof(bitmap_word) ;
      bbytes = bwords * sizeof(bitmap_word) ;

      memset(((byte*)pa) + bbytes, 0, abytes - bbytes) ;

      cwords = bwords ;
    } ;

  for (i = 0 ; i < cwords ; ++i)
    pa[i] &= pb[i] ;
} ;

/*------------------------------------------------------------------------------
 * xor bitmap b into a -- truncate b or extend with zeros, as required
 */
extern void
_bm_xor(bitmap a, uint awords, bitmap b, uint bwords)
{
  bitmap_word* pa, * pb ;
  uint i, cwords ;

  pa = (bitmap_word*)a ;
  pb = (bitmap_word*)b ;

  cwords = (awords <= bwords) ? awords : bwords ;
  for (i = 0 ; i < cwords ; ++i)
    pa[i] ^= pb[i] ;
} ;

