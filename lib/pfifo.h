/* Periodic Fifo -- header
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_PFIFO_H
#define _QUAGGA_BGP_PFIFO_H

#include "qtime.h"
#include "list_util.h"


/*==============================================================================
 * Periodic Fifo -- pfifo.
 *
 */

/* The period number is a simple unsigned long, which is assumed never to
 * wrap.  (The unsigned-ness is important.)
 *
 * It is the callers responsibility to manage these.
 */
typedef qtime_period_t pfifo_period_t ;

enum
{
  PFIFO_PERIOD_MIN   = 0,       /* unsigned     */
  PFIFO_PERIOD_FIRST = 1,
  PFIFO_PERIOD_MAX   = QTIME_PERIOD_MAX,
} ;
CONFIRM(QTIME_PERIOD_MIN == 0) ;
CONFIRM(sizeof(pfifo_period_t) > 4) ;

/* An item in a Periodic Fifo must contain a list pointer pair, so that the
 * item can be added/removed from the list.
 */
typedef void* pfifo_item ;

typedef struct dl_list_pair(pfifo_item) pfifo_pair_t ;

/* An item in the body of a pfifo has an index -- being the index of the
 * entry in the auxiliary pointers table.
 */
typedef ushort pfifo_index_t ;
enum
{
  PFIFO_INDEX_MIN   = 0,

  PFIFO_INDEX_MAX   = USHRT_MAX / 4,
  PFIFO_INDEX_COUNT = PFIFO_INDEX_MAX + 1,

  PFIFO_INDEX_EX    = USHRT_MAX,
} ;

/* The Periodic Fifo itself comprises the pfifo's P0, the pre-P0 list and
 * the auxiliary pointers for each period.
 *
 * There are np auxiliary pointers.  This supports up to nx (nx == np - 1)
 * periods and a final pointer to the last item in the pfifo.
 *
 * At any moment cannot have anything in the body of the pfifo whose period is
 * less than P0, or more than P0 + nx - 1.
 *
 * The body of the pfifo is empty when pf->pz == 0 (and pf->pf == 0).
 */
typedef struct pfifo  pfifo_t ;
typedef struct pfifo* pfifo ;

struct pfifo
{
  pfifo_period_t p0 ;   /* first possible period                        */
  pfifo_period_t pb ;   /* period associated with f[0]                  */

  ushort    fi ;        /* index of first not-empty period              */
  ushort    zi ;        /* index of pointer to last item                */

  pfifo_period_t pf ;   /* first not-empty period    : ie fi's period   */
  pfifo_period_t pz ;   /* last not-empty period + 1 : ie zi's period   */

  ushort    np ;        /* length of the f[] array                      */
  ushort    nx ;        /* length of the f[] array - 1                  */
  ushort    n_slack ;   /* number of periods to have "spare"            */

  uint      off ;       /* offset of pointer pair in pfifo_item         */

  /* The ex list comprises any items which have been "taken" from the pfifo
   * -- see pfifo_take() -- or were added for some period before p0, or
   * had to be moved from the pfifo when p0 is advanced.
   */
  struct dl_base_pair(pfifo_item) ex ;

  /* If pf->pz != 0, then the auxiliary index contains entries from f[fi]
   * to f[zi] inclusive (noting that the indexes can wrap round), corresponding
   * to periods pf to pz.
   *
   * NB: the first period may not be empty.
   *
   *     the last period may not be empty.
   *
   *     where there are at least 3 periods, the intermediate periods may be
   *     empty, and that is signalled by f[i] == f[i+1] -- where fi < i < ni-1.
   *
   *     where the last period contains only one item f[zi-1] == f[zi], so
   *     need to be a little careful here.
   */
  pfifo_item  f[] ;
} ;

/*==============================================================================
 * Functions
 */
extern pfifo pfifo_init_new(pfifo pf, uint n_max, uint n_slack, uint offset) ;
extern pfifo pfifo_free(pfifo pf) ;

extern pfifo_index_t pfifo_item_add(pfifo pf, pfifo_item item,
                                                             pfifo_period_t p) ;
extern void pfifo_item_del(pfifo pf, pfifo_item item, pfifo_index_t i) ;
extern pfifo_index_t pfifo_item_move(pfifo pf, pfifo_item item, pfifo_index_t i,
                                                             pfifo_period_t p) ;

extern pfifo_item pfifo_item_head(pfifo pf) ;
extern pfifo_item pfifo_item_next(pfifo pf) ;

extern pfifo_item pfifo_take(pfifo pf, pfifo_period_t p, bool set) ;
extern pfifo_item pfifo_flush(pfifo pf) ;
extern pfifo_item pfifo_flush_empty(pfifo pf) ;

extern pfifo_period_t pfifo_first_period(pfifo pf) ;
extern pfifo_period_t pfifo_first_not_ex_period(pfifo pf) ;

Inline pfifo_pair_t* pfifo_pair_get(pfifo pf, pfifo_item item) ;
Inline pfifo_period_t pfifo_period_get(pfifo pf, pfifo_index_t i) ;
Inline pfifo_period_t pfifo_period_fi(pfifo pf, pfifo_index_t i) ;

/*==============================================================================
 * Inlines
 */

/*------------------------------------------------------------------------------
 * Get address of pointer pair in the given pfifo item.
 */
Inline pfifo_pair_t*
pfifo_pair_get(pfifo pf, pfifo_item item)
{
  return (pfifo_pair_t*)(((byte*)item) + pf->off) ;
} ;

/*------------------------------------------------------------------------------
 * Get period from given index.
 *
 * NB: if the index is outside the body of the pfifo (eg PFIFO_INDEX_EX) will
 *     return P0.
 *
 *     It is the caller's responsibility to ensure that is meaningful.
 */
Inline pfifo_period_t
pfifo_period_get(pfifo pf, pfifo_index_t i)
{
  if (i <= pf->nx)
    return pfifo_period_fi(pf, i) ;
  else
    return pf->p0 - 1 ;
} ;

/*------------------------------------------------------------------------------
 * Get period from index -- using the fact: Pb <= P0 < Pb + np
 *
 * NB: given index is assumed to be within the body of the pfifo
 */
Inline pfifo_period_t
pfifo_period_fi(pfifo pf, pfifo_index_t i)
{
  pfifo_period_t p ;

  qassert(i <= pf->nx) ;

  p = pf->pb + i ;
  if (p < pf->p0)
    p += pf->np ;

  return p ;
} ;

#endif /* _QUAGGA_BGP_PFIFO_H */
