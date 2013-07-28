/* Quagga Atomic Operations support
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#include "qatomic.h"
#include "qpthreads.h"

/*==============================================================================
 * Quagga Atomic Operations -- atomic wrt pthreads (not signals).
 *
 */

/*==============================================================================
 * Start-up, shut down etc.
 *
 * Currently the operations are implemented with a spin-lock, so this is it and
 * the start-up and shut down is initialise, uninitialise of this.
 */
qpt_spin_t qatomic_lock = { 0 } ;

/*------------------------------------------------------------------------------
 * First stage initialisation -- before any pthreads are started
 *
 */
extern void
qatomic_start_up(void)
{
  qpt_spin_zeroize(qatomic_lock) ;
} ;

/*------------------------------------------------------------------------------
 * Second stage start up -- initialise spin-lock as required.
 */
extern void
qatomic_second_stage(void)
{
  qpt_spin_init(qatomic_lock) ;
} ;

/*------------------------------------------------------------------------------
 * Shut down -- destroy the spin-lock as required.
 */
extern void
qatomic_finish(void)
{
  qpt_spin_destroy(qatomic_lock) ;
} ;
