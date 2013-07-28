/* Memory Pool System -- header
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

#ifndef _ZEBRA_MEMPOOL_H
#define _ZEBRA_MEMPOOL_H

#include "misc.h"
#include "memory.h"
#include "workqueue.h"

/*------------------------------------------------------------------------------
 * Sort out QMEMPOOL_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if QMEMPOOL_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set QMEMPOOL_DEBUG    == 0 to turn off debug
 *       *  or set QMEMPOOL_DEBUG    != 0 to turn on debug
 *       *  or set QMEMPOOL_NO_DEBUG != 0 to force debug off
 */

#ifdef QMEMPOOL_DEBUG          /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(QMEMPOOL_DEBUG)
#  undef  QMEMPOOL_DEBUG
#  define QMEMPOOL_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define QMEMPOOL_DEBUG QDEBUG
#endif

#ifdef QMEMPOOL_NO_DEBUG       /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(QMEMPOOL_NO_DEBUG)
#  undef  QMEMPOOL_DEBUG
#  define QMEMPOOL_DEBUG 0
# endif
#endif

enum { qmempool_debug = QMEMPOOL_DEBUG } ;

/*==============================================================================
 * Pools of fixed size pieces of memory.
 *
 */
typedef struct qmem_pool* qmem_pool ;

/*==============================================================================
 * Functions:
 */
extern void qmp_start_up(void) ;
extern void qmp_second_stage(void) ;
extern void qmp_finish(bool mem_stats) ;

extern qmem_pool qmp_create(const char* name, mtype_t mtype, uint item_size,
                                uint item_align, uint item_count, bool shared) ;

extern void* qmp_alloc(qmem_pool pool) ;
extern void* qmp_free(qmem_pool pool, void* item) ;

extern wq_ret_code_t qmp_garbage_collect(qmem_pool pool,
                                                      qtime_mono_t yield_time) ;

#endif /* _ZEBRA_MEMPOOL_H */
