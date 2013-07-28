/* BGP Engine pThread -- header
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_ENGINE_H
#define _QUAGGA_BGP_ENGINE_H

#include "lib/misc.h"

#include "bgpd/bgpd.h"

#include "lib/mqueue.h"
#include "lib/qpnexus.h"
#include "lib/log.h"

/*==============================================================================
 * BGP_ENGINE_DEBUG setting
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if BGP_ENGINE_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set BGP_ENGINE_DEBUG == 0 to turn off debug
 *       *  or set BGP_ENGINE_DEBUG != 0 to turn on debug
 *       *  or set BGP_ENGINE_NO_DEBUG != to force debug off
 */
#ifdef BGP_ENGINE_DEBUG         /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(BGP_ENGINE_DEBUG)
#  undef  BGP_ENGINE_DEBUG
#  define BGP_ENGINE_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define BGP_ENGINE_DEBUG QDEBUG
#endif

#ifdef BGP_ENGINE_NO_DEBUG      /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(BGP_ENGINE_NO_DEBUG)
#  undef  BGP_ENGINE_DEBUG
#  define BGP_ENGINE_DEBUG 0
# endif
#endif

enum
{
  bgp_engine_debug = BGP_ENGINE_DEBUG,
} ;

enum
{
  bgp_engine_debug_to_bgp      = 0,
  bgp_engine_debug_to_routeing = 1,

  bgp_engine_debug_count       = 2,
} ;

/*==============================================================================
 * Functions
 */
Inline void bgp_to_bgp_engine(mqueue_block mqb, mqb_rank_b priority) ;
Inline void bgp_to_routing_engine(mqueue_block mqb, mqb_rank_b priority) ;

extern void bgp_engine_cops_change() ;
extern void bgp_engine_() ;

Private void bgp_queue_logging(mqueue_queue mq, uint which) ;

/*------------------------------------------------------------------------------
 * Send given message to the BGP Engine -- priority/ordinary
 */
Inline void
bgp_to_bgp_engine(mqueue_block mqb, mqb_rank_b priority)
{
  mqueue_enqueue(bgp_nexus->queue, mqb, priority) ;
  if (bgp_engine_debug)
    bgp_queue_logging(bgp_nexus->queue, bgp_engine_debug_to_bgp) ;
} ;

/*------------------------------------------------------------------------------
 * Send given message to the Routing Engine -- priority/ordinary
 */
Inline void
bgp_to_routing_engine(mqueue_block mqb, mqb_rank_b priority)
{
  mqueue_enqueue(routing_nexus->queue, mqb, priority) ;
  if (bgp_engine_debug)
    bgp_queue_logging(bgp_nexus->queue, bgp_engine_debug_to_routeing) ;
} ;

#endif /* QUAGGA_BGP_ENGINE_H */
