/* BGP Engine pThread -- functions
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

#include <zebra.h>

#include "bgpd/bgp_engine.h"

/*==============================================================================
 * The BGP Engine pThread contains:
 *
 *   * the BGP Finite State Machine (FSM) for BGP Connections
 *   * the BGP listen and accept stuff
 *   * the encoding and decoding of BGP protocol messages
 *   * all related socket handling and I/O
 *   * all related timers
 */

/*==============================================================================
 * Logging debug support for tracking volumes of messages flowing between
 * the BGP Engine and the Routeing Engine.
 */
typedef struct bgp_engine_queue_stats  bgp_engine_queue_stats_t ;
typedef struct bgp_engine_queue_stats* bgp_engine_queue_stats ;

struct bgp_engine_queue_stats
{
  uint     count ;
  urlong   total ;
  uint     max ;
  uint     recent ;

  uint     xon ;
  uint     event ;
  uint     update ;
} ;

static bgp_engine_queue_stats_t queue_stats[bgp_engine_debug_count]
                      = { {0}, {0} } ;

static const char* queue_name[] =
  {
    [bgp_engine_debug_to_bgp]      = "BGP Engine",
    [bgp_engine_debug_to_routeing] = "Routeing Engine",
  } ;

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_queue_logging(mqueue_queue mq, uint which)
{
  bgp_engine_queue_stats stats ;
  urlong average ;
  uint   av_i ;
  uint   av_f ;
  uint   my_count ;
  mqueue_block mqb ;

  stats = &queue_stats[which] ;
  ++stats->count ;

  MQUEUE_LOCK(mq) ;

  if (mq->count > stats->max)
    stats->max    = mq->count ;
  if (mq->count > stats->recent)
    stats->recent = mq->count ;

  stats->total += mq->count ;

  if (stats->count < 1000)
    {
      MQUEUE_UNLOCK(mq) ;
      return ;
    } ;

  my_count = 0 ;

  mqb = mq->head ;
  while (mqb != NULL)
    {
      ++my_count ;
      mqb = mqb->next ;
    } ;

  assert(my_count == mq->count) ;

  MQUEUE_UNLOCK(mq) ;

  average = stats->total * 1000 ;
  average = (average / stats->count) + 5 ;
  av_i = average / 1000 ;
  av_f = (average % 1000) / 10 ;

  zlog_debug("%s queue: max=%u  recent: max=%u av=%d.%.2d (%u) [x=%u e=%u u=%u]",
                 queue_name[which],
                         stats->max, stats->recent, av_i, av_f, stats->count,
                                      stats->xon, stats->event, stats->update) ;

  stats->recent = 0 ;
  stats->count  = 0 ;
  stats->total  = 0 ;

  stats->event  = 0 ;
  stats->update = 0 ;
  stats->xon    = 0 ;
} ;

