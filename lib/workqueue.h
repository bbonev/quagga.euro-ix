/* Quagga Work Queues -- header.
 *
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_WORK_QUEUE_H
#define _QUAGGA_WORK_QUEUE_H

#include "misc.h"
#include "list_util.h"
#include "qtime.h"

/*==============================================================================
 * See workqueue.c for description of the work queue item function and return
 * code.
 */
typedef enum wq_ret_code wq_ret_code_t ;

enum wq_ret_code
{
  wqrc_retain           = 0,
  wqrc_rerun            = 1,
  wqrc_reschedule       = 2,
  wqrc_rerun_reschedule = 3,

  wqrc_remove           = 4,
  wqrc_release          = 5,

  wqrc_action_mask = BIT(4) - 1,

  wqrc_nothing     = 0,
  wqrc_something   = BIT(4),
} ;

typedef wq_ret_code_t wq_function(void* data, qtime_mono_t yield_time) ;

/*------------------------------------------------------------------------------
 * Work Queue Item
 */
typedef struct wq_item  wq_item_t ;
typedef struct wq_item* wq_item ;

struct wq_item
{
  struct dl_list_pair(wq_item) queue ;

  wq_function*  func ;
  void*         data ;
} ;

/*------------------------------------------------------------------------------
 * Base of a Work Queue
 */
typedef struct dl_base_pair(wq_item) wq_base_t ;
typedef wq_base_t* wq_base ;

/*------------------------------------------------------------------------------
 * Functions
 */
extern wq_item wq_item_init_new(wq_item wqi, wq_function func, void* data) ;
extern wq_item wq_item_free(wq_item wqi) ;

extern wq_item wq_item_add(wq_base wq, wq_item wqi) ;
extern wq_item wq_item_del(wq_base wq, wq_item wqi) ;
extern wq_item wq_item_del_free(wq_base wq, wq_item wqi) ;

extern void wq_init(wq_base wq) ;
extern bool wq_run(wq_base wq, qtime_mono_t yield_time, qtime_mono_t* p_now) ;

/*==============================================================================
 * Previous workqueue implementation.
 *
 * Copyright (C) 2005 Sun Microsystems, Inc.
 */
#include "command.h"

/* Hold time for the initial schedule of a queue run, in  millisec
 */
enum { WORK_QUEUE_DEFAULT_HOLD = 50 } ;

/* action value, for use by item processor and item error handlers
 */
typedef enum
{
  WQ_SUCCESS = 0,
  WQ_ERROR,             /* Error, run error handler if provided         */
  WQ_RETRY_NOW,         /* retry immediately                            */
  WQ_RETRY_LATER,       /* retry later, cease processing work queue     */
  WQ_REQUEUE,           /* requeue item, continue processing work queue */
  WQ_QUEUE_BLOCKED,     /* Queue cant be processed at this time.
                         * Similar to WQ_RETRY_LATER, but doesn't penalise
                         * the particular item..                        */
} wq_item_status;

/* A single work queue item, unsurprisingly
 */
typedef struct work_queue_item* work_queue_item ;
typedef struct work_queue_item work_queue_item_t ;

struct work_queue_item
{
  void*  data ;

  struct work_queue_item* next ;        /* the queue itself             */
  struct work_queue_item* prev ;

  uint  ran;                            /* # of times item has been run */
} ;

#define WQ_UNPLUGGED    (1 << 0) /* available for draining */

/* work_queue -- comprises a list of work_queue_items and the red-tape
 *               required to process those.
 *
 * When a work_queue is waiting to be run a thread object sits on the
 * thread_master's 'background' queue, or (when first dispatched and if the
 * hold time is not zero) on the 'timer' queue.
 *
 * When a work_queue is run,
 */
typedef struct work_queue* work_queue ;
typedef struct work_queue  work_queue_t ;

typedef wq_item_status wq_workfunc(work_queue, work_queue_item);
typedef void           wq_errorfunc(work_queue, work_queue_item);
typedef void           wq_del_item_data(work_queue, work_queue_item);
typedef void           wq_completion_func(work_queue);

struct work_queue
{
  /* Everything but the specification struct is private
   * the following may be read
   */
  struct thread_master *master;

  struct thread *thread;              /* thread, if one is active       */
  char *name;                         /* work queue name                */

  /* Specification for this work queue.
   *
   * Public, must be set before use by caller. May be modified at will.
   */
  struct {
    /* optional opaque user data, global to the queue.
     */
    void *data;

    /* work function to process items with:
     * First argument is the workqueue queue.
     * Second argument is the item data
     */
    wq_workfunc* workfunc ;

    /* error handling function -- optional
     */
    wq_errorfunc* errorfunc ;

    /* callback to delete user specific item data -- optional
     */
    wq_del_item_data* del_item_data ;

    /* completion callback, called when queue is emptied -- optional
     */
    wq_completion_func* completion_func ;

    /* max number of retries to make for item that errors
     */
    uint        max_retries;

    /* hold time for first run, in ms
     */
    uint        hold;
  } spec;

  /* remaining fields should be opaque to users
   */
  work_queue_item head ;              /* queue item list        */
  work_queue_item tail ;
  uint            list_count ;

  ulong runs ;

  struct {
    unsigned int  best;
    unsigned int  granularity;
    unsigned long total;
  } cycles;     /* cycle counts */

  /* private state
   */
  u_int16_t flags;                      /* user set flag */
};

/* User API */

extern struct work_queue *work_queue_new (struct thread_master *,
                                          const char *);
extern void work_queue_free (struct work_queue *);
Inline void work_queue_add (struct work_queue *, void *);
extern work_queue_item work_queue_item_add(struct work_queue* wq) ;

extern void work_queue_plug (struct work_queue *wq);
extern void work_queue_unplug (struct work_queue *wq);

/* Helpers, exported for thread.c and command.c
 */
extern int work_queue_run (struct thread *);

/* Reporting commands
 */
extern cmd_table workqueue_cmd_table ;

/*==============================================================================
 * The Inline functions
 */
Inline void work_queue_add (struct work_queue* wq, void* data)
{
  work_queue_item item ;

  item = work_queue_item_add(wq) ;
  item->data = data ;
}

#endif /* _QUAGGA_WORK_QUEUE_H */
