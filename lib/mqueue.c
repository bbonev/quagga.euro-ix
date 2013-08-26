/* Message Queue data structure -- functions
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

#include "mqueue.h"
#include "mempool.h"
#include "qfstring.h"

/*==============================================================================
 * These message queues are designed for inter-qpthread communication.
 *
 * A message queue carries messages from one or more qpthreads to one or more
 * other qpthreads.
 *
 * If !qpthreads_enabled, then a message queue holds messages for the program
 * to consume later.  There are never any waiters.  Timeouts are ignored.
 *
 * A message queue has one ordinary priority queue and one high priority
 * queue.
 *
 * There are four types of queue, depending on how qpthreads wait and how they
 * are woken up:
 *
 *   mqt_cond_unicast     -- wait on condition variable, one waiter kicked
 *   mqt_cond_broadcast   -- wait on condition variable, all waiters kicked
 *   mqt_signal_unicast   -- wait for signal,            one waiter kicked
 *   mqt_signal_broadcast -- wait for signal,            all waiters kicked
 *
 * For condition variables there is a timeout mechanism so that waiters
 * are woken up at least every now and then.  The message queue maintains
 * a timeout time and a timeout interval.  The timeout time is a qtime_mono_t
 * time -- so is monotonic.
 *
 * When waiting, an explicit timeout may be given, otherwise the stored timeout
 * will be used:
 *
 *   wait until explicit/stored timeout
 *   if times out and there is a stored interval:
 *     new stored timeout = stored timeout + stored interval
 *     if new stored timeout < time now
 *       new stored timeout = time now + stored interval
 *
 * Left to its own devices, this will produce a regular timeout every interval,
 * assuming that the queue is waited on within the interval.  Otherwise the
 * "clock" will slip.
 *
 * There is a default timeout period.  The period may be set "infinite".
 *
 * For waiters kicked by signal, the wait does not occur within the message
 * queue code, but the need for a signal is recorded in the message queue.
 *
 *------------------------------------------------------------------------------
 * Message Blocks and Arguments
 *
 * Messages take the form of a small block of information which contain:
 *
 *   * struct args -- embedded argument structure
 *   * arg0        -- void* argument
 *   * action      -- void action(mqueue_block)   message dispatch
 *
 * There are set/get functions for action/arguments -- users should not poke
 * around inside the structure.
 *
 * To send a message, first initialise/allocate a message block
 * (see mqb_init_new), then fill in the arguments and enqueue it.
 *
 * NB: arg0 is expected to be used as the "context" for the message -- to
 *     point to some data common to both ends of the conversation.
 *
 *     For specific revoke, arg0 is assumed to identify the messages to be
 *     revoked.
 *
 * NB: the struct args is expected to be a modest sized structure, carrying
 *     the key elements of the message.
 *
 *     Some other structure must be overlaid on this, in the same way by sender
 *     and receiver of the message.  So:
 *
 *        mqueue_block mqb = mqb_init_new(NULL, arg0, action_func) ;
 *
 *        struct my_message* args = mqb_get_args(mqb) ;
 *
 *     allocates mqueue block, filling in arg0 and the action func.  Then
 *     args can be used to fill in a "struct my_message" form of args.
 *
 * NB: the sizeof(struct my_message) MUST BE <= sizeof(mqb_args_t) !!!
 *
 *     The macro MQB_ARGS_SIZE_OK(s) is a CONFIRM for this, eg:
 *
 *       struct my_args { ... } ;
 *       MQB_ARGS_SIZE_OK(struct my_args) ;
 *
 *==============================================================================
 * Local Queues
 *
 * A local queue may be used within a thread to requeue messages for later
 * processing.
 *
 * Local queues are simple FIFO queues.
 */

/*==============================================================================
 * Initialise and shut down Message Queue and Message Block handling
 *
 * Message blocks are organised as a qmem_pool.
 */
static qmem_pool mqb_pool ;

/*------------------------------------------------------------------------------
 * Initialise Message Queue handling.
 *
 * Must be called before any qpt_threads are started.
 */
extern void
mqueue_initialise(void)
{
  Need_alignof(mqueue_block_t) ;

  mqb_pool = qmp_create("MQ Blocks", MTYPE_MQUEUE_BLOCK, sizeof(mqueue_block_t),
                               alignof(mqueue_block_t), 100, true /* shared*/) ;
} ;

/*------------------------------------------------------------------------------
 * Shut down Message Queue handling.
 *
 * Nothing much to do here... the qmem_pool will be emptied, shortly.
 */
extern void
mqueue_finish(void)
{
} ;

/*==============================================================================
 * Initialisation etc. for Message Queue
 *
 */

/*------------------------------------------------------------------------------
 * Initialise new Message Queue, if required (mq == NULL) allocating it.
 *
 * NB: once any message queue has been initialised, it is TOO LATE to enable
 *     qpthreads.
 */
extern mqueue_queue
mqueue_init_new(mqueue_queue mq, void* parent, const char* name)
{
  if (mq == NULL)
    mq = XCALLOC(MTYPE_MQUEUE_QUEUE, sizeof(mqueue_queue_t)) ;
  else
    memset(mq, 0, sizeof(mqueue_queue_t)) ;

  /* Zeroising has set:
   *
   *    mutex           -- NULL     -- set below, if required
   *
   *    head            -- NULL
   *    tail_priority   -- NULL
   *    tail            -- NULL
   *    count           -- 0
   *
   *    revoking        -- false    -- not revoking !
   *
   *    do_signal       -- NULL     -- none
   */
  if (qpthreads_freeze())
    mq->mutex = qpt_mutex_new(qpt_mutex_quagga, qfs_gen("%s MQ", name).str) ;

  return mq ;
} ;


/*------------------------------------------------------------------------------
 * Set the signal function and data for the
 */
extern void
mqueue_set_signal(mqueue_queue mq, mqueue_signal_func signal_func)
{
  if (mq != NULL)
    {
      MQUEUE_LOCK(mq) ;

      mq->do_signal = signal_func ;

      MQUEUE_UNLOCK(mq) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Empty message queue -- by revoking everything.
 *
 * Leaves queue ready for continued use with all existing settings.
 *
 * If there were any waiters, they are still waiting.
 */
extern void
mqueue_empty(mqueue_queue mq)
{
  mqueue_revoke(mq, NULL, 0) ;

  assert((mq->head == NULL) && (mq->count == 0)) ;
} ;

/*------------------------------------------------------------------------------
 * Reset message queue -- empty it out by revoking everything.
 *
 * Frees the structure if required, and returns NULL.
 * Otherwise zeroises the structure, and returns address of same.
 *
 * NB: there MUST NOT be ANY waiters !
 *
 * NB: assumes caller has good reason to believe they have sole control !
 */
extern mqueue_queue
mqueue_reset(mqueue_queue mq, free_keep_b free_structure)
{
  if (mq == NULL)
    return NULL ;

  mqueue_empty(mq) ;

  mq->mutex = qpt_mutex_destroy(mq->mutex) ;

  if (free_structure)
    XFREE(MTYPE_MQUEUE_QUEUE, mq) ;     /* sets mq == NULL      */
  else
    memset(mq, 0, sizeof(mqueue_queue_t)) ;

  return mq ;
} ;

/*------------------------------------------------------------------------------
 * Initialise new Local Message Queue, if required (lmq == NULL) allocating it.
 *
 * Returns address of Local Message Queue
 */
extern mqueue_local_queue
mqueue_local_init_new(mqueue_local_queue lmq)
{
  if (lmq == NULL)
    lmq = XCALLOC(MTYPE_MQUEUE_QUEUE, sizeof(mqueue_local_queue_t)) ;
  else
    memset(lmq, 0, sizeof(mqueue_local_queue_t)) ;

  /* Zeroising the structure is enough to initialise:
   *
   *   * head   -- NULL
   *   * tail   -- NULL
   */

  return lmq ;
} ;

/*------------------------------------------------------------------------------
 * Reset Local Message Queue, and if required free it.
 *
 * Dequeues entries and dispatches them "mqb_destroy", to empty the queue.
 *
 * Returns address of Local Message Queue
 */
extern mqueue_local_queue
mqueue_local_reset(mqueue_local_queue lmq, free_keep_b free_structure)
{
  mqueue_block mqb ;

  while ((mqb = lmq->head) != NULL)
    {
      lmq->head = mqb->next ;
      mqb_dispatch_destroy(mqb) ;
    } ;

  if (free_structure)
    XFREE(MTYPE_MQUEUE_QUEUE, lmq) ;    /* sets lmq = NULL      */
  else
    memset(lmq, 0, sizeof(mqueue_local_queue_t)) ;

  return lmq ;
} ;

/*==============================================================================
 * Message Block memory management.
 *
 * Allocates message block structures when required.
 *
 * Places those structures on the free list when they are freed.
 *
 * Keeps a count of free structures.  (Could at some later date reduce the
 * number of free structures if it is known that some burst of messages has
 * now passed.)
 *
 * mqueue_initialise MUST be called before the first message block is allocated.
 */

/*------------------------------------------------------------------------------
 * Initialise message block (allocate if required) and set action & arg0.
 *
 * Zeroises the struct args.
 *
 * Returns address of message block.
 */
extern mqueue_block
mqb_init_new(mqueue_block mqb, mqueue_action action, void* arg0)
{
  if (mqb == NULL)
    mqb = qmp_alloc(mqb_pool) ;

  memset(mqb, 0, sizeof(mqueue_block_t)) ;

  /* Zeroising the mqb sets:
   *
   *    args           -- zeroised
   *
   *    arg0           -- X       -- set below
   *
   *    next           -- NULL
   *
   *    action         -- X       -- set below
   *
   *    state          -- 0       -- mqb_s_undef
   */
  confirm(mqb_s_undef == 0) ;

  mqb->action = action ;
  mqb->arg0   = arg0 ;

  return mqb ;
} ;

/*------------------------------------------------------------------------------
 * Free message block when done with it.
 *
 * NB: it is the caller's responsibility to free the value of any argument that
 *     requires it.
 */
extern mqueue_block
mqb_free(mqueue_block mqb)
{
  return qmp_free(mqb_pool, mqb) ;
} ;

/*==============================================================================
 * Enqueue and dequeue messages.
 */

static mqueue_block mqb_revoke_this(mqueue_block this, mqueue_queue mq,
                                                            mqueue_block prev) ;

/*------------------------------------------------------------------------------
 * Enqueue message.
 *
 * If priority, will enqueue after any previously enqueued priority messages.
 *
 * When queues message, sets mqb->state == mqb_s_queued.
 *
 * If mq is NULL, the message is not queued but is immediately destroyed.
 *
 * If the queue is empty when adding a new item, will invoke the 'do_signal',
 * if any -- while HOLDING the message queue lock.
 */
extern void
mqueue_enqueue(mqueue_queue mq, mqueue_block mqb, mqb_rank_b priority)
{
  qassert(mqb->state != mqb_s_queued) ;

  if (mq == NULL)
    {
      /* Trying to queue on a non-existent list is daft... but if a queue once
       * existed, but has been destroyed, then messages which were on the queue
       * at the time would have been revoked... so we treat this as if it had
       * made it to the queue before the queue was destroyed !
       */
      mqb->state = mqb_s_revoked ;
      return mqb_dispatch_destroy(mqb) ;
    } ;

  mqb->state = mqb_s_queued ;

  MQUEUE_LOCK(mq) ;

  ++mq->count ;

  if (mq->head == NULL)
    {
      qassert(mq->count == 1) ;

      mqb->next         = NULL ;
      mq->head          = mqb ;
      mq->tail_priority = priority ? mqb : NULL ;
      mq->tail          = mqb ;

      if (mq->do_signal != NULL)
        mq->do_signal(mq) ;
    }
  else
    {
      qassert(mq->count > 1) ;

      if (priority)
        {
          /* Adding as a priority item, after any other priority items.
           */
          mqueue_block after ;

          after = mq->tail_priority ;
          if (after == NULL)
            {
              /* Is first priority item, and queue is not empty.
               */
              mqb->next = mq->head ;
              mq->head  = mqb ;
            }
          else
            {
              /* Is second or subsequent priority item.
               */
              mqb->next   = after->next ;
              after->next = mqb ;

              if (mq->tail == after)
                mq->tail = mqb;
            } ;

          mq->tail_priority = mqb ;
        }
      else
        {
          /* Adding at the end of the queue.
           */
          qassert(mq->tail != NULL) ;
          mqb->next      = NULL ;
          mq->tail->next = mqb ;
          mq->tail       = mqb ;
        } ;
    } ;

  MQUEUE_UNLOCK(mq) ;
} ;

/*------------------------------------------------------------------------------
 * Dequeue message.
 *
 * Returns a message block if one is available.  (And not otherwise.)
 *
 * When dequeues message, sets mqb->state == mqb_s_undef.
 *
 * NB: if mq is NULL, returns NULL -- nothing available
 */
extern mqueue_block
mqueue_dequeue(mqueue_queue mq)
{
  mqueue_block mqb ;

  if (mq == NULL)
    return NULL ;

  MQUEUE_LOCK(mq) ;

  mqb = mq->head ;
  if (mqb != NULL)
    {
      /* Have something to pull off the queue
       */
      qassert(mq->count > 0) ;
      --mq->count ;

      mq->head   = mqb->next ;
      mqb->state = mqb_s_undef ;

      /* fix tails if at either or both
       */
      if (mqb == mq->tail)
        mq->tail = NULL ;

      if (mqb == mq->tail_priority)
        mq->tail_priority = NULL ;
    } ;

  MQUEUE_UNLOCK(mq) ;

  return mqb ;
} ;

/*------------------------------------------------------------------------------
 * Revoke message(s)
 *
 * Revokes all messages, or only messages whose arg0 matches the given value.
 * (If the given value is NULL revokes everything.)
 *
 * Revokes by calling mqb_dispatch_destroy().
 *
 * NB: for safety, holds the queue locked for the duration of the revoke
 *     operation.
 *
 *     If the destroy code can handle it, this means that can revoke stuff
 *     from one thread even though it is usually only dequeued by another.
 *
 *     The danger is that if queues get very long, and many revokes happen,
 *     may (a) spend a lot of time scanning the message queue, which stops
 *     other threads as soon as they try to enqueue anything, and (b) if this
 *     happens a lot, could end up in an O(n^2) thing scanning the message
 *     queue once for each revoked object type.
 *
 *     ALSO: mqb_dispatch_destroy() MUST NOT attempt to fiddle with the
 *           queue !!
 *
 *     AND:  mqb_dispatch_destroy() MUST avoid deadlocking on other mutexes !!
 *
 *           Simplest is to avoid all locking, with the exception of memory
 *           management or other "deep" stuff which definitely won't use this
 *           message queue's lock !
 *
 * If mq is NULL, does nothing.
 *
 * If num > 0, stops after revoking that many messages.
 *
 * Returns: number of messages revoked.
 */
extern uint
mqueue_revoke(mqueue_queue mq, void* arg0, uint num)
{
  mqueue_block mqb ;
  mqueue_block prev ;
  uint  did ;

  if (mq == NULL)
    return 0 ;

  MQUEUE_LOCK(mq) ;
  mq->revoking = true ;

  did  = 0 ;
  prev = NULL ;
  mqb  = mq->head ;
  while (mqb != NULL)
    {
      if ((arg0 == NULL) || (arg0 == mqb->arg0))
        {
          mqb = mqb_revoke_this(mqb, mq, prev) ;

          ++did ;

          if (num == 1)
            break ;

          if (num > 1)
            --num ;
        }
      else
        {
          prev = mqb ;
          mqb  = mqb->next ;
        } ;
    } ;

  mq->revoking = false ;
  MQUEUE_UNLOCK(mq) ;

  return did ;
} ;

/*------------------------------------------------------------------------------
 * Revoke given mqb from given queue.
 *
 * There is some deep magic here.  The problem is that where a message queue is
 * used by more than one pthread, it is possible to become confused if more
 * than one pthread may revoke a given message.
 *
 * To avoid confusion, the message queue in question could have a higher level
 * lock, so that the state of a given message can be managed under that lock.
 *
 * But, it is possible for a message queue to be revoked, wholesale, which
 * makes a higher level lock more problematic, particularly where a message
 * queue may contain a number of quite different sorts of message.
 *
 * So, if we have a message that might be revoked by more than one pthread,
 * then (provided, of course, that the mqb_destroy operation does not free
 * the mqb) we can use this function to:
 *
 *   (a) revoke a given mqb, if it is on the queue -- in the usual way,
 *       calling mqb_dispatch_destroy() under the message queue lock.
 *
 * or:
 *
 *   (b) discover that the mqb has already been revoked.
 *
 * Once revoked, the mqb stays in that state until it is queued again.
 *
 * So, an mqb can be revoked by mqueue_revoke() or by mqb_revoke(), and
 * mqb_revoke() can be used to revoke or test the revocation state of a given
 * mqb.
 *
 * NB: this is only really useful if one pthread is responsible for enqueuing
 *     messages, or there is some other interlock to avoid being confused by
 *     learning that an mqb has been revoked, but then it being requeued by
 *     some other pthread !
 *
 * Returns: true <=> is now, or was already, revoked.
 *          false => not revoked
 */
extern bool
mqb_revoke(mqueue_block mqb, mqueue_queue mq)
{
  mqb_state_t mst ;

  if (mq == NULL)
    return true ;

  MQUEUE_LOCK(mq) ;
  mq->revoking = true ;

  mst = mqb->state ;

  if (mst == mqb_s_queued)
    {
      mqueue_block prev, this ;

      prev = NULL ;
      this = mq->head ;

      while ((mqb != this) && (this != NULL))
        {
          prev = this ;
          this = this->next ;
        } ;

      if (mqb == this)
        {
          /* Possible (if unlikely for this application) that the mqb will be
           * freed, so we do not depend on "this" hereafter.
           */
          mqb_revoke_this(this, mq, prev) ;
          mst = mqb_s_revoked ;
        }
      else
        qassert(false) ;
    } ;

  mq->revoking = false ;
  MQUEUE_UNLOCK(mq) ;

  return (mst == mqb_s_revoked) ;
} ;

/*------------------------------------------------------------------------------
 * Revoke given mqb from given mqueue.
 *
 * Must have the mqueue locked.
 *
 * Sets mqb_s_revoked.
 *
 * May free the given mqb !
 *
 * Returns: the next mqb
 */
static mqueue_block
mqb_revoke_this(mqueue_block this, mqueue_queue mq, mqueue_block prev)
{
  mqueue_block next ;

  assert(mq->count > 0) ;
  qassert(mq->revoking) ;

  next = this->next ;

  if (prev == NULL)
    mq->head   = next ;
  else
    prev->next = next ;

  if (this == mq->tail)
    mq->tail = prev ;

  if (this == mq->tail_priority)
    mq->tail_priority = prev ;

  --mq->count ;

  this->state = mqb_s_revoked ;

  mqb_dispatch_destroy(this) ;

  return next ;
} ;


/*------------------------------------------------------------------------------
 * Enqueue message on local queue -- at tail
 */
extern void
mqueue_local_enqueue(mqueue_local_queue lmq, mqueue_block mqb)
{
  if (lmq->head == NULL)
    lmq->head       = mqb ;
  else
    lmq->tail->next = mqb ;
  lmq->tail = mqb ;
  mqb->next = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Enqueue message on local queue -- at head
 */
extern void
mqueue_local_enqueue_head(mqueue_local_queue lmq, mqueue_block mqb)
{
  if (lmq->head == NULL)
    lmq->tail = mqb ;

  mqb->next = lmq->head ;
  lmq->head = mqb ;
} ;

/*------------------------------------------------------------------------------
 * Dequeue message from local queue -- returns NULL if empty
 */
extern mqueue_block
mqueue_local_dequeue(mqueue_local_queue lmq)
{
  mqueue_block mqb = lmq->head ;

  if (mqb != NULL)
    lmq->head = mqb->next ;

  return mqb ;
} ;

