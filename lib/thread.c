/* Thread management routine
 * Copyright (C) 1998, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

/* #define DEBUG */

#include <zebra.h>
#include "miyagi.h"

#include "thread.h"
#include "memory.h"
#include "log.h"
#include "hash.h"
#include "command.h"
#include "sigevent.h"
#include "qpthreads.h"
#include "qtimers.h"

struct thread_master* master = NULL ;

/* Recent absolute time of day */
struct timeval recent_time;
static struct timeval last_recent_time;
/* Relative time, since startup */
static struct timeval relative_time;
static struct timeval relative_time_base;
/* init flag */
static unsigned short timers_inited;

/* cpu stats needs to be qpthread safe. */
static qpt_mutex thread_mutex = NULL ;
#define LOCK qpt_mutex_lock(thread_mutex);
#define UNLOCK qpt_mutex_unlock(thread_mutex);
static struct hash *cpu_record = NULL;

/* Pointer to qtimer pile to be used, if any    */
static qtimer_pile use_qtimer_pile     = NULL ;
static qtimer      spare_qtimers       = NULL ;
static bool        used_standard_timer = false ;

/* Struct timeval's tv_usec one second value.   */
#define TIMER_SECOND_MICRO 1000000L

/* Adjust so that tv_usec is in the range [0,TIMER_SECOND_MICRO).
   And change negative values to 0. */
static struct timeval
timeval_adjust (struct timeval a)
{
  while (a.tv_usec >= TIMER_SECOND_MICRO)
    {
      a.tv_usec -= TIMER_SECOND_MICRO;
      a.tv_sec++;
    }

  while (a.tv_usec < 0)
    {
      a.tv_usec += TIMER_SECOND_MICRO;
      a.tv_sec--;
    }

  if (a.tv_sec < 0)
      /* Change negative timeouts to 0. */
      a.tv_sec = a.tv_usec = 0;

  return a;
}

static struct timeval
timeval_subtract (struct timeval a, struct timeval b)
{
  struct timeval ret;

  ret.tv_usec = a.tv_usec - b.tv_usec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  return timeval_adjust (ret);
}

static long
timeval_cmp (struct timeval a, struct timeval b)
{
  return (a.tv_sec == b.tv_sec
          ? a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

static unsigned long
timeval_elapsed (struct timeval a, struct timeval b)
{
  return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
          + (a.tv_usec - b.tv_usec));
}

#ifndef HAVE_CLOCK_MONOTONIC
static void
quagga_gettimeofday_relative_adjust (void)
{
  struct timeval diff;
  if (timeval_cmp (recent_time, last_recent_time) < 0)
    {
      relative_time.tv_sec++;
      relative_time.tv_usec = 0;
    }
  else
    {
      diff = timeval_subtract (recent_time, last_recent_time);
      relative_time.tv_sec += diff.tv_sec;
      relative_time.tv_usec += diff.tv_usec;
      relative_time = timeval_adjust (relative_time);
    }
  last_recent_time = recent_time;
}
#endif /* !HAVE_CLOCK_MONOTONIC */

/* gettimeofday wrapper, to keep recent_time updated */
static int
quagga_gettimeofday (struct timeval *tv)
{
  int ret;

  assert (tv);

  if (!(ret = gettimeofday (&recent_time, NULL)))
    {
      /* init... */
      if (!timers_inited)
        {
          relative_time_base = last_recent_time = recent_time;
          timers_inited = 1;
        }
      /* avoid copy if user passed recent_time pointer.. */
      if (tv != &recent_time)
        *tv = recent_time;
      return 0;
    }
  return ret;
}

static int
quagga_get_relative (struct timeval *tv)
{
  int ret;

#ifdef HAVE_CLOCK_MONOTONIC
  {
    struct timespec tp;
    if (!(ret = clock_gettime (CLOCK_MONOTONIC, &tp)))
      {
        relative_time.tv_sec = tp.tv_sec;
        relative_time.tv_usec = tp.tv_nsec / 1000;
      }
  }
#else /* !HAVE_CLOCK_MONOTONIC */
  if (!(ret = quagga_gettimeofday (&recent_time)))
    quagga_gettimeofday_relative_adjust();
#endif /* HAVE_CLOCK_MONOTONIC */

  if (tv)
    *tv = relative_time;

  return ret;
}

/* Get absolute time stamp, but in terms of the internal timer
 * Could be wrong, but at least won't go back.
 */
static void
quagga_real_stabilised (struct timeval *tv)
{
  *tv = relative_time_base;
  tv->tv_sec += relative_time.tv_sec;
  tv->tv_usec += relative_time.tv_usec;
  *tv = timeval_adjust (*tv);
}

/* Exported Quagga timestamp function.
 * Modelled on POSIX clock_gettime.
 */
int
quagga_gettime (enum quagga_clkid clkid, struct timeval *tv)
{
  switch (clkid)
    {
      case QUAGGA_CLK_REALTIME:
        return quagga_gettimeofday (tv);
      case QUAGGA_CLK_MONOTONIC:
        return quagga_get_relative (tv);
      case QUAGGA_CLK_REALTIME_STABILISED:
        quagga_real_stabilised (tv);
        return 0;
      default:
        errno = EINVAL;
        return -1;
    }
}

/* time_t value in terms of stabilised absolute time.
 * replacement for POSIX time()
 */
time_t
quagga_time (time_t *t)
{
  struct timeval tv;
  quagga_real_stabilised (&tv);
  if (t)
    *t = tv.tv_sec;
  return tv.tv_sec;
}

/* Public export of recent_relative_time by value */
struct timeval
recent_relative_time (void)
{
  return relative_time;
}

/* Uses the address of the function (or at least ls part of same) as the hash
 * key.  (The function name is for display, only.)
 */
static unsigned int
cpu_record_hash_key (const void* data)
{
  const struct cpu_thread_history *a ;

  a = data ;
  return (uintptr_t)a->func % UINT_MAX ;
}

static bool
cpu_record_hash_equal(const void* p1, const void* p2)
{
  const struct cpu_thread_history *a ;
  const struct cpu_thread_history *b ;

  a = p1 ;
  b = p2 ;

  return a->func == b->func;
}

static void *
cpu_record_hash_alloc (const void* data)
{
  const struct cpu_thread_history *a ;
  const char* b ;
  const char* e ;
  char* n ;
  int l ;
  struct cpu_thread_history *new ;

  /* Establish start and length of name, removing leading/trailing
   * spaces and any enclosing (...) -- recursively.
   */
  a = data ;

  b = a->funcname ;
  e = b + strlen(b) - 1 ;

  while (1)
    {
      while (*b == ' ')
        ++b ;                   /* strip leading spaces         */
      if (*b == '\0')
        break ;                 /* quit if now empty            */
      while (*e == ' ')
        --e ;                   /* strip trailing spaces        */
      if ((*b != '(') || (*e != ')'))
        break ;                 /* quit if not now (...)        */
      ++b ;
      --e ;                     /* discard ( and )              */
    } ;

  l = (e + 1) - b ;             /* length excluding trailing \0 */

  n = XMALLOC(MTYPE_THREAD_FUNCNAME, l + 1) ;
  memcpy(n, b, l) ;
  n[l] = '\0' ;

  /* Allocate empty structure and set address and name          */
  new = XCALLOC (MTYPE_THREAD_STATS, sizeof (struct cpu_thread_history));
  new->func     = a->func;
  new->funcname = n ;

  return new ;
}

static void
cpu_record_hash_free (void *a)
{
  struct cpu_thread_history *hist = a;

  XFREE (MTYPE_THREAD_FUNCNAME, hist->funcname);
  XFREE (MTYPE_THREAD_STATS, hist);
}

static void
vty_out_cpu_thread_history(struct vty* vty,
                           const struct cpu_thread_history *a)
{
#ifdef HAVE_RUSAGE
  vty_out(vty, "%7ld.%03ld %9d %8ld %9ld %8ld %9ld",
          a->cpu.total/1000, a->cpu.total%1000, a->total_calls,
          a->cpu.total/a->total_calls, a->cpu.max,
          a->real.total/a->total_calls, a->real.max);
#else
  vty_out(vty, "%7ld.%03ld %9d %8ld %9ld",
          a->real.total/1000, a->real.total%1000, a->total_calls,
          a->real.total/a->total_calls, a->real.max);
#endif
  vty_out(vty, " %c%c%c%c%c%c %s%s",
          a->types & (1 << THREAD_READ) ? 'R':' ',
          a->types & (1 << THREAD_WRITE) ? 'W':' ',
          a->types & (1 << THREAD_TIMER) ? 'T':' ',
          a->types & (1 << THREAD_EVENT) ? 'E':' ',
          a->types & (1 << THREAD_EXECUTE) ? 'X':' ',
          a->types & (1 << THREAD_BACKGROUND) ? 'B' : ' ',
          a->funcname, VTY_NEWLINE);
}

static void
cpu_record_hash_print(struct hash_backet *bucket,
                      void *args[])
{
  struct cpu_thread_history *totals = args[0];
  struct vty *vty = args[1];
  thread_type *filter = args[2];
  struct cpu_thread_history *a = bucket->item;

  a = bucket->item;
  if ( !(a->types & *filter) )
       return;
  vty_out_cpu_thread_history(vty,a);
  totals->total_calls += a->total_calls;
  totals->real.total += a->real.total;
  if (totals->real.max < a->real.max)
    totals->real.max = a->real.max;
#ifdef HAVE_RUSAGE
  totals->cpu.total += a->cpu.total;
  if (totals->cpu.max < a->cpu.max)
    totals->cpu.max = a->cpu.max;
#endif
}

static void
cpu_record_print(struct vty *vty, thread_type filter)
{
  struct cpu_thread_history tmp;
  void *args[3] = {&tmp, vty, &filter};

  memset(&tmp, 0, sizeof tmp);
  tmp.funcname = miyagi("TOTAL");   /* NB: will not free tmp in the usual way,
                                           in particular, will not attempt
                                           to free this !!                    */
  tmp.types = filter;

#ifdef HAVE_RUSAGE
  vty_out(vty, "%21s %18s %18s%s",
          "", "CPU (user+system):", "Real (wall-clock):", VTY_NEWLINE);
#endif
  vty_out(vty, "Runtime(ms)   Invoked Avg uSec Max uSecs");
#ifdef HAVE_RUSAGE
  vty_out(vty, " Avg uSec Max uSecs");
#endif
  vty_out(vty, "  Type  Thread%s", VTY_NEWLINE);

  LOCK
  hash_iterate(cpu_record,
               (void(*)(struct hash_backet*,void*))cpu_record_hash_print,
               args);

  if (tmp.total_calls > 0)
    vty_out_cpu_thread_history(vty, &tmp);

  UNLOCK
}

DEFUN_CALL(show_thread_cpu,
      show_thread_cpu_cmd,
      "show thread cpu [FILTER]",
      SHOW_STR
      "Thread information\n"
      "Thread CPU usage\n"
      "Display filter (rwtexb)\n")
{
  int i = 0;
  thread_type filter = (thread_type) -1U;

  if (argc > 0)
    {
      filter = 0;
      while (argv[0][i] != '\0')
        {
          switch ( argv[0][i] )
            {
            case 'r':
            case 'R':
              filter |= (1 << THREAD_READ);
              break;
            case 'w':
            case 'W':
              filter |= (1 << THREAD_WRITE);
              break;
            case 't':
            case 'T':
              filter |= (1 << THREAD_TIMER);
              break;
            case 'e':
            case 'E':
              filter |= (1 << THREAD_EVENT);
              break;
            case 'x':
            case 'X':
              filter |= (1 << THREAD_EXECUTE);
              break;
            case 'b':
            case 'B':
              filter |= (1 << THREAD_BACKGROUND);
              break;
            default:
              break;
            }
          ++i;
        }
      if (filter == 0)
        {
          vty_out(vty, "Invalid filter \"%s\" specified,"
                  " must contain at least one of 'RWTEXB'%s",
                  argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  cpu_record_print(vty, filter);
  return CMD_SUCCESS;
}

static void
cpu_record_hash_clear (struct hash_backet *bucket, void *args)
{
  thread_type *filter = args;
  struct cpu_thread_history *a = bucket->item;

  a = bucket->item;
  if ( !(a->types & *filter) )
       return;

  hash_release (cpu_record, bucket->item);
}

static void
cpu_record_clear (thread_type filter)
{
  thread_type *tmp = &filter;
  hash_iterate (cpu_record,
               (void (*) (struct hash_backet*,void*)) cpu_record_hash_clear,
               tmp);
}

DEFUN(clear_thread_cpu,
      clear_thread_cpu_cmd,
      "clear thread cpu [FILTER]",
      "Clear stored data\n"
      "Thread information\n"
      "Thread CPU usage\n"
      "Display filter (rwtexb)\n")
{
  int i = 0;
  thread_type filter = (thread_type) -1U;

  if (argc > 0)
    {
      filter = 0;
      while (argv[0][i] != '\0')
       {
         switch ( argv[0][i] )
           {
           case 'r':
           case 'R':
             filter |= (1 << THREAD_READ);
             break;
           case 'w':
           case 'W':
             filter |= (1 << THREAD_WRITE);
             break;
           case 't':
           case 'T':
             filter |= (1 << THREAD_TIMER);
             break;
           case 'e':
           case 'E':
             filter |= (1 << THREAD_EVENT);
             break;
           case 'x':
           case 'X':
             filter |= (1 << THREAD_EXECUTE);
             break;
           case 'b':
           case 'B':
             filter |= (1 << THREAD_BACKGROUND);
             break;
           default:
             break;
           }
         ++i;
       }
      if (filter == 0)
       {
         vty_out(vty, "Invalid filter \"%s\" specified,"
                  " must contain at least one of 'RWTEXB'%s",
                 argv[0], VTY_NEWLINE);
         return CMD_WARNING;
       }
    }

  cpu_record_clear (filter);
  return CMD_SUCCESS;
}

/* List allocation and head/tail print out. */
static void
thread_list_debug (struct thread_list *list)
{
  printf ("count [%d] head [%p] tail [%p]\n",
          list->count, list->head, list->tail);
}

/* Debug print for thread_master. */
static void  __attribute__ ((unused))
thread_master_debug (struct thread_master *m)
{
  printf ("-----------\n");
  printf ("readlist  : ");
  thread_list_debug (&m->list[THREAD_READ]);
  printf ("writelist : ");
  thread_list_debug (&m->list[THREAD_WRITE]);
  printf ("timerlist : ");
  thread_list_debug (&m->list[THREAD_TIMER]);
  printf ("eventlist : ");
  thread_list_debug (&m->list[THREAD_EVENT]);
  printf ("unuselist : ");
  thread_list_debug (&m->list[THREAD_UNUSED]);
  printf ("bgndlist : ");
  thread_list_debug (&m->list[THREAD_BACKGROUND]);
  printf ("total alloc: [%ld]\n", m->alloc);
  printf ("-----------\n");
}

/* Allocate new thread master.  */
struct thread_master *
thread_master_create ()
{
  return (struct thread_master *) XCALLOC (MTYPE_THREAD_MASTER,
                                           sizeof (struct thread_master));
}

/* Add a new thread to the list.  */
static struct thread *
thread_list_add (struct thread_master *m, struct thread *thread,
                                                            thread_type_t queue)
{
  struct thread_list *list ;

  qassert(queue < THREAD_LIST_COUNT) ;
  qassert(thread->master == m) ;
  qassert(thread->queue  == THREAD_LIST_NONE) ;

  if (queue >= THREAD_LIST_COUNT)
    return thread ;

  thread->queue = queue ;
  list          = &m->list[queue] ;

  thread->next = NULL;
  thread->prev = list->tail;
  if (list->tail)
    list->tail->next = thread;
  else
    list->head = thread;
  list->tail = thread;
  list->count++;

  return thread ;
}

/* Add a new thread just before the point.  */
static struct thread *
thread_list_add_before (struct thread_master *m,
                        struct thread *point,
                        struct thread *thread,
                        thread_type_t queue)
{
  struct thread_list *list ;

  qassert(queue < THREAD_LIST_COUNT) ;
  qassert(thread->master == m) ;
  qassert(thread->queue  == THREAD_LIST_NONE) ;
  qassert(point->queue   == queue) ;

  if (queue >= THREAD_LIST_COUNT)
    return thread ;

  thread->queue = queue ;
  list          = &m->list[queue] ;

  thread->next = point;
  thread->prev = point->prev;
  if (point->prev)
    point->prev->next = thread;
  else
    list->head = thread;
  point->prev = thread;
  list->count++;

  return thread ;
}

static void thread_qtimer_unset(struct thread* thread) ;

/* Delete a thread from the list. */
static struct thread *
thread_list_delete (struct thread_master *m, struct thread *thread)
{
  struct thread_list* list ;
  thread_type_t queue ;

  qassert(thread->master == m) ;

  queue = thread->queue ;

  switch (queue)
    {
      case THREAD_READ:
        assert (FD_ISSET (thread->u.fd, &m->readfd));
        FD_CLR (thread->u.fd, &m->readfd);
        break;
      case THREAD_WRITE:
        assert (FD_ISSET (thread->u.fd, &m->writefd));
        FD_CLR (thread->u.fd, &m->writefd);
        break;
      case THREAD_TIMER:
        if (use_qtimer_pile != NULL)
          thread_qtimer_unset(thread) ;
        break;
      case THREAD_EVENT:
      case THREAD_READY:
      case THREAD_BACKGROUND:
      case THREAD_UNUSED:
        break;

      default:
        qassert(false) ;
        return thread ;
    } ;

  thread->queue = THREAD_LIST_NONE ;

  list = &m->list[queue] ;

  if (thread->next)
    thread->next->prev = thread->prev;
  else
    list->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  else
    list->head = thread->next;
  thread->next = thread->prev = NULL;
  list->count--;
  return thread;
}

/* Move thread to unuse list. */
static void
thread_add_unuse (struct thread_master *m, struct thread *thread)
{
  assert ((m != NULL) && (thread != NULL));
  qassert((thread->next == NULL) && (thread->prev == NULL));
  thread_list_add (m, thread, THREAD_UNUSED) ;
}

static struct thread* thread_head(struct thread_master *m, thread_type_t queue);

/* Free all unused thread. */
static void
thread_list_free (struct thread_master *m, thread_type_t queue)
{
  struct thread *thread;
  struct thread *next;
  bool  qtimer ;
  int count ;

  qtimer = ((queue == THREAD_TIMER) && (use_qtimer_pile != NULL)) ;

  count = 0 ;
  for (thread = thread_head(m, queue); thread; thread = next)
    {
      qassert(thread->queue  == queue) ;
      qassert(thread->master == m) ;

      next = thread->next;

      if (qtimer && (thread->u.qtr != NULL))
        qtimer_free(thread->u.qtr) ;

      XFREE (MTYPE_THREAD, thread);
      count += 1 ;
    }

  qassert(m->list[queue].count == count) ;

  m->list[queue].head   = m->list[queue].tail = NULL ;
  m->list[queue].count -= count ;
  m->alloc             -= count ;
}

/*------------------------------------------------------------------------------
 * Stop thread scheduler (if any).
 *
 * Empties out all the thread lists and releases the given thread master.
 */
extern struct thread_master *
thread_master_free (struct thread_master *m)
{
  if (m != NULL)
    {
      thread_type_t queue ;

      for (queue = 0 ; queue < THREAD_LIST_COUNT ; ++queue)
        thread_list_free (m, queue);

      XFREE (MTYPE_THREAD_MASTER, m);   /* sets m = NULL        */
    } ;

  return m ;
}

/* Thread list is empty or not.  */
static struct thread*
thread_head(struct thread_master *m, thread_type_t queue)
{
  struct thread* head ;

  if (queue >= THREAD_LIST_COUNT)
    return NULL ;

  head = m->list[queue].head ;

  if (head != NULL)
    qassert((head->queue == queue) && (head->master == m)) ;

  return head ;
}

/* Delete top of the list and return it. */
static struct thread *
thread_trim_head (struct thread_master *m, thread_type_t queue)
{
  struct thread* head ;

  head = thread_head(m, queue) ;

  if (head != NULL)
    return thread_list_delete (m, head);

  return NULL;
}

/* Return remain time in second. */
unsigned long
thread_timer_remain_second (struct thread *thread)
{
  quagga_get_relative (NULL);

  if (thread->u.sands.tv_sec - relative_time.tv_sec > 0)
    return thread->u.sands.tv_sec - relative_time.tv_sec;
  else
    return 0;
}

/* Get new cpu history          */

static struct cpu_thread_history*
thread_get_hist(struct thread* thread, const char* funcname)
{
  struct cpu_thread_history  tmp ;
  struct cpu_thread_history* hist ;

  tmp.func     = thread->func ;
  tmp.funcname = miyagi(funcname);  /* NB: will not free tmp in the usual way,
                                           in particular, will not attempt
                                           to free this !!                    */
  LOCK

  /* This looks up entry which matches the tmp just set up.
   *
   * If does not find one, allocates a new one -- taking a copy of the
   * funcname.
   */
  hist = hash_get (cpu_record, &tmp, cpu_record_hash_alloc);
  UNLOCK

  return hist ;
} ;

/* Get new thread.
 *
 * Sets thread->queue == THREAD_LIST_NONE -- to be tidy !
 */
static struct thread *
thread_get (struct thread_master *m, u_char type,
            int (*func) (struct thread *), void *arg, const char* funcname)
{
  struct thread *thread;

  thread = thread_trim_head (m, THREAD_UNUSED) ;

  if (thread != NULL)
    {
      memset(thread, 0, sizeof (struct thread)) ;
    }
  else
    {
      thread = XCALLOC (MTYPE_THREAD, sizeof (struct thread));
      m->alloc++;
    }
  thread->queue    = THREAD_LIST_NONE;
  thread->type     = type;
  thread->master   = m;
  thread->func     = func;
  thread->arg      = arg;

  thread->hist     = thread_get_hist(thread, funcname) ;

  return thread ;
}

/* Add new read thread. */
struct thread *
funcname_thread_add_read (struct thread_master *m,
                 int (*func) (struct thread *), void *arg, int fd, const char* funcname)
{
  struct thread *thread;

  assert (m != NULL);

  if (FD_ISSET (fd, &m->readfd))
    {
      zlog (NULL, LOG_WARNING, "There is already read fd [%d]", fd);
      return NULL;
    }

  thread = thread_get (m, THREAD_READ, func, arg, funcname);
  FD_SET (fd, &m->readfd);
  thread->u.fd = fd;
  return thread_list_add (m, thread, THREAD_READ);
}

/* Add new write thread. */
struct thread *
funcname_thread_add_write (struct thread_master *m,
                 int (*func) (struct thread *), void *arg, int fd, const char* funcname)
{
  struct thread *thread;

  assert (m != NULL);

  if (FD_ISSET (fd, &m->writefd))
    {
      zlog (NULL, LOG_WARNING, "There is already write fd [%d]", fd);
      return NULL;
    }

  thread = thread_get (m, THREAD_WRITE, func, arg, funcname);
  FD_SET (fd, &m->writefd);
  thread->u.fd = fd;
  return thread_list_add (m, thread, THREAD_WRITE);
}

/*==============================================================================
 * Timer Threads -- THREAD_TIMER and THREAD_BACKGROUND
 *
 * Standard Timer Threads are sorted by the "struct timeval sands", and
 * processed by thread_timer_process() -- which moves any expired timer
 * threads onto the THREAD_READY queue.  So, the scheduling of background stuff
 * is done by not processing the THREAD_BACKGROUND queue until there is
 * nothing else to do.
 *
 * When using a qtimer_pile:
 *
 *  * THREAD_TIMER threads have an associated qtimer.
 *
 *    When the timer expires, the qtimer is cut from the thread (and put onto
 *    the spare_qtimers list).  The thread is then queued on the THREAD_READY
 *    queue (as before).
 *
 *  * THREAD_BACKGROUND threads which have a non-zero delay are treated much
 *    as THREAD_TIMER, except that when the timer expires, the thread is
 *    queued on the THREAD_BACKGROUND queue.
 *
 *    The THREAD_BACKGROUND queue is visited only when there is nothing else
 *    to do.
 *
 * Note that when using a qtimer_pile, and there is an active qtimer associated
 * with the thread, the thread will be on the THREAD_TIMER queue -- so that it
 * can be collected up and released if required.
 *
 * NB: when using a qtimer_pile, if there is a qtimer associated with a
 *     THREAD_TIMER or a THREAD_BACKGROUND thread, then thread->u.qtr points
 *     at the qtimer.
 *
 *     AND, conversely, if there is no qtimer, then thread->u.qtr == NULL.
 */

/*------------------------------------------------------------------------------
 * Set use_qtimer_pile !
 */
extern void
thread_set_qtimer_pile(qtimer_pile pile)
{
  passert(!used_standard_timer) ;

  use_qtimer_pile = pile ;
} ;

/*------------------------------------------------------------------------------
 * Unset qtimer associated with the given THREAD_TIMER or THREAD_BACKGROUND
 * thread -- if any.
 *
 * Moves any qtimer onto the spare_qtimers list.
 */
static void
thread_qtimer_unset(struct thread* thread)
{
  qtimer qtr ;
  assert (thread->queue == THREAD_TIMER );
  assert ( (thread->type == THREAD_TIMER) ||
           (thread->type == THREAD_BACKGROUND)) ;
  qassert(use_qtimer_pile != NULL) ;

  qtr = thread->u.qtr ;
  if (qtr != NULL)
    {
      if ((qtr->state & qtrs_active) != 0)
        qassert((use_qtimer_pile != NULL) && (use_qtimer_pile == qtr->pile)) ;

      qtimer_unset(qtr) ;

      qtr->pile = (void*)spare_qtimers ;
      spare_qtimers = qtr ;

      thread->u.qtr = NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * The qtimer action function -- when using qtimer pile (!)
 *
 * Remove thread from the THREAD_TIMER queue and unset the qtimer, place
 * thread on the THREAD_READY or the THREAD_BACKGROUND queue as required.
 */
static void
thread_qtimer_dispatch(qtimer qtr, void* timer_info, qtime_mono_t when)
{
  struct thread* thread = timer_info ;

  qassert(thread->queue == THREAD_TIMER) ;
  qassert(thread->u.qtr == qtr) ;

  thread_list_delete (thread->master, thread) ;

  switch (thread->type)
  {
    case THREAD_TIMER:
      thread_list_add (thread->master, thread, THREAD_READY);
      break ;

    case THREAD_BACKGROUND:
      thread_list_add (thread->master, thread, THREAD_BACKGROUND);
      break ;

    default:
      zabort("invalid thread type in thread_qtimer_dispatch") ;
  } ;
} ;

/*------------------------------------------------------------------------------
 * For standard timers, return time left on first timer on the given list.
 */
static struct timeval *
thread_timer_wait (struct thread_master *m, thread_type_t queue,
                                                      struct timeval *timer_val)
{
  struct thread* head ;

  head = thread_head(m, queue) ;

  if (head != NULL)
    {
      *timer_val = timeval_subtract (head->u.sands, relative_time);
      return timer_val;
    }

  return NULL;
}

/*------------------------------------------------------------------------------
 * Add timer of given type -- either standard or qtimer_pile as required.
 *
 * Timer interval is given as a struct timeval.
 */
static struct thread *
funcname_thread_add_timer_timeval(struct thread_master *m,
                                  int (*func) (struct thread *),
                                  int type,
                                  void *arg,
                                  struct timeval *time_relative,
                                  const char* funcname)
{
  struct thread *thread;

  assert (m != NULL);
  assert (time_relative != NULL);

  qassert ((type == THREAD_TIMER) || (type == THREAD_BACKGROUND));
  if ((type != THREAD_TIMER) && (type != THREAD_BACKGROUND))
    return NULL ;

  thread = thread_get (m, type, func, arg, funcname);

  if (use_qtimer_pile == NULL)
    {
      struct timeval alarm_time;
      struct thread *tt;

      /* Do we need jitter here? */
      quagga_get_relative (NULL);
      alarm_time.tv_sec  = relative_time.tv_sec  + time_relative->tv_sec;
      alarm_time.tv_usec = relative_time.tv_usec + time_relative->tv_usec;
      thread->u.sands = timeval_adjust(alarm_time);

      /* Sort by timeval. */

      for (tt = thread_head(m, type); tt; tt = tt->next)
        if (timeval_cmp (thread->u.sands, tt->u.sands) <= 0)
          break;

      if (tt)
        thread_list_add_before (m, tt, thread, type);
      else
        thread_list_add (m, thread, type);

      used_standard_timer = true ;
    }
  else
    {
      qtimer qtr = spare_qtimers ;
      if (qtr != NULL)
        spare_qtimers = (qtimer)(qtr->pile) ;

      qtr = qtimer_init_new(qtr, use_qtimer_pile, NULL, thread) ;
      thread->u.qtr = qtr ;

      qtimer_set_interval(qtr, timeval2qtime(time_relative),
                                                       thread_qtimer_dispatch) ;
      thread_list_add(m, thread, THREAD_TIMER) ;
    } ;

  return thread;
}

/*------------------------------------------------------------------------------
 * Add a THREAD_TIMER timer -- either standard or qtimer_pile as required.
 *
 * Timer interval is given in seconds.
 */
struct thread *
funcname_thread_add_timer (struct thread_master *m,
                           int (*func) (struct thread *),
                           void *arg, long timer, const char* funcname)
{
  struct timeval trel;

  trel.tv_sec  = timer;
  trel.tv_usec = 0;

  return funcname_thread_add_timer_timeval (m, func, THREAD_TIMER, arg,
                                            &trel, funcname);
}

/*------------------------------------------------------------------------------
 * Add a THREAD_TIMER timer -- either standard or qtimer_pile as required.
 *
 * Timer interval is given in milliseconds.
 */
struct thread *
funcname_thread_add_timer_msec (struct thread_master *m,
                                int (*func) (struct thread *),
                                void *arg, long timer, const char* funcname)
{
  struct timeval trel;

  trel.tv_sec  =  timer / 1000 ;
  trel.tv_usec = (timer % 1000) * 1000 ;

  return funcname_thread_add_timer_timeval (m, func, THREAD_TIMER,
                                                          arg, &trel, funcname);
}

/*------------------------------------------------------------------------------
 * Add a THREAD_BACKGROUND thread -- either standard or qtimer_pile as required.
 *
 * Timer interval is given in milliseconds.
 *
 * For qtimer_pile, if the delay is zero, the thread is placed straight onto
 * the THREAD_BACKGROUND queue.
 */
struct thread *
funcname_thread_add_background (struct thread_master *m,
                                int (*func) (struct thread *),
                                void *arg, long delay,
                                const char *funcname)
{
  if ((delay != 0) || (use_qtimer_pile == NULL))
    {
      struct timeval trel;

      trel.tv_sec  =  delay / 1000;
      trel.tv_usec = (delay % 1000) * 1000 ;

      return funcname_thread_add_timer_timeval (m, func, THREAD_BACKGROUND,
                                                arg, &trel, funcname);
    }
  else
    {
      struct thread* thread ;

      assert (m != NULL);

      thread = thread_get (m, THREAD_BACKGROUND, func, arg, funcname);
      return thread_list_add (m, thread, THREAD_BACKGROUND) ;
    } ;
}

/*----------------------------------------------------------------------------*/
/* Add simple event thread. */
struct thread *
funcname_thread_add_event (struct thread_master *m,
                  int (*func) (struct thread *), void *arg, int val,
                                                           const char* funcname)
{
  struct thread *thread;

  assert (m != NULL);

  thread = thread_get (m, THREAD_EVENT, func, arg, funcname);
  thread->u.val = val;
  return thread_list_add (m, thread, THREAD_EVENT);
}

/*------------------------------------------------------------------------------
 * Cancel thread from scheduler.
 *
 * Note that when using qtimer_pile need to unset any associated qtimer.
 */
void
thread_cancel (struct thread *thread)
{
  thread_list_delete (thread->master, thread);
  thread_add_unuse (thread->master, thread);
}

/* Delete all events which has argument value arg. */
unsigned int
thread_cancel_event (struct thread_master *m, void *arg)
{
  unsigned int ret = 0;
  struct thread *thread;

  thread = thread_head(m, THREAD_EVENT);
  while (thread)
    {
      struct thread *next;

      qassert(thread->queue == THREAD_EVENT) ;

      next = thread->next;

      if (thread->arg == arg)
        {
          thread_cancel (thread) ;
          ret++;
        }

      thread = next ;
    }
  return ret;
}

static struct thread *
thread_run (struct thread_master *m, struct thread *thread,
            struct thread *fetch)
{
  qassert(thread->queue  == THREAD_LIST_NONE) ;
  qassert(thread->master == m) ;

  *fetch = *thread;
  thread_add_unuse (m, thread);
  return fetch;
}

static int
thread_process_fd (struct thread_master *m, thread_type_t queue, fd_set *fdset)
{
  struct thread *thread;
  struct thread *next;
  int ready = 0;

  for (thread = thread_head(m, queue); thread; thread = next)
    {
      qassert(thread->queue  == queue) ;
      qassert(thread->master == m) ;

      next = thread->next;

      if (FD_ISSET (THREAD_FD (thread), fdset))
        {
          thread_list_delete (m, thread);
          thread_list_add (m, thread, THREAD_READY);
          ready++;
        }
    }
  return ready;
}

/* Add all timers that have popped to the ready list. */
static unsigned int
thread_timer_process (struct thread_master *m, thread_type_t queue,
                                                        struct timeval *timenow)
{
  struct thread *thread;
  struct thread *next;
  unsigned int ready = 0;

  for (thread = thread_head(m, queue); thread; thread = next)
    {
      qassert(thread->queue  == queue) ;
      qassert(thread->master == m) ;

      next = thread->next;
      if (timeval_cmp (*timenow, thread->u.sands) < 0)
        return ready;
      thread_list_delete (m, thread);
      thread_list_add (m, thread, THREAD_READY);
      ready++;
    }
  return ready;
}

/*------------------------------------------------------------------------------
 * Move the given list of threads to the back of the THREAD_READY queue.
 */
static unsigned int
thread_process (struct thread_master *m, thread_type_t queue)
{
  struct thread *thread;
  struct thread *next;
  unsigned int ready = 0;

  for (thread = thread_head(m, queue); thread; thread = next)
    {
      qassert(thread->queue  == queue) ;
      qassert(thread->master == m) ;

      next = thread->next;
      thread_list_delete (m, thread);
      thread_list_add (m, thread, THREAD_READY);
      ready++;
    }
  return ready;
}

/*------------------------------------------------------------------------------
 * Fetch next ready thread -- for standard thread handing.
 *
 * (This is not used when using qtimer_pile, or qnexus stuff.)
 */
struct thread *
thread_fetch (struct thread_master *m, struct thread *fetch)
{
  struct thread *thread;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  struct timeval timer_val ;
  struct timeval timer_val_bg;
  struct timeval *timer_wait ;
  struct timeval *timer_wait_bg;

  while (1)
    {
      int num = 0;

      /* Signals pre-empt everything */
      quagga_sigevent_process ();

      /* Drain the ready queue of already scheduled jobs, before scheduling
       * more.
       */
      if ((thread = thread_trim_head (m, THREAD_READY)) != NULL)
        return thread_run (m, thread, fetch);

      /* To be fair to all kinds of threads, and avoid starvation, we
       * need to be careful to consider all thread types for scheduling
       * in each quanta. I.e. we should not return early from here on.
       */

      /* Normal event are the next highest priority.  */
      thread_process (m, THREAD_EVENT);

      /* Structure copy.  */
      readfd = m->readfd;
      writefd = m->writefd;
      exceptfd = m->exceptfd;

      /* Calculate select wait timer if nothing else to do */
      if (m->list[THREAD_READY].count == 0)
        {
          quagga_get_relative (NULL);
          timer_wait = thread_timer_wait (m, THREAD_TIMER, &timer_val);
          timer_wait_bg = thread_timer_wait (m, THREAD_BACKGROUND, &timer_val_bg);

          if (timer_wait_bg &&
              (!timer_wait || (timeval_cmp (*timer_wait, *timer_wait_bg) > 0)))
            timer_wait = timer_wait_bg;
        }
      else
        {
          timer_val.tv_sec   = 0 ;
          timer_val.tv_usec  = 0 ;
          timer_wait = &timer_val ;
        } ;

      num = select (FD_SETSIZE, &readfd, &writefd, &exceptfd, timer_wait);

      /* Signals should get quick treatment */
      if (num < 0)
        {
          if (errno == EINTR)
          continue; /* signal received - process it */
          zlog_warn ("select() error: %s", errtoa(errno, 0).str);
            return NULL;
        }

      /* Check foreground timers.  Historically, they have had higher
         priority than I/O threads, so let's push them onto the ready
         list in front of the I/O threads. */
      quagga_get_relative (NULL);
      thread_timer_process (m, THREAD_TIMER, &relative_time);

      /* Got IO, process it */
      if (num > 0)
        {
          /* Normal priority read thead. */
          thread_process_fd (m, THREAD_READ, &readfd);
          /* Write thead. */
          thread_process_fd (m, THREAD_WRITE, &writefd);
        }

#if 0
      /* If any threads were made ready above (I/O or foreground timer),
         perhaps we should avoid adding background timers to the ready
         list at this time.  If this is code is uncommented, then background
         timer threads will not run unless there is nothing else to do. */
      if ((thread = thread_trim_head (&m->ready)) != NULL)
        return thread_run (m, thread, fetch);
#endif

      /* Background timer/events, lowest priority */
      thread_timer_process (m, THREAD_BACKGROUND, &relative_time);

      if ((thread = thread_trim_head (m, THREAD_READY)) != NULL)
        return thread_run (m, thread, fetch);
    }
}

/*------------------------------------------------------------------------------
 * Empties the event and ready queues.
 *
 * This is used when qnexus is managing most things, including I/O.  Must be
 * using qtimer_pile !
 *
 * This runs "legacy" event and ready queues only.
 *
 * Returns: the number of threads dispatched.
 *
 * Legacy timers are handled by the qtimer_pile, and their related threads will
 * be placed on the ready queue when they expire.
 *
 * The background queue is handled separately.
 */
extern int
thread_dispatch(struct thread_master *m)
{
  int   count = 0 ;

  while (1)
    {
      struct thread* thread ;
      struct thread fetch ;

      if ((thread = thread_trim_head(m, THREAD_EVENT)) == NULL)
        if ((thread = thread_trim_head(m, THREAD_READY)) == NULL)
          return count ;

      thread_call(thread_run(m, thread, &fetch)) ;

      ++count ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch first item on the background queue, if any.
 *
 * This is used when qnexus is managing most things.
 *
 * Background threads spend their lives being cycled around the background
 * queue -- possibly via the timer queue, if a delay is put in before the next
 * invocation.
 *
 * Returns: 1 if dispatched a background thread
 *          0 if there are no background threads
 */
extern int
thread_dispatch_background(struct thread_master *m)
{
  struct thread* thread ;
  struct thread fetch ;

  if ((thread = thread_trim_head (m, THREAD_BACKGROUND)) == NULL)
    return 0 ;

  thread_call(thread_run(m, thread, &fetch)) ;

  return 1 ;
} ;


unsigned long
thread_consumed_time (RUSAGE_T *now, RUSAGE_T *start, unsigned long *cputime)
{
#ifdef HAVE_RUSAGE
  /* This is 'user + sys' time.  */
  *cputime = timeval_elapsed (now->cpu.ru_utime, start->cpu.ru_utime) +
             timeval_elapsed (now->cpu.ru_stime, start->cpu.ru_stime);
#else
  *cputime = 0;
#endif /* HAVE_RUSAGE */
  return timeval_elapsed (now->real, start->real);
}

/* We should aim to yield after THREAD_YIELD_TIME_SLOT milliseconds.
   Note: we are using real (wall clock) time for this calculation.
   It could be argued that CPU time may make more sense in certain
   contexts.  The things to consider are whether the thread may have
   blocked (in which case wall time increases, but CPU time does not),
   or whether the system is heavily loaded with other processes competing
   for CPU time.  On balance, wall clock time seems to make sense.
   Plus it has the added benefit that gettimeofday should be faster
   than calling getrusage. */
int
thread_should_yield (struct thread *thread)
{
  quagga_get_relative (NULL);
  return (timeval_elapsed(relative_time, thread->ru.real) >
          THREAD_YIELD_TIME_SLOT);
}

void
thread_getrusage (RUSAGE_T *r)
{
  quagga_get_relative (NULL);
#ifdef HAVE_RUSAGE
  getrusage(RUSAGE_SELF, &(r->cpu));
#endif
  r->real = relative_time;

#ifdef HAVE_CLOCK_MONOTONIC
  /* quagga_get_relative() only updates recent_time if gettimeofday
   * based, not when using CLOCK_MONOTONIC. As we export recent_time
   * and guarantee to update it before threads are run...
   */
  quagga_gettimeofday(&recent_time);
#endif /* HAVE_CLOCK_MONOTONIC */
}

/* We check thread consumed time. If the system has getrusage, we'll
   use that to get in-depth stats on the performance of the thread in addition
   to wall clock time stats from gettimeofday. */
void
thread_call (struct thread *thread)
{
  unsigned long realtime, cputime;
  RUSAGE_T ru;

  GETRUSAGE (&thread->ru);

  (*thread->func) (thread);

  GETRUSAGE (&ru);

  realtime = thread_consumed_time (&ru, &thread->ru, &cputime);

  if (thread->hist != NULL)
    {
      LOCK
      thread->hist->real.total += realtime;
      if (thread->hist->real.max < realtime)
        thread->hist->real.max = realtime;
#ifdef HAVE_RUSAGE
      thread->hist->cpu.total += cputime;
      if (thread->hist->cpu.max < cputime)
        thread->hist->cpu.max = cputime;
#endif

      ++(thread->hist->total_calls);
      thread->hist->types |= (1 << thread->type);
      UNLOCK
    } ;

#ifdef CONSUMED_TIME_CHECK
  if (realtime > CONSUMED_TIME_CHECK)
    {
      /*
       * We have a CPU Hog on our hands.
       * Whinge about it now, so we're aware this is yet another task
       * to fix.
       */
      zlog_warn ("SLOW THREAD: task %s (%lx) ran for %lums (cpu time %lums)",
                 (thread->hist != NULL) ? thread->hist->funcname : "??",
                 (unsigned long) thread->func,
                 realtime/1000, cputime/1000);
    }
#endif /* CONSUMED_TIME_CHECK */

}

/* Execute thread */
struct thread *
funcname_thread_execute (struct thread_master *m,
                int (*func)(struct thread *),
                void *arg,
                int val,
                const char* funcname)
{
  struct thread dummy;

  memset (&dummy, 0, sizeof (struct thread));

  dummy.queue  = THREAD_LIST_NONE;
  dummy.type   = THREAD_EXECUTE;
  dummy.master = NULL;
  dummy.func = func;
  dummy.arg = arg;
  dummy.u.val = val;
  dummy.hist = thread_get_hist(&dummy, funcname) ;
  thread_call (&dummy);

  return NULL;
}

/* First stage initialisation -- before any pthreads are started
 *
 * Set up the global "master" thread_master.
 */
extern void
thread_start_up(void)
{
  qassert(!qpthreads_enabled) ;

  master = thread_master_create ();

  cpu_record = hash_create_size (1011, cpu_record_hash_key,
                                                        cpu_record_hash_equal) ;
  thread_mutex        = NULL ;

  use_qtimer_pile     = NULL ;
  spare_qtimers       = NULL ;

  used_standard_timer = false ;
} ;

/* Second stage initialisation if qpthreaded */
void
thread_init_r (void)
{
  thread_mutex = qpt_mutex_new(qpt_mutex_quagga, "Legacy Threads");
}

/* Finished with module
 */
void
thread_finish (void)
{
  qtimer qtr ;

  qassert(!qpthreads_active) ;

  master = thread_master_free(master) ;

  if (cpu_record != NULL)
    {
      hash_clean (cpu_record, cpu_record_hash_free);
      hash_free (cpu_record);
      cpu_record = NULL;
    }

  while ((qtr = spare_qtimers) != NULL)
    {
      spare_qtimers = (void*)(qtr->pile) ;
      qtimer_free(qtr) ;
    } ;

  thread_mutex = qpt_mutex_destroy(thread_mutex);
}

/*------------------------------------------------------------------------------
 * Thread commands
 */
CMD_INSTALL_TABLE(extern, thread_cmd_table, ALL_RDS) =
{
  { RESTRICTED_NODE, &show_thread_cpu_cmd                               },
  { VIEW_NODE,       &show_thread_cpu_cmd                               },
  { ENABLE_NODE,     &show_thread_cpu_cmd                               },

  { ENABLE_NODE,     &clear_thread_cpu_cmd                              },

  CMD_INSTALL_END
} ;

