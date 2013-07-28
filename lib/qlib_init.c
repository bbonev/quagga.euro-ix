/* Quagga library initialise/closedown -- functions
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

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "qlib_init.h"
#include "zassert.h"
#include "memory.h"
#include "mempool.h"
#include "qlump.h"
#include "qpnexus.h"
#include "qpthreads.h"
#include "qatomic.h"
#include "qtime.h"
#include "qpselect.h"
#include "thread.h"
#include "privs.h"
#include "mqueue.h"
#include "pthread_safe.h"
#include "log_local.h"
#include "qiovec.h"
#include "prefix_id.h"

/*==============================================================================
 * Quagga Library Initialise/Closedown
 *
 * This gathers together the essential initialisation and closedown for the
 * library.  This ensures that any changes in the library are contained here,
 * and do not require changes in all users of the library.
 *
 * There are two stages of initialisation:
 *
 *   1) first stage
 *
 *      this is expected to be called before the program does anything at all.
 *
 *      Collects a small number of useful system parameters -- see below.
 *
 *      This performs all initialisation required to support asserts, logging,
 *      basic I/O (but not the remote console), trap signals... and so on.
 *
 *      After this has been done, the system is in good shape to deal with
 *      command line options, configuration files and so on.
 *
 *   2) second stage
 *
 *      this is expected to be called before the program does any serious work.
 *
 *      This performs all initialisation required to support socket I/O,
 *      thread handling, timers, and so on.
 *
 *      NB: at this stage the system is set into pthread mode, if required.
 *
 *          No pthreads may be started before this.  Up to this point
 *          the system operates in non-pthread mode -- all mutexes are
 *          implicitly free.
 *
 * There is one stage of closedown.  This is expected to be called last, and
 * is passed the exit code.
 *
 *==============================================================================
 * System parameters:
 *
 */
static struct qlib_sysconf qlib_s  = { 0 } ;

/* extern */ const struct qlib_sysconf* qlib = &qlib_s ;

struct
{
  int*        p_var ;
  int         sc ;
  const char* name ;
  long        min ;
  long        max ;
} qlib_vars[] =
{
    { .p_var = &qlib_s.iov_max,        .sc =  _SC_IOV_MAX,
                                     .name = "_SC_IOV_MAX",
                                      .min =  16,
                                      .max = INT_MAX
    },
    { .p_var = &qlib_s.open_max,       .sc =  _SC_OPEN_MAX,
                                     .name = "_SC_OPEN_MAX",
                                      .min = 256,
                                      .max = INT_MAX
    },
    { .p_var = &qlib_s.pagesize,       .sc =  _SC_PAGESIZE,
                                     .name = "_SC_PAGESIZE",
                                      .min = 256,
                                      .max = (INT_MAX >> 1) + 1
    },
    { .p_var = &qlib_s.thread_cputime, .sc =  _SC_THREAD_CPUTIME,
                                     .name = "_SC_THREAD_CPUTIME",
                                      .min =  -1,
                                      .max = INT_MAX
    },
    { .p_var = &qlib_s.cputime,        .sc =  _SC_CPUTIME,
                                     .name = "_SC_CPUTIME",
                                      .min =  -1,
                                      .max = INT_MAX
    },
    { .p_var = NULL }
} ;

/*------------------------------------------------------------------------------
 * First stage initialisation.
 *
 * Required for all users of the quagga library, whether running pthreaded or
 * not.
 *
 * Should be absolutely the first action -- other than, perhaps, saying hello
 * on stderr or the like.
 *
 * Must precede any command line option handling, so can set defaults for
 * things which may be affected by such options.
 */
extern void
qlib_init_first_stage(mode_t cmask)
{
  int   i ;

  /* Set umask at a very early stage, if required.
   */
  if (cmask != 0)
    umask(cmask) ;

  /* Fetch the system parameters per the table above
   */
  for (i = 0 ; qlib_vars[i].p_var != NULL ; ++i)
    {
      long  val ;

      errno = 0 ;
      val = sysconf(qlib_vars[i].sc) ;

      if (val == -1)
        {
          if (errno == 0)
            val = INT_MAX ;
          else
            {
              fprintf(stderr, "Failed to sysconf(%s): %s\n",
                                  qlib_vars[i].name, errtoa(errno, 0).str) ;
              exit(1) ;
            } ;
        } ;

      if ((val < qlib_vars[i].min) || (val > qlib_vars[i].max))
        {
          fprintf(stderr, "sysconf(%s) = %ld: which is < %ld or > %ld\n",
                   qlib_vars[i].name, val, qlib_vars[i].min, qlib_vars[i].max) ;
          exit(1) ;
        } ;

      *(qlib_vars[i].p_var) = (int)val ;
    } ;

  /* Initialise as required.
   *
   * The start_up initialisers really ought to have few if any dependencies,
   * and ay there are must be documented here:
   *
   *  1. memory is the first to be initialised, and the last to be shut down.
   *
   *     memory pools are initialised just after the malloc wrappers, and
   *     memory lumps are initialised after that.
   *
   *  2. qtime is initialised early, so that crafted monotonic time etc are
   *     available just in case other initialisation wants it.
   *
   *  3. qpthreads is also initialised early, to make sure that its state is
   *     correct, just in case.
   */
  memory_start_up(qlib->pagesize) ;
  qmp_start_up() ;
  qlump_start_up() ;
  qs_start_up() ;               /* after qlump  */
  qt_start_up() ;
  qpt_start_up(qlib->cputime, qlib->thread_cputime) ;
  qatomic_start_up() ;
  qps_start_up() ;
  qiovec_start_up(qlib->iov_max) ;
  thread_start_up();
  qpn_wd_start_up() ;
  prefix_id_init() ;
} ;

/*------------------------------------------------------------------------------
 * Second stage initialisation.
 *
 * At this point we know whether will run pthreaded, and that is set for the
 * duration, followed by any further initialisation that depends on knowing
 * the pthreaded-ness.
 *
 * This is done fairly late during start up, after any configuration has been
 * read which may choose whether to run pthreaded or not.
 *
 * Not required for daemons that do not use any of the newer facilities, but
 * is recommended.
 */
extern void
qlib_init_second_stage(bool pthreaded)
{
  qpt_second_stage(pthreaded);
  qatomic_second_stage() ;
  memory_init_r();
  qmp_second_stage() ;
  qt_second_stage() ;
  qpn_init() ;
  thread_init_r();
  log_init_r() ;
  zprivs_init_r();
  mqueue_initialise();
  safe_init_r();
}

/*------------------------------------------------------------------------------
 * Shut down
 *
 * NB: at this point it is assumed that all pthreads but one (probably the
 *     main pthread) have stopped or are stopping -- and that either no
 *     new pthreads will be started, or any that are started will quickly
 *     stop.
 *
 *     Will collect all pthreads, joinable and detached, and destroy all
 *     qpt_thread objects -- then clear qpt_threads_active for remainder of
 *     shut down.
 *
 * NB: memory is the last thing to be shut down, and if the given
 *     "mem_stats_name" is not NULL, will spew out information about any
 *     memory that has not been freed to stderr !
 */
extern void
qexit(int exit_code, bool mem_stats)
{
  qatomic_finish() ;
  qpt_finish() ;

  prefix_id_finish() ;
  safe_finish();
  mqueue_finish();
  zprivs_finish();
  log_finish();
  thread_finish();
  qt_finish() ;
  qs_finish() ;
  qlump_finish() ;
  qmp_finish(mem_stats) ;
  memory_finish(mem_stats);
  exit (exit_code);
}


