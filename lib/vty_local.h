/* VTY top level
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * Revisions: Copyright (C) 2010 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_VTY_LOCAL_H
#define _ZEBRA_VTY_LOCAL_H

#include "misc.h"
#include "list_util.h"
#include "vty_common.h"         /* First and foremost                   */
#include "command_common.h"

#include "vargs.h"

#include "qpthreads.h"
#include "qpnexus.h"
#include "qpath.h"

/*==============================================================================
 * This is for access to some things in vty.c which are not required
 * by external users, who use vty.h.
 *
 * This is for use within the command/vty family.
 *
 * Should not be used with vty.h !  (Except in vty.c itself.)
 *
 * This may duplicate things published in vty.h, but also includes things
 * which are not intended for "external" use.
 */

/*------------------------------------------------------------------------------
 * Sort out VTY_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if VTY_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set VTY_DEBUG    == 0 to turn off debug
 *       *  or set VTY_DEBUG    != 0 to turn on debug
 *       *  or set VTY_NO_DEBUG != 0 to force debug off
 */

#ifdef VTY_DEBUG                /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(VTY_DEBUG)
#  undef  VTY_DEBUG
#  define VTY_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define VTY_DEBUG QDEBUG
#endif

#ifdef VTY_NO_DEBUG             /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(VTY_NO_DEBUG)
#  undef  VTY_DEBUG
#  define VTY_DEBUG 0
# endif
#endif

enum { vty_debug = VTY_DEBUG } ;

/*------------------------------------------------------------------------------
 * The VTYSH uses a unix socket to talk to the daemon.
 *
 * The ability to respond to a connection from VTYSH appears to be a *compile*
 * time option.  In the interests of keeping the code up to date, the VTYSH
 * option is turned into a testable constant.
 */
#ifdef VTYSH
  enum { VTYSH_ENABLED = true  } ;
#else
  enum { VTYSH_ENABLED = false } ;
#endif

/*==============================================================================
 * Variables in vty.c -- used in any of the family
 */
typedef struct dl_base_pair(vty_io) vio_list_t ;

extern vio_list_t vio_live_list ;
extern vio_list_t vio_monitor_list ;

extern struct vio_child* vio_childer_list ;

extern bool vty_nexus ;
extern bool vty_multi_nexus ;

extern qpn_nexus vty_cli_nexus ;
extern qpn_nexus vty_cmd_nexus ;

extern qpt_mutex vty_child_signal_mutex ;
extern qpn_nexus vty_child_signal_nexus ;

extern volatile sig_atomic_t vty_SIGINT ;

/*==============================================================================
 * To make vty qpthread safe we use a single mutex.
 *
 * A recursive mutex is used, which allows for the vty internals to call
 * each other.
 *
 * There are some "uty" functions which assume the mutex is locked.
 *
 * vty is closely bound to the command handling -- the main vty structure
 * contains the context in which commands are parsed and executed.
 *
 * vty also interacts with logging functions.  Note that where it needs to
 * LOG_LOCK() and VTY_LOCK() it will acquire the VTY_LOCK() *first*.
 */

extern qpt_mutex vty_mutex ;

/*------------------------------------------------------------------------------
 * Locking and related functions.
 *
 * Note that under vty_debug keeps track of the lock count, even if is not
 * qpthreads_active -- however, VTY_ASSERT_LOCKED() only triggers an assert if
 * is vty_debug AND is qpthreads_active.
 */
extern int vty_lock_count ;

Inline void
VTY_LOCK(void)          /* if is qpthreads_active, lock vty_mutex       */
{
  qpt_mutex_lock(vty_mutex) ;
  if (vty_debug)
    ++vty_lock_count ;
} ;

Inline void
VTY_UNLOCK(void)        /* if is qpthreads_active, unlock vty_mutex     */
{
  if (vty_debug)
    --vty_lock_count ;
  qpt_mutex_unlock(vty_mutex) ;
} ;

Inline bool             /* true => is (effectively) cli thread          */
vty_is_cli_thread(void)
{
  return !qpthreads_active || (qpt_thread_self_data() == vty_cli_nexus) ;
} ;

Inline bool             /* true => is (effectively) cmd thread          */
vty_is_cmd_thread(void)
{
  return !qpthreads_active || (qpt_thread_self_data() == vty_cmd_nexus) ;
} ;

Inline bool             /* true => running with more than one pthread   */
vty_is_multi_pthreaded(void)
{
  return !qpthreads_active && (vty_cli_nexus != vty_cmd_nexus) ;
} ;

/* For debug (and documentation) purposes, will VTY_ASSERT_LOCKED where that
 * is required.  Note that the check is not precise... it may give a false
 * positive if the vty_mutex is held by *another* pthread !
 *
 * Sadly, VTY_ASSERT_UNLOCKED is empty... because it would give a false
 * negative if the vty_mutex is held by *another* pthread !
 *
 * In some cases, need also to be running in the CLI thread as well.
 *
 * Note that both these checks will pass if !qpthreads_active.  So can have
 * code which is called before qpthreads are started up, or which will never
 * run qpthreaded, or which is called after all threads have rejoined !
 */

extern int vty_assert_fail ;

Inline void
VTY_ASSERT_FAILED(void)
{
  if (vty_assert_fail == 0)
    {
      vty_assert_fail = 1 ;
      assert(0) ;
    } ;
} ;

Inline void
VTY_ASSERT_LOCKED(void)
{
  if (vty_debug)
    if ((vty_lock_count == 0) && (qpthreads_active))
      VTY_ASSERT_FAILED() ;
} ;

Inline void
VTY_ASSERT_UNLOCKED(void)
{
} ;

Inline void
VTY_ASSERT_CLI_THREAD(void)
{
  if (vty_debug)
    if (!vty_is_cli_thread())
      VTY_ASSERT_FAILED() ;
} ;

Inline void
VTY_ASSERT_CLI_THREAD_LOCKED(void)
{
  if (vty_debug)
    {
      VTY_ASSERT_CLI_THREAD() ;
      VTY_ASSERT_LOCKED() ;
    } ;
} ;

Inline void
VTY_ASSERT_CMD_THREAD(void)
{
  if (vty_debug)
    if (!vty_is_cmd_thread())
      VTY_ASSERT_FAILED() ;
} ;

/*==============================================================================
 * Functions in vty.c -- used in any of the vty and command family
 */
extern void vty_hello (vty vty);

extern uint vty_out(vty vty, const char *format, ...) PRINTF_ATTRIBUTE(2, 3) ;
extern void vty_err(vty vty, const char *format, ...) PRINTF_ATTRIBUTE(2, 3) ;

extern int vty_write(struct vty *vty, const void* buf, int n) ;

extern cmd_ret_t vty_cat_file(vty vty, qpath path, const char* desc) ;

extern void uty_suspended_scan(void) ;

#endif /* _ZEBRA_VTY_LOCAL_H */
