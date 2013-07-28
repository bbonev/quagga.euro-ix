/* Quagga pselect support -- header
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

#ifndef _ZEBRA_QPSELECT_H
#define _ZEBRA_QPSELECT_H

#include <sys/select.h>
#include <errno.h>

#include "misc.h"
#include "zassert.h"
#include "qtime.h"
#include "vector.h"

/*==============================================================================
 * Quagga pselect -- qps_xxxx
 *
 * Here and in qpselect.c is a data structure for managing multiple file
 * descriptors and running pselect to wait for I/O activity and to multiplex
 * between the file descriptors.
 */

enum qps_mnum                   /* "mode" numbers: error/read/write     */
{
  qps_mnum_first = 0,

  qps_error_mnum = 0,
  qps_read_mnum  = 1,
  qps_write_mnum = 2,

  qps_mnum_count = 3
} ;

typedef enum qps_mnum qps_mnum_t ;

#define qps_mbit(mnum) (1 << mnum)

enum qps_mbits                  /* "mode" bits: error/read/write        */
{
  qps_no_mbits    = 0,

  qps_error_mbit  = qps_mbit(qps_error_mnum),
  qps_read_mbit   = qps_mbit(qps_read_mnum),
  qps_write_mbit  = qps_mbit(qps_write_mnum),

  qps_all_mbits   = qps_mbit(qps_mnum_count) - 1
} ;

typedef enum qps_mbits qps_mbit_t ;

/* "fd_undef" -- used when fd is undefined
 */
typedef enum
{
  fd_undef = -1,
  fd_first = 0,
  fd_huge  = 65535,
} fd_t ;

/*==============================================================================
 * fd_super_set.
 *
 * To speed up scanning of large fd_set's this structure overlays a 32-bit
 * word and a byte array over the (assumed) fd_set bit vector.
 *
 * There is no guarantee that FD_SETSIZE is a multiple of 32 (or of 8, for
 * that matter) -- so some care must be taken.
 */

typedef uint32_t fd_word_t ;

#define FD_WORD_BITS  32
#define FD_WORD_BYTES (FD_WORD_BITS / 8)

CONFIRM(FD_WORD_BITS == (FD_WORD_BYTES * 8)) ;  /* for completeness     */

#define FD_SUPER_SET_WORD_SIZE ((FD_SETSIZE + FD_WORD_BITS - 1) / FD_WORD_BITS)
#define FD_SUPER_SET_BYTE_SIZE (FD_SUPER_SET_WORD_SIZE * FD_WORD_BYTES)

/* Make sure that the overlay is at least as big as the fd_set !        */
CONFIRM(FD_SUPER_SET_BYTE_SIZE >= sizeof(fd_set)) ;

typedef union           /* see qps_make_super_set_map()         */
{
  fd_word_t words[FD_SUPER_SET_WORD_SIZE] ;
  uint8_t   bytes[FD_SUPER_SET_BYTE_SIZE] ;
  fd_set    fdset ;
} fd_super_set ;

/* Make sure that the fd_super_set is an exact number of fd_word_t words  */
CONFIRM(sizeof(fd_super_set) == (FD_SUPER_SET_WORD_SIZE * FD_WORD_BYTES)) ;

/*==============================================================================
 * Data Structures
 */
typedef fd_super_set fd_full_set[qps_mnum_count] ;

/*------------------------------------------------------------------------------
 * A collection of fd for which we are doing pselect().
 */
typedef struct qps_selection  qps_selection_t ;
typedef struct qps_selection* qps_selection ;

struct qps_selection
{
  int   fd_count ;      /* number of fds we are looking after             */
  int   fd_direct ;     /* direct lookup in vector or not                 */

  vector_t files ;      /* mapping fd to qfile                            */

  int   fd_last ;       /* highest numbered fd; -1 => none at all         */
  int   enabled_count[qps_mnum_count] ;  /* no. enabled fds in each mode  */
  fd_full_set enabled ; /* bit vectors for pselect enabled stuff          */

  int   tried_fd_last ; /* highest numbered fd on last pselect            */
  int   tried_count[qps_mnum_count] ;    /* enabled_count on last pselect */
  fd_full_set results ; /* last set of results from pselect               */

  int         pend_count ;  /* results pending               (if any)     */
  qps_mnum_t  pend_mnum ;   /* error/read/write mode pending (if any)     */
  int         pend_fd ;     /* fd pending                    (if any)     */

  const sigset_t* sigmask ; /* sigmask to use for duration of pselect     */
} ;

/*------------------------------------------------------------------------------
 * A file which may be a member of a selection
 */
typedef struct qfile  qfile_t ;
typedef struct qfile* qfile ;

/* Each file has three action functions, to be called in qps_dispatch_next()
 * when pselect() has reported error/read/write for the file.
 *
 * For further discussion, see: qfile_init().
 */
typedef void qps_action(qfile qf, void* file_info) ;

/* For sockets where may be shutdown() in various ways, we keep some state.
 */
typedef enum qfile_state qfile_state_t ;
enum qfile_state
{
  /* The state of the qfile reflects the state of the 'fd', if any.
   *
   *    qfDown    -- if 'fd' is undef, has been closed.
   *                    if 'fd' defined, has been SHUT_RDWR !
   *
   *    qfUp_RD   -- the 'fd' has been SHUT_WR -- so is half-open for RD
   *
   *    qfUP_WR   -- the 'fd' has been SHUT_RD -- so is half-open for WR
   *
   *    qfUp_RDWR -- the 'fd' is open, but downgraded in some way.
   *
   *                    the standard state for open is qfUp.  This is an
   *                    extra state which may be used to mean (for example)
   *                    that the 'fd' is in the process of being closed.
   *
   *    qfUp      -- the 'fd' is open.
   */
  qfDown        = 0,
  qfUp_RD       = BIT(0),
  qfUp_WR       = BIT(1),
  qfUp_RDWR     = qfUp_RD  | qfUp_WR,
  qfUp          = BIT(2) | qfUp_RDWR,
} ;

CONFIRM(qfUp & qfUp_RD) ;         /* deliberately */
CONFIRM(qfUp & qfUp_WR) ;         /* likewise     */

struct qfile
{
  /* When a qfile is added to a selection, this pointer is set.
   */
  qps_selection selection ;

  /* The 'fd', its state and what is currently enabled for it.
   */
  fd_t          fd ;
  qfile_state_t   state ;
  int           err ;

  qps_mbit_t    enabled_bits ;

  /* The action functions and the pointer argument there-for.
   */
  qps_action*   actions[qps_mnum_count] ;
  void*         file_info ;             /* passed to action functions.  */
} ;

/*==============================================================================
 * qps_selection handling
 */
extern void qps_start_up(void) ;
extern qps_selection qps_selection_init_new(qps_selection qps) ;
extern void qps_add_qfile(qps_selection qps, qfile qf, fd_t fd,
                                                              void* file_info) ;
extern void qps_remove_qfile(qfile qf) ;
extern qfile qps_selection_ream(qps_selection qps,
                                                   free_keep_b free_structure) ;

extern void qps_set_signal(qps_selection qps, const sigset_t* sigmask) ;
extern int qps_pselect(qps_selection qps, qtime_mono_t timeout) ;
extern int qps_dispatch_next(qps_selection qps) ;

/*==============================================================================
 * qfile structure handling
 */
extern qfile qfile_init_new(qfile qf, qfile template) ;
extern qfile_state_t qfile_shutdown(qfile qf, qfile_state_t shut) ;
extern void qfile_close(qfile qf) ;
extern qfile qfile_free(qfile qf) ;

extern void qfile_enable_mode(qfile qf, qps_mnum_t mnum, qps_action* action) ;
extern void qfile_set_action(qfile qf, qps_mnum_t mnum, qps_action* action) ;
extern void qfile_disable_modes(qfile qf, qps_mbit_t mbits) ;
extern fd_t qfile_fd_unset(qfile qf) ;

Inline fd_t qfile_fd_get(qfile qf) ;
Inline bool qfile_modes_are_set(qfile qf, qps_mbit_t mbits) ;
Inline qfile_state_t qfile_state_get(qfile qf) ;
Inline qfile_state_t qfile_state_mask(qfile qf, qfile_state_t mask) ;
Inline int qfile_err_get(qfile qf) ;
Inline int qfile_err_set(qfile qf, int err) ;
Inline void* qfile_info_get(qfile qf) ;
Inline void  qfile_info_set(qfile qf, void* info) ;

/*==============================================================================
 * Inline functions
 */

/*------------------------------------------------------------------------------
 * Get the "fd" (if any)
 */
Inline fd_t
qfile_fd_get(qfile qf)
{
  return (qf != NULL) ? qf->fd : fd_undef ;
} ;

/*------------------------------------------------------------------------------
 * Returns true if is currently enabled for any of the given modes.
 *
 * Assumes qf exists and is in a suitable state for this.
 */
Inline bool
qfile_modes_are_set(qfile qf, qps_mbit_t mbits)
{
  return (qf->enabled_bits & mbits) != 0 ;
} ;

/*------------------------------------------------------------------------------
 * Get the current state for the given qf (if any).
 *
 * Returns:  current state -- qfDown if qf is NULL
 *
 * NB: qfDown can mean:  (a) qf == NULL
 *                       (b) qf->fd is unset (file closed)
 *                       (c) qf->fd is set   (file shutdown RD and WR)
 */
Inline qfile_state_t
qfile_state_get(qfile qf)
{
  return (qf != NULL) ? qf->state : qfDown ;
} ;

/*------------------------------------------------------------------------------
 * Mask down the current state for the given qf (if any).
 *
 * This is provided so that caller can drop from qfUp to qfUp_RDWR, by masking
 * with qfUp_RDWR.  If the qfile is not qfUp, this will make no difference to
 * the state !
 *
 * Returns:  new state -- qfDown if qf is NULL
 *
 * See notes on meaning of qfDown.
 */
Inline qfile_state_t
qfile_state_mask(qfile qf, qfile_state_t mask)
{
  return (qf != NULL) ? qf->state &= mask : qfDown ;
} ;

/*------------------------------------------------------------------------------
 * Get the 'err'
 *
 * Returns:  current err
 *           -1 <=> qf == NULL !
 */
Inline int
qfile_err_get(qfile qf)
{
  return (qf != NULL) ? qf->err : -1 ;
} ;

/*------------------------------------------------------------------------------
 * Set the 'err' -- returning the current value (if any)
 *
 * Returns:  current err
 *           -1 <=> qf == NULL !
 */
Inline int
qfile_err_set(qfile qf, int err)
{
  int err_was ;

  if (qf == NULL)
    return -1 ;

  err_was = qf->err ;
  qf->err = err ;
  return err_was ;
} ;

/*------------------------------------------------------------------------------
 * Get the 'file_info'
 */
Inline void*
qfile_info_get(qfile qf)
{
  return (qf != NULL) ? qf->file_info : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set the 'file_info'
 */
Inline void
qfile_info_set(qfile qf, void* info)
{
  if (qf != NULL)
    qf->file_info = info ;
} ;

/*==============================================================================
 * Miniature pselect
 *
 */
struct qps_mini
{
  fd_full_set sets ;    /* bit vectors for pselect enabled stuff          */
  int   fd_last ;       /* highest numbered fd; -1 => none at all         */

  bool  timeout_set ;   /* see qps_mini_wait                              */
  bool  indefinite ;    /* no time-out                                    */

  qtime_mono_t  end_time ;
} ;

typedef struct qps_mini  qps_mini_t[1] ;
typedef struct qps_mini* qps_mini ;

extern qps_mini qps_mini_set(qps_mini qm, int fd, qps_mnum_t mode) ;
extern void qps_mini_add(qps_mini qm, int fd, qps_mnum_t mode) ;
extern int qps_mini_wait(qps_mini qm, uint timeout, const sigset_t* sigmask) ;

extern uint qps_mini_timeout_debug ;

#endif /* _ZEBRA_QPSELECT_H */
