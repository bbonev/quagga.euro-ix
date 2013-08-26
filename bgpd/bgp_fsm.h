/* BGP-4 Finite State Machine
 * From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Recast for pthreaded bgpd: Copyright (C) Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_FSM_H
#define _QUAGGA_BGP_FSM_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_notification.h"

#include "qpselect.h"

/*==============================================================================
 * The BGP Finite State Machine
 *
 * Each connection has its FSM.
 */

/*------------------------------------------------------------------------------
 * Connection "meta-events".
 */
typedef enum bgp_fsm_meta bgp_fsm_meta_t ;

enum bgp_fsm_meta
{
  bgp_fmStop             = 0,
  bgp_fmRun              = BIT( 0),

  bgp_fmKeepaliveTimer   = BIT( 1),
  bgp_fmHoldTimer        = BIT( 2),
  bgp_fmIO               = BIT( 3),
  bgp_fmSocket           = BIT( 4),
  bgp_fmAdmin            = BIT( 5),

  bgp_fmNULL             = 0,           /* for no event set     */
} ;

/*------------------------------------------------------------------------------
 * The idle state is used to manage timer(s) in fsIdle/fsStop.
 *
 * If some I/O is running, IO-Hold-Timer is running.
 *
 * In fsIdle, there will be a follow on IdleHoldTime, and possibly an
 * extension to that.
 *
 * In fsStop, there can only be the IO-Hold-Time.
 *
 * The IO-Hold-Time is a local invention.  It is
 *
 *   1) the time we are prepared to wait for an outgoing NOTIFICATION
 *      (and/or any other pending stuff) to be written away to the system.
 *
 *   2) the time we are prepared to wait for the reader to hit eof, or fail
 *      or for a NOTIFICATION to arrive.  We do this so that we tidy up any
 *      remaining input, which may include a NOTIFICATION.
 *
 *      If the write side detects an error it may do so before the read side
 *      sees it, because the read side defers errors while there is buffered
 *      input.  So we allow some time to keep reading to tidy that up.  When
 *      the write side does detect an error it will SHUT_WR, so the far end
 *      should see that, and act accordingly.
 *
 *   3) the minimum IdleHoldTime if there was any of (1) or (2) when
 *      enters fsIdle.
 *
 *      If goes from fsIdle to fsStop, as soon as the io_state goes fDown, the
 *      connection will be stopped.
 *
 * The idle state is:
 *
 *     1. fisExtended   -- fsIdle only -- qfDown
 *
 *        When the extension timer goes off, will leave fsIdle.
 *
 *        If goes to stopping, can exit immediately.
 *
 *     2. fisHold       -- fsIdle only -- qfDown
 *
 *        When the timer goes off the fsIdle is done, unless we extend it.
 *
 *        When fsIdle is done, if there is a sibling in fsOpenSent or
 *        fsOpenConfirm, then the IdleHoldTime is extended by a little, once.
 *
 *     3. fisIO         -- fsIdle or fsStop
 *
 *        in fsIdle:
 *
 *          * if the connection goes fDown, for whatever reason, the
 *            connection can be closed -- but the timer is left running.
 *
 *          * when the timer goes off, the connection can be closed.
 *
 *            Proceeds to fisHold, to run the balance of the full IdleHoldTime
 *            (the balance is arranged to not be zero).
 *
 *        in fsStop:
 *
 *          * if the connection goes fDown, for whatever reason, the
 *            connection is stopped.
 *
 *          * when the timer goes off, the connection is stopped.
 */
typedef enum bgp_fsm_idle_state bgp_fsm_idle_state_t ;
enum bgp_fsm_idle_state
{
  bgp_fisNULL   = 0,
  bgp_fisExtended,
  bgp_fisHold,
  bgp_fisIO,
} ;

/*------------------------------------------------------------------------------
 * A parcel for an event in the FSM, which may be copied to the session and
 * back to the peer.
 */
typedef struct bgp_fsm_eqb* bgp_fsm_eqb ;
typedef struct bgp_fsm_eqb  bgp_fsm_eqb_t ;

struct bgp_fsm_eqb
{
  bgp_fsm_event_t  fsm_event ;
  bgp_note         note ;
  int              err ;
} ;

/*------------------------------------------------------------------------------
 * FSM Timer.
 */
enum bgp_fsm_timer_state
{
  bfts_stopped      = 0,
  bfts_running,
  bfts_suspended,
  bfts_expired,
} ;
typedef enum bgp_fsm_timer_state bgp_fsm_timer_state_t ;

typedef struct bgp_fsm_timer  bgp_fsm_timer_t ;
typedef struct bgp_fsm_timer* bgp_fsm_timer ;

struct bgp_fsm_timer
{
  bgp_connection  connection ;
  bgp_fsm_meta_t  fsm_meta ;
  bgp_fsm_event_t fsm_event ;

  qtimer        qtr ;
  qtime_t       interval ;

  uint          jitter ;
  qtime_t       jitter_unit ;

  bgp_fsm_timer_state_t state ;
} ;

/*==============================================================================
 * Prototypes.
 */
extern void bgp_fsm_start_session(bgp_session session) ;
extern bgp_note bgp_fsm_stop_session(bgp_session session, bgp_note note) ;
extern void bgp_fsm_start_connection(bgp_session session,
                                                          bgp_conn_ord_t ord) ;
extern void bgp_fsm_restart_connection(bgp_connection connection,
                                                                bgp_note note) ;
extern void bgp_fsm_stop_connection(bgp_connection connection,
                                                                bgp_note note) ;

extern void bgp_fsms_init(void) ;
extern void bgp_fsms_stop(void) ;
extern void bgp_fsm_events_flush(bgp_connection connection) ;
extern int bgp_fsm_events_run(void) ;

extern void bgp_fsm_io_event(bgp_connection connection) ;

extern void bgp_fsm_accept_event(bgp_session session,
                                                    bgp_fsm_event_t fsm_event) ;
extern void bgp_fsm_connect_event(bgp_connection connection,
                                                         int sock_fd, int err) ;

extern bgp_fsm_event_t bgp_fsm_io_failed(bgp_connection_logging plox,
                                      int sock_fd, int err, const char* where) ;

extern void bgp_fsm_timer_init(bgp_fsm_timer ft, bgp_connection connection) ;
extern void bgp_fsm_timer_stop(bgp_fsm_timer ft) ;
extern void bgp_fsm_timer_free(bgp_fsm_timer ft) ;
extern void bgp_keepalive_timer_recharge(bgp_connection connection) ;
extern void bgp_keepalive_timer_suspend(bgp_connection connection) ;

#endif /* _QUAGGA_BGP_FSM_H */
