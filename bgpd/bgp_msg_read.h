/* BGP Message Read Handling -- header
 * Copyright (C) 2010 Chris Hall (GMCH), Highwayman
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
#ifndef BGP_MSG_READ_H_
#define BGP_MSG_READ_H_

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_notification.h"

#include "ring_buffer.h"
#include "qpselect.h"

/*==============================================================================
 * The message reader.
 *
 * The message reader has an internal buffer, so that it can read in reasonable
 * chunks from the system.  That internal buffer wraps round to ensure we
 * read as much as possible each time goes read-ready.
 *
 * To actually process messages, the body of each must be transferred to a
 * ring-buffer segment -- where it is contiguous.  Note that the message
 * reader's internal buffer is not guaranteed to be large enough for the
 * largest possible message -- particularly when that becomes 64K !  So, the
 * transfer to a ring-buffer deals with three issues (1) making sure we have the
 * complete message body, and (2) making sure the body is contiguous, and
 * (3) providing a modest margin for overrun on sucking.
 *
 * When a message header has been processed (and the marker is OK and the
 * length is: BGP_MSG_MIN_L <= length <= BGP_MSG_MAX_L) then will create a
 * suitable size ring-buffer segment, and will place the body of the message
 * into it.  If the complete body has not been read yet, the balance of the
 * body will be read into the ring-buffer segment, directly.
 */

/*------------------------------------------------------------------------------
 * Message reader return types
 */
typedef enum bgp_msg_state bgp_msg_state_t ;
enum bgp_msg_state
{
  /* We do not yet have a header for the next message
   */
  bms_await_header   = 0,

  /* Have a partial message.
   *
   * NB: while we have a partial message we know the type of same... which
   *     may be an unknown type, and may be a known type but with an invalid
   *     length... those will be dealt with when the complete message is
   *     collected.
   */
  bms_partial,

  /* Have a complete message -- hurrah !
   *
   * Message is at least the mimumum required length for its type and no
   * greater than any maximum length for its type -- but type may be unknown.
   */
  bms_complete,

  /* A complete message -- but mixed result.
   *
   *   complete_too_short  => too short for a *known* message type
   *   complete_too_long   => too long for a *known* message type
   */
  bms_complete_too_short,
  bms_complete_too_long,

  /* I/O events -- these do not appear at the message level until there are no
   * more complete messages to be read.
   *
   * While there are complete messages in the buffer, the reader will continue
   * to deliver them, even if the I/O is brs_eof/_io_error/_down.
   */
  bms_fail_eof,         /* brs_eof      )                               */
  bms_fail_io,          /* brs_io_error ) & no more complete            */
  bms_fail_down,        /* brs_down     )              messages         */

  /* Message events which terminate the processing of messages.
   */
  bms_fail_bad_marker,  /* marker != 16 x 0xFF                          */
  bms_fail_bad_length,  /* length < BGP_MSG_MIN_L or > BGP_MSG_MAX_L    */
} ;

/*------------------------------------------------------------------------------
 * Message reader locations
 */
typedef enum bgp_msg_in_state bgp_msg_in_state_t ;
enum bgp_msg_in_state
{
  bms_in_hand   = 0,            /* in main reader buffer        */
  bms_in_temp,                  /* in temp reader buffer        */
  bms_in_other,                 /* in some other buffer         */
} ;

/*------------------------------------------------------------------------------
 * A dense set of the BGP Messages known to Quagga
 */
typedef enum qBGP_MSG qBGP_MSG_t ;
enum qBGP_MSG
{
  qBGP_MSG_unknown    = 0,

  qBGP_MSG_OPEN,
  qBGP_MSG_UPDATE,
  qBGP_MSG_NOTIFICATION,
  qBGP_MSG_KEEPALIVE,
  qBGP_MSG_ROUTE_REFRESH,
  qBGP_MSG_CAPABILITY,
  qBGP_MSG_ROUTE_REFRESH_pre,

  qBGP_MSG_count,
} ;

/*------------------------------------------------------------------------------
 * Message reader control structure
 */
enum
{
  bgp_msg_reader_size   = 16 * 1024
};

typedef enum bgp_reader_state bgp_reader_state_t ;
enum bgp_reader_state
{
  brs_ok        = 0,

  brs_eof,
  brs_io_error,

  brs_down,
} ;

typedef struct bgp_msg_reader  bgp_msg_reader_t ;

struct bgp_msg_reader
{
  /* The pointer to the parent lox can simply be discarded.  While a reader
   * is active, there must be a parent and it must have lox !
   */
  bgp_connection_logging plox ;         /* pointer to parent lox        */

  /* Message processing status.
   *
   *   msg_state           -- main state, as above
   *
   *   msg_in_state        -- where any buffered message currently
   *                          resides.
   *
   *       bms_in_hand   => any message is in the reader buffer
   *                        and msg_body == NULL
   *
   *       bms_in_temp   => message is in the reader's temp_buffer
   *                        and msg_body == temp_buffer
   *
   *       bms_in_other  => message is in some other buffer
   *                        and msg_body == that buffer
   *
   *   * bms_await_header
   *
   *       msg_in_state      == bms_in_hand
   *       msg_state_pending -- N/A
   *       msg_skip          == amount to skip before header
   *       msg_awaited       == 0
   *
   *       msg_body_length    )
   *       msg_bgp_type       ) N/A
   *       msg_qtype          )
   *
   *       msg_body          -- NULL -- since is bms_in_hand
   *       msg_header        -- N/A
   *
   *   * bms_partial
   *
   *       msg_in_state      == bms_in_hand/bms_in_temp/bms_in_other
   *       msg_state_pending == bms_complete_xxx, set from message header
   *       msg_skip          == 0
   *       msg_awaited       != 0  == amount of message awaited
   *
   *       msg_body_length    )
   *       msg_bgp_type       ) set from message header
   *       msg_qtype          )
   *
   *       msg_body          -- per msg_in_state
   *       msg_header        -- N/A
   *
   *   * bms_complete
   *   * bms_complete_too_short
   *   * bms_complete_too_long
   *
   *       msg_in_state      == bms_in_hand/bms_in_temp/bms_in_other
   *       msg_state_pending == N/A
   *       msg_skip          == 0
   *       msg_awaited       == 0
   *
   *       msg_body_length    )
   *       msg_bgp_type       ) set from message header
   *       msg_qtype          )
   *
   *       msg_body          -- per msg_in_state
   *       msg_header        -- N/A
   *
   *   * bms_fail_eof
   *   * bms_fail_io
   *   * bms_fail_down
   *
   *       msg_in_state      == bms_in_hand
   *       msg_state_pending == N/A
   *       msg_skip          == 0
   *       msg_awaited       == 0
   *
   *       msg_body_length    )
   *       msg_bgp_type       ) N/A
   *       msg_qtype          )
   *
   *       msg_body          == NULL
   *       msg_header        -- N/A
   *
   *   * bms_fail_bad_marker
   *   * bms_fail_bad_length
   *
   *       msg_in_state      == bms_in_hand
   *       msg_state_pending == N/A
   *       msg_skip          == 0
   *       msg_awaited       == 0
   *
   *       msg_body_length    )
   *       msg_bgp_type       ) N/A
   *       msg_qtype          )
   *
   *       msg_body          == NULL
   *       msg_header        == copy of the failed header
   */
  bgp_msg_state_t     msg_state ;
  bgp_msg_in_state_t  msg_in_state ;

  bgp_msg_state_t     msg_state_pending ;

  uint          msg_skip ;
  uint          msg_awaited ;

  uint          msg_body_length ;
  uint8_t       msg_bgp_type ;
  qBGP_MSG_t    msg_qtype ;

  ptr_t         msg_body ;
  byte          msg_header[BGP_MSG_HEAD_L] ;

  /* I/O processing state
   */
  bgp_reader_state_t state ;

  /* The reader buffer has in_hand bytes in it, sp is the first.
   */
  ptr_t         sp ;
  uint          in_hand ;
  uint          size ;

  ptr_t         buffer ;
  ptr_t         limit ;

  /* The reader also holds a temporary buffer for message processing.
   */
  ptr_t         temp_buff ;
  uint          temp_buff_size ;
} ;

/*==============================================================================
 * Functions
 */
extern bgp_msg_reader bgp_msg_reader_init_new(bgp_msg_reader reader,
                                                  bgp_connection_logging plox) ;
extern bgp_msg_reader bgp_msg_reader_reset_new(bgp_msg_reader reader,
                                                  bgp_connection_logging plox) ;
extern bgp_msg_reader bgp_msg_read_reset(bgp_msg_reader reader) ;
extern bgp_msg_reader bgp_msg_reader_free(bgp_msg_reader reader) ;

extern bool bgp_msg_read_raw(bgp_msg_reader reader, qfile qf) ;

extern void bgp_msg_read_continue(bgp_msg_reader reader, qfile qf) ;
extern void bgp_msg_read_take(ptr_t msg_body, bgp_msg_reader reader);
extern void bgp_msg_read_take_to_temp(bgp_msg_reader reader);
extern void bgp_msg_read_done(bgp_msg_reader reader) ;
extern bool bgp_msg_read_stop(bgp_msg_reader reader) ;
extern void bgp_msg_read_log(bgp_msg_reader reader) ;

extern bgp_note bgp_msg_read_bad(bgp_msg_reader reader, qfile qf) ;
extern bgp_note bgp_msg_read_bad_type(bgp_msg_reader reader) ;
extern bgp_fsm_event_t bgp_msg_read_failed(bgp_msg_reader reader, qfile qf) ;
extern bgp_note bgp_msg_open_bad_id(bgp_id_t id) ;

extern bgp_note bgp_msg_open_parse(bgp_connection connection,
                                                        bgp_msg_reader reader) ;
extern bgp_note bgp_msg_route_refresh_parse(bgp_connection connection,
                                                        bgp_msg_reader reader) ;
extern bgp_note bgp_msg_notify_parse(bgp_connection connection,
                                                        bgp_msg_reader reader) ;

#endif /* BGP_MSG_READ_H_ */
