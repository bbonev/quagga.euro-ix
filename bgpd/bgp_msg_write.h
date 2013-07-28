/* BGP message writing -- in BGP Engine -- header
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * Recast for pthreaded bgpd: Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_MSG_WRITE_H
#define _QUAGGA_BGP_MSG_WRITE_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_route_refresh.h"

#include "lib/stream.h"
#include "lib/sockunion.h"
#include "lib/iovec.h"
#include "lib/ring_buffer.h"

/*------------------------------------------------------------------------------
 * Message writer object for use by connection.
 */
enum
{
  bgp_msg_writer_size   = 16 * 1024
};

typedef enum bgp_writer_state bgp_writer_state_t ;
enum bgp_writer_state
{
  bws_ok        = 0,
  bws_clearing,         /* OK, but will accept nothing more into buffer */

  bws_shut,             /* => seen EPIPE => err == 0                    */
  bws_io_error,

  bws_down,             /* finished -- any error belongs to reader      */
} ;

typedef struct bgp_msg_writer* bgp_msg_writer ;
typedef struct bgp_msg_writer  bgp_msg_writer_t ;

enum
{
  bgp_msg_writer_buf_part_count = 2,
  bgp_msg_writer_msg_part_count = 3,

  bgp_msg_writer_part_count = bgp_msg_writer_buf_part_count
                            + bgp_msg_writer_msg_part_count
} ;
CONFIRM(bgp_msg_writer_part_count <= (uint)IOV_MIN_MAX) ;

struct bgp_msg_writer
{
  /* The pointer to the parent lox can simply be discarded.  While a reader
   * is active, there must be a parent and it must have lox !
   */
  bgp_connection_logging plox ; /* pointer to parent lox        */

  /* I/O processing state
   */
  bgp_writer_state_t state ;

  /* The writer buffer has free bytes available, pp is the first to put to.
   *
   * NB: we allow pp to equal limit... and wrap before putting stuff into
   *     the buffer.
   */
  ptr_t         pp ;
  uint          free ;
  uint          size ;

  ptr_t         buffer ;
  ptr_t         limit ;

  /* While creating a message, and while are waiting to transfer that to the
   * buffer, we may use these.
   *
   * NB: before creating a message, need to check that the msg_iv_count is
   *     zero !
   */
  iovec_t       buf_vec[bgp_msg_writer_buf_part_count] ;
  iovec_t       msg_vec[bgp_msg_writer_msg_part_count] ;

  uint          msg_iv_count ;

  byte          msg_header[BGP_MSG_HEAD_L] ;

  /* The temp buffer used when constructing some messages & when closing.
   */
  ptr_t         temp_buff ;
  uint          temp_buff_size ;
} ;

CONFIRM(offsetof(bgp_msg_writer_t, msg_vec) ==
        (offsetof(bgp_msg_writer_t, buf_vec)
                                      + sizeof(((bgp_msg_writer)0)->buf_vec))) ;

/*==============================================================================
 * Functions for use in BGP_Engine for construction and sending of BGP
 * messages.
 */
extern bgp_msg_writer bgp_msg_writer_init_new(bgp_msg_writer writer,
                                                  bgp_connection_logging plox) ;
extern bgp_msg_writer bgp_msg_writer_reset_new(bgp_msg_writer writer,
                                                  bgp_connection_logging plox) ;
extern bgp_msg_writer bgp_msg_write_reset(bgp_msg_writer writer) ;
extern bgp_msg_writer bgp_msg_writer_free(bgp_msg_writer writer) ;

extern void bgp_msg_write_stuff(bgp_connection connection, ring_buffer rb) ;

extern void bgp_msg_write_open(bgp_connection connection) ;
extern void bgp_msg_write_keepalive(bgp_connection connection, bool must) ;

extern uint bgp_msg_write_move_to_temp(bgp_msg_writer writer,
                                                           uint more_required) ;
extern bool bgp_msg_write_complete(bgp_connection connection,
                                                      bgp_notify notification) ;
extern void bgp_msg_write_stop(bgp_msg_writer writer) ;
extern bool bgp_msg_write_raw(bgp_msg_writer writer, qfile qf) ;

#if 0
/*==============================================================================
 * Functions for the construction of BGP messages
 *
 * Pro tem some messages are constructed in the Routing Engine, and use these
 * when filling in the stream.
 */
extern void bgp_packet_set_marker(stream s, uint8_t type) ;
extern uint bgp_packet_set_size (stream s) ;

extern uint bgp_packet_check_size(stream s, sockunion remote) ;


#endif

#endif /* _QUAGGA_BGP_MSG_WRITE_H */
