/* BGP message writing -- in BGP Engine
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

#include <zebra.h>
#include <stdbool.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_msg_write.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_route_refresh.h"
#include "bgpd/bgp_names.h"
#include "bgpd/bgp_debug.h"

#include "stream.h"
#include "prefix.h"
#include "log.h"
#include "iovec.h"
#include "sockopt.h"
#include "qatomic.h"

/*==============================================================================
 * BGP Engine BGP Message encoding and sending.
 */
static const byte marker[] = { 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF } ;
CONFIRM(sizeof(marker) == BGP_MH_MARKER_L) ;

/*==============================================================================
 * UPDATE -- send an UPDATE message
 *
 * PRO TEM -- this is passed a raw BGP message in a stream buffer
 */

/*------------------------------------------------------------------------------
 * Make UPDATE message and dispatch.
 *
 * Returns: 1 => written to wbuff -- qpselect will write from there
 *          0 => nothing written  -- insufficient space in wbuff
 *
 * NB: actual I/O occurs in the qpselect action function -- so this cannot
 *     fail !
 *
 * NB: requires the session LOCKED -- connection-wise
 */
extern int
bgp_msg_send_update(bgp_connection connection, stream s)
{
  qa_add_to_uint(&connection->session->stats.update_out, 1) ;
} ;

#if 0
/*==============================================================================
 * Utilities for creating BGP messages
 *
 * NB: these are used by the BGP Engine and by the Routing Engine.
 */
                                /*   0   1   2   3   4   5   6   7 */
static const char bgp_header[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" /*  8 */
                                 "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" /* 16 */
                                 "\x00" ;
CONFIRM(sizeof(bgp_header)      == (BGP_MH_MARKER_L + 2)) ;
CONFIRM(sizeof(BGP_MH_LENGTH_T) ==                    2) ;

/*------------------------------------------------------------------------------
 * Insert BGP message standard header
 *
 *   16 bytes of 0xFF
 *    2 bytes -- total length of message -- filled in later
 *    1 byte  -- the type of message as given
 */
extern void
bgp_packet_set_marker(blower br, uint8_t type)
{
  /* Fill in marker & dummy total length (to be filled in later on)
   */
  blow_n(br, bgp_header, BGP_MH_MARKER_L + 2) ;

  /* BGP packet type.
   */
  blow_b(br, type);

  confirm(sizeof(BGP_MH_TYPE_T) == 1) ;

  confirm(BGP_MSG_HEAD_L == (BGP_MH_MARKER_L + sizeof(BGP_MH_LENGTH_T)
                                             + sizeof(BGP_MH_TYPE_T))) ;
} ;

/*------------------------------------------------------------------------------
 * Set BGP message header size entry and return same.
 *
 * NB: we assume it is *impossible* to construct a stream whose length exceeds
 *     an unsigned integer.
 *
 *     But, just in case it exceeds a 16-bit unsigned, we truncate the message
 *     length in the header to 0xFFFF !!
 *
 * NB: at the last moment will check whether message exceeds BGP_MSG_MAX_L, and
 *     discards the message, rather than send it -- see bgp_connection_write()
 */
extern uint
bgp_packet_set_size (blower br)
{
  uint cp;

  /* Insert message size -- includes all of header and the 16 bytes of "marker"
   */
  cp = stream_get_len(s) ;
  stream_putw_at(s, BGP_MH_MARKER_L, (cp < 0xFFFF) ? cp : 0xFFFF) ;

  return cp;
} ;

/*------------------------------------------------------------------------------
 * Get and check size of given BGP Message
 *
 * If it cannot be sent because it is too big, log that fact !
 *
 * Returns:  > 0 == length of BGP Message, <= max allowed length
 *          == 0 => BGP Message was too long !
 */
extern uint
bgp_packet_check_size(blower br, sockunion remote)
{
  uint    length ;
  uint8_t type ;

  length = stream_get_len(s) ;

  if (length <= BGP_MSG_MAX_L)
    return length ;

  /* This BGP Message cannot be sent !
   *
   * Pick out message type and record that, the message size and the intended
   * destination.
   *
   * TODO -- could do with a way of logging rather more useful information,
   *         and, possibly, some other alert mechanism.
   */
  type = stream_getc_from(s, BGP_MH_TYPE) ;

  zlog_err("Invalid size %s BGP message (%s%u bytes) for %s",
                          map_direct(bgp_message_type_map, type).str,
                            stream_has_overflowed(s) ? "more than " : "",
                                                    length, sutoa(remote).str) ;

  return 0 ;            /* suppress message     */
} ;
#endif

/*==============================================================================
 *
 */
static uint bgp_msg_write_header(bgp_msg_writer writer, uint body_length,
                                                                    uint type) ;
static void bgp_msg_write_body_part(bgp_msg_writer writer, ptr_c part,
                                                             uint part_length) ;
static uint bgp_msg_write_away(bgp_msg_writer writer, uint msg_length) ;
static uint bgp_msg_write_msg_check(bgp_msg_writer writer, uint msg_length) ;
static uint bgp_msg_write_msg_stomp(bgp_msg_writer writer) ;
static uint bgp_msg_write_transfer(bgp_msg_writer writer, uint msg_iv) ;

static uint bgp_msg_write_update(bgp_msg_writer writer, ptr_t rb_body,
                                                               uint rb_length) ;
static uint bgp_msg_write_eor(bgp_msg_writer writer, ptr_t rb_body,
                                                               uint rb_length) ;
static uint bgp_msg_write_rr(bgp_msg_writer writer, ptr_t rb_body,
                            uint rb_length, bgp_session session, bool* p_done) ;

/*------------------------------------------------------------------------------
 * Initialise writer -- allocates, if required.
 *
 * Returns:  new or existing writer
 *
 * NB: if does not allocate, then assumes the given writer has never been
 *     kissed.
 *
 * NB: the writer buffer is created at the same time, and will exist while
 *     the writer itself exists.
 */
extern bgp_msg_writer
bgp_msg_writer_init_new(bgp_msg_writer writer, bgp_connection_logging plox)
{
  if (writer == NULL)
    writer = XMALLOC(MTYPE_BGP_WRITER, sizeof(bgp_msg_writer_t)) ;

  writer->buffer = XMALLOC(MTYPE_BGP_WRITER, bgp_msg_writer_size) ;
  writer->limit  = writer->buffer + bgp_msg_writer_size ;

  writer->plox   = plox;

  return bgp_msg_write_reset(writer) ;
} ;

/*------------------------------------------------------------------------------
 * Reset writer -- allocates, if required.
 *
 * Returns:  new or existing writer
 *
 * NB: if does not allocate, then assumes the given writer just needs to be
 *     reset.
 */
extern bgp_msg_writer
bgp_msg_writer_reset_new(bgp_msg_writer writer, bgp_connection_logging plox)
{
  if (writer == NULL)
    return bgp_msg_writer_init_new(writer, plox) ;
  else
    return bgp_msg_write_reset(writer) ;
} ;

/*------------------------------------------------------------------------------
 * Reset given message writer, if any.
 *
 * Resets everything except: buffer & limit
 *                           plox
 *
 * Returns:  writer as given (NULL if was NULL)
 */
extern bgp_msg_writer
bgp_msg_write_reset(bgp_msg_writer writer)
{
  if (writer != NULL)
    {
      bgp_msg_writer_t was[1] ;

      *was = *writer ;
      memset(writer, 0, sizeof(bgp_msg_writer_t)) ;

      /* Zeroizing sets:
       *
       *   * plox               -- zz       -- restored, below
       *
       *   * state              -- bws_ok
       *
       *   * pp                 -- X        -- set to start of buffer, below
       *   * free               -- X        -- set to size of buffer, below
       *   * size               -- X        -- set to size of buffer, below
       *
       *   * buffer             -- zz       -- restored, below
       *   * limit              -- zz       -- restored, below
       *
       *   * buf_vec            -- all 0    -- embedded iovec
       *   * msg_vec            -- all 0    -- embedded iovec
       *   * msg_iv_count       -- 0        -- none, yet
       *
       *   * msg_header         -- X        -- set, below
       *
       *   * temp_buff          -- zz       -- restored, below
       *   * temp_buff_size     -- zz       -- restored, below
       */
      confirm(bws_ok == 0) ;

      writer->plox           = was->plox ;
      writer->buffer         = was->buffer ;
      writer->limit          = was->limit ;
      writer->temp_buff      = was->temp_buff ;
      writer->temp_buff_size = was->temp_buff_size ;

      writer->pp             = writer->buffer ;
      writer->free           = writer->limit - writer->buffer ;
      writer->size           = writer->limit - writer->buffer ;

      /* The message header marker is preset to all 0xFF, so is permanently set
       * as required.
       */
      memset(&writer->msg_header[BGP_MH_MARKER], 0xFF, BGP_MH_MARKER_L) ;
    } ;

  return writer ;
} ;

/*------------------------------------------------------------------------------
 * Arrange for a writer->temp_buff of at least the given size, please
 *                                            (plus the usual blow_buffer_slack)
 *
 * Returns:  address if writer->temp_buf  -- never NULL (even if size == 0)
 */
static ptr_t
bgp_msg_write_get_temp(bgp_msg_writer writer, uint size)
{
  qassert((writer->temp_buff == NULL) == (writer->temp_buff_size == 0)) ;

  size += blow_buffer_slack ;

  if (writer->temp_buff_size < size)
    {
      writer->temp_buff_size = uround_up(size, 512) ;

      writer->temp_buff = XREALLOC(MTYPE_BGP_MSG_BUFF, writer->temp_buff,
                                                       writer->temp_buff_size) ;

      memset(writer->temp_buff, 0, writer->temp_buff_size) ;
    } ;

  return writer->temp_buff ;
} ;

/*------------------------------------------------------------------------------
 * Free given message writer (if any) and its buffer.
 *
 * Returns:  NULL
 */
extern bgp_msg_writer
bgp_msg_writer_free(bgp_msg_writer writer)
{
  if (writer != NULL)
    {
      XFREE(MTYPE_BGP_MSG_BUFF, writer->temp_buff) ;
      XFREE(MTYPE_BGP_WRITER, writer->buffer) ;
      XFREE(MTYPE_BGP_WRITER, writer) ;
    } ;

  return NULL ;
} ;





/*------------------------------------------------------------------------------
 * Write messages from the given ring-buffer, into the write buffer, until run
 * out or until buffer fills.
 *
 * In the outbound ring-buffer UPDATE messages may come in two sections.  The
 * first two bytes of the contents of the ring buffer are not part of the
 * message, they are length of the second section in the ring-buffer, which
 * is destined to be the first section in the output !
 */
extern void
bgp_msg_write_stuff(bgp_connection connection, ring_buffer rb)
{
  bgp_msg_writer writer ;
  ptr_t msg_body ;

  writer = connection->writer ;

  if      (writer->msg_iv_count != 0)
    {
      qassert((writer->state == bws_ok) || ((writer->state == bws_clearing))) ;
      qassert(writer->free == 0) ;
    }
  else if (writer->state != bws_ok)
    {
      /* We are not going to write any more, so we can simply discard
       * everything in the ring-buffer.
       *
       * This leaves anything in the write buffer to clear in its own time.
       */
      rb_get_discard(rb) ;
      return ;
    } ;

  while (writer->free > 0)
    {
      uint   body_length, msg_length ;
      uint   type ;
      bool   done ;

      qassert(writer->msg_iv_count == 0) ;

      /* rb_get_step_first() will step past the last segment we fetched, if
       * any, before presenting the first segment after that and setting a new
       * last segment.
       *
       * If the buffer fills, then will exit before getting here after writing
       * the current message.  So, the current segment is held in the
       * ring-buffer, to be stepped past next time we arrive here.
       *
       * The bgp_msg_write_rr() is a little peculiar.  It generates one message
       * at a time, and until it is "done", it will clear the current last
       * segment, before looping... which means it is not stepped past !!
       */
      msg_body = rb_get_body(rb_get_step_first(rb, true /* set waiting */),
                                                          &body_length, &type) ;
      if (msg_body == NULL)
        break ;                         /* <<< exit, ring-buffer empty  */

      switch((bgp_rb_msg_out_type_t)type)
        {
          case bgp_rbm_out_null:
          default:
            qassert(false) ;
            continue ;                  /* <<< loop back                */

          case bgp_rbm_out_update:
            msg_length = bgp_msg_write_update(writer, msg_body, body_length) ;
            break ;

          case bgp_rbm_out_eor:
            msg_length = bgp_msg_write_eor(writer, msg_body, body_length) ;
            break ;

          case bgp_rbm_out_rr:
            msg_length = bgp_msg_write_rr(writer, msg_body, body_length,
                                                   connection->session, &done) ;
            if (!done)
              rb_get_drop(rb) ;         /* keep ring-buffer message     */
            break ;
        } ;

      bgp_msg_write_away(writer, msg_length) ;

      if (!qfile_modes_are_set(connection->qf, qps_write_mbit))
         qfile_enable_mode(connection->qf, qps_write_mnum, NULL) ;

      if (writer->state != bws_ok)
        {
          /* Something has gone wrong (eg: in bgp_msg_write_msg_check(), and
           * we are not going to write any more, so we can simply discard
           * everything in the ring-buffer.
           *
           * This leaves anything in the write buffer to clear in its own time.
           */
          rb_get_discard(rb) ;
          break ;                       /* failed               */
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Write given message to the write buffer.
 *
 * NB: it is the caller's responsibility to ensure that the writer has no
 *     current message part(s) in hand -- ie writer->msg_iv_count == 0
 *
 * NB: it is the caller's responsibility to ensure that the body of the
 *     message remains "alive" until the entire contents have been moved
 *     to the writer buffer.
 *
 * NB: it is the caller's responsibility to ensure that the body of the
 *     message is freed -- if an how required -- once the message has
 *     been moved to the writer buffer !
 *
 * Using the writer->temp_buff is one way of achieving the second two of
 * these !
 */
static void
bgp_msg_write_msg(bgp_msg_writer writer, ptr_c body, uint body_length,
                                                                      uint type)
{
  uint msg_length ;

  qassert(writer->msg_iv_count == 0) ;

  msg_length = bgp_msg_write_header(writer, body_length, type) ;

  bgp_msg_write_body_part(writer, body, body_length) ;

  bgp_msg_write_away(writer, msg_length) ;
} ;

/*------------------------------------------------------------------------------
 * Move any outstanding message fragments, and move them to the temp_buff.
 *
 * This is used when the source of an any outstanding write may point somewhere
 * which is about to be freed... so we need to move that into the temp_buff,
 * to take it into our care.
 *
 * Reduces the contents of the msg_vec to a single entry, pointing into the
 * temp_buff.
 *
 * Returns:  length of the fragment we have just taken into care.
 */
extern uint
bgp_msg_write_move_to_temp(bgp_msg_writer writer, uint more_required)
{
  uint  fragment_length, total_required ;
  uint  iv ;
  ptr_t old_temp, dst, fragment ;

  /* First, establish how much, if anything we have in the way of a fragment.
   */
  fragment_length    = 0 ;
  for (iv = 0 ; iv < writer->msg_iv_count ; ++iv)
    fragment_length += writer->msg_vec[iv].len ;

  total_required = fragment_length + more_required ;

  if (fragment_length == 0)
    {
      qassert(writer->msg_iv_count == 0) ;

      if (more_required != 0)
        bgp_msg_write_get_temp(writer, total_required) ;

      return 0 ;
    } ;

  /* It is possible that the msg_vec contains stuff which has already been
   * taken into care, in which case we are OK, provided that the current
   * temp_buff is large enough for the total_required.
   *
   * NB: we do allow for blow_buffer_slack.
   */
  if ((writer->msg_iv_count == 1)
                              && (writer->msg_vec[0].base == writer->temp_buff))
    {
      if ((more_required == 0)
           || ((total_required + blow_buffer_slack) <= writer->temp_buff_size))
        return fragment_length ;
    } ;

  /* For whatever reason, we need to move the contents of the msg_vec.
   *
   * This may be because the current temp_buff is too small for the
   * 'more_required', or because we have header + message in the temp_buff.
   * In any case, we need to preserve any current temp_buff for the duration.
   */
  old_temp = writer->temp_buff ;

  writer->temp_buff      = NULL ;
  writer->temp_buff_size = 0 ;

  fragment = bgp_msg_write_get_temp(writer, total_required) ;

  dst = fragment ;

  for (iv = 0 ; iv < writer->msg_iv_count ; ++iv)
    {
      size_t len ;

      len = writer->msg_vec[iv].len ;
      if (len > 0)
        memcpy(dst, writer->msg_vec[iv].base, len) ;

      dst += len ;
    } ;

  qassert((dst - fragment) == fragment_length) ;

  writer->msg_vec[0].base = fragment ;
  writer->msg_vec[0].len  = fragment_length ;
  writer->msg_iv_count = 1 ;

  if (old_temp != NULL)
    XFREE(MTYPE_BGP_MSG_BUFF, old_temp) ;       /* done with it now     */

  return fragment_length ;
} ;

/*------------------------------------------------------------------------------
 * We propose to write nothing more, other than the given notification (if any)
 *
 * Makes sure that any remaining writing is entirely self contained: anything
 * which is waiting to be written will be in the writer buffer itself, or the
 * writer's temp_buff -- created for the purpose.  NB: the temp_buff is
 * used to generate messages in, and may have a message in it, pointed at by
 * the writer iovec.  So, here we have to create a new temp_buff, just in case.
 * However, in the process of pulling any outstanding stuff into the new
 * temp_buff, the old one becomes redundant !
 *
 * Does nothing if the writer is already down, or shut or failed.
 *
 * If the writer is bws_ok, will become bws_clearing if there is stuff (still)
 * in the buffer -- which will now include any notification given.
 *
 * If the writer is bws_ok (or bws_clearing), if the buffers are now empty,
 * will drop to bws_done and shutdown the writer.
 *
 * Returns:  true <=> the writer has nothing more to do or can do.
 */
extern bool
bgp_msg_write_complete(bgp_connection connection, bgp_notify notification)
{
  bgp_msg_writer writer ;
  ptr_t notify_msg ;
  uint  fragment_length, notify_msg_length ;

  /* If is bws_ok, will complete whatever is currently buffered, plus the
   * given notification (if any), and go bws_clearing.
   *
   * If is already bws_clearing, will complete whatever is currently buffered,
   * but ignore the given notification, if any.
   *
   * Otherwise, there is nothing more that can be done.
   */
  writer = connection->writer ;

  notify_msg_length = 0 ;        /* assume none         */
  notify_msg        = NULL ;

  switch(writer->state)
    {
      case bws_ok:
        notify_msg = bgp_notify_message(notification, &notify_msg_length) ;

        writer->state = bws_clearing ;  /* after (any) notification     */
        break ;

      case bws_clearing:
        break ;

      default:
        qassert(false) ;
        fall_through ;

      case bws_shut:
      case bws_io_error:
      case bws_down:
        return true ;           /* all set      */
    } ;

  /* First, make sure any existing fragments are taken into care, in the
   * temp_buff.
   *
   * Whether or not there are any fragments, ensures that the temp_buff has
   * space for the entire NOTIFICATION message (if any).
   */
  fragment_length = bgp_msg_write_move_to_temp(writer, notify_msg_length) ;

  /* Now, if we have a notification, append it to the temp_buffer -- keeps
   * things simple -- then transfer whatever can be transferred to the write
   * buffer.
   *
   * Note that if fails to transfer the entire notification message to the
   * write buffer, then the balance has already been taken into care.
   *
   * [Notifications happen once in a blue moon -- so don't care that we may
   *  well have copied it to the temp_buff and then again into the main buffer.
   *  Notifications are also, short, 99.99...% of the time !]
   */
  if (notify_msg_length != 0)
    {
      uint iv ;

      memcpy(writer->temp_buff + fragment_length, notify_msg,
                                                            notify_msg_length) ;
      iv = writer->msg_iv_count ;
      qassert(iv == ((fragment_length == 0) ? 0 : 1)) ;

      writer->msg_vec[iv].base = writer->temp_buff + fragment_length ;
      writer->msg_vec[iv].len  = notify_msg_length ;

      bgp_msg_write_transfer(writer, 0) ;
    } ;

  /* And finally...
   *
   * ...if the buffer is not empty, make sure that we are write-ready.
   * ...if buffer is empty, can SHUT_WR.
   *
   * Returns "everything is complete".
   */
  if (writer->free < writer->size)
    {
      qfile_enable_mode(connection->qf, qps_write_mnum, NULL) ;
      return false ;            /* something left to do */
    }
  else
    {
      qfile_shutdown(connection->qf, qfUp_WR) ;
      return true ;             /* all set              */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Stop writer
 *
 * Crashes writing discarding whatever has in hand, and will write no more.
 *
 * If is bws_ok, then forces bws_down
 */
extern void
bgp_msg_write_stop(bgp_msg_writer writer)
{
  bgp_writer_state_t state ;

  state = writer->state ;
  bgp_msg_write_reset(writer) ;

  if ((state == bws_ok) || (state == bws_clearing))
    state = bws_down ;

  writer->state = state ;       /* restore or set new state     */
};

/*------------------------------------------------------------------------------
 * Write the given body length and message type into the scratch header
 * we have in the given writer -- set first available entry of the message
 * parts.
 *
 * NB: it is the caller's responsibility to ensure that any previous user of
 *     the scratch header and message parts has been cleared.
 *
 *     It is "unusual" for writer->msg_iv_count != 0, but can happen if
 *     a message has been taken into care.
 */
static uint
bgp_msg_write_header(bgp_msg_writer writer, uint body_length, uint type)
{
  uint  msg_length ;
  uint  iv ;

  if (body_length <= (UINT16_MAX - BGP_MSG_HEAD_L))
    msg_length = body_length + BGP_MSG_HEAD_L ;
  else
    msg_length = UINT16_MAX ;

  qassert(memcmp(&writer->msg_header[BGP_MH_MARKER], marker,
                                                        BGP_MH_MARKER_L) == 0) ;
  store_ns(&writer->msg_header[BGP_MH_LENGTH], msg_length) ;
  store_b( &writer->msg_header[BGP_MH_TYPE], (type <= UINT8_MAX) ? type
                                                                 : UINT8_MAX) ;

  iv = writer->msg_iv_count ;
  qassert(iv <  bgp_msg_writer_msg_part_count) ;

  if (iv < bgp_msg_writer_msg_part_count)
    {
      writer->msg_vec[iv].base = writer->msg_header ;
      writer->msg_vec[iv].len  = BGP_MSG_HEAD_L ;

      writer->msg_iv_count = iv + 1 ;
    } ;

  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * Append a body part to the current message -- unless zero length.
 *
 * NB: should be possible, but we avoid running off the end of the iovec !
 */
static void
bgp_msg_write_body_part(bgp_msg_writer writer, ptr_c part, uint part_length)
{
  uint iv ;

  qassert( (writer->msg_iv_count > 0) &&
           (writer->msg_iv_count < bgp_msg_writer_msg_part_count) ) ;

  iv = writer->msg_iv_count ;

  if ((part_length == 0) || (iv >= bgp_msg_writer_msg_part_count))
    return ;

  writer->msg_vec[iv].base = part ;
  writer->msg_vec[iv].len  = part_length ;

  writer->msg_iv_count = iv + 1 ;
} ;

/*------------------------------------------------------------------------------
 * Check that the message we are about to send is correctly framed, and
 * of an acceptable length.
 *
 * This is a belt-and-braces thing, to avoid sending complete rubbish.
 *
 * This replaces a rubbish message with a NOTIFICATION, and drops the writer
 * state to bws_clearing.
 *
 * NB: this is all a touch magic.
 *
 *     In bws_clearing the writer does not accept anything further into the
 *     write buffer, and will discard stuff from the ring-buffer.
 *
 *     So far, so simple.
 *
 *     The caller does not need to worry about the substitution... as far as
 *     it is concerned the message it was writing has been written.
 *
 *     When the NOTIFICATION gets written away by the pselect side, the writer
 *     will move from bws_clearing to bws_down, and it all looks as if the
 *     writer has been 'shut'.
 *
 *     So... the event which will never happen, does not have to be considered
 *     in the main path !!  Except that any output of messages, or any loop to
 *     do so, has to look out for the writer going bws_clearing !
 *
 * Returns:  length of result message -- the given length, unless failed !
 */
static uint
bgp_msg_write_msg_check(bgp_msg_writer writer, uint msg_length)
{
  uint msg_iv_count, iv, check_length, msg_length_in_header ;

  msg_iv_count = writer->msg_iv_count ;

  if ((msg_iv_count < 1) || (msg_iv_count > bgp_msg_writer_msg_part_count))
    {
      zlog_err("BUG in %s() for %s: unready to write", __func__,
                                                           writer->plox->host) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  check_length = writer->msg_vec[0].len ;
  for (iv = 1 ; iv < msg_iv_count ; ++iv)
    check_length += writer->msg_vec[iv].len ;

  if (msg_length != check_length)
    {
      zlog_err("BUG in %s() for %s: expected message length = %u, actual = %u",
                       __func__, writer->plox->host, msg_length, check_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  if ((msg_length < BGP_MSG_MIN_L) || (msg_length > BGP_MSG_MAX_L))
    {
      zlog_err("BUG in %s() for %s: invalid message length = %u",
                                     __func__, writer->plox->host, msg_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  msg_length_in_header = load_ns(&writer->msg_header[BGP_MH_LENGTH]) ;

  if (msg_length_in_header != msg_length)
    {
      zlog_err("BUG in %s() for %s: message length in header = %u, actual = %u",
               __func__, writer->plox->host, msg_length_in_header, msg_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * This replaces anything there is in the msg_vec with a NOTIFICATION, and
 * drops the writer state to bws_clearing.
 *
 * NB: this is all a touch magic.
 *
 *     In bws_clearing the writer does not accept anything further into the
 *     write buffer, and will discard stuff from the ring-buffer.
 *
 *     So far, so simple.
 *
 *     The caller does not need to worry about the substitution... as far as
 *     it is concerned the message it was writing has been written.
 *
 *     When the NOTIFICATION gets written away by the pselect side, the writer
 *     will move from bws_clearing to bws_down, and it all looks as if the
 *     writer has been 'shut'.
 *
 *     So... the event which will never happen, does not have to be considered
 *     in the main path !!  Except that any output of messages, or any loop to
 *     do so, has to look out for the writer going bws_clearing !
 *
 * Returns: length of the substitute message
 */
static uint
bgp_msg_write_msg_stomp(bgp_msg_writer writer)
{
  static const byte crash_notification[] =
    {
      0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,
      0, BGP_NOM_MIN_L,                 /* network order, word  */
      BGP_MT_NOTIFICATION,
      BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC,
    } ;
  confirm(sizeof(crash_notification) == BGP_NOM_MIN_L) ;

  writer->msg_vec[0].base = crash_notification ;
  writer->msg_vec[0].len  = sizeof(crash_notification) ;
  writer->msg_iv_count    = 1 ;

  qassert(memcmp(&crash_notification[BGP_MH_MARKER], marker,
                                                        BGP_MH_MARKER_L) == 0) ;
  qassert(load_ns(&crash_notification[BGP_MH_LENGTH]) ==
                                                   sizeof(crash_notification)) ;

  writer->state = bws_clearing ;
  return sizeof(crash_notification) ;
} ;

/*------------------------------------------------------------------------------
 * Check message in the msg_vec, and transfer (as much as possible) to the
 *                                                                writer buffer.
 *
 * Note that we don't care what writer->state we have, this is a buffer
 * operation.
 *
 * Returns:  updated writer->free
 */
static uint
bgp_msg_write_away(bgp_msg_writer writer, uint msg_length)
{
  bgp_msg_write_msg_check(writer, msg_length) ;

  return bgp_msg_write_transfer(writer, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Transfer as much of the current message as possible into the writer buffer.
 *
 * Note that we don't care what writer->state we have, this is a buffer
 * operation.
 *
 * When have just created a new message, 'msg_iv' == 0.  For tidying up after
 * writing, 'msg_iv' is where we managed to get to.
 *
 * Returns:  updated writer->free
 */
static uint
bgp_msg_write_transfer(bgp_msg_writer writer, uint msg_iv)
{
  ptr_t  pp ;
  uint   free, have, msg_iv_count ;

  free = writer->free ;
  pp   = writer->pp ;

  qassert(free <= writer->size) ;
  qassert((writer->buffer <= pp) && (pp <= writer->limit)) ;

  if (free == 0)
    return 0 ;                  /* full to the brim     */

  /* Set things up so that 'have' is the space available in the first part
   * of the buffer (may be the only part).
   *
   * NB: if pp == writer->limit, then the initial 'have' will be zero,
   *     so will immediately wrap.
   *
   *     Even if we put in the checks to wrap pp as soon as it hits limit,
   *     this would be the safe thing to do !
   */
  if (free <= (writer->limit - pp))
    have = free ;
  else
    have = writer->limit - pp ;

  /* Now we transfer what we can to the buffer
   */
  msg_iv_count =  writer->msg_iv_count ;

  for ( ; msg_iv < msg_iv_count ; ++msg_iv)
    {
      ptr_c src ;
      uint  want ;

      src  = writer->msg_vec[msg_iv].base ;
      want = writer->msg_vec[msg_iv].len ;

      if (want == 0)
        continue ;              /* unlikely, but tidy   */

      while (want > have)
        {
          /* We cannot accommodate everything we want from the current message
           * part, in the current part of the buffer.
           *
           * Take what we can into the current destination part, which reduces
           * what we want, and advances the src pointer, and reduces the free
           * count.
           */
          if (have > 0)
            {
              memcpy(pp, src, have) ;
              src   += have ;
              want  -= have ;

              pp    += have ;
              free  -= have ;
            } ;

          /* If there is nothing now free, then we are done...
           *
           *   pp = next place to put to (when no longer full !)
           */
          if (free == 0)
            {
              /* Update the msg_vec -- moving the remaining entries down,
               * as required.
               *
               * In most cases we expect to write the entire message away,
               * so this is generally not going to be needed.  If we have eaten
               * the first entry in the vector, the there are at most 1 or
               * 2 left.
               */
              qassert(want != 0) ;

              writer->msg_vec[0].base = src ;
              writer->msg_vec[0].len  = want ;

              if (msg_iv != 0)
                {
                  uint iv ;

                  iv      = 1 ;
                  msg_iv += 1 ;

                  while (msg_iv < msg_iv_count)
                    writer->msg_vec[iv++] = writer->msg_vec[msg_iv++] ;

                  msg_iv_count = iv ;
                } ;

              goto done ;               /* break out    */
            } ;

          /* There is still space free, so we wrap around.
           */
          pp   = writer->buffer ;
          have = free ;

          qassert(want > 0) ;   /* still true ! */
        } ;

      /* Whatever we want from the current msg_part, we can accommodate.
       */
      memcpy(pp, src, want) ;

      pp    += want ;
      have  -= want ;
      free  -= want ;
    } ;

  /* When appears here, we have transferred the entire message to the write
   * buffer.
   */
  msg_iv_count = 0 ;

  /* When we arrive here, we have done as much as we can.
   *
   *   pp   = next place to put to
   *   free = remaining free count.
   *   msg_iv_count = new number of entries in the msg_vec[]
   */
 done:
  writer->pp           = pp ;
  writer->free         = free ;
  writer->msg_iv_count = msg_iv_count ;

  return free ;
} ;

/*------------------------------------------------------------------------------
 * Blow the contents of the writer buffer and any message stuff on the side.
 *
 * If there is stuff in the msg_vec, then the main buffer must be full.  If
 * frees any space will copy stuff into the main buffer, until there is nothing
 * in the msg_vec, or the buffer is full again.
 *
 * Note: the aggregation of writes into the write buffer means that we are
 *       always in a position to write a sizable chunk all in one go.
 *
 *       This means that everything which is written is copied to the write
 *       buffer.
 *
 *       The msg_vec etc means that where a message fills the buffer, the
 *       balance is held in the msg_vec, until there is space.  Stuff may be
 *       written from there directly, or the copy to the write buffer may
 *       be done later.  Either way, each byte is copied at most once.
 *
 * Will not write anything if an error or shut-ness have already been
 * encountered.
 *
 * Unlike reading, when an error or shut-ness is encountered, the problem is
 * reported immediately -- and the buffers can be flushed.
 *
 * Disables write-ready if gets an error or shut-ness, or is already not bws_ok
 * or bws_clearing, or if the buffer becomes empty and is bws_clearing.  If all
 * is well, does not turn off write-ready unless buffer was empty when we
 * arrived -- so does not immediately turn off write-ready, in case more
 * stuff is put in the buffer.
 *
 * Returns:  true <=> there is space available in the buffer,
 *                    or some sort of failure.
 *          false  => OK, but buffer is full !
 */
extern bool
bgp_msg_write_raw(bgp_msg_writer writer, qfile qf)
{
  uint    iv, iv_x, total, free ;

  if ((writer->state != bws_ok) && (writer->state != bws_clearing))
    goto do_disable ;

  qassert(qfile_fd_get(qf) >= fd_first) ;       /* must be valid !      */

  /* Set up the iovec stuff.
   *
   * We work with the writer->buf_vec[].  This has at most two entries, and
   * sits immediately before writer->msg_vec.  We arrange for iv and iv_x
   * to be the start and limit of the effective vector.
   */
  iv   = bgp_msg_writer_buf_part_count ;
  iv_x = iv + writer->msg_iv_count ;

  confirm(&writer->buf_vec[bgp_msg_writer_buf_part_count]
                                                       == &writer->msg_vec[0]) ;
  qassert(iv_x <= bgp_msg_writer_part_count) ;

  free = writer->free ;
  if (free >= writer->size)
    {
      /* Buffer is empty -- so iovec must also be !
       *
       * Can reset the writer->pp but otherwise nothing to output.
       */
      qassert(free == writer->size) ;
      qassert(iv == iv_x) ;

      writer->pp = writer->buffer ;
    }
  else
    {
      /* Buffer is not empty -- may be full
       */
      uint  have, above ;
      ptr_t pp, sp ;

      /* Now fill in the iovec entries for the main buffer.
       *
       * We slightly simplify by setting pp = limit if writer->pp = buffer.
       *
       * let have  = writer->size - free  -- which we know is not zero.
       *     above = pp - buffer          -- which we also know is not zero
       *
       * Case (1) 0 < have <= above
       *
       *       +-------+
       *       . free2 |     empty, if pp + free == limit (buffer full)
       *   sp->|-------|
       *       . have  .     have > 0  and  have + free2 == above
       *   pp->|-------|
       *       . free1 .     empty, if pp + free == limit
       *       +-------+
       *
       * Case (2) have > above > 0
       *
       *       +-------+
       *       . have2 .     have2 > 0 since have2 == above && above > 0
       *   pp->|-------|
       *       . free  .     empty, if free == 0
       *   sp->|-------|
       *       . have1 .     have1 > 0 since have1 == have - above
       *       +-------+                                    && have > above
       */
      pp = writer->pp ;

      if (pp == writer->buffer)
        pp = writer->limit ;        /* simplifies things    */

      have = writer->size - free ;
      qassert((have > 0) && (have <= writer->size)) ;

      above = (pp - writer->buffer) ;
      if (have <= above)
        {
          /* Case (1) -- just the one part to go
           */
          sp    = pp - above ;
        }
      else
        {
          /* Case (2) -- two parts to go -- insert second part.
           */
          iv -= 1 ;
          writer->buf_vec[iv].base = writer->buffer ;
          writer->buf_vec[iv].len  = have - above ;

          sp    = pp + free ;
          have = above ;
        } ;

      qassert(have != 0) ;

      iv -= 1 ;
      writer->buf_vec[iv].base = sp ;
      writer->buf_vec[iv].len  = have ;
    } ;

  /* Loop to write or pick up any pending error.
   *
   * On error or "EOF" update the reader->state.
   */
  qassert((writer->state == bws_ok) || (writer->state == bws_clearing)) ;

  total = 0 ;                   /* nothing, yet         */
  do
    {
      int    put ;
      size_t gone ;

      /* If we have something to write, we do the full writev.
       *
       * Otherwise, now is a good moment to check for any pending error.
       */
      if (iv < iv_x)
        put = writev(qfile_fd_get(qf), (struct iovec*)(&writer->buf_vec[iv]),
                                                                    iv_x - iv) ;
      else
        put = getsockopt_so_error(qfile_fd_get(qf)) ;

      if (put <= 0)
        {
          /* We arrive here if have a new I/O error or is disabled.
           *
           * Except that if we have put == 0
           *
           * Definitely have an error if put < 0.  If put == 0 and errno == 0,
           * then all is well or writer->state != bws_ok.
           *
           * NB: EPIPE is returned only when an attempt is made to write to
           *     a socket which has been shut by us... or is no longer
           *     connected.  We treat this in much the same way as 'eof',
           *     including mapping EPIPE to 0.
           */
          int  err ;
          qfile_state_t qfs ;

          err = errno ;         /* actual error                 */

          if ((put == 0) && (err == 0))
            break ;             /* do nothing with nothing      */

          if (err == EINTR)
            continue ;

          if ((err == EAGAIN) || (err == EWOULDBLOCK))
            break ;

          if (err == EPIPE)
            err = 0 ;           /* "soften" the error.  cf eof  */

          /* If was OK or done, then we are now shut or we have an error.
           *
           * We SHUT_WR -- leaving the read side to complete as much
           * as it can... which may be nothing if we have an io_error,
           * but that is up to it to discover.
           *
           * Unlike the read side, what is in the buffers is no of no use
           * at all, so we can crash those straight away.
           *
           * If the reader has been SHUT_RD already, then we assume that it
           * has posted an error or eof' -- in any case, that takes precedence,
           * and the writer goes bws_down.
           *
           * Otherwise, we post this error or shut, and go bws_io_error or
           * bws_eof.
          */
          qfs = qfile_shutdown(qf, qfUp_WR) ;

          if (qfs & qfUp_RD)
            {
              writer->state = (err == 0) ? bws_shut : bws_io_error ;
              qfile_err_set(qf, err) ;  /* register first error */
            }
          else
            {
              writer->state = bws_down ;
            } ;

          bgp_msg_write_stop(writer) ;
          goto do_disable ;
        } ;

      /* We have successfully put something
       */
      qassert((put > 0) && (iv < iv_x)) ;

      gone   = put ;
      total += put ;

      while ((gone > 0) && (iv < iv_x)) ;
        {
          iovec  vec ;
          size_t had ;

          vec = &writer->buf_vec[iv] ;
          had = vec->len ;

          if (vec->len > gone)
            {
              vec->base = ((const char*)vec->base) + gone ;
              vec->len  = had                      - gone ;
              gone      = 0 ;
            }
          else
            {
              gone -= had ;
              iv   += 1 ;
            } ;
        } ;

      qassert(gone == 0) ;
    }
  while (iv < iv_x) ;

  /* We arrive here after writing 'total' bytes.
   *
   * NB: 'total' can be zero if buffer was empty, and all is well.
   */
  if (iv < iv_x)
    {
      /* There is something left to output.
       *
       * Update the free count -- noting that the total may include
       * part of any message fragment, and may be zero !
       */
      uint free ;

      free = writer->free + total ;
      if (free > writer->size)
        {
          qassert(writer->msg_iv_count != 0) ;

          free = writer->size ;
          writer->pp = writer->buffer ; /* may as well  */
        } ;

      /* If there was a message fragment, then transfer as much as will now fit
       * into the main buffer.
       */
      if (iv_x > bgp_msg_writer_buf_part_count)
        {
          /* We have at least one fragment, and at least one byte remains.
           *
           * We have: iv = index into the buf_vec[].  If that is greater than
           * the _buf_part_count, that means that the writev() has eaten into
           * the msg_vec[], so we need to tell bgp_msg_write_transfer() where
           * to start.
           */
          uint msg_iv ;

          if (iv > bgp_msg_writer_buf_part_count)
            msg_iv = iv - bgp_msg_writer_buf_part_count ;
          else
            msg_iv = 0 ;

          writer->free = free ;
          free = bgp_msg_write_transfer(writer, msg_iv) ;
        } ;

      /* All is well, return with a "kick" if there is space in the main
       * buffer.
       */
      writer->free = free ;

      if (free == 0)
        return false ;              /* no space currently free      */

      qassert(writer->msg_iv_count == 0) ;

      return true ;                 /* can write some more          */
    }
  else
    {
      /* There is nothing left to output, so the buffer must now be
       * completely empty -- so tidy up and then disable write-ready, if we
       * wrote nothing at all this time around, or is bws_clearing.
       */
      qassert(iv == iv_x) ;

      writer->pp   = writer->buffer ;   /* may as well  */
      writer->free = writer->size ;     /* definitely   */

      writer->msg_iv_count = 0 ;        /* in any case  */

      /* If we are bws_clearing, then we are finished so -> bws_down.
       */
      if      (writer->state == bws_clearing)
        bgp_msg_write_stop(writer) ;
      else if (total != 0)
        return true ;
    } ;

  /* Now, if concluded that we should be disabled, turn off write-ready, and
   * return with a "kick", because this is the last time we will be here until
   * is set write-ready again.
   *
   * We are a teensy bit careful here -- if the qfile has already been
   * closed, then there's no point clearing write-ready.  Expect to be here
   * after write-ready -- but no harm in being careful.
   *
   * Note that will qps_disable_modes() unconditionally (to be sure !).
   */
 do_disable:
  if (qfile_fd_get(qf) >= fd_first)
    qfile_disable_modes(qf, qps_write_mbit) ;

  return true ;
} ;

/*==============================================================================
 * OPEN message -- transform bgp_open_state into BGP message
 */
static bool bgp_open_options(blower br, bgp_open_state open_state) ;
static ptr_t bgp_msg_write_get_temp(bgp_msg_writer writer, uint size) ;

/*------------------------------------------------------------------------------
 * Make OPEN message and dispatch -- BGP Engine operation.
 *
 * OPEN is the first message to be sent.  If the buffers are not empty,
 * something is badly wrong !
 *
 * Creates connection->open_sent if required, and fills it in from the
 * connection->session arguments etc.
 *
 * If connection->cap_suppress, the opensent->args refelect the effect of
 * the suppression.
 *
 * NB: actual I/O occurs in the qpselect action function -- so this cannot
 *     fail !
 */
extern void
bgp_msg_write_open(bgp_connection connection)
{
  bgp_open_state     open_sent ;
  bgp_session_args   args_sent ;
  bgp_session_args_c args_config ;
  blower_t br[1], sbr[1] ;
  uint   msg_body_length ;
  bool ok ;

  qa_add_to_uint(&connection->session->stats.open_out, 1) ;

  /* Fill in connection->open_sent (creating, if required.)
   *
   * We copy the session arguments if !connection->cap_suppress.  But if is
   * cap_suppress we leave everything turned off and just fill in what we can
   * do and copy just the bits we need.
   *
   * NB: args_sent->keepalive_secs is the value the session is configured for.
   *
   *     The KeepaliveTime is not actually sent.  The HoldTime is sent in the
   *     OPEN and a (maximum) KeepaliveTime of HoldTime/3 is implied.
   *
   *     Nevertheless, in the args_sent we keep the configured KeepaliveTime,
   *     and that is used when the values for the session are negotiated.
   *
   * NB: neither args_sent->connect_retry_secs nor args_sent->open_hold_secs
   *     are actually sent either... for completeness we copy from the
   *     session configured values, anyway.
   */
  open_sent = connection->open_sent =
                                bgp_open_state_init_new(connection->open_sent) ;

  open_sent->my_as   = connection->session->local_as ;
  open_sent->my_as2  = (open_sent->my_as <= BGP_AS2_MAX)
                                  ? (uint16_t)open_sent->my_as : BGP_ASN_TRANS ;
  open_sent->bgp_id  = connection->session->local_id ;

  args_sent   = open_sent->args ;
  args_config = connection->session->args_config  ;

  if (!connection->cap_suppress)
    {
      bgp_session_args_copy(args_sent, args_config) ;
      args_sent->cap_suppressed  = false ;      /* for completeness     */
    }
  else
    {
      /* Suppressing capabilities.
       *
       * The args_sent have already been reset when the open_sent was created,
       * see bgp_session_args_reset().  So here we copy across what is left
       * after capability negotiation is suppressed !
       *
       * Note that cap_af_override and cap_strict still have effect.
       */
      args_sent->cap_suppressed  = true ;

      args_sent->can_af          = args_config->can_af ;
      args_sent->cap_af_override = args_config->cap_af_override ;
      args_sent->cap_strict      = args_config->cap_strict ;

      if (!args_sent->cap_af_override)
        args_sent->can_af &= qafx_ipv4_unicast ;

      args_sent->holdtime_secs      = args_config->holdtime_secs ;
      args_sent->keepalive_secs     = args_config->keepalive_secs ;
    } ;

  /* We are completely paranoid about this.
   */
  if ((args_sent->holdtime_secs < 3) && (args_sent->holdtime_secs != 0))
    args_sent->holdtime_secs = 3 ;

  /* Prepare blower and set OPEN message fixed part
   *
   * Note that we prepare the body of the message in the writer's temp_buff.
   */
  bgp_msg_write_get_temp(connection->writer, BGP_OPM_MAX_L);
  blow_init(br, connection->writer->temp_buff, BGP_OPM_MAX_L) ;

  blow_b(br, BGP_VERSION_4) ;
  blow_w(br, open_sent->my_as2) ;
  blow_w(br, args_sent->holdtime_secs) ;
  blow_ipv4(br, open_sent->bgp_id) ;

  qassert(blow_has_not_overrun(br)) ;

  /* Set OPEN message options
   */
  blow_sub_init(sbr, br, 1, 0, 255) ;
  ok = bgp_open_options(sbr, open_sent) ;
  blow_sub_end_b(br, sbr) ;

  msg_body_length = blow_length(br) ;

  if (ok && (msg_body_length <= BGP_OPM_MAX_L)) {} ;

  /* Set BGP message length.
   *
   * Cannot overflow the BGP Message size, and if it did, there is damn all
   * we could do about it !
   */
  if (BGP_DEBUG (normal, NORMAL) || BGP_DEBUG (io, IO_OUT))
    {
      const char* no_cap ;
      const char* as4 ;

      if (args_sent->can_capability)
        {
          no_cap = "" ;

          if (args_sent->can_as4)
            as4 = "(AS4)" ;
          else
            as4 = "" ;
        }
      else
        {
          if (args_config->can_capability)
            no_cap = " (capabilities suppressed)" ;
          else
            no_cap = " (sans capabilities)" ;

          as4 = "" ;
        } ;

      zlog_debug("%s sending OPEN, version %d, my as %u%s, "
                                                        "holdtime %d, id %s%s",
                  connection->lox.host, BGP_VERSION_4, open_sent->my_as, as4,
                    args_sent->holdtime_secs,
                     siptoa(AF_INET, &open_sent->bgp_id).str, no_cap) ;
    } ;

  /* Finally -- write the temp buffer away
   */
  bgp_msg_write_msg(connection->writer, blow_start(br), msg_body_length,
                                                                  BGP_MT_OPEN) ;
} ;

/*------------------------------------------------------------------------------
 * Add options to given encoded OPEN message.
 *
 * Supports the status quo: only Capability Options.
 *
 * Creates an empty options part of there are no capabilities to set.
 *
 * Returns:  true <=> OK
 *           false => .....
 */
static bool
bgp_open_options(blower br, bgp_open_state open_state)
{
  bgp_session_args args ;
  bool     wrap ;
  bgp_open_orf_type_t orf_type[1] ;
  blower_t sbr[1] ;

  args = open_state->args ;

  /* If may not send capability, quit now -- zero options.
   */
  if (!args->can_capability)
    return true ;

  /* Lay down the capabilities.
   *
   * We send CAP_MP_EXT for each afi/safi -- even if the only one supported
   * is IPv4 Unicast.  If there are no afi/safi, then no CAP_MP_EXT can be
   * sent.  The peer will assume that IPv4 Unicast is (implicitly) supported,
   * but the session will be dropped because there are no agreed afi/safi !
   */
  wrap = false ;                /* ie: one Option               */

  bgp_open_make_cap_option(sbr, br, !wrap) ;

  if (!args->can_mp_ext)
    bgp_open_make_cap_mp_ext(sbr, args->can_af, wrap) ;

  bgp_open_make_cap_r_refresh(sbr, args->can_r_refresh, wrap) ;

  if (args->can_as4)
    bgp_open_make_cap_as4(sbr, open_state->my_as, wrap) ;

  if (args->can_orf & bgp_form_rfc)
    {
      /* We are prepared to send out the RFC ORF Capability.
       *
       * We only know about Prefix ORF.  We announce only the RFC Prefix ORF
       * Type in the RFC ORF Capability.
       */
      bool have ;

      have = bgp_open_prepare_orf_type(orf_type, BGP_CAP_ORFT_T_PFX,
                            args->can_orf_pfx, bgp_form_rfc, args->can_mp_ext) ;
      if (have)
        {
          bgp_open_make_cap_orf(sbr, BGP_CAN_ORF, 1, orf_type,
                                                      args->can_mp_ext, wrap) ;
          if (!blow_is_ok(sbr))
            {
              goto quit ;
            } ;
        } ;
    } ;

  if (args->can_orf & bgp_form_pre)
    {
      /* We are prepared to send out the pre-RFC ORF Capability.
       *
       * We only know about Prefix ORF.  We announce only the pre-RFC Prefix
       * ORF Type in the pre-RFC ORF Capability.
       */
      bool have ;

      have = bgp_open_prepare_orf_type(orf_type, BGP_CAP_ORFT_T_PFX_pre,
                            args->can_orf_pfx, bgp_form_pre, args->can_mp_ext) ;
      if (have)
        {
          bgp_open_make_cap_orf(sbr, BGP_CAN_ORF, 1, orf_type,
                                                       args->can_mp_ext, wrap) ;
          if (!blow_is_ok(sbr))
            {
              goto quit ;
            } ;
        } ;
    } ;

  if (args->can_dynamic_dep)
    {
    } ;

  if (args->can_dynamic)
    {
    } ;

  if (args->gr.can)
    {
      bgp_open_make_cap_gr(sbr, &args->gr, args->can_mp_ext, wrap) ;

      if (!blow_is_ok(sbr))
        {
          goto quit ;
        } ;
    } ;

 quit:
  bgp_open_make_cap_end(br, sbr, !wrap) ;

  return blow_is_ok(br) ;
} ;

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * If the writer buffer is empty, fire off a Keepalive (if is bws_ok).
 *
 * For the KEEPALIVE after OPEN, we allow 'must' to force the issue -- unlikely
 * to be an issue -- but it would be embarrassing not to send same if the
 * OPEN is yet to be processed by the qpselect() side !
 */
extern void
bgp_msg_write_keepalive(bgp_connection connection, bool must)
{
  bgp_msg_writer writer ;

  writer = connection->writer ;

  if (writer->state != bws_ok)
    return ;

  if (writer->free == writer->size)
    {
      /* Buffer is empty -- so MUST be OK to send message.
       */
      qassert(writer->msg_iv_count == 0) ;
    }
  else if (must)
    {
      /* Even though the buffer is not empty, we must send KEEPALIVE.
       *
       * This is only required after sending an OPEN.  It is possible that the
       * incoming OPEN has already arrived, so immediately after sending the
       * OPEN, the incoming one is processed, so a KEEPALIVE *must* be sent.
       *
       * The OPEN is sent when the buffer is empty, so is GUARANTEED to clear
       * into the write buffer, so the msg_vec MUST be clear !
       */
      if (writer->msg_iv_count != 0)
        {
          zlog_err ("%s not sending KEEPALIVE, even though 'must'"
                               " -- iovec NOT empty ??", connection->lox.host) ;
          return ;
        } ;
    }
  else
    {
      /* Buffer is not empty, and we aren't required to send KEEPALIVE,
       * so we don't.
       */
      if (BGP_DEBUG (keepalive, KEEPALIVE))
        zlog_debug ("%s not sending KEEPALIVE -- buffer not empty",
                                                         connection->lox.host) ;
      return ;
    } ;

  /* Now if 'must' or not 'holdtimer_suppressed', create our KEEPALIVE
   * message -- which (as any fule kno) is just a header -- and push it into
   * the (empty) buffer.
   */
  if (must || !connection->holdtimer_suppressed)
    {
      uint msg_length ;

      msg_length = bgp_msg_write_header(writer, BGP_KAM_L - BGP_MSG_HEAD_L,
                                                             BGP_MT_KEEPALIVE) ;
      confirm((BGP_KAM_L - BGP_MSG_HEAD_L) == 0) ;
      qassert(msg_length == BGP_KAM_L) ;

      bgp_msg_write_away(writer, msg_length) ;

      if (BGP_DEBUG (keepalive, KEEPALIVE) && !BGP_DEBUG (io, IO_OUT))
        zlog_debug ("%s sending KEEPALIVE", connection->lox.host);

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s send message type %d, length (incl. header) %u",
                       connection->lox.host, BGP_MT_KEEPALIVE, msg_length) ;

      qa_add_to_uint(&connection->session->stats.keepalive_out, 1) ;
    } ;

  /* Now, even if the buffer is empty, force write-ready so that we will
   * at the very least check for I/O errors.
   */
  qfile_enable_mode(connection->qf, qps_write_mnum, NULL) ;
} ;

/*==============================================================================
 * Writing of messages from the ring-buffer
 */
static bool bgp_msg_orf_part(blower br, bgp_msg_writer writer,
                                        bgp_route_refresh rr, bgp_form_t form) ;
static bool bgp_msg_orf_prefix(blower br, uint8_t common,
                                                       orf_prefix_value orfpv) ;


/*------------------------------------------------------------------------------
 * Write a bgp_rbm_out_update message from the ring-buffer to the write
 * buffer.
 *
 * bgp_rbm_out_update messages can have two parts (where have MP_REACH_NLRI).
 */
static uint
bgp_msg_write_update(bgp_msg_writer writer, ptr_t rb_body, uint rb_length)
{
  uint  body_length, msg_length, part1_length, part2_length ;
  ptr_t msg_body, part2 ;
  uint wl, al ;

  qassert(writer->msg_iv_count == 0) ;

  /* For bgp_rbm_out_update we have an extra word of red-tape, which gives
   * the offset of "out-of-order" part 1.
   *
   * For update messages which contain MP_REACH_NLRI, the attributes are
   * generated before the MP_REACH_NLRI, so in the ring-buffer segment we
   * see:
   *          +-----------+
   *          | Part2 Len |  2 bytes of in local machine order
   *  Part 2->|-----------|
   *          .           .
   *          | Attrib    |  ie all the attributes other than the MP_REACH
   *          .           .     attribute
   *  Part 1->|-----------|
   *          | 0         |  "Withdrawn Routes Length (2 octets)"
   *          | Attr Len  |  "Total Path Attributes Length (2 octets)"
   *          |-----------|
   *          .           .
   *          | MP_REACH  |  ie the MP_REACH_NLRI
   *          .           .
   *          +-----------+
   *
   * This allows the creator of the message to generate all attributes first,
   * and then as many MP NLRI as will fit into the message.  Here we collect
   * the result in the write buffer, in the required order.
   *
   * All other UPDATEs do not need this, so the 'offset' is zero... ie there
   * is no part 2.
   */
  if (rb_length < 2)
    {
      zlog_err("BUG in %s() for %s: ring-buffer message length %u",
                                      __func__, writer->plox->host, rb_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  part2_length = load_s(rb_body) ;
  part2        = rb_body   + 2 ;
  body_length  = rb_length - 2 ;
  part1_length = body_length - part2_length ;

  if (part2_length > body_length)
    {
      zlog_err("BUG in %s() for %s: part2_length %u > body %u",
                      __func__, writer->plox->host, part2_length, body_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  if (part1_length < BGP_UPM_BODY_MIN_L)
    {
      zlog_err("BUG in %s() for %s: part1_length %u < minumum %u",
               __func__, writer->plox->host, part1_length, BGP_UPM_BODY_MIN_L) ;
      return bgp_msg_write_msg_stomp(writer) ;
   } ;

  /* Set up the header of the message, followed by part 1 and any part 2.
   */
  msg_length = bgp_msg_write_header(writer, body_length, BGP_MT_UPDATE) ;

  msg_body = part2 + part2_length ;

  bgp_msg_write_body_part(writer, msg_body, part1_length) ;
  if (part2_length != 0)
    bgp_msg_write_body_part(writer, part2, part2_length) ;

  /* Check the framing.
   */
  wl = load_ns(msg_body + 0) ;
  if (wl > (part1_length - BGP_UPM_BODY_MIN_L))
    {
      if (wl > (body_length - BGP_UPM_BODY_MIN_L))
        zlog_err("BUG in %s() for %s: withdraw length %u > body %u - %u",
            __func__, writer->plox->host, wl, body_length, BGP_UPM_BODY_MIN_L) ;
      else
        zlog_err("BUG in %s() for %s: withdraw length %u > part1 %u - %u",
           __func__, writer->plox->host, wl, part1_length, BGP_UPM_BODY_MIN_L) ;

      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  al = load_ns(msg_body + 2 + wl) ;
  if (al > (body_length - BGP_UPM_BODY_MIN_L - wl))
    {
      zlog_err("BUG in %s() for %s: attribute length %u > "
                                                   "body %u - withdraw %u - %u",
        __func__, writer->plox->host, al, body_length, wl, BGP_UPM_BODY_MIN_L) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  /* Log as required.
   */
  if (BGP_DEBUG (io, IO_OUT))
    {
      uint nl ;

      nl = body_length - BGP_UPM_BODY_MIN_L - wl - al ;

      zlog (writer->plox->log, LOG_DEBUG,
             "%s [IO] dispatch UPDATE %u bytes: %u bytes withdraw, "
                                     "%u bytes attributes, %u bytes NLRI",
                    writer->plox->host, msg_length, wl, al, nl) ;
    } ;

  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * Write a bgp_rbm_out_eor message from the ring-buffer to the write
 * buffer.
 *
 * bgp_rbm_out_eor messages comprise the qafx for the EoR.
 */
static uint
bgp_msg_write_eor(bgp_msg_writer writer, ptr_t rb_body, uint rb_length)
{
  uint   body_length, msg_length ;
  qafx_t qafx ;
  ptr_t  msg_buff ;

  qassert(writer->msg_iv_count == 0) ;

  /* For bgp_rbm_out_eor we have:
   *
   *   0: qafx   -- 1 byte
   *
   * we create the body of the message in the writer->temp_buff.  Note that
   * this is not reused until the ring buffer entry can be freed, by which
   * time we know the message has cleared into the write buffer.
   */
  qassert(rb_length == 1) ;

  qafx = load_b(rb_body) ;

  /* The the qafx is qafx_ipv4_unicast, we need to send an UPDATE with
   * no Withdrawn Routes and no Attributes.
   *
   * For all other qafx we need send an an UPDATE with no Withdrawn Routes
   * and an otherwise empty MP_UNREACH_NLRI.
   *
   * Start with a buffer long enough for the general case, and go from there.
   */
  enum
    {
      empty_mp_unreach_nlri = 1 + 1 + 1 + 2 + 1,

      max_eor_msg_len       = 2 + 2 + empty_mp_unreach_nlri,
    } ;

  /* BGP_UPM_A_LEN      == offset of attributes length, if no Withdrawn Routes
   * BGP_UPM_ATTR       == offset of attributes, if no Withdrawn Routes
   * BGP_ATTR_MIN_L     == length of minimum size (empty) attribute
   * BGP_ATT_MPU_MIN_L  == length of body of minimum size MP_UNREACH_NLRI
   */
  confirm(empty_mp_unreach_nlri == (BGP_ATTR_MIN_L + BGP_ATT_MPU_MIN_L)) ;
  confirm(max_eor_msg_len       == (BGP_UPM_ATTR   + empty_mp_unreach_nlri)) ;

  msg_buff = bgp_msg_write_get_temp(writer, max_eor_msg_len) ;
  memset(msg_buff, 0, max_eor_msg_len) ;

  if (qafx == qafx_ipv4_unicast)
    {
      body_length = BGP_UPM_ATTR ;
    }
  else
    {
      body_length = max_eor_msg_len ;

      confirm((BGP_UPM_A_LEN    == 2) && (sizeof(BGP_UPM_W_LEN_T)    == 2)) ;
      confirm((BGP_UPM_ATTR     == 4)) ;
      confirm((BGP_ATTR_FLAGS   == 0) && (sizeof(BGP_ATTR_FLAGS_T)   == 1)) ;
      confirm((BGP_ATTR_TYPE    == 1) && (sizeof(BGP_ATTR_TYPE_T)    == 1)) ;
      confirm((BGP_ATTR_LEN     == 2) && (sizeof(BGP_ATTR_LEN_T)     == 1)) ;
      confirm((BGP_ATT_MPU_AFI  == 0) && (sizeof(BGP_ATT_MPU_AFI_T)  == 2)) ;
      confirm((BGP_ATT_MPU_SAFI == 2) && (sizeof(BGP_ATT_MPU_SAFI_T) == 1)) ;

      store_ns(&msg_buff[2], empty_mp_unreach_nlri) ;

      store_b( &msg_buff[4 + 0],     BGP_ATF_OPTIONAL) ;
      store_b( &msg_buff[4 + 1],     BGP_ATT_MP_UNREACH_NLRI) ;
      store_b( &msg_buff[4 + 2],     2 + 1);
      store_ns(&msg_buff[4 + 3 + 0], get_iAFI(qafx)) ;
      store_b( &msg_buff[4 + 3 + 2], get_iSAFI(qafx)) ;
    } ;

  /* Set up the header of the message, followed by part 1 and any part 2.
   */
  msg_length = bgp_msg_write_header(writer, body_length, BGP_MT_UPDATE) ;

  bgp_msg_write_body_part(writer, msg_buff, body_length) ;

  /* Log as required.
   */
  if (BGP_DEBUG (normal, NORMAL) || BGP_DEBUG (io, IO_OUT))
    zlog_debug ("send End-of-RIB for %s to %s", get_qafx_name(qafx),
                                                           writer->plox->host) ;

  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * Make one Route-Refresh message(s)
 *
 * The ring-buffer entry contains:
 *
 *   0: iAFI     -- 2 bytes, host order
 *   2: iSAFI    -- 1 byte,
 *   3: bool     -- has ORF.
 *
 * May return before all required messages have been sent, if the write
 * buffer is or becomes full.  The 'next_index' entry in the bgp_route_refresh
 * allows the process to be continued, later.
 *
 * If has to send more than one message, then all but the last will be set
 * "defer".  The last will be set as per the defer flag.
 *
 * Supports the status quo, only Address-Prefix ORF.
 *
 * Returns:  length of the Route-Refresh message generated
 *
 * NB: sends any ORF stuff using the Internet AFI/SAFI in the route refresh
 *     object.  Those may, or may not be known to quagga, so may or may not be
 *     the same as the qafx.
 */
static uint
bgp_msg_write_rr(bgp_msg_writer writer, ptr_t rb_body, uint rb_length,
                                              bgp_session session, bool* p_done)
{
  iAFI_t  afi ;
  iSAFI_t safi ;
  bool    has_orf ;

  blower_t br[1] ;

  bgp_session_args_c args ;
  uint8_t    msg_type ;
  bgp_form_t form ;

  bool      done ;
  ptr_t     msg_buff ;
  uint      msg_size ;
  uint      msg_length ;

  bgp_route_refresh rr ;

  qassert(writer->msg_iv_count == 0) ;

  /* Get and check contents of the ring buffer.
   */
  if (rb_length != 4)
    {
      zlog_err("BUG in %s() for %s: unexpected ring-buffer message length %u",
                                      __func__, writer->plox->host, rb_length) ;
      return bgp_msg_write_msg_stomp(writer) ;
    } ;

  afi     = load_s(&rb_body[0]) ;
  safi    = load_b(&rb_body[2]) ;
  has_orf = load_b(&rb_body[3]) ;

  /* If we have ORF, then we want the temp buffer to be big enough for a
   * maximum size message, and some.
   *
   * Also, if we have ORF, fetch the first rr object from the session list.
   *
   * NB: at this stage we do not remove it form the list.
   */
  if (has_orf)
    {
      msg_size = BGP_MSG_MAX_L ;
      rr = session->rr_out ;

      qassert(rr->afi  == afi) ;
      qassert(rr->safi == safi) ;
    }
  else
    {
      msg_size = BGP_RRM_MIN_L ;
      rr = NULL ;
    } ;

  msg_buff = bgp_msg_write_get_temp(writer, msg_size) ;

  /* Decide early on what form of Route Refresh and ORF Prefix Type we can use,
   * if any.
   */
  args = session->args ;

  msg_type = (args->can_r_refresh == bgp_form_pre) ? BGP_MT_ROUTE_REFRESH_pre
                                                   : BGP_MT_ROUTE_REFRESH ;

  if      (args->can_orf_pfx[rr->qafx] & ORF_SM)
    form = bgp_form_rfc ;
  else if (args->can_orf_pfx[rr->qafx] & ORF_SM_pre)
    form = bgp_form_pre ;
  else
    form = bgp_form_none ;

  /* Encode Route Refresh message.
   */
  blow_init(br, msg_buff, msg_size) ;

  blow_w(br, afi) ;
  blow_b(br, 0);
  blow_b(br, safi);

  /* Process as many (remaining) ORF entries as can into message
   */
  if ((rr != NULL) && (form != bgp_form_none))
    done = bgp_msg_orf_part(br, writer, rr, form) ;
  else
    done = true ;

  /* Construct message in the msg_iv
   */
  msg_length = bgp_msg_write_header(writer, blow_length(br), msg_type) ;

  bgp_msg_write_body_part(writer, blow_start(br), blow_length(br)) ;

  /* Set BGP message length & dispatch -- noting that orf entry
   * construction ensures that the length does not exceed the maximum.
   */
  qa_add_to_uint(&session->stats.refresh_out, 1) ;

  if (BGP_DEBUG (normal, NORMAL) || BGP_DEBUG (io, IO_OUT))
    zlog_debug ("%s sending REFRESH_REQ for afi/safi: %u/%u length %u",
                                    writer->plox->host, afi, safi, msg_length) ;

  /* If we have a route refresh object and we are done with it, release it.
   */
  if (done && (rr != NULL))
    {
      .... !!! ;
    } ;

  /* Return result.
   */
  *p_done = done ;
  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * Set the length of the current collection, if any.
 *
 * NB: if the collection is zero length, crashes the blow pointer back to the
 *     before the collection.
 */
inline static void
bgp_msg_orf_part_set_length(blower br, ptr_t collp)
{
  if (collp != NULL)
    {
      uint length ;

      length = blow_ptr(br) - &collp[BGP_ORF_ENTRIES] ;

      if (length != 0)
        store_ns(&collp[BGP_ORF_LEN], length) ;
      else
        br->ptr = collp ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Put ORF entries to the given blower until run out of entries or run out
 * of room.
 *
 * There MUST BE at least one ORF entry to go.
 *
 * Returns true <=> done all available entries.
 */
static bool
bgp_msg_orf_part(blower br, bgp_msg_writer writer,
                                          bgp_route_refresh rr, bgp_form_t form)
{
  bgp_orf_entry entry ;
  uint  next_index ;

  uint8_t orf_type ;

  ptr_t whenp ;                 /* where the "when" byte is             */
  ptr_t collp ;                 /* start of the latest collection       */

  bool  done ;

  /* Heading for Prefix-Address ORF type section -- pro tem, set defer.
   */
  whenp = blow_ptr(br) ;        /* position of "when"           */
  blow_b(br, BGP_ORF_WTR_DEFER) ;

  /* Process ORF entries until run out of entries or space
   */
  collp      = NULL ;           /* no collection, yet   */
  orf_type   = 0 ;              /* no ORF type, yet     */

  next_index = rr->next_index ; /* where we started     */
  while (1)
    {
      entry = bgp_orf_get_entry(rr, next_index) ;
      done = (entry == NULL) ;

      if (done)
        break ;

      /* How much space is there left -- give up if very little
       *
       * What is "very little" is arbitrary, BUT MUST cover the ORF Type
       * byte and the Length of ORF entries word, AT LEAST.
       * */
      if (blow_left(br) < 16)
        break ;                         /* NB: done == false    */

      confirm(16 > BGP_ORF_MIN_L) ;     /* Type & Length        */

      /* Start new collection of ORF entries, if required.
       */
      if ((collp == NULL) || (orf_type != entry->orf_type))
        {
          uint8_t orf_type_sent ;

          /* fill in length of previous ORF entries, if any
           */
          bgp_msg_orf_part_set_length(br, collp) ;

          /* set type and dummy entries length.
           */
          orf_type      = entry->orf_type ;
          orf_type_sent = entry->orf_type ;

          if ((orf_type == BGP_ORF_T_PFX) && (form == bgp_form_pre))
            orf_type_sent = BGP_ORF_T_PFX_pre ;

          collp = blow_step(br, BGP_ORF_MIN_L) ;        /* type & length */

          store_b(&collp[BGP_ORF_TYPE], orf_type_sent) ;
        } ;

      /* Insert the entry, if will fit.
       *
       * sets done <=> fitted
       */
      if (entry->unknown)
        {
          done = (blow_left(br) <= entry->body.orf_unknown.length) ;
          if (done)
            blow_n(br, entry->body.orf_unknown.data,
                       entry->body.orf_unknown.length) ;
        }
      else
        {
          if (entry->remove_all)
            {
              /* Put remove all ORF entry to stream -- if possible.
               */
              done = (blow_left(br) >= 1) ;     /* just the one byte    */
              if (done)
                blow_b(br, BGP_ORF_EA_RM_ALL) ;
            }
          else
            {
              uint8_t common =   (entry->remove ? BGP_ORF_EA_REMOVE
                                                : BGP_ORF_EA_ADD)
                               | (entry->deny   ? BGP_ORF_EA_DENY
                                                : BGP_ORF_EA_PERMIT) ;
              switch (entry->orf_type)
                {
                  case BGP_ORF_T_PFX:
                    qassert(entry->deny ==
                                      (entry->body.orfpv.type == PREFIX_DENY)) ;

                    done = bgp_msg_orf_prefix(br, common, &entry->body.orfpv) ;
                    break ;

                  default:
                    zabort("unknown ORF type") ;
                    break ;
                } ;
            } ;
        } ;

      /* exit loop now if not enough room for current ORF entry
       */
      if (!done)
        break ;

      /* Done ORF entry.  Step to the next.  NB: done == true
       */
      next_index += 1 ;
    } ;

  /* Set the length of what we have collected.
   *
   * If we haven't collected anything, then that's because there wasn't
   * enough room, so will have collapsed back to the start of the collection.
   */
  bgp_msg_orf_part_set_length(br, collp) ;

  /* If we are done, then we set the true defer/
   *
   */
  if (done)
    {
      if (!rr->defer)
        store_b(whenp, BGP_ORF_WTR_IMMEDIATE) ;
    }
  else
    {
      if (next_index == rr->next_index)
        {
          /* Something has gone wrong if nothing has been processed:
           *
           *   a) have been called again after having reported "done" (so there
           *      are no more entries to deal with.
           *
           *   b) have been asked to output an "unknown" ORF entry which is too
           *      long for a BGP message !!
           */
          if (entry == NULL)
            zabort("called bgp_msg_send_route_refresh() after said was done") ;

          if (entry->unknown)
            zlog_err("%s sending REFRESH_REQ with impossible length (%d) ORF",
                          writer->plox->host, entry->body.orf_unknown.length) ;
          else
            zabort("failed to put even one ORF entry") ;

          done = true ;
        }
    }

  rr->next_index = next_index ;
  return done ;
} ;

/*------------------------------------------------------------------------------
 * Put given Address-Prefix ORF entry to stream -- if possible.
 */
static bool
bgp_msg_orf_prefix(blower br, uint8_t common, orf_prefix_value orfpv)
{
  int blen ;

  blen = PSIZE(orfpv->pfx.prefixlen) ;

  if (blow_left(br) < (BGP_ORF_E_P_MIN_L + blen))
    return false ;

  blow_b(br, common) ;
  blow_l(br, orfpv->seq) ;
  blow_b(br, orfpv->ge) ;       /* aka min      */
  blow_b(br, orfpv->le) ;       /* aka max      */
  blow_b(br, orfpv->pfx.prefixlen) ;
  blow_n(br, &orfpv->pfx.u.prefix, blen) ;

  return true ;
} ;

