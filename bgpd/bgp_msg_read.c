/* BGP Message Read -- functions
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#include <zebra.h>
#include <time.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_msg_read.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_route_refresh.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_names.h"

#include "qatomic.h"
#include "qfstring.h"
#include "memory.h"
#include "iovec.h"
#include "sockopt.h"

/*==============================================================================
 * Header validation and sexing of messages
 */                                           /*   0     1     2     3    */
static const uint8_t bgp_header_marker[] = { 0xFF, 0xFF, 0xFF, 0xFF, /*  4 */
                                             0xFF, 0xFF, 0xFF, 0xFF, /*  8 */
                                             0xFF, 0xFF, 0xFF, 0xFF, /* 12 */
                                             0xFF, 0xFF, 0xFF, 0xFF  /* 16 */
                                 } ;
CONFIRM(sizeof(bgp_header_marker) == BGP_MH_MARKER_L) ;

/* Array to map real BGP message type to qBGP message type
 */
static const uint8_t bgp_type_map[256] =
{
  [BGP_MT_OPEN]              = qBGP_MSG_OPEN,
  [BGP_MT_UPDATE]            = qBGP_MSG_UPDATE,
  [BGP_MT_NOTIFICATION]      = qBGP_MSG_NOTIFICATION,
  [BGP_MT_KEEPALIVE]         = qBGP_MSG_KEEPALIVE,
  [BGP_MT_ROUTE_REFRESH]     = qBGP_MSG_ROUTE_REFRESH,
  [BGP_MT_CAPABILITY]        = qBGP_MSG_CAPABILITY,
  [BGP_MT_ROUTE_REFRESH_pre] = qBGP_MSG_ROUTE_REFRESH_pre
} ;
CONFIRM(qBGP_MSG_unknown == 0) ;

/* Array of minimum message body length -- by qBGP_MSG_xxx
 */
static const bgp_size_t bgp_type_min_body_size[] =
{
  [qBGP_MSG_unknown]           = BGP_MSG_MIN_L,         /* not zero     */

  [qBGP_MSG_OPEN]              = BGP_OPM_MIN_L,
  [qBGP_MSG_UPDATE]            = BGP_UPM_MIN_L,
  [qBGP_MSG_NOTIFICATION]      = BGP_NOM_MIN_L,
  [qBGP_MSG_KEEPALIVE]         = BGP_KAM_L,
  [qBGP_MSG_ROUTE_REFRESH]     = BGP_RRM_MIN_L,
  [qBGP_MSG_CAPABILITY]        = BGP_MSG_MIN_L,         /* pro tem      */
  [qBGP_MSG_ROUTE_REFRESH_pre] = BGP_RRM_MIN_L,
} ;

/* Array of maximum message body length -- by qBGP_MSG_xxx
 *
 * Note that for an unknown message we arrange to always fail the test for
 * minimum <= length <= maximum !!
 */
static const bgp_size_t bgp_type_max_body_size[] =
{
  [qBGP_MSG_unknown]           = 0,                     /* only zero !  */

  [qBGP_MSG_OPEN]              = BGP_OPM_MAX_L,
  [qBGP_MSG_UPDATE]            = BGP_MSG_MAX_L,
  [qBGP_MSG_NOTIFICATION]      = BGP_MSG_MAX_L,
  [qBGP_MSG_KEEPALIVE]         = BGP_KAM_L,
  [qBGP_MSG_ROUTE_REFRESH]     = BGP_MSG_MAX_L,
  [qBGP_MSG_CAPABILITY]        = BGP_MSG_MAX_L,         /* pro tem      */
  [qBGP_MSG_ROUTE_REFRESH_pre] = BGP_MSG_MAX_L,
} ;
CONFIRM(BGP_MSG_MIN_L > 0) ;

/*==============================================================================
 * Message Reader
 */

/*------------------------------------------------------------------------------
 * Initialise reader -- allocates, if required.
 *
 * Returns:  new or existing reader
 *
 * NB: if does not allocate, then assumes the given reader has never been
 *     kissed.
 *
 * NB: the reader buffer is created at the same time, and will exist while
 *     the reader itself exists.
 */
extern bgp_msg_reader
bgp_msg_reader_init_new(bgp_msg_reader reader, bgp_connection_logging plox)
{
  if (reader == NULL)
    reader = XCALLOC(MTYPE_BGP_READER, sizeof(bgp_msg_reader_t)) ;
  else
    memset(reader, 0, sizeof(bgp_msg_reader_t)) ;

  reader->plox   = plox;
  reader->buffer = XMALLOC(MTYPE_BGP_READER, bgp_msg_reader_size) ;
  reader->limit  = reader->buffer + bgp_msg_reader_size ;

  return bgp_msg_read_reset(reader) ;
} ;

/*------------------------------------------------------------------------------
 * Reset reader -- allocates, if required.
 *
 * Returns:  new or existing reader
 *
 * NB: if does not allocate, then assumes the given reader just needs to be
 *     reset.
 */
extern bgp_msg_reader
bgp_msg_reader_reset_new(bgp_msg_reader reader, bgp_connection_logging plox)
{
  if (reader == NULL)
    return bgp_msg_reader_init_new(reader, plox) ;
  else
    return bgp_msg_read_reset(reader) ;
} ;

/*------------------------------------------------------------------------------
 * Reset given message reader, if any.
 *
 * Resets everything except: buffer & limit
 *                           plox
 *
 * Returns:  reader as given (NULL if was NULL)
 */
extern bgp_msg_reader
bgp_msg_read_reset(bgp_msg_reader reader)
{
  if (reader != NULL)
    {
      bgp_msg_reader_t was[1] ;

      *was = *reader ;
      memset(reader, 0, sizeof(bgp_msg_reader_t)) ;

      /* Zeroizing sets:
       *
       *   * plox               -- zz       -- restored, below
       *
       *   * msg_state          -- bms_await_header
       *   * msg_in_state       -- bms_in_hand
       *   * msg_state_pending  -- x        --  N/A while bms_await_header
       *
       *   * msg_skip           -- 0        -- none, yet
       *   * msg_awaited        -- 0        -- in bms_await_header
       *
       *   * msg_body_length    -- x          )
       *   * msg_bgp_type       -- x          ) N/A while bms_await_header
       *   * msg_qtype          -- x          )
       *   * msg_body           -- NULL      -- while bms_in_hand
       *
       *   * msg_header         -- all 0's
       *
       *   * state              -- brs_ok
       *
       *   * sp                 -- X        -- set to start of buffer, below
       *   * in_hand            -- 0        -- empty
       *   * size               -- X        -- set to size of buffer, below
       *
       *   * buffer             -- zz       -- restored, below
       *   * limit              -- zz       -- restored, below
       *
       *   * temp_buff          -- zz       -- restored, below
       *   * temp_buff_size     -- zz       -- restored, below
       */
      confirm(bms_await_header == 0) ;
      confirm(bms_in_hand      == 0) ;
      confirm(brs_ok == 0) ;

      reader->plox           = was->plox ;
      reader->buffer         = was->buffer ;
      reader->limit          = was->limit ;
      reader->temp_buff      = was->temp_buff ;
      reader->temp_buff_size = was->temp_buff_size ;

      reader->sp             = reader->buffer ;
      reader->size           = reader->limit - reader->buffer ;
    } ;

  return reader ;
} ;

/*------------------------------------------------------------------------------
 * Arrange for a reader->temp_buff of at least the given size, please
 *                                            (plus the usual suck_buffer_slack)
 *
 * Is about to read into the first length bytes.  Returned buffer will be
 * zeroized from requested size onwards.
 *
 * Returns:  address if reader->temp_buf  -- never NULL (even if size == 0)
 */
static ptr_t
bgp_msg_read_get_temp(bgp_msg_reader reader, uint size)
{
  uint length ;

  qassert((reader->temp_buff == NULL) == (reader->temp_buff_size == 0)) ;

  length = size ;
  size  += suck_buffer_slack ;

  confirm(suck_buffer_slack != 0) ;     /* so size > length !   */

  if (reader->temp_buff_size < size)
    {
      reader->temp_buff_size = uround_up(size, 512) ;

      reader->temp_buff = XREALLOC(MTYPE_BGP_MSG_BUFF, reader->temp_buff,
                                                       reader->temp_buff_size) ;
    } ;

  qassert(reader->temp_buff_size > length) ;

  memset(&reader->temp_buff[length], 0, reader->temp_buff_size - length) ;

  return reader->temp_buff ;
} ;

/*------------------------------------------------------------------------------
 * Free given message reader (if any) and its buffer.
 *
 * Returns:  NULL
 */
extern bgp_msg_reader
bgp_msg_reader_free(bgp_msg_reader reader)
{
  if (reader != NULL)
    {
      XFREE(MTYPE_BGP_MSG_BUFF, reader->temp_buff) ;
      XFREE(MTYPE_BGP_READER, reader->buffer) ;
      XFREE(MTYPE_BGP_READER, reader) ;
    } ;

  return NULL ;
} ;

/*==============================================================================
 * Message Reader reading of messages
 */
static bool bgp_msg_read_update_state(bgp_msg_reader reader) ;
static bool bgp_msg_read_header(bgp_msg_reader reader) ;
static bool bgp_msg_read_set_bad_header(bgp_msg_reader reader, ptr_t hp,
                                                    bgp_msg_state_t msg_state) ;
static bool bgp_msg_read_stop_fail(bgp_msg_reader reader) ;
static void bgp_msg_read_take_from_in_hand(ptr_t msg_body,
                       bgp_msg_reader reader, bgp_msg_in_state_t msg_in_state) ;
static void bgp_msg_read_take_to_body(ptr_t msg_body, bgp_msg_reader reader,
                                              bgp_msg_in_state_t msg_in_state) ;

/*------------------------------------------------------------------------------
 * "Raw" message read -- for read-ready action.
 *
 * Will not read anything if an error or eof have already been encountered.
 *
 * NB: while there is stuff to be read, does not expect to receive any
 *     errors, and will not report any.
 *
 *     If the write side has encountered an error, it will defer that to
 *     the reader (if it is running) by setting the qfile 'err', and then
 *     SHUT_WR.
 *
 *     So here... if we hit EOF without incident, then we pick up the
 *     deferred error.  ... if we hit an error here, then it takes precedence
 *     (so reader errors take precedence over writer ones).
 *
 * Returns:  true  => have something which may require attention
 *           false => waiting for more bytes to complete a header or a message
 *
 * NB: it is up to the caller to decide when to examine the reader->state.
 *
 *     May choose to empty the buffer before looking, or not.
 *
 * NB: if the buffer is already full when arrives, will turn off read-ready.
 *
 *     Does not turn off read-ready when buffer fills... assumes that the
 *     caller will take steps to move stuff out of the buffer, so turning off
 *     read-ready immediately is most likely redundant.
 *
 * NB: if does I/O and gets EOF or an error of any kind, sets:
 *
 *       reader->state    == brs_eof or brs_io_error (or brs_down)
 *       reader->err      == errno or 0 <=> EOF
 *       reader->sock_fd  == fd for diagnostics
 *
 *     the first EOF or error is latched -- once reader->state is not brs_ok
 *     no further I/O is attempted.
 */
extern bool
bgp_msg_read_raw(bgp_msg_reader reader, qfile qf)
{
  static byte skip_buffer[4 * 1024] ;

  uint  iv_x, iv, total, msg_awaited ;
  iovec_t vec[3] ;

  confirm(3 <= IOV_MIN_MAX) ;

  /* Set up the iovec stuff -- if not already "disabled".
   *
   * If the buffer is full, we end up with no iovec entries.
   *
   * If there is msg_awaited, and we are not bms_in_hand, then we are reading
   * into the msg_body buffer first.  The buffer must be empty, so we end up
   * with two iovec entries.
   *
   * Otherwise, we end up with one or two entries.
   *
   * [But note that we budget for three... just in case.]
   */
  if (reader->state != brs_ok)
    goto do_disable ;

  qassert(qfile_fd_get(qf) >= fd_first) ;       /* must be valid !      */
  qassert((reader->msg_in_state == bms_in_hand) == (reader->msg_body == NULL)) ;

  iv_x = 0 ;

  if (reader->msg_state != bms_partial)
    {
      qassert(reader->msg_awaited == 0) ;
      msg_awaited = 0 ;
    }
  else
    {
      qassert(reader->msg_awaited != 0) ;
      msg_awaited = reader->msg_awaited ;

      if (reader->msg_in_state != bms_in_hand)
        {
          /* Read to msg_body, first.
           */
          qassert(reader->msg_body_length >= msg_awaited) ;
          qassert(reader->msg_body        != NULL) ;
          qassert(reader->in_hand         == 0) ;

          vec[iv_x].base = reader->msg_body
                                     + (reader->msg_body_length - msg_awaited) ;
          vec[iv_x].len  = msg_awaited  ;
          iv_x += 1 ;
        } ;
    } ;

  if      (reader->in_hand == 0)
    {
      /* Buffer is empty
       *
       * Can reset the reader->sp and make sure that reader->size is set.
       */
      reader->sp   = reader->buffer ;
      reader->size = reader->limit - reader->buffer ;

      vec[iv_x].base  = reader->buffer ;
      vec[iv_x].len   = reader->size ;
      iv_x += 1 ;
    }
  else if (reader->in_hand >= reader->size)
    {
      /* The buffer is full already !
       */
      qassert((iv_x == 0) && (reader->msg_skip == 0)) ;
      goto do_disable ;
    }
  else
    {
      /* Buffer is not empty and is not full
       */
      uint  have ;
      ptr_t fp ;

      qassert( (reader->buffer <= reader->sp) &&
                                 (reader->sp < reader->limit) ) ;

      have = reader->size - reader->in_hand ;
      fp   = reader->sp   + reader->in_hand ;

      if (fp >= reader->limit)
        {
          /* The in_hand section wraps around or exactly reaches the end of
           * the buffer, so there is only one free section -- above the
           * reader->sp.
           */
          fp = reader->buffer + (fp - reader->limit) ;
        }
      else
        {
          /* There is at least one byte after the in_hand section, and
           * before the end of the buffer.
           *
           * Sets:  have  == number of bytes at the top of the buffer
           *        fp    == address of the top of the buffer
           */
          uint  after ;

          after = reader->limit - fp ;

          vec[iv_x].base  = fp ;
          vec[iv_x].len   = after ;
          iv_x += 1 ;

          fp    = reader->buffer ;
          have -= after ;
        } ;

      /* There may be space above sp
       */
      if (have != 0)
        {
          vec[iv_x].base  = fp ;
          vec[iv_x].len   = have ;
          iv_x += 1 ;
        } ;
    } ;

  /* Loop to read -- we have something to read to and we are brs_ok.
   *
   * On error or "EOF" update the reader->state.
   */
  qassert((iv_x != 0) && (reader->state == brs_ok)) ;

  iv      = 0 ;                 /* from the beginning   */
  total   = 0 ;                 /* nothing, yet         */
  do
    {
      int    get ;
      uint   skip ;
      size_t have ;

      /* Deal with any skip required.
       *
       * NB: we don't count anything skipped into the total read.
       */
      skip = reader->msg_skip ;
      if (skip != 0)
        {
          qassert(reader->msg_state == bms_await_header) ;
          qassert(reader->in_hand   == 0) ;

          do
            {
              uint take ;

              if (skip > sizeof(skip_buffer))
                take = sizeof(skip_buffer) ;
              else
                take = skip ;

              get = read(qfile_fd_get(qf), skip_buffer, take) ;

              if (get <= 0)
                break ;             /* bad news             */
              else
                skip -= get ;
            }
          while (skip > 0) ;

          reader->msg_skip = skip ;
        } ;

      /* If there is now no skip outstanding, we can now readv().
       */
      if (skip == 0)
        get = readv(qfile_fd_get(qf), (struct iovec*)&vec[iv], iv_x - iv) ;

      if (get <= 0)
        {
          /* We arrive here if have an I/O error or hit eof.
           */
          qfile_state_t qfs ;
          int  err ;

          if      (get < 0)
            err = errno ;       /* actual error         */
          else
            err = 0 ;           /* stand-in for EOF     */

          if (err == EINTR)
            continue ;

          if ((err == EAGAIN) || (err == EWOULDBLOCK))
            break ;

          /* EOF or Error.
           *
           * We SHUT_RD -- leaving the write side to complete as much
           * as it can... which may be nothing if we have an io_error,
           * but that is up to it to discover.
           *
           * If the writer has been SHUT_WR already, then we assume that it
           * has posted an error or simply found the output 'shut' -- in any
           * case, that takes precedence, and the reader goes brs_down.
           *
           * Otherwise, we post this error or eof, and go brs_io_error or
           * brs_eof.
           */
          qfs = qfile_shutdown(qf, qfUp_RD) ;

          if (qfs & qfUp_WR)
            {
              reader->state = (err == 0) ? brs_eof : brs_io_error ;
              qfile_err_set(qf, err) ;  /* register first error */
            }
          else
            {
              reader->state = brs_down ;
            } ;

          qfile_disable_modes(qf, qps_read_mbit) ;
          break ;
        } ;

      /* Is not error and not EOF.
       */
      qassert((get > 0) && (iv_x > iv)) ;

      have   = get ;
      total += get ;

      while ((have > 0) && (iv_x > iv)) ;
        {
          if (vec[iv].len > have)
            {
              vec[iv].base = ((const char*)vec[iv].base) + have ;
              vec[iv].len -= have ;
              have      = 0 ;
            }
          else
            {
              have -= vec[iv].len ;
              iv   += 1 ;
            } ;
        } ;

      qassert(have == 0) ;
    }
  while (iv_x > iv) ;

  /* We arrive here after reading 'total' bytes.
   *
   * NB: 'total' can be zero if have collected an error or EOF, or buffer was
   *     full, or already had an error or EOF.
   *
   * If we had some msg_awaited, then need to update that, and may (well)
   * change state from bms_partial to bms_complete_xxx.  If we were reading
   * to the side buffer, then need to discount the total we now add to the
   * in_hand count.
   */
  if (msg_awaited != 0)
    {
      qassert(reader->msg_state == bms_partial) ;

      if (total >= msg_awaited)
        {
          /* Hurrah -- read everything we were waiting for, and possibly more.
           *
           * If we read into msg_buff first, reduce total that we have added
           * to the main buffer.
           *
           * Change up to bms_complete_xxx
           */
          reader->msg_state   = reader->msg_state_pending ;
          reader->msg_awaited = 0 ;

          if (reader->msg_in_state != bms_in_hand)
            total = total - msg_awaited ;
        }
      else
        {
          /* Shame -- we are still waiting for something, but less.
           *
           * If we read into msg_buff first, we have added nothing to the main
           * buffer.
           */
          reader->msg_awaited = msg_awaited - total ;

          if (reader->msg_in_state != bms_in_hand)
            total = 0 ;
        } ;
    } ;

  reader->in_hand += total ;

  /* All is well, now update the state, which takes care of:
   *
   *   * having read a complete header and then forwards from there.
   *
   *   * collecting the brs_eof/_io_error/_down states if we are waiting for
   *     header or a partial message.
   *
   * Returns: true unless all is well, but is waiting for header or rest of
   *                                                   a (then) partial message.
   */
  return bgp_msg_read_update_state(reader) ;

  /* Now, if concluded that we should be disabled, turn off read-ready, and
   * return with a "kick", because this is the last time we will be here until
   * is set read-ready again.
   *
   * We are a teensy bit careful here -- if the qfile has already been
   * closed, then there's no point clearing read-ready.  Expect to be here
   * after read-ready -- but no harm in being careful.
   *
   * Note that will qps_disable_modes() even if !reader->read_ready, to force
   * the issue.
   */
 do_disable:
   if (qfile_fd_get(qf) >= fd_first)
     qfile_disable_modes(qf, qps_read_mbit) ;

   return true ;
} ;

/*------------------------------------------------------------------------------
 * Update the state of the reader after I/O or step.
 *
 * Returns:  true  => have something which may require attention
 *           false => waiting for more bytes to complete a header or a message
 */
static bool
bgp_msg_read_update_state(bgp_msg_reader reader)
{
  switch (reader->msg_state)
    {
      /* Still waiting for header to complete.
       *
       * If is not OK, then now: bms_fail_eof/_io_error/_down.
       */
      case bms_await_header:
        qassert(reader->msg_body == NULL) ;

        if (reader->in_hand >= BGP_MSG_HEAD_L)
          return bgp_msg_read_header(reader) ;

        if (reader->state != brs_ok)
          return bgp_msg_read_stop_fail(reader) ;

        return false ;

      /* We have a partial message.
       *
       * If is not OK, then now: bms_fail_eof/_io_error/_down.
       */
      case bms_partial:
        qassert(reader->msg_awaited != 0) ;

        if (reader->state != brs_ok)
          return bgp_msg_read_stop_fail(reader) ;

        return false ;

      /* These states are all OK, and remain unchanged.
       */
      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        return true ;

      /* These states are all bad, and also remain unchanged.
       */
      default:
        qassert(false) ;
        fall_through ;

      case bms_fail_eof:
      case bms_fail_io:
      case bms_fail_down:
      case bms_fail_bad_length:
      case bms_fail_bad_marker:
        return bgp_msg_read_stop(reader) ;      /* for completeness     */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Deal with new message header.
 *
 * Returns:  true  => have something which may require attention
 *           false => waiting for more bytes to complete a header or a message
 */
static bool
bgp_msg_read_header(bgp_msg_reader reader)
{
  ptr_t       hp, sp ;
  uint        in_hand, msg_bgp_length, msg_body_length ;
  uint8_t     msg_bgp_type ;
  qBGP_MSG_t  msg_qtype ;
  bgp_msg_state_t msg_state_pending ;

  qassert(reader->msg_state   == bms_await_header) ;
  qassert(reader->msg_awaited == 0) ;
  qassert(reader->in_hand     >= BGP_MSG_HEAD_L) ;

  confirm(BGP_MSG_HEAD_L == (uint)BGP_MSG_MIN_L) ;

  qassert((reader->buffer <= reader->sp) && (reader->sp < reader->limit)) ;
  qassert(reader->msg_awaited == 0) ;
  qassert(reader->msg_body    == NULL) ;

  /* Get the header -- either as a contiguous lump in the reader buffer, or
   * in the little buffer we have to hand.  (Copying the header to one side
   * will happen very rarely -- but makes life easier !
   *
   * If header exactly reaches the end of the buffer, then we need to wrap
   * round !
   */
  hp = reader->sp ;
  sp = hp + BGP_MSG_HEAD_L ;

  if (sp >= reader->limit)
    {
      /* The header of the message either exactly reaches the end of the
       * buffer, or wraps around -- we need to wrap the sp.
       */
      uint   t1, t2 ;

      t2 = sp - reader->limit ;

      if (t2 != 0)
        {
          /* The header of the message breaks across the wrap point.
           */
          t1 = BGP_MSG_HEAD_L - t2 ;
          memcpy(reader->msg_header,      hp,             t1) ;
          memcpy(reader->msg_header + t1, reader->buffer, t2) ;

          hp = reader->msg_header ;
        } ;

      sp = reader->buffer + t2 ;    /* wrap         */
    } ;

  /* Get and set what we can from the header, assuming all is OK.
   */
  msg_bgp_length  = load_ns(&hp[BGP_MH_LENGTH]) ;
  msg_bgp_type    = load_b (&hp[BGP_MH_TYPE]) ;
  msg_qtype       = bgp_type_map[msg_bgp_type] ;

  msg_body_length = msg_bgp_length - BGP_MSG_HEAD_L ;

  reader->msg_body_length = msg_body_length ;
  reader->msg_bgp_type    = msg_bgp_type ;
  reader->msg_qtype       = msg_qtype ;

  msg_state_pending = bms_complete ;            /* assume OK    */

  /* Check the header
   */
  if (memcmp(hp, bgp_header_marker, BGP_MH_MARKER_L) != 0)
    return bgp_msg_read_set_bad_header(reader, hp, bms_fail_bad_marker) ;

  if ( (msg_bgp_length < bgp_type_min_body_size[msg_qtype]) ||
       (msg_bgp_length > bgp_type_max_body_size[msg_qtype]) )
    {
      /* The message length is unacceptable or message type is unknown.
       *
       * If it is completely mad, we give up right away.  Otherwise, we
       * set the required return code for when the message is complete.
       */
      confirm((uint)BGP_MSG_HEAD_L == (uint)BGP_MSG_MIN_L) ;

      if ( (msg_bgp_length < BGP_MSG_MIN_L) ||
           (msg_bgp_length > BGP_MSG_MAX_L) )
        return bgp_msg_read_set_bad_header(reader, hp, bms_fail_bad_length) ;

      if (msg_qtype != qBGP_MSG_unknown)
        {
          if (msg_bgp_length < bgp_type_min_body_size[msg_qtype])
            msg_state_pending = bms_complete_too_short ;
          else
            msg_state_pending = bms_complete_too_long;
        } ;
    } ;

  /* Update the reader state given the header we've just processed.
   */
  in_hand = reader->in_hand - BGP_MSG_HEAD_L ;

  reader->sp           = sp ;       /* stepped past */
  reader->in_hand      = in_hand ;  /* updated      */

  reader->msg_in_state = bms_in_hand ;
  reader->msg_body     = NULL ;

  if (msg_body_length > in_hand)
    {
      /* We had the header, but we don't have the complete message.
       *
       * If is not OK, then now is the time to report that.
       */
      if (reader->state != brs_ok)
        return bgp_msg_read_stop_fail(reader) ;

      reader->msg_state         = bms_partial ;
      reader->msg_state_pending = msg_state_pending ;
      reader->msg_awaited       = msg_body_length > in_hand ;

      return false ;
    }
  else
    {
      /* We have the message, all in one go.
       */
      reader->msg_state         = msg_state_pending ;
      reader->msg_awaited       = 0 ;

      return true ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Continue reading.
 *
 * If the reader is OK, make sure we are read-ready, unless the buffer is full.
 *
 * Otherwise, set !read-ready.
 */
extern void
bgp_msg_read_continue(bgp_msg_reader reader, qfile qf)
{
  if (reader->state == brs_ok)
    {
      /* We are OK -- so MUST have a valid qf.
       */
      qassert(qfile_fd_get(qf) >= fd_first) ;

      if (!qfile_modes_are_set(qf, qps_read_mbit) &&
                                               (reader->in_hand < reader->size))
        qfile_enable_mode(qf, qps_read_mnum, NULL) ;
    }
  else
    {
      /* Not OK, so ensure not read-ready.
       *
       * We are a teensy bit careful here -- if the qfile has already been
       * closed, then there's no point clearing read-ready !
       *
       * Note that will qps_disable_modes() even if !reader->read_ready, to
       * force the issue.
       */
      if (qfile_fd_get(qf) >= fd_first)
        qfile_disable_modes(qf, qps_read_mbit) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Reject header of message: bms_bad_marker or bms_bad_length
 *
 * Makes sure have a copy of the header -- for logging etc.  Then crashes
 * the reading, so will read no more.
 *
 * Returns:  true <=> there is something to be attended to
 */
static bool
bgp_msg_read_set_bad_header(bgp_msg_reader reader, ptr_t hp,
                                                      bgp_msg_state_t msg_state)
{
  if (hp != reader->msg_header)
    memcpy(reader->msg_header, hp, BGP_MSG_HEAD_L) ;

  reader->msg_state = msg_state ;

  return bgp_msg_read_stop(reader) ;
} ;

/*------------------------------------------------------------------------------
 * Stop reader on bgp_reader_state_t and return new bgp_msg_state_t
 *
 * Discards contents of the buffer, so there is definitely nothing more to
 * be read.
 *
 * NB: the reader->state MUST NOT be brs_ok -- but if it is, it is forced to
 *                                                                   brs_down !!
 * Returns:  true <=> there is something to be attended to
 */
static bool
bgp_msg_read_stop_fail(bgp_msg_reader reader)
{
  /* Update the msg_state to reflect the reader state.
   *
   * If is brs_ok, is about to go brs_down.
   */
  switch (reader->state)
    {
      case brs_eof:
        reader->msg_state = bms_fail_eof ;
        break ;

      case brs_io_error:
        reader->msg_state = bms_fail_io ;
        break ;

      default:
        qassert(false) ;
        fall_through ;

      case brs_ok:
        reader->state = brs_down ;
        fall_through ;

      case brs_down:
        reader->msg_state = bms_fail_down ;
        break ;
    } ;

  /* Stop reading !
   */
  return bgp_msg_read_stop(reader) ;
} ;

/*------------------------------------------------------------------------------
 * Stop reader
 *
 * Crashes reading discarding whatever has in hand, and will read no more.
 *
 * If is brs_ok, then forces brs_down
 *
 * If not bms_fail_xxx, force bms_fail_down
 *
 * Returns:  true <=> there is something to be attended to
 */
extern bool
bgp_msg_read_stop(bgp_msg_reader reader)
{
  if (reader->state == brs_ok)
    reader->state = brs_down ;          /* going down   */

  switch (reader->msg_state)
    {
      default:
        qassert(false) ;
        fall_through ;

      case bms_await_header:
      case bms_partial:
      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        reader->msg_state = bms_fail_down ;
        break ;

      case bms_fail_eof:
      case bms_fail_io:
      case bms_fail_down:
      case bms_fail_bad_marker:
      case bms_fail_bad_length:
        break ;
    } ;

  reader->msg_awaited      = 0 ;                /* not any more */
  reader->msg_skip         = 0 ;                /* ditto        */

  reader->msg_body_length  = 0 ;                /* discard      */
  reader->msg_bgp_type     = 0 ;                /* ditto        */
  reader->msg_qtype        = 0 ;                /* ditto        */

  reader->msg_in_state     = bms_in_hand ;      /* discard      */
  reader->msg_body         = NULL ;             /* discard      */

  reader->in_hand          = 0 ;                /* discard      */

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Take the current message body into the given msg_body buffer and set same.
 *
 * Do nothing if not bms_partial or bms_complete_xxx.
 *
 * Will move as much of the message as has arrived to the given buffer, and
 * (if necessary) set things up so that I/O will read the balance directly into
 * that buffer.
 *
 * NB: iff the reader->msg_body_length is zero, then the msg_body may be NULL !
 */
extern void
bgp_msg_read_take(ptr_t msg_body, bgp_msg_reader reader)
{
  switch (reader->msg_state)
    {
      default:
        return ;

      case bms_partial:
      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        break ;
    } ;

  switch (reader->msg_in_state)
    {
      case bms_in_hand:
        bgp_msg_read_take_from_in_hand(msg_body, reader, bms_in_other) ;
        break ;

      case bms_in_temp:
      case bms_in_other:
        bgp_msg_read_take_to_body(msg_body, reader, bms_in_other) ;
        break ;

      default:
        qassert(false) ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Take the current message body into the reader's temporary buffer.
 *
 * Do nothing if not bms_partial or bms_complete_xxx.
 *
 * Also do nothing if already in the temp_buff.
 *
 * Will move as much of the message as has arrived to the given buffer, and
 * (if necessary) set things up so that I/O will read the balance directly into
 * that buffer.
 */
extern void
bgp_msg_read_take_to_temp(bgp_msg_reader reader)
{
  ptr_t msg_body ;

  switch (reader->msg_state)
    {
      default:
        return ;

      case bms_partial:
      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        break ;
    } ;

  switch (reader->msg_in_state)
    {
      case bms_in_hand:
        msg_body = bgp_msg_read_get_temp(reader, reader->msg_body_length) ;
        bgp_msg_read_take_from_in_hand(msg_body, reader, bms_in_temp) ;
        break ;

      case bms_in_temp:
        break ;

      case bms_in_other:
        msg_body = bgp_msg_read_get_temp(reader, reader->msg_body_length) ;
        bgp_msg_read_take_to_body(msg_body, reader, bms_in_temp) ;
        break ;

      default:
        qassert(false) ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Take the current message body into the given msg_body buffer and set same.
 *
 * MUST be bms_in_hand and bms_partial or bms_complete_xx !!
 *
 * Will move as much of the message as has arrived to the given buffer, and
 * (if necessary) leave things up so that I/O will read the balance directly
 * into that buffer -- not into the reader->buffer.
 *
 * NB: iff the reader->msg_body_length is zero, then the msg_body may be NULL !
 */
static void
bgp_msg_read_take_from_in_hand(ptr_t msg_body, bgp_msg_reader reader,
                                               bgp_msg_in_state_t msg_in_state)
{
  ptr_t sp ;
  uint  have, take, take_1, take_2 ;

  qassert(reader->msg_in_state == bms_in_hand) ;
  qassert(reader->msg_body     == NULL) ;

  switch (reader->msg_state)
    {
      case bms_partial:
        qassert(reader->msg_awaited != 0) ;
        break ;

      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        qassert(reader->msg_awaited == 0) ;
        break ;

      default:
        qassert(false) ;
        return ;
    } ;

  /* Take what we can from the current sp downwards.
   *
   * If that that wrap around the end of the buffer, do that in two takes.
   */
  take = reader->msg_body_length - reader->msg_awaited ;
  qassert(reader->in_hand  >= take) ;

  if (take != 0)
    {
      qassert(msg_body != NULL) ;
      qassert( (reader->buffer <= reader->sp) &&
                                 (reader->sp < reader->limit) ) ;

      sp   = reader->sp ;
      have = reader->limit - sp ;   /* expect > 0, cope with 0      */

      if      (have >= take)
        {
          take_1 = take ;           /* all in one go                */
          take_2 = 0 ;
        }
      else
        {
          take_1 = have ;
          take_2 = take - have ;
        } ;

      if (take_1 != 0)              /* in case have == 0 !          */
        memcpy(msg_body, sp, take_1) ;

      if (take_2 == 0)
        {
          sp += take_1 ;
          if (sp == reader->limit)
            sp = reader->buffer ;
        }
      else
        {
          sp = reader->buffer ;
          memcpy(msg_body + take_1, sp, take_2) ;
          sp += take_2 ;
        } ;

      reader->sp       = sp ;
      reader->in_hand -= take ;
    } ;

  reader->msg_in_state = msg_in_state ;
  reader->msg_body     = msg_body ;
} ;

/*------------------------------------------------------------------------------
 * Take the current message body from the current msg_body buffer to another.
 *
 * MUST be bms_in_hand and bms_partial or bms_complete_xx !!
 *
 * Will move as much of the message as has arrived to the given buffer, and
 * (if necessary) leave things up so that I/O will read the balance directly
 * into that buffer -- not into the reader->buffer.
 *
 * NB: iff the reader->msg_body_length is zero, then the msg_body may be NULL !
 */
static void
bgp_msg_read_take_to_body(ptr_t msg_body, bgp_msg_reader reader,
                                               bgp_msg_in_state_t msg_in_state)
{
  uint take ;

  qassert(reader->msg_in_state != bms_in_hand) ;
  qassert((reader->msg_body     != NULL) || (reader->msg_body_length == 0)) ;

  switch (reader->msg_state)
    {
      case bms_partial:
        qassert(reader->msg_awaited != 0) ;
        break ;

      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        qassert(reader->msg_awaited == 0) ;
        break ;

      default:
        qassert(false) ;
        return ;
    } ;

  /* Take what we can from the current sp downwards.
   *
   * If that that wrap around the end of the buffer, do that in two takes.
   */
  take = reader->msg_body_length - reader->msg_awaited ;

  if (take != 0)
    memcpy(msg_body, reader->msg_body, take) ;

  reader->msg_in_state = msg_in_state ;
  reader->msg_body     = msg_body ;
} ;

/*------------------------------------------------------------------------------
 * Done with the current message in the reader -- if any.
 *
 * If have a complete message, drops down to bms_await_header and clears down
 * other state.
 *
 * If have a partial message, discard what we have, and set to skip the
 * rest, dropping down to bms_await_header and clearing other state.
 */
extern void
bgp_msg_read_done(bgp_msg_reader reader)
{
  uint msg_awaited ;

  switch (reader->msg_state)
    {
      /* If we are waiting for a new header, we are already done with previous
       * message.
       */
      case bms_await_header:
        qassert(reader->msg_in_state == bms_in_hand) ;
        qassert(reader->msg_body     == NULL) ;
        return ;

      /* We have a partial message somewhere.
       *
       * Discard what we know about the partial message and arrange to skip
       * the rest.
       */
      case bms_partial:
        qassert(reader->msg_awaited != 0) ;

        msg_awaited = reader->msg_awaited ;
        break ;

      /* In these states we have a complete message, so we now discard what
       * we knew about it here.
       */
      case bms_complete:
      case bms_complete_too_short:
      case bms_complete_too_long:
        qassert(reader->msg_awaited == 0) ;

        msg_awaited = 0 ;
        break ;

      /* These states are all bad, but we are already done with any previous
       * message.
       */
      default:
        qassert(false) ;
        fall_through ;

      case bms_fail_eof:
      case bms_fail_io:
      case bms_fail_bad_length:
      case bms_fail_bad_marker:
        return ;
    } ;

  /* If we get here, we have:
   *
   *   bms_partial       -- skip == msg_awaited
   *   bms_complete_xxx  -- skip == 0
   *
   * If we have stuff bms_in_hand, then need to discard that, now.
   */
  if (reader->msg_in_state != bms_in_hand)
    {
      /* The partial or complete message is not in the main read buffer,
       * so we can simple forget the message.
       */
      reader->msg_in_state = bms_in_hand ;
      reader->msg_body     = NULL ;
    }
  else
    {
      /* The partial or complete message is in the reader buffer, so we need
       * now to discard that.
       */
      uint step ;

      qassert(reader->msg_body_length <= msg_awaited) ;

      step = reader->msg_body_length - msg_awaited ;
      qassert(step <= reader->in_hand) ;

      reader->sp += step ;
      if (reader->sp >= reader->limit)
        reader->sp = reader->buffer + (reader->sp - reader->limit) ;

      reader->in_hand -= step ;
    } ;

  /* Can now set bms_await_header, complete with any msg_skip that may be
   * required.
   */
  reader->msg_state    = bms_await_header ;
  reader->msg_awaited  = 0 ;
  reader->msg_skip     = msg_awaited ;

  if (msg_awaited != 0)
    qassert(reader->in_hand == 0) ;

  /* So now update the state, because may have enough in-hand to read the next
   * header or, indeed the next complete message.  It is possible than now
   * is the time to discover read errors !
   */
  bgp_msg_read_update_state(reader) ;
} ;

/*------------------------------------------------------------------------------
 * Logging message exactly as read.
 */
extern void
bgp_msg_read_log(bgp_msg_reader reader)
{
  ptr_t   msg_body ;
  uint    type ;
  uint    length ;

  type     = reader->msg_bgp_type ;
  length   = reader->msg_body_length + BGP_MSG_HEAD_L ;
  msg_body = reader->msg_body ;

  if ((type == BGP_MT_UPDATE) && (msg_body != NULL))
    {
      uint wl, al, nl, p ;

      p  = 0 ;
      wl = load_ns(msg_body + p) ;
      p += 2 + wl ;
      al = load_ns(msg_body + p) ;
      p += 2 + al ;
      nl = (length - BGP_MSG_HEAD_L) - p ;

      plog_debug(reader->plox->log,
             "%s [IO] received UPDATE %u bytes: %u bytes withdraw, "
                                     "%u bytes attributes, %u bytes NLRI",
                                     reader->plox->host, length, wl, al, nl) ;
    }
  else
    {
      plog_debug(reader->plox->log, "%s [IO] received %s %u bytes",
       reader->plox->host, map_direct(bgp_message_type_map, type).str, length) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the address of the marker bytes in the current bad header
 */
static ptr_t
bgp_msg_read_get_bad_marker(bgp_msg_reader reader)
{
  qassert(reader->msg_state == bms_fail_bad_marker) ;

  return &reader->msg_header[BGP_MH_MARKER] ;
} ;

/*------------------------------------------------------------------------------
 * Get the length field from the current bad header
 */
static uint
bgp_msg_read_get_bad_length(bgp_msg_reader reader)
{
  qassert(reader->msg_state == bms_fail_bad_length) ;

  return load_ns(&reader->msg_header[BGP_MH_LENGTH]) ;
} ;

/*------------------------------------------------------------------------------
 * Log bgp_msg_reader failure and construct suitable notification.
 *
 * Logs eof and io failures, but does not create a notification (!)
 *
 * For bms_in_hand, bms_partial and bms_complete: assumes the problem is that
 * the message type is either unknown or not supported.
 *
 * Does nothing for bms_await_header.
 *
 * Returns:  notification
 *       or: NULL => no failure
 */
extern bgp_note
bgp_msg_read_bad(bgp_msg_reader reader, qfile qf)
{
  bgp_note    note ;
  const char* log_msg ;
  uint length ;
  qfb_gen_t  QFB_QFS(qfb, qfs) ;

  note = NULL ;

  /* Deal with incomplete message and errors.
   */
  switch (reader->msg_state)
    {
      /* Cannot have a bad message if have no header.
       */
      case bms_await_header:
        break ;

      /* If presented, will log EOF and other I/O issues
       */
      case bms_fail_eof:
      case bms_fail_io:
        bgp_msg_read_failed(reader, qf) ;
        break ;

      /* If presented, we do not treat bms_fail_down as an error... the
       * reader is in this state because the writer "owns" the error, since
       * it got there first.
       */
      case bms_fail_down:
        break ;

      /* We don't have an explicit error -- so this must be an unknown or
       * unsupported message type.
       */
      case bms_partial:
      case bms_complete:
        note = bgp_msg_read_bad_type(reader) ;
        break ;

      /* The message header "marker" bytes are invalid
       */
      case bms_fail_bad_marker:
        confirm((BGP_MH_MARKER_L * 3) < sizeof(qfb.str)) ;
        qfs_put_n_hex(qfs, bgp_msg_read_get_bad_marker(reader), BGP_MH_MARKER_L,
                                                             pf_uc | pf_space) ;
        qfs_term(qfs) ;

        plog_warn(reader->plox->log, "%s bad message marker: %s",
                                                  reader->plox->host, qfb.str) ;

        note = bgp_note_new(BGP_NOMC_HEADER, BGP_NOMS_H_NOT_SYNC) ;
        break ;

      /* The message header message length is completely invalid, or the
       * message is too short for the given (known) type.
       */
      case bms_fail_bad_length:
      case bms_complete_too_long:
      case bms_complete_too_short:
        switch (reader->msg_state)
          {
            case bms_fail_bad_length:
            default:
              log_msg = "%s bad message length: %u (type %s)" ;
              length  = bgp_msg_read_get_bad_length(reader) ;
              break ;

            case bms_complete_too_long:
              log_msg = "%s message length %u too long for %s message" ;
              length  = reader->msg_body_length + BGP_MSG_HEAD_L ;
              break ;

            case bms_complete_too_short:
              log_msg = "%s message length %u too long for %s message" ;
              length  = reader->msg_body_length + BGP_MSG_HEAD_L ;
              break ;
          } ;
        plog_warn(reader->plox->log, log_msg, reader->plox->host, length,
                   map_direct(bgp_message_type_map, reader->msg_bgp_type).str) ;
        note = bgp_note_append_w(
                            bgp_note_new(BGP_NOMC_HEADER, BGP_NOMS_H_BAD_LEN),
                                                                       length) ;
        break ;

      /* Any other state is a mistake.
       */
      default:
        qassert(false) ;

        note = bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
        break ;
    } ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * The message type is either unknown, or not enabled by capability exchange.
 *
 * Log the issue, and generate suitable notification.
 *
 * Returns:  notification
 */
extern bgp_note
bgp_msg_read_bad_type(bgp_msg_reader reader)
{
  if (reader->msg_qtype == qBGP_MSG_unknown)
    plog_warn(reader->plox->log, "%s unknown message type 0x%02x",
                                     reader->plox->host, reader->msg_bgp_type) ;
  else
    plog_err (reader->plox->log, "%s [Error] BGP %s message is not enabled",
              reader->plox->host,
                   map_direct(bgp_message_type_map, reader->msg_bgp_type).str) ;

  return bgp_note_append_b(bgp_note_new(BGP_NOMC_HEADER, BGP_NOMS_H_BAD_TYPE),
                                                         reader->msg_bgp_type) ;
} ;

/*------------------------------------------------------------------------------
 * Have some sort of I/O error or EOF -- classify and log, as required.
 *
 * Returns:  required fsm_event type.
 */
extern bgp_fsm_event_t
bgp_msg_read_failed(bgp_msg_reader reader, qfile qf)
{
  return bgp_fsm_io_failed(reader->plox, qfile_fd_get(qf), qfile_err_get(qf),
                                                                       "read") ;
} ;

/*==============================================================================
 * Parsing simple message types
 */

/*------------------------------------------------------------------------------
 * BGP NOTIFICATION message parser
 */
extern bgp_note
bgp_msg_notify_parse(bgp_connection connection, bgp_msg_reader reader)
{
  bgp_note          note ;
  bgp_nom_code_t    code ;
  bgp_nom_subcode_t subcode ;
  sucker_t          sr[1] ;

  /* OK.  Process the NOTIFICATION.
   */
  if (connection->session != NULL)
  qa_add_to_uint(&connection->session->stats.notify_in, 1) ;

  suck_init(sr, reader->msg_body, reader->msg_body_length) ;

  code    = suck_b(sr) ;
  subcode = suck_b(sr) ;

  note = bgp_note_new_with_data(code, subcode, sr->ptr, suck_left(sr)) ;
  note->received = true ;

#if 0   // TODO need to move logging elsewhere
  bgp_notify_print(session->peer, note) ; XXX ;  /* Logging */
#endif

  return note ;
} ;

/*==============================================================================
 * BGP OPEN message
 */
static bgp_note bgp_msg_open_option_parse(bgp_open_state open_recv,
                                       sucker sr, bgp_connection_logging plox) ;
static bgp_note bgp_msg_capability_option_parse(bgp_open_state open_recv,
                                       sucker sr, bgp_connection_logging plox) ;
static bgp_note bgp_msg_open_error(bgp_nom_subcode_t subcode) ;
static bgp_note bgp_msg_open_bad_as(as_t asn, bool as4) ;

/*------------------------------------------------------------------------------
 * Parse the given BGP OPEN message into the connection's open_recv.
 *
 * NB: this can be done whatever the state of the connection.
 *
 *     We expect this while is fsOpenSent (or fsConnect/fsActive), but if rolls
 *     up at any other time, will complete the parsing into
 *     connection->open_recv and leaves it up to the FSM to deal with the
 *     result.
 *
 * NB: does two checks which use information set in the connection when it
 *     was created.
 *
 * Returns:  NULL <=> OK
 *       or: NOTIFICATION message to reject the OPEN.
 */
extern bgp_note
bgp_msg_open_parse(bgp_connection connection, bgp_msg_reader reader)
{
  bgp_open_state     open_recv ;
  bgp_session_args   args_recv ;        /* pointer into open_recv       */
  bgp_session_args_c args_config ;      /* pointer from session         */
  bgp_note           reject ;
  bgp_connection_logging plox ;
  sucker_t    sr[1] ;
  u_char      version;
  u_char      optlen;

  /* Parse fixed part of the open packet
   */
  qassert(reader->msg_body        != NULL) ;
  qassert(reader->msg_body_length >= (BGP_OPM_MIN_L - BGP_MSG_HEAD_L)) ;

#if 0
  /* If we don't have a session, get out now.
   */
  session = connection->session ;
  if (session == NULL)
    return ;

  /* Accept and count the OPEN -- may reject later on, though.
   */
  qa_add_to_uint(&session->stats.open_in, 1) ;
#endif

  /* Start with no notification, an empty open_recv and an empty set of result
   * session arguments.
   */
  plox = reader->plox ;

  reject    = NULL ;

  open_recv = connection->open_recv
                              = bgp_open_state_init_new(connection->open_recv) ;
  args_recv = connection->open_recv->args ;

  args_config = connection->session->args_config ;

  /* Parse fixed part of the open packet
   */
  suck_init(sr, reader->msg_body, reader->msg_body_length) ;

  version = suck_b(sr) ;
  args_recv->remote_as =
         open_recv->my_as2 = suck_w(sr) ;
  args_recv->holdtime_secs = suck_w(sr) ;
  args_recv->remote_id     = suck_ipv4(sr) ;

  optlen = suck_b(sr) ;

  qassert(suck_check_read(sr, BGP_OPM_MIN_L - BGP_MSG_HEAD_L)
                                                && suck_overrun_check(sr)) ;

  /* Receive OPEN message log
   */
  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (plox->log,
         "%s rcv OPEN, version %d, remote-as (in open) %u, holdtime %d, id %s",
                plox->host, version,
                   args_recv->remote_as, args_recv->holdtime_secs,
                                  siptoa(AF_INET, &args_recv->remote_id ).str) ;

  /* Peer BGP version check.
   */
  if (version != BGP_VERSION_4)
    {
      if (BGP_DEBUG (normal, NORMAL))
        plog_debug(plox->log,
                 "%s bad protocol version, remote requested %d, local max %d",
                                 plox->host, version, BGP_VERSION_4) ;

      return bgp_note_append_w(bgp_msg_open_error(BGP_NOMS_O_VERSION),
                                                                BGP_VERSION_4) ;
    } ;

  /* Remote bgp_id must be valid unicast and must not be the same as here
   */
  if ( IPV4_NET0 (ntohl(args_recv->remote_id ))         ||
       IPV4_CLASS_DE (ntohl(args_recv->remote_id ))     ||
       (args_recv->remote_id  == args_config->local_id) )
    {
      plog_debug (plox->log, "%s rcv OPEN, multicast or our id %s",
                      plox->host, siptoa(AF_INET, &args_recv->remote_id ).str) ;
      return bgp_msg_open_bad_id(args_recv->remote_id ) ;
    } ;

  /* RFC4271: "...a BGP speaker MUST calculate the value of the Hold Timer by
   *           using the smaller of its configured Hold Time and the Hold Time
   *           received in the OPEN message.  The Hold Time MUST be either zero
   *           or at least three seconds.  An implementation may reject
   *           connections on the basis of the Hold Time."
   *
   * Also:    "The suggested default value for the KeepaliveTime is 1/3 of the
   *           HoldTime."
   *
   * We set the args_recv->keepalive_secs to the implied default, but we don't
   * really use this... see below.
   */
  if ((args_recv->holdtime_secs < 3) && (args_recv->holdtime_secs != 0))
    return bgp_msg_open_error(BGP_NOMS_O_H_TIME) ;

  args_recv->keepalive_secs = args_recv->holdtime_secs / 3 ;

  /* Open option part parse
   */
  if (BGP_DEBUG (normal, NORMAL))
    plog_debug(plox->log, "%s rcv OPEN w/ OPTION parameter len: %u",
                                                           plox->host, optlen) ;

  if (optlen != suck_left(sr))
    {
      plog_err(plox->log, "%s bad OPEN, message length %u but option length %u",
                  plox->host, reader->msg_body_length + BGP_MSG_HEAD_L, optlen) ;
      return bgp_msg_open_error(BGP_NOMS_UNSPECIFIC) ;
    } ;

  reject = bgp_msg_open_option_parse(open_recv, sr, plox) ;
  if (reject != NULL)
    return reject ;

  /* Now worry about the AS number
   *
   * ASN == 0 is an error !
   */
  if (args_recv->remote_as == 0)
    {
      if (args_recv->can_as4)
        {
          plog_err (plox->log, "%s [AS4] bad OPEN, got AS4 capability, "
                                               "but AS4 set to 0", plox->host) ;
          return bgp_msg_open_error(BGP_NOMS_O_BAD_AS) ;
        }
      else
        {
          if (BGP_DEBUG (as4, AS4))
            plog_debug (plox->log,
                           "%s [AS4] OPEN remote_as is 0 (not AS4 speaker)"
                                " odd, but proceeding.", plox->host) ;
        } ;
    } ;

  /* ASN = BGP_AS_TRANS is odd for AS2, error for AS4
   */
  if (args_recv->remote_as == BGP_ASN_TRANS)
    {
      if (args_recv->can_as4)
        {
          plog_err(plox->log, "%s [AS4] NEW speaker using AS_TRANS for AS4, "
                                                    "not allowed", plox->host) ;
          return bgp_msg_open_error(BGP_NOMS_O_BAD_AS) ;
        }
      else
        {
          if (BGP_DEBUG (as4, AS4))
            plog_debug (plox->log, "%s [AS4] OPEN remote_as is AS_TRANS "
                        "(not AS4 speaker) odd, but proceeding.", plox->host) ;
        } ;
    } ;

  /* For AS4 speaker: worry about my_as2, if as2 != as4
   */
  if ((args_recv->can_as4) && (args_recv->remote_as != open_recv->my_as2))
    {
      if (open_recv->my_as2 == BGP_ASN_TRANS)
        {
          if ((args_recv->remote_as <= BGP_AS2_MAX) && BGP_DEBUG(as4, AS4))
            plog_debug(plox->log, "%s [AS4] OPEN remote_as is AS_TRANS,"
                               " but AS4 (%u) fits in 2-bytes, very odd peer",
                                             plox->host, args_recv->remote_as) ;
        }
      else
        {
          plog_err(plox->log, "%s bad OPEN, got AS4 capability, "
                                     "but remote_as %u != 'my asn' %u in open",
                          plox->host, args_recv->remote_as, open_recv->my_as2) ;

          return bgp_msg_open_bad_as(args_recv->remote_as, true) ;
        } ;
    } ;

  /* Finally -- require the AS to be the configured AS
   */
  if (args_recv->remote_as != args_config->remote_as)
    {
      if (BGP_DEBUG (normal, NORMAL))
        plog_debug (plox->log, "%s bad OPEN, remote AS is %u, expected %u",
                    plox->host, args_recv->remote_as, args_config->remote_as) ;

      return bgp_msg_open_bad_as(args_recv->remote_as, args_recv->can_as4) ;
    } ;

  /* Success !
   */
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Create notification to BGP_NOMC_OPEN with the given subcode.
 *
 * Returns:  address of new notification
 */
static bgp_note
bgp_msg_open_error(bgp_nom_subcode_t subcode)
{
  return bgp_note_new(BGP_NOMC_OPEN, subcode) ;
} ;

/*------------------------------------------------------------------------------
 * Create notification to BGP_NOMC_OPEN with the given subcode.
 *
 * Returns:  address of new notification
 */
static bgp_note
bgp_msg_open_bad_as(as_t asn, bool as4)
{
  bgp_note note ;

  note = bgp_msg_open_error(BGP_NOMS_O_BAD_AS) ;

  if (as4)
    bgp_note_append_l(note, asn) ;
  else
    bgp_note_append_w(note, asn) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Create notification for BGP_NOMC_OPEN/BGP_NOMS_O_BAD_ID and set the data
 * part to be the given bad id.
 *
 * Returns:  address of new notification
 *
 * NB: the bgp_id_t is in Network Order
 */
extern bgp_note
bgp_msg_open_bad_id(bgp_id_t id)
{
  bgp_note note ;

  note = bgp_msg_open_error(BGP_NOMS_O_BAD_ID) ;
  bgp_note_append_data(note, &id, 4) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Parse OPEN message options part.
 *
 * Expects the notification to be set up: BGP_NOMC_OPEN, BGP_NOMS_UNSPECIFIC
 *                                        with no data, yet.
 *
 * Expects connection->open_recv to be in initial state, in particular:
 *
 *   * args->can_capability        -- false
 *   * args->can_mp_ext            -- false
 *   * args->can_as4               -- false
 *   * args->can_af                -- empty
 *   * args->can_rr                -- none
 *   * args->gr.can                -- false
 *   * args->gr.restarting         -- false
 *   * args->gr.restart_time       -- 0
 *   * args->gr.can_preserve       -- empty
 *   * args->gr.has_preserved      -- empty
 *   * args->can_orf               -- empty
 *   * args->can_orf_pfx           -- all 0
 *   * args->can_dynamic           -- false
 *   * args->can_dynamic_dep       -- false
 *
 * and:
 *
 *    unknowns               -- empty vector
 *    afi_safi               -- empty vector
 *
 * The above are updated to reflect any capabilities that are received.
 *
 * Returns:  NULL <=> OK
 *       or: address of notification
 */
static bgp_note
bgp_msg_open_option_parse(bgp_open_state open_recv, sucker sr,
                                                    bgp_connection_logging plox)
{
  bgp_note         note ;
  bgp_cap_afi_safi cap ;
  int  left ;
  uint i ;

  /* Prepare to read BGP OPEN message options
   */
  while ((left = suck_left(sr)) > 0)
    {
      sucker_t ssr[1] ;
      u_char opt_type ;
      u_char opt_length ;

      /* Fetch option type and length, if possible
       */
      if ((left -= 2) > 0)
        {
          opt_type   = suck_b(sr);
          opt_length = suck_b(sr);
          left -= opt_length ;
        }
      else
        {
          opt_type   = 0 ;      /* ensure initialised   */
          opt_length = 0 ;
        }

      /* Must not have exceeded available bytes
       */
      if (left < 0)
        {
          plog_warn(plox->log, "%s Option length error", plox->host) ;
          return bgp_msg_open_error(BGP_NOMS_UNSPECIFIC) ;
        }

      if (BGP_DEBUG (normal, NORMAL))
        plog_debug(plox->log,
                      "%s rcvd OPEN w/ optional parameter type %u (%s) len %u",
                         plox->host, opt_type,
                         opt_type == BGP_OPT_AUTH ? "Authentication" :
                         opt_type == BGP_OPT_CAPS ? "Capability"
                                                  : "Unknown", opt_length) ;

      suck_sub_init(ssr, sr, opt_length) ;

      switch (opt_type)
        {
        case BGP_OPT_AUTH:
          return bgp_msg_open_error(BGP_NOMS_O_AUTH) ;

        case BGP_OPT_CAPS:
          open_recv->args->can_capability = true ;       /* did => can   */

          note = bgp_msg_capability_option_parse(open_recv, ssr, plox) ;
          if (note != NULL)
            return note ;

          qassert(suck_check_complete(ssr)) ;

          break;

        default:
          return bgp_msg_open_error(BGP_NOMS_O_OPTION) ;
        } ;
    } ;

  /* All OPEN options have been parsed, so all Capabilities have been parsed.
   *
   * First, if we received no MP_EXT capabilities at all, then we assume that
   * IPv4 Unicast is supported.
   *
   * NB: this is done here so that if there are any other afi/safi related
   *     settings for IPv4 Unicast, then they will be accepted.
   *
   *     Also arranges for open_recv->can_af to be IPc4 Unicast.
   */
  if (!open_recv->args->can_mp_ext)
    {
      iAFI_SAFI_t mp[1] ;

      mp->i_afi  = iAFI_IP ;
      mp->i_safi = iSAFI_Unicast ;

      cap = bgp_open_state_afi_safi_find(open_recv, mp) ;

      cap->mp_ext.seen = true ;         /* Not quite, but near enough   */
    } ;

  /* Now, work through all the afi/safi related stuff, and:
   *
   *   * discard anything for which we don't have cap->mp_ext.seen !
   *
   *   * collect open_recv->can_af for all afi/safi we know.
   *
   *   * collect can_preserve and has_preserved for all afi/safi we know.
   *
   *   * collect  can_orf_pfx for all afi/safi we know.
   *
   *     NB: when reading the capabilities, we preferred the RFC capability
   *         setting over the pre-RFC one.
   *
   *         Here we also prefer the RFC Prefix ORF type.  If the sender
   *         declares both RFC and pre-RFC we don't care if the modes for the
   *         two don't match, we just take the RFC one !
   */
  i = 0 ;
  while (1)
    {
      cap = bgp_open_state_afi_safi_cap(open_recv, i) ;

      if (cap->mp_ext.seen)
        {
          /* We accept afi/safi settings only for those afi/safi which the
           * far end has included in MP EXT capabilities (or of none, then
           * implicitly for IPv4 Unicast -- as arranged above).
           */
          if ((cap->qafx >= qafx_first) && (cap->qafx <= qafx_last))
            {
              qafx_bit_t          qb ;

              qb = qafx_bit(cap->qafx) ;

              /* Collect the afi/safi capability,
               *                      includes implied IPv4 Unicast if required.
               */
              open_recv->args->can_af |= qb ;

              /* Collect Graceful Restart ability to preserve forwarding state
               * for the afi/safi and whether actually has done so this time.
               */
              if (cap->gr.seen)
                {
                  open_recv->args->gr.can_preserve |= qb ;

                  if (cap->gr.has_preserved)
                    open_recv->args->gr.has_preserved |= qb ;
                } ;

              /* Collect Prefix ORF state, if any.
               */

              if (cap->orf.count != 0)
                {
                  bgp_cap_orf_mode pfx ;
                  bgp_form_t  form ;
                  uint8_t     mode ;

                  /* If we have RFC Prefix ORF type we use it, otherwise if
                   * we have pre-RFC ORF type, we use that.
                   */
                  pfx = &cap->orf.types[BGP_CAP_ORFT_T_PFX] ;
                  if (pfx->form != bgp_form_none)
                    {
                      form = bgp_form_rfc ;
                      mode = pfx->mode ;
                    }
                  else
                    {
                      pfx = &cap->orf.types[BGP_CAP_ORFT_T_PFX_pre] ;
                      if (pfx->form != bgp_form_none)
                        {
                          form = bgp_form_pre ;
                          mode = pfx->mode ;
                        }
                      else
                        {
                          form = bgp_form_none ;
                          mode = 0 ;

                          confirm(BGP_CAP_ORFT_M_FIRST > 0) ;
                        } ;
                    } ;

                  /* We now have:
                   *
                   *   form: bgp_form_rfc or bgp_form_pre or bgp_form_none.
                   *   mode: the mode received for the chosen type, or 0
                   *                                       if there is no type.
                   */
                  if ( (mode >= BGP_CAP_ORFT_M_FIRST) &&
                       (mode <= BGP_CAP_ORFT_M_LAST) )
                    {
                      bgp_orf_cap_bits_t orf ;

                      orf = 0 ;

                      if (mode & BGP_CAP_ORFT_M_SEND)
                        {
                          if (form == bgp_form_rfc)
                            orf |= ORF_SM ;
                          else
                            orf |= ORF_SM_pre ;
                        } ;

                      if (mode & BGP_CAP_ORFT_M_RECV)
                        {
                          if (form == bgp_form_rfc)
                            orf |= ORF_RM ;
                          else
                            orf |= ORF_RM_pre ;
                        } ;

                      open_recv->args->can_orf_pfx[cap->qafx] = orf;
                    } ;
                } ;
            } ;

          ++i ;
        }
      else
        {
          if (cap->orf.count != 0)
            {
              plog_info(plox->log, "%s dropped ORF capability(ies) for "
                                            "AFI/SAFI %u/%u-- not in MP_EXT",
                                    plox->host, cap->mp.i_afi, cap->mp.i_safi) ;
            } ;

          if (cap->gr.seen)
            {
              plog_info(plox->log, "%s dropped Graceful Restart state for "
                                            "AFI/SAFI %u/%u -- not in MP_EXT",
                                    plox->host, cap->mp.i_afi, cap->mp.i_safi) ;
            } ;

          bgp_open_state_afi_safi_drop(open_recv, i) ;
        } ;
    } ;

  if (!open_recv->args->can_mp_ext)
    qassert(open_recv->args->can_af == qafx_ipv4_unicast_bit) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * From IANA "Capability Codes (last updated 2009-08-04) Reference: [RFC5492]"
 *
 *   Range      Registration Procedures
 *   ---------  --------------------------
 *     1- 63    IETF Review
 *    64-127    First Come First Served
 *   128-255    Reserved for Private Use    (IANA does not assign)
 *
 *    1  Multiprotocol Extensions for BGP-4                     [RFC2858]
 *    2  Route Refresh Capability for BGP-4                     [RFC2918]
 *    3  Outbound Route Filtering Capability                    [RFC5291]
 *    4  Multiple routes to a destination capability            [RFC3107]
 *    5  Extended Next Hop Encoding                             [RFC5549]
 *   64  Graceful Restart Capability                            [RFC4724]
 *   65  Support for 4-octet AS number capability               [RFC4893]
 *   66  Deprecated (2003-03-06)
 *   67  Support for Dynamic Capability (capability specific)      [Chen]
 *   68  Multisession BGP Capability                            [Appanna]
 *   69  ADD-PATH Capability                   [draft-ietf-idr-add-paths]
 *
 * 66 is, in fact, for draft-ietf-idr-dynamic-cap-02 of the Support for
 *                                      Dynamic Capability (capability specific)
 *
 * Supported:
 *
 *    1  BGP_CAN_MP_EXT           -- Multiprotocol Extensions
 *    2  BGP_CAN_R_REFRESH        -- Route Refresh
 *    3  BGP_CAN_ORF              -- Outbound Route Filtering
 *   64  BGP_CAN_G_RESTART        -- Graceful Restart
 *   65  BGP_CAN_AS4              -- AS4
 *   66  BGP_CAN_DYNAMIC_CAP_dep  -- Dynamic Capability (old form)
 *  128  BGP_CAN_R_REFRESH_pre    -- pre-RFC Route Refresh
 *  130  BGP_CAN_ORF_pre          -- pre-RFC Outbound Route Filtering
 */

/* Minimum sizes for length field of each cap (so not inc. the header)
 */
static const unsigned cap_minsizes[] =
{
  [BGP_CAN_MP_EXT]          = BGP_CAP_MPE_L,
  [BGP_CAN_R_REFRESH]       = BGP_CAP_RRF_L,
  [BGP_CAN_ORF]             = BGP_CAP_ORFE_MIN_L,       /* at least 1   */
  [BGP_CAN_G_RESTART]       = BGP_CAP_GR_MIN_L,
  [BGP_CAN_AS4]             = BGP_CAP_AS4_L,
  [BGP_CAN_DYNAMIC_CAP_dep] = BGP_CAP_DYN_L,
  [BGP_CAN_DYNAMIC_CAP]     = BGP_CAP_DYN_L,
  [BGP_CAN_R_REFRESH_pre]   = BGP_CAP_RRF_L,
  [BGP_CAN_ORF_pre]         = BGP_CAP_ORFE_MIN_L,       /* at least 1   */
} ;

static const unsigned cap_maxsizes[] =
{
  [BGP_CAN_MP_EXT]          = BGP_CAP_MPE_L,
  [BGP_CAN_R_REFRESH]       = BGP_CAP_RRF_L,
  [BGP_CAN_ORF]             = BGP_CAP_MAX_L,            /* variable      */
  [BGP_CAN_G_RESTART]       = BGP_CAP_MAX_L,            /* variable      */
  [BGP_CAN_AS4]             = BGP_CAP_AS4_L,
  [BGP_CAN_DYNAMIC_CAP_dep] = BGP_CAP_DYN_L,
  [BGP_CAN_DYNAMIC_CAP]     = BGP_CAP_MAX_L,            /* variable      */
  [BGP_CAN_R_REFRESH_pre]   = BGP_CAP_RRF_L,
  [BGP_CAN_ORF_pre]         = BGP_CAP_MAX_L,            /* variable      */
} ;

typedef enum cap_ret cap_ret_t ;
enum cap_ret
{
  cap_ret_ok       = 0,
  cap_ret_unknown,
  cap_ret_invalid,
} ;

/* Functions
 */
static cap_ret_t bgp_msg_capability_mp(bgp_open_state open_recv,
                                       sucker sr, bgp_connection_logging plox) ;
static cap_ret_t bgp_msg_capability_orf(bgp_open_state open_recv,
                      bgp_form_t form, sucker sr, bgp_connection_logging plox) ;
static cap_ret_t bgp_msg_capability_gr(bgp_open_state open_recv,
                                       sucker sr, bgp_connection_logging plox) ;
static cap_ret_t bgp_msg_capability_as4(bgp_open_state open_recv,
                                       sucker sr, bgp_connection_logging plox) ;

/*------------------------------------------------------------------------------
 * Set notification to malformed/invalid.
 *
 * Returns:  false
 */
static bgp_note
bgp_msg_capability_bad(void)
{
  return bgp_note_new(BGP_NOMC_OPEN, BGP_NOMS_UNSPECIFIC) ;
} ;

/*------------------------------------------------------------------------------
 * Parse given capability option -- may contain multiple capabilities.
 *
 * Adjusts the open_recv according to the capabilities seen.
 *
 * If an invalid or malformed capability is found, the notification is set
 * BGP_NOMS_UNSPECIFIC -- see bgp_msg_capability_bad() above.
 *
 * Returns:  NULL <=> OK
 *       or: address of notification
 */
static bgp_note
bgp_msg_capability_option_parse(bgp_open_state open_recv,
                                         sucker sr, bgp_connection_logging plox)
{
  int   left ;

  while ((left = suck_left(sr)) > 0)
    {
      cap_ret_t ret ;
      sucker_t  ssr[1] ;
      uint      cap_code ;
      uint      cap_length ;

      /* We need at least capability code and capability length.
       */
      if (left < 2)
        {
          plog_warn(plox->log,
                          "%s Capability length error %u bytes for red tape",
                                                            plox->host, left) ;
          return bgp_msg_capability_bad() ;
        } ;

      cap_code   = suck_b(sr);
      cap_length = suck_b(sr);

      if ((uint)left < (2 + cap_length))
        {
          plog_warn(plox->log,
                         "%s Capability length error: expect %u, have %u",
                                             plox->host, cap_length, left - 2) ;
          return bgp_msg_capability_bad() ;
        } ;

      /* So... we know that the cap_length is within the current capability
       * option.
       */
      if (BGP_DEBUG (normal, NORMAL))
        plog_debug (plox->log,
                       "%s OPEN has %s capability (%u), length %u",
                           plox->host,
                               map_direct(bgp_capcode_name_map, cap_code).str,
                                                         cap_code, cap_length) ;

      /* Length sanity check, type-specific, for known capabilities
       */
      switch (cap_code)
        {
          case BGP_CAN_MP_EXT:
          case BGP_CAN_R_REFRESH:
          case BGP_CAN_ORF:
          case BGP_CAN_G_RESTART:
          case BGP_CAN_AS4:
          case BGP_CAN_DYNAMIC_CAP_dep:
          case BGP_CAN_DYNAMIC_CAP:
          case BGP_CAN_R_REFRESH_pre:
          case BGP_CAN_ORF_pre:
              /* Check length.
               */
              if ( (cap_length < cap_minsizes[cap_code]) ||
                   (cap_length > cap_maxsizes[cap_code]) )
                {
                  const char* tag ;

                  if (cap_minsizes[cap_code] != cap_maxsizes[cap_code])
                    tag = "at least " ;
                  else
                    tag = "" ;

                  plog_warn(plox->log,
                      "%s %s Capability length error: got %u, expected %s%u",
                         plox->host,
                             map_direct(bgp_capcode_name_map, cap_code).str,
                               cap_length, tag, (uint) cap_minsizes[cap_code]) ;

                  return bgp_msg_capability_bad() ;     /* invalid: stop dead */
                } ;
              break ;

          /* we deliberately ignore unknown codes, see below
           */
          default:
            break ;
        } ;

      /* By this point the capability length is exactly right for the
       * fixed length capabilities, and is at least the minimum length for
       * the rest.
       *
       * Also, the capability length fits within the capability option.
       */
      suck_sub_init(ssr, sr, cap_length) ;

      ret = cap_ret_ok ;
      switch (cap_code)
        {
          case BGP_CAN_MP_EXT:
            open_recv->args->can_mp_ext = true ;

            ret = bgp_msg_capability_mp(open_recv, ssr, plox) ;
            break;

          case BGP_CAN_R_REFRESH:
            open_recv->args->can_rr |= bgp_form_rfc ;
            break ;

          case BGP_CAN_R_REFRESH_pre:
            open_recv->args->can_rr |= bgp_form_pre ;
            break;

          case BGP_CAN_ORF:
            ret = bgp_msg_capability_orf(open_recv, bgp_form_rfc, ssr, plox) ;
            break ;

          case BGP_CAN_ORF_pre:
            ret = bgp_msg_capability_orf(open_recv, bgp_form_pre, ssr, plox) ;
            break;

          case BGP_CAN_G_RESTART:
            ret = bgp_msg_capability_gr(open_recv, ssr, plox) ;
            break;

          case BGP_CAN_DYNAMIC_CAP_dep:
            open_recv->args->can_dynamic_dep = true ;
            break;

          case BGP_CAN_DYNAMIC_CAP:
            open_recv->args->can_dynamic = true ;
            break;

          case BGP_CAN_AS4:
            ret = bgp_msg_capability_as4(open_recv, ssr, plox) ;
            break;

          default:
            if (cap_code >= 128)
              plog_debug(plox->log,
                      "%s unknown vendor specific capability %d -- ignored",
                                                         plox->host, cap_code) ;
            else
              plog_debug(plox->log,
                             "%s unknown capability %d -- ignored",
                                                         plox->host, cap_code) ;

            ret = cap_ret_unknown ;

            /* Add given unknown capability and its value
             */
            bgp_open_state_unknown_add(open_recv, cap_code,
                                             suck_start(ssr), suck_total(ssr)) ;
        } ;

      switch(ret)
        {
          case cap_ret_ok:
            qassert(suck_check_complete(ssr)) ;
            break ;

          case cap_ret_unknown:
            break ;

          case cap_ret_invalid:
          default:
            return bgp_msg_capability_bad() ;
        } ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Suck up afi, 0, safi combination and return the qafx_bit (if any)
 */
static void
bgp_msg_afi_safi(iAFI_SAFI mp, sucker sr)
{
  mp->i_afi  = suck_w(sr) ;
               suck_x(sr) ;
  mp->i_safi = suck_b(sr) ;
} ;

/*------------------------------------------------------------------------------
 * Process value of Multiprotocol Extensions -- BGP_CAN_MP_EXT -- RFC4760
 *
 * Capability is:  AFI       -- word
 *                 reserved  -- byte
 *                 SAFI      -- byte
 *
 * This is a fixed length capability, so that's been dealt with.
 *
 * Returns:  cap_ret_ok => OK
 *
 * NB: in this context "OK" includes unknown or invalid values for AFI/SAFI.
 *
 *     Also includes repeated capability for the same AFI/SAFI.
 */
static cap_ret_t
bgp_msg_capability_mp(bgp_open_state open_recv, sucker sr,
                                                    bgp_connection_logging plox)
{
  iAFI_SAFI_t mp[1] ;
  bgp_cap_afi_safi cap ;

  bgp_msg_afi_safi(mp, sr) ;

  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (plox->log,
                      "%s OPEN has MP_EXT capability for afi/safi: %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;

  cap = bgp_open_state_afi_safi_find(open_recv, mp) ;
  cap->mp_ext.seen = true ;

  /* Complain if the afi/safi is "reserved" (so nobody should send)
   * and whimper if is not known to us.
   */
  if      (cap->qafx == qafx_undef)
    {
      plog_info(plox->log,
                       "%s MP_EXT capability for reserved AFI/SAFI %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;
    }
  else if (cap->qafx == qafx_other)
    {
      plog_debug (plox->log,
                      "%s MP_EXT capability for unknown AFI/SAFI %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;
    } ;

  return cap_ret_ok ;
} ;

/*------------------------------------------------------------------------------
 * Process value of Outbound Route Filtering -- BGP_CAN_ORF -- RFC5291
 *                                         and: BGP_CAN_ORF_pre -- pre-RFC
 *
 * ORF <=> Route Refresh.
 *
 * Must have at least one ORF Entry, but may have several and each is of
 * variable length.
 *
 * Requirement for at least one entry has already been checked.
 *
 * Returns:  cap_ret_ok      => OK
 *           cap_ret_invalid => malformed -- not enough bytes for an ORF entry
 *
 * NB: in this context "OK" includes unknown or invalid values for: AFI, SAFI,
 *     type and mode.  Also includes cases where repeat entries have different
 *     modes for the same afi/safi and type -- where "info" log messages have
 *     been issued, and the later mode has replaced the earlier one or the
 *     later mode has been discarded.
 *
 * RFC5291 does not specify:
 *
 *   * how to deal with two or more instances of the capability
 *
 *   * how to deal with repeated ORF Type and Send/Receive flags, for a
 *     given AFI/SAFI.
 *
 * Nothing says what to do if have both RFC and pre-RFC capabilities, or
 * what to do if they don't match.
 *
 * Generally (RFC5492) sender is forgiven for saying the same thing more than
 * once -- so we allow any number of separate capability values to each
 * specify any number of times the same type and mode of orf for the same
 * afi/safi.
 *
 * Will issue "info" log messages about any invalid modes.
 *
 * Then, for a given type and afi/safi, if a mode exists and a new, different
 * mode rolls up, will issue an "info" log message and:
 *
 *   - an RFC mode will override any previous RFC mode or pre-RFC mode, whether
 *     the new mode is valid, or not.
 *
 *   - a pre-RFC mode will only override a previous pre-RFC mode, whether
 *     the new mode is valid, or not.
 *
 * So, if both RFC and pre-RFC capabilities arrive: if the modes for a given
 * type and afi/safi are the same, tant pis; otherwise, RFC takes precedence.
 *
 * There are two types for outbound prefix filtering, also RFC and pre-RFC.
 * We ignore that here -- we accept any and all types at this stage.
 */
static cap_ret_t bgp_msg_capability_orf_entry(bgp_open_state open_recv,
                      bgp_form_t form, sucker sr, bgp_connection_logging plox) ;

static cap_ret_t
bgp_msg_capability_orf(bgp_open_state open_recv, bgp_form_t form, sucker sr,
                                                    bgp_connection_logging plox)
{
  cap_ret_t ret ;

  open_recv->args->can_orf |= form ;

  ret = cap_ret_ok ;
  while (suck_left(sr) > 0)
    {
      ret = bgp_msg_capability_orf_entry (open_recv, form, sr, plox) ;

      if (ret != cap_ret_ok)
        break ;
    } ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Process ORF Entry:
 *
 * Entry is:  AFI                  -- word ) fixed
 *            reserved             -- byte )
 *            SAFI                 -- byte )
 *            number (may be 0)    -- byte )
 *
 *            type                 -- byte ) repeated "number"
 *            send/recv (aka mode) -- byte )
 *
 * See notes above.
 *
 * Returns:  cap_ret_ok      => OK
 *           cap_ret_invalid => malformed -- not enough bytes for the fixed
 *                                           part or the number of type/mode
 *                                           entries.
 *
 * NB: in this context "OK" includes unknown or invalid values for: AFI, SAFI,
 *     type and mode.  Also includes cases where repeat entries have different
 *     modes for the same afi/safi and type -- where "info" log messages have
 *     been issued, and the later mode has replaced the earlier one or the
 *     later mode has been discarded.
 */
static cap_ret_t
bgp_msg_capability_orf_entry(bgp_open_state open_recv, bgp_form_t form,
                                         sucker sr, bgp_connection_logging plox)
{
  iAFI_SAFI_t  mp[1] ;
  uint         number ;
  uint         length ;
  sucker_t     ssr[1] ;
  bgp_cap_afi_safi cap ;
  const char* pre ;

  qassert((form == bgp_form_rfc) || (form == bgp_form_pre)) ;
  if (form == bgp_form_rfc)
    pre = "" ;
  else
    {
      form = bgp_form_pre ;     /* make sure    */
      pre = "_pre" ;
    } ;

  if (suck_left(sr) < BGP_CAP_ORFE_MIN_L)
    {
      plog_warn(plox->log,
                   "%s ORF%s capability length error, Cap length left %u",
                                               plox->host, pre, suck_left(sr)) ;
      return cap_ret_invalid ;
    } ;

  /* ORF Entry header
   */
  bgp_msg_afi_safi(mp, sr) ;
  number = suck_b(sr) ;

  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (plox->log,
                   "%s ORF%s capability entry for afi/safi %u/%u %d types",
                               plox->host, pre, mp->i_afi, mp->i_safi, number) ;

  /* Validate number field
   */
  length = number * BGP_CAP_ORFT_L ;
  if (suck_left(sr) < (int)length)
    {
      plog_info (plox->log, "%s ORF%s capability entry for afi/safi %u/%u: "
                                 "number error, number %u but length left %u",
                plox->host, pre, mp->i_afi, mp->i_safi, number, suck_left(sr)) ;
      return cap_ret_invalid ;
    } ;

  suck_sub_init(ssr, sr, length) ;

  /* Check AFI and SAFI and get the required cap entry
   */
  cap = bgp_open_state_afi_safi_find(open_recv, mp) ;

  /* Complain if the afi/safi is "reserved" (so nobody should send)
   * and whimper if is not known to us.
   */
  if      (cap->qafx == qafx_undef)
    {
      plog_warn(plox->log, "%s ORF%s capability for reserved AFI/SAFI %u/%u",
                                       plox->host, pre, mp->i_afi, mp->i_safi) ;
    }
  else if (cap->qafx == qafx_other)
    {
      plog_debug(plox->log, "%s ORF%s capability for unknown AFI/SAFI %u/%u",
                                       plox->host, pre, mp->i_afi, mp->i_safi) ;
    } ;

  /* Process the supported ORF types
   */
  while (number--)
    {
      bool set ;

      uint8_t type = suck_b(ssr) ;
      uint8_t mode = suck_b(ssr) ;

      confirm(BGP_CAP_ORF_ORFT_T_MAX >= 255) ;
                                /* so type <= BGP_CAP_ORF_ORFT_T_MAX !  */

      /* ORF Mode error check
       */
      switch (mode)
        {
          case BGP_CAP_ORFT_M_RECV:
          case BGP_CAP_ORFT_M_SEND:
          case BGP_CAP_ORFT_M_BOTH:
            break;

          default:
            plog_warn(plox->log, "%s ORF%s capability for afi/safi %u/%u: "
                                       "invalid send/receive 'mode' value %u",
                                 plox->host, pre, mp->i_afi, mp->i_safi, mode) ;
            break ;
        } ;

      /* Now see if we have
       *
       */
      if (cap->orf.types[type].form == bgp_form_none)
        {
          /* Nothing set, so count number of orf types for which we have
           * something and prepare to set the mode -- valid or not.
           */
          cap->orf.count += 1 ;
          set = true ;
        }
      else
        {
          /* Something already set.
           *
           * Whimper if we are not setting the same thing.  Note that this
           * whimpers if BGP_CAN_ORF and BGP_CAN_ORF_pre are inconsistent
           * with each other -- even though BGP_CAN_ORF takes precedence.
           */
          set = ( (form == bgp_form_rfc) ||
                  (form == cap->orf.types[type].form) ) ;

          if (mode != cap->orf.types[type].mode)
            {
              plog_info(plox->log,
                        "%s ORF%s capability for afi/safi %u/%u: "
                           "inconsistent send/receive 'modes' value was %u, "
                                                                  "new %u %s",
                                        plox->host, pre, mp->i_afi, mp->i_safi,
                                               cap->orf.types[type].mode, mode,
                                                set ? "replaces" : "ignored") ;
            } ;
        } ;

      cap->orf.types[type].form |= form ;
      if (set)
        cap->orf.types[type].mode = mode ;
    } ;

  qassert(suck_check_complete(ssr)) ;

  return cap_ret_ok ;
} ;

/*------------------------------------------------------------------------------
 * Process value of Graceful Restart capability -- BGP_CAN_G_RESTART -- RFC4724
 *
 * Capability is:  time      -- word
 *                 AFI       -- word )
 *                 SAFI      -- byte ) repeated 0 or more times
 *                 flag      -- byte )
 *
 * This is a variable length capability, minimum size already checked.
 *
 * The sr covers from the start to the end of the capability value.
 *
 * RFC4724: "... speaker MUST NOT include more than one instance...
 *           the receiver... MUST ignore all but the last instance..."
 *
 * If a second (or subsequent) Graceful Restart Capability is received, this
 * issues a "info" log message and discards everything it ever knew about
 * the previous capability.  Note that for PEER_FLAG_STRICT_CAP_MATCH this
 * means that only the last instance is considered.
 *
 * At this stage we don't care what afi/safi are declared "can preserve" or
 * "has preserved" -- we record everything.
 *
 * Sets:
 *
 *    open_recv->can_g_restart  -- true
 *    open_recv->restarting  -- as received
 *    open_recv->restart_time   -- as received
 *    open_recv->can_preserve   -- as received, for known afi/safi
 *    open_recv->has_preserved  -- as received, for known afi/safi
 *
 * Returns:  cap_ret_ok      => OK
 *           cap_ret_invalid => malformed !
 *
 */
static cap_ret_t
bgp_msg_capability_gr(bgp_open_state open_recv,
                                         sucker sr, bgp_connection_logging plox)
{
  u_int16_t restart_flag_time ;
  int length ;

  /* Get the minimum value (the Restart Flags and Restart Time) and then check
   * that the remaining length is valid.
   */
  length = suck_left(sr) ;      /* total length of value, for reporting */

  restart_flag_time = suck_w(sr) ;

  if ((suck_left(sr) % BGP_CAP_GRE_L) != 0)
    {
      plog_warn(plox->log,
                 "%s Graceful Restart Capability length error, Cap length %u",
                                                           plox->host, length) ;
      return cap_ret_invalid ;
    } ;

  /* Issue complaint if we have already seen one of these, and purge what we
   * know about it !
   */
  if (open_recv->args->gr.can)
    {
      uint i ;

      plog_info(plox->log,
                "%s Graceful Restart Capability repeated: ignoring previous",
                                                                   plox->host) ;

      i = 0 ;
      while (1)
        {
          bgp_cap_afi_safi cap ;

          cap = bgp_open_state_afi_safi_cap(open_recv, i) ;
          if (cap == NULL)
            break ;

          cap->gr.seen           = false ;
          cap->gr.has_preserved  = false ;

          ++i ;
        } ;
    } ;

  /* Set all Graceful Restart state -- overwriting any previous.
   */
  open_recv->args->gr.can = true ;

  open_recv->args->gr.restarting   = (restart_flag_time & BGP_CAP_GR_T_R_FLAG)
                                                                          != 0 ;
  open_recv->args->gr.restart_time =  restart_flag_time & BGP_CAP_GR_T_MASK ;

  open_recv->args->gr.can_preserve  = 0 ;
  open_recv->args->gr.has_preserved = 0 ;

  if (BGP_DEBUG (normal, NORMAL))
    {
      plog_debug (plox->log,
                     "%s OPEN has Graceful Restart capability", plox->host) ;
      plog_debug (plox->log,
                     "%s Peer has%srestarted. Restart Time : %u", plox->host,
                               open_recv->args->gr.restarting ? " " : " not ",
                               open_recv->args->gr.restart_time);
    } ;

  /* Now process all the afi/safi.
   *
   * Appends each one to the collection of afi/safi related state for the
   * open_recv.
   */
  while (suck_left(sr) > 0)
    {
      iAFI_SAFI_t  mp[1] ;
      uint8_t      flags ;
      bgp_cap_afi_safi cap ;

      mp->i_afi  = suck_w(sr) ;
      mp->i_safi = suck_b(sr) ;
      flags      = suck_b(sr) ;

      cap = bgp_open_state_afi_safi_find(open_recv, mp) ;

      if (cap->gr.seen)
        {
          /* Complain about repeated afi/safi !
           */
          plog_info (plox->log,
                      "%s Graceful Restart capability repeats AFI/SAFI %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;
        }
      else
        {
          /* Complain if the afi/safi is "reserved" (so nobody should send)
           * and whimper if is not known to us.
           */
          if      (cap->qafx == qafx_undef)
            {
              plog_warn(plox->log,
                         "%s Graceful Restart capability for reserved "
                                                             "AFI/SAFI %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;
            }
          else if (cap->qafx == qafx_other)
            {
              plog_debug(plox->log,
                          "%s Graceful Restart capability for unknown "
                                                            "AFI/SAFI %u/%u",
                                            plox->host, mp->i_afi, mp->i_safi) ;
            } ;
        } ;

      /* Set the (latest) properties for the afi/safi
       */
      cap->gr.has_preserved = ((flags & BGP_CAP_GRE_F_FORW) != 0) ;
    } ;

  return cap_ret_ok ;
} ;

/*------------------------------------------------------------------------------
 * Process value of AS4 capability -- BGP_CAN_AS4 -- RFC4893
 *
 * Capability is:  ASN       -- long word (4 bytes)
 *
 * This is a fixed length capability, so that's been dealt with.
 *
 * Validation of ASN and cross-check against my_as2, done elsewhere.
 *
 * Returns:  0 => OK
 */
static cap_ret_t
bgp_msg_capability_as4 (bgp_open_state open_recv,
                                         sucker sr, bgp_connection_logging plox)
{
  open_recv->args->can_as4   = true ;
  open_recv->args->remote_as = suck_l(sr) ;

  if (BGP_DEBUG (as4, AS4))
    plog_debug (plox->log, "%s [AS4] received AS4 Capability ASN=%u",
                                       plox->host, open_recv->args->remote_as) ;
  return cap_ret_ok ;
} ;

/*==============================================================================
 * BGP ROUTE-REFRESH message parsing
 */
/*------------------------------------------------------------------------------
 * Parse BGP ROUTE-REFRESH message
 *
 * This may contain ORF stuff !
 *
 * Returns:  NULL <=> OK  -- *p_rr set to the bgp_route_refresh object
 *           otherwise = bgp_notify for suitable error message
 *                        -- *p_rr set to NULL
 *
 * NB: if the connection is not fsEstablished, then will not parse
 */
extern bgp_note
bgp_msg_route_refresh_parse(bgp_connection connection, bgp_msg_reader reader)
{
  iAFI_SAFI_t  mp[1] ;
  sucker_t     sr[1] ;
  qafx_bit_t   qb ;
  bgp_form_t   form ;

  /* If we are not established, get out now.
   */
  if (connection->fsm_state != bgp_fsEstablished)
    return NULL ;

  /* If peer does not have the capability, treat as bad message type
   */
  switch (reader->msg_qtype)
    {
      case qBGP_MSG_ROUTE_REFRESH:
        form = bgp_form_rfc ;
        break ;

      case qBGP_MSG_ROUTE_REFRESH_pre:
        form = bgp_form_pre ;
        break ;

      default:                            /* should not happen, really    */
        form = bgp_form_none ;
        break ;
    } ;

  if ((connection->session->args->can_rr & form) == bgp_form_none)
    return bgp_msg_read_bad_type(reader) ;

  qa_add_to_uint(&connection->session->stats.refresh_in, 1) ;

  /* Set about parsing the message
   */
  suck_init(sr, reader->msg_body, reader->msg_body_length) ;

  /* Check the AFI/SAFI
   */
  bgp_msg_afi_safi(mp, sr) ;

  qb = qafx_bit_from_i(mp->i_afi, mp->i_safi) ;

  qb &= qafx_ipv4_unicast_bit | qafx_ipv4_multicast_bit |
        qafx_ipv6_unicast_bit | qafx_ipv6_multicast_bit |
        qafx_ipv4_mpls_vpn_bit ;

  if ((qb & connection->session->args->can_af) == qafx_set_empty)
    {
      plog_warn (reader->plox->log,
            "%s rcvd REFRESH_REQ for %s afi/safi: %u/%u", reader->plox->host,
                  (qb == 0) ? "unknown" : "unexpected", mp->i_afi, mp->i_safi) ;

      return bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
    } ;


  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (reader->plox->log,
                        "%s rcvd REFRESH_REQ for afi/safi: %u/%u",
                                    reader->plox->host, mp->i_afi, mp->i_safi) ;

  return NULL ;
} ;

#if 0

static bool bgp_msg_orf_recv(bgp_connection connection,
                               bgp_route_refresh rr, qafx_bit_t qb, sucker sr,
                                                  bgp_connection_logging plox) ;
static bool bgp_msg_orf_prefix_recv(orf_prefix_value orfpv, bool deny,
                                                     qafx_bit_t qb, sucker sr) ;

/*------------------------------------------------------------------------------
 * Parse BGP ROUTE-REFRESH message
 *
 * This may contain ORF stuff !
 *
 * Returns:  NULL <=> OK  -- *p_rr set to the bgp_route_refresh object
 *           otherwise = bgp_notify for suitable error message
 *                        -- *p_rr set to NULL
 *
 * NB: if the connection is not fsEstablished, then will not parse
 */
extern bgp_note
bgp_msg_route_refresh_parse(bgp_route_refresh* p_rr,
                               bgp_connection connection, bgp_msg_reader reader)
{
  iAFI_SAFI_t  mp[1] ;
  sucker_t     sr[1] ;
  qafx_bit_t   qb ;
  bgp_route_refresh rr ;
  bool         ok ;
  uint         form ;

  *p_rr = NULL ;                /* default      */

  /* If we are not established or don't have a session, get out now.
   */
  if (connection->fsm_state != bgp_fsEstablished)
    return NULL ;

  /* If peer does not have the capability, treat as bad message type
   */
  switch (reader->msg_qtype)
    {
      case qBGP_MSG_ROUTE_REFRESH:
        form = bgp_form_rfc ;
        break ;

      case qBGP_MSG_ROUTE_REFRESH_pre:
        form = bgp_form_pre ;
        break ;

      default:                            /* should not happen, really    */
        form = bgp_form_none ;
        break ;
    } ;

  if ((connection->session->args->can_rr & form) == bgp_form_none)
    return bgp_msg_read_bad_type(reader) ;

  qa_add_to_uint(&connection->session->stats.refresh_in, 1) ;

  /* Set about parsing the message
   */
  suck_init(sr, reader->msg_body, reader->msg_body_length) ;

  /* Start with AFI, reserved, SAFI
   */
  bgp_msg_afi_safi(mp, sr) ;

  qb = qafx_bit_from_i(mp->i_afi, mp->i_safi) ;

  qb &= qafx_ipv4_unicast_bit | qafx_ipv4_multicast_bit |
        qafx_ipv6_unicast_bit | qafx_ipv6_multicast_bit |
        qafx_ipv4_mpls_vpn_bit ;

  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (reader->plox->log,
                        "%s rcvd REFRESH_REQ for afi/safi: %u/%u%s",
                                      reader->plox->host, mp->i_afi, mp->i_safi,
                                   (qb == 0) ? " -- unknown combination" : "") ;

  rr = bgp_route_refresh_new(mp->i_afi, mp->i_safi, 0) ;

  /* If there are any ORF entries, time to suck them up now.
   */
  ok = true ;

  if ((suck_left(sr) != 0) && ok)
    {
      uint8_t when_to_refresh ;
      bool    defer ;

      when_to_refresh = suck_b(sr) ;

      switch (when_to_refresh)
        {
          case BGP_ORF_WTR_IMMEDIATE:
            defer = false ;
            break ;

          case BGP_ORF_WTR_DEFER:
            defer = true ;
            break ;

          default:
            plog_warn(reader->plox->log,
               "%s ORF route refresh invalid 'when' value %d (AFI/SAFI %u/%u)",
                   reader->plox->host, when_to_refresh, rr->i_afi, rr->i_safi) ;
            defer = false ;
            ok    = false ;
            break ;
        } ;

      if (ok)
        {
          bgp_route_refresh_set_orf_defer(rr, defer) ;

          /* After the when to refresh, expect 1 or more ORFs           */
          do
            {
              ok = bgp_msg_orf_recv(connection, rr, qb, sr, reader->plox) ;
            } while ((suck_left(sr) != 0) && ok) ;
        } ;
    } ;

  if (!ok)
    {
      bgp_route_refresh_free(rr) ;
      return bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
    } ;

  *p_rr = rr ;
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Process ORF Type and following ORF Entries.
 *
 * Expects there to be at least one ORF entry -- that is, the length of the
 * ORF Entries may not be 0.
 *
 * Returns:  true  <=> OK
 *           false  => invalid or malformed
 */
static bool
bgp_msg_orf_recv(bgp_connection connection, bgp_route_refresh rr,
                          qafx_bit_t qb, sucker sr, bgp_connection_logging plox)
{
  bgp_session_args args ;
  sucker_t   ssr[1] ;
  int        left ;
  uint8_t    orf_type ;
  bgp_size_t orf_len ;
  bool       can ;

  /* Suck up the ORF type and the length of the entries that follow
   */
  left = suck_left(sr) - BGP_ORF_MIN_L ;
  if (left >= 0)
    {
      orf_type  = suck_b(sr) ;
      orf_len   = suck_w(sr) ;
    }
  else
    {
      orf_type  = 0 ;   /* ensure initialised   */
      orf_len   = 0 ;
    } ;

  /* The length may not be zero and may not exceed what there is left
   */
  if ((orf_len == 0) || (left < orf_len))
    {
      plog_warn(plox->log,
                  "%s ORF route refresh length error: %d when %d left"
                                       " (AFI/SAFI %d/%d, type %d length %d)",
          plox->host, orf_len, left, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
      return false ;
    } ;

  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (plox->log, "%s rcvd ORF type %d length %d",
                                                plox->host, orf_type, orf_len) ;

  /* Sex the ORF type -- accept only if negotiated it
   *
   * We assume that if both are negotiated, that we need only process the
   * RFC Type.
   *
   * Note that for the negotiated can_orf_pfx, ORF_RM is set if we have
   * received *either* Type, but ORF_RM_pre is set only if we only received
   * the pre-RFC type.
   */
  args = connection->session->args ;
  switch (orf_type)
    {
      case BGP_ORF_T_PFX:
        can = (args->can_orf_pfx[rr->qafx] & (ORF_RM | ORF_RM_pre))
                                          ==  ORF_RM ;
        break ;

      case BGP_ORF_T_PFX_pre:
        can = (args->can_orf_pfx[rr->qafx] & (ORF_RM | ORF_RM_pre))
                                          == (ORF_RM | ORF_RM_pre);
        break ;

      default:
        can = false ;
        break ;
    } ;

  /* Suck up the ORF entries.  NB: orf_len != 0
   */
  suck_sub_init(ssr, sr, orf_len) ;

  if (!can)
    bgp_orf_add_unknown(rr, orf_type, orf_len, suck_step(ssr, orf_len)) ;
  else
    {
      /* We only actually know about BGP_ORF_T_PFX and BGP_ORF_T_PFX_pre
       *
       * We store the ORF as BGP_ORF_T_PFX (the RFC version), and somewhere
       * deep in the output code we look after outputting stuff in pre-RFC
       * form, if that is required.
       */
      while (suck_left(ssr) > 0)
        {
          bool remove_all, remove ;
          uint8_t common ;

          remove_all = false ;
          remove     = false ;
          common = suck_b(ssr) ;
          switch (common & BGP_ORF_EA_MASK)
            {
              case BGP_ORF_EA_ADD:
                break ;

              case BGP_ORF_EA_REMOVE:
                remove = true ;
                break ;

              case BGP_ORF_EA_RM_ALL:
                remove_all = true ;
                break ;

              default:
                plog_warn(plox->log,
                            "%s ORF route refresh invalid common byte: %u"
                                        " (AFI/SAFI %d/%d, type %d length %d)",
                 plox->host, common, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
                return cap_ret_invalid ;
            } ;

          if (remove_all)
            bgp_orf_add_remove_all(rr, BGP_ORF_T_PFX) ;
          else
            {
              bgp_orf_entry orfe ;
              bool    deny, ok ;

              deny = (common & BGP_ORF_EA_DENY) ;

              orfe = bgp_orf_add(rr, BGP_ORF_T_PFX, remove, deny) ;

              ok  = bgp_msg_orf_prefix_recv(&orfe->body.orfpv, deny, qb, ssr) ;

              if (!ok)
                {
                  plog_info (plox->log,
                              "%s ORF route refresh invalid Prefix ORF entry"
                                       " (AFI/SAFI %d/%d, type %d length %d)",
                         plox->host, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
                  return false ;
                } ;
            } ;

        } ;
    } ;

  return suck_check_complete(ssr) ;
} ;

/*------------------------------------------------------------------------------
 * Process ORF Prefix entry, from after the common byte.
 *
 * This is for entries which are *not* remove-all
 *
 * Returns:  true  <=> OK
 *           false  => invalid or malformed
 */
static bool
bgp_msg_orf_prefix_recv(orf_prefix_value orfpv, bool deny,
                                                      qafx_bit_t qb, sucker sr)
{
  sa_family_t paf ;
  int left ;

  assert(qb != 0) ;
  paf = get_qafx_sa_family(qafx_num(qb)) ;

  /* Must have the minimum Prefix ORF entry, less the common byte, left
   */
  left = suck_left(sr) - (BGP_ORF_E_P_MIN_L - BGP_ORF_E_COM_L) ;
  if (left >= 0)
    {
      uint8_t plen ;
      uint8_t blen ;

      memset(orfpv, 0, sizeof(orf_prefix_value_t)) ;

      orfpv->seq   = suck_l(sr) ;
      orfpv->type  = deny ? PREFIX_DENY : PREFIX_PERMIT ;
      orfpv->ge    = suck_b(sr) ;       /* aka min      */
      orfpv->le    = suck_b(sr) ;       /* aka max      */
      plen         = suck_b(sr) ;

      blen = (plen + 7) / 8 ;
      if ((left -= blen) >= 0)
        {
          orfpv->pfx.family    = paf ;
          orfpv->pfx.prefixlen = plen ;
          if (blen != 0)
            {
              if (blen <= prefix_byte_len(&orfpv->pfx))
                memcpy(&orfpv->pfx.u.prefix, suck_step(sr, blen), blen) ;
              else
                left = -1 ;
            } ;
        } ;
    } ;

  return (left == 0) ;
} ;

#endif
