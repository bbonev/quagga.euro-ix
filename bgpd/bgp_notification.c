/* BGP Notification state handling
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
#include "misc.h"

#include <netinet/in.h>

#include "lib/zassert.h"
#include "lib/memory.h"

#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_names.h"

/*==============================================================================
 * A bgp_note structure encapsulates the contents of a BGP NOTIFICATION
 * message.
 */

/*==============================================================================
 * Create/Destroy bgp_note
 */
static void bgp_notify_now_need(bgp_note note, uint need) ;

/*------------------------------------------------------------------------------
 * Allocate and initialise new notification
 *
 * Can add data later if required.
 *
 * NB: returns a 'NOT received' notification.
 */
extern bgp_note
bgp_note_new(bgp_nom_code_t code, bgp_nom_subcode_t subcode)
{
  bgp_note note ;

  note = XCALLOC(MTYPE_BGP_NOTIFY, sizeof(bgp_note_t)) ;

  /* Zeroizing sets:
   *
   *   * received               -- false    -- not yet
   *
   *   * code                   -- X        -- set below
   *   * subcode                -- X        -- set below
   *
   *   * data                   -- X        -- set below
   *   * length                 -- 0        -- none, yet
   *   * size                   -- X        -- set below
   *
   *   * msg_buff               -- X        -- set below
   *
   *   * embedded               -- 0's      -- nicely cleared out
   */
  note->code     = code ;
  note->subcode  = subcode ;

  note->msg_buff = note->embedded ;
  note->data     = note->embedded   + BGP_NOM_MIN_L ;
  note->size     = bgp_notify_embedded_size - BGP_NOM_MIN_L ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Allocate and initialise new notification -- expecting some data.
 *
 * Can specify an expected amount of data -- may use more or less than this...
 * ...but pre-allocates at least the expected amount.
 *
 * May expect 0.
 *
 * NB: returns a 'NOT received' notification.
 */
extern bgp_note
bgp_note_new_need(bgp_nom_code_t code, bgp_nom_subcode_t subcode, uint need)
{
  bgp_note note ;

  note = bgp_note_new(code, subcode) ;
  bgp_notify_now_need(note, need) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Need enough space for 'need' bytes of notification data.
 *
 * Tidies up, so that everything in buffer from the given 'need' onwards is
 * zeroized -- assuming that was tidy before any new allocation.
 *
 * NB: when a notification is initialised it is set to point at the embedded
 *     buffer.
 */
static void
bgp_notify_now_need(bgp_note note, uint need)
{
  uint zero_to ;

  if (note->size >= need)
    {
      qassert(note->length <= note->size) ;
      zero_to = note->length ;
    }
  else
    {
      ptr_t msg_buff ;
      uint  full_size ;

      msg_buff  = note->msg_buff ;
      full_size = uround_up_up(need + BGP_NOM_MIN_L, 32) ;

      if (msg_buff != note->embedded)
        msg_buff = XREALLOC(MTYPE_TMP, msg_buff, full_size) ;
      else
        {
          msg_buff = XMALLOC(MTYPE_TMP, full_size) ;
          memcpy(msg_buff, note->embedded, bgp_notify_embedded_size) ;
        } ;

      note->msg_buff = msg_buff ;
      note->data     = msg_buff  + BGP_NOM_MIN_L ;
      note->size     = full_size - BGP_NOM_MIN_L ;

      zero_to = note->size ;
  } ;

  if ((need < zero_to) && (zero_to <= note->size))
    memset(note->data + need, 0, zero_to - need) ;
} ;

/*------------------------------------------------------------------------------
 * Allocate and initialise new notification, complete with data
 *
 * Can specify an expected amount of data -- copes with len == 0 (and data may
 * be NULL iff len == 0).
 *
 * NB: returns a 'NOT received' notification.
 */
extern bgp_note
bgp_note_new_with_data(bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                                     const void* data, uint len)
{
  bgp_note note ;

  note = bgp_note_new_need(code, subcode, len) ;
  bgp_note_append_data(note, data, len) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Reset notification structure (if any)
 *
 * Does nothing if there is no structure.
 */
extern bgp_note
bgp_note_reset(bgp_note note)
{
  if (note != NULL)
    {
      ptr_t     msg_buff ;
      uint      size ;

      msg_buff = note->msg_buff ;
      size     = note->size ;

      memset(note, 0, sizeof(*note)) ;

      /* Zeroizing sets:
       *
       *   * received               -- false    -- not yet
       *
       *   * code                   -- BGP_NOMC_UNDEF
       *   * subcode                -- BGP_NOMS_UNSPECIFIC
       *
       *   * data                   -- X        -- restored below
       *   * length                 -- 0        -- none, yet
       *   * size                   -- X        -- restored below
       *
       *   * msg_buff               -- X        -- restored below
       *
       *   * embedded               -- 0's      -- nicely cleared out
       */
      confirm(BGP_NOMC_UNDEF      == 0) ;
      confirm(BGP_NOMS_UNSPECIFIC == 0) ;

      if (msg_buff != note->embedded)
        memset(msg_buff, 0, size) ;

      note->msg_buff = msg_buff ;
      note->data     = msg_buff + BGP_NOM_MIN_L ;
      note->size     = size ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Free notification structure
 *
 * Does nothing if there is no structure.
 */
extern bgp_note
bgp_note_free(bgp_note note)
{
  if (note != NULL)
    {
      if (note->msg_buff != note->embedded)
        XFREE(MTYPE_BGP_NOTIFY, note->msg_buff) ;

      XFREE(MTYPE_BGP_NOTIFY, note) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Duplicate existing notification (if any)
 */
extern bgp_note
bgp_note_dup(bgp_note note)
{
  bgp_note dup ;

  if (note == NULL)
    return NULL ;

  dup = bgp_note_new_need(note->code, note->subcode, note->length) ;
  dup->received = note->received ;

  if (note->length != 0)
    {
      dup->length   = note->length ;
      memcpy(dup->data, note->data, dup->length) ;
    } ;

  return dup ;
} ;

/*------------------------------------------------------------------------------
 * Copy existing notification (if any), creating as required.
 *
 * If the src is NULL, but the dst is not, the dst is cleared and set to
 * BGP_NOMC_UNDEF/BGP_NOMS_UNSPECIFIC  (0/0).
 */
extern bgp_note
bgp_note_copy(bgp_note dst, bgp_note src)
{
  ptr_t     msg_buff ;
  uint      size, length ;

  if (dst == NULL)
    return bgp_note_dup(src) ;          /* Does nothing if src is NULL  */

  if (src == NULL)
    return bgp_note_reset(dst) ;        /* reset to BGP_NOMC_UNDEF/
                                         *          BGP_NOMS_UNSPECIFIC */

  /* Copy the src to the dst, preserving the dst msg_buff/size/data.
   */
  msg_buff      = dst->msg_buff ;       /* preserve                     */
  size          = dst->size ;
  length        = dst->length ;

  *dst          = *src ;                /* copy                         */

  dst->msg_buff = msg_buff ;            /* restore                      */
  dst->data     = msg_buff  + BGP_NOM_MIN_L ;
  dst->size     = size ;

  /* If both src and dst are embedded, then we have done everything we need
   * to do.
   *
   * Otherwise, we need to copy:
   *
   *   * from embedded to not-embedded
   *
   *   * from not-embedded to embedded or not-embedded
   *
   * In either case we sweep out the dst->embedded, because that is now a
   * copy of the src->embedded.  Then if the dst is embedded, we set its
   * length to zero, but if was not-embedded we restore its length.
   */
  if ((src->msg_buff != src->embedded) || (dst->msg_buff != dst->embedded))
    {
      memset(dst->embedded, 0, bgp_notify_embedded_size) ;
      if (dst->msg_buff == dst->embedded)
        dst->length = 0 ;
      else
        dst->length = length ;

      bgp_notify_now_need(dst, src->length) ;

      memcpy(dst->data, src->data, src->length) ;
      dst->length = src->length ;
    } ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Set new Code and Subcode and discard and data accumulated so far.
 *
 * NB: does not change the received state of the notification.
 */
extern bgp_note
bgp_note_set(bgp_note note, bgp_nom_code_t code, bgp_nom_subcode_t subcode)
{
  if (note == NULL)
    return bgp_note_new(code, subcode) ;

  bgp_note_reset(note) ;

  note->code    = code ;
  note->subcode = subcode ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Set a default Code and Subcode.
 */
extern bgp_note
bgp_note_default(bgp_note note, bgp_nom_code_t code,
                                                      bgp_nom_subcode_t subcode)
{
  if (note == NULL)
    return bgp_note_new(code, subcode) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Duplicate or Create a new default Code and Subcode.
 */
extern bgp_note
bgp_note_dup_default(bgp_note note, bgp_nom_code_t code,
                                                      bgp_nom_subcode_t subcode)
{
  if (note == NULL)
    return bgp_note_new(code, subcode) ;

  return bgp_note_dup(note) ;
} ;

/*==============================================================================
 * Appending stuff to a notification
 */

/*------------------------------------------------------------------------------
 * Prepare for new data at the end of the given notification (if any)
 *
 * Extends the length of the data part of the notification.
 *
 * Returns:  address for the new data.
 *
 * NB: does nothing if no notification, and returns NULL !
 */
extern ptr_t
bgp_note_prep_data(bgp_note note, uint want)
{
  uint length ;

  if (note == NULL)
    return NULL ;

  length = note->length ;

  bgp_notify_now_need(note, length + want) ;

  note->length = length + want ;

  return &note->data[length] ;
} ;

/*------------------------------------------------------------------------------
 * Append data to given notification (if any)
 *
 * Copes with zero length append (and data may be NULL if len == 0).
 *
 * Returns:  address of the notification -- as given or new.
 *
 * NB: if creates new, sets: BGP_NOMC_UNDEF/BGP_NOMS_UNSPECIFIC (0/0)
 *
 */
extern bgp_note
bgp_note_append_data(bgp_note note, const void* data, uint len)
{
  ptr_t p ;

  if (note == NULL)
    return bgp_note_new_with_data(BGP_NOMC_UNDEF, BGP_NOMS_UNSPECIFIC,
                                                                    data, len) ;

  p = bgp_note_prep_data(note, len) ;

  if (len > 0)
    memcpy(p, data, len) ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Append one byte to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_note
bgp_note_append_b(bgp_note note, uint8_t b)
{
  return bgp_note_append_data(note, &b, 1) ;
} ;

/*------------------------------------------------------------------------------
 * Append one word (uint16_t), in network byte order to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_note
bgp_note_append_w(bgp_note note, uint16_t w)
{
  w = htons(w) ;
  return bgp_note_append_data(note, &w, 2) ;
} ;

/*------------------------------------------------------------------------------
 * Append one long (uint32_t), in network byte order to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_note
bgp_note_append_l(bgp_note note, uint32_t l)
{
  l = htonl(l) ;
  return bgp_note_append_data(note, &l, 4) ;
} ;

/*==============================================================================
 * Other functions
 */

/*------------------------------------------------------------------------------
 * Return pointer to a NOTIFICATION message
 *
 * The message is complete with BGP Message header -- so can be written
 * directly.
 *
 * NB: the message is part of the notification object.
 *
 *     So... caller MUST NOT hold on to the pointer to the message beyond
 *     any change to the notification or after it is freed !!
 */
extern ptr_t
bgp_note_message(bgp_note note, uint* p_msg_length)
{
  uint  msg_length ;
  ptr_t msg ;

  if (note == NULL)
    {
      *p_msg_length = 0 ;
      return NULL ;
    } ;

  /* Make sure we have note->msg_buff & note->data set up.
   */
  bgp_notify_now_need(note, note->length) ;

  msg_length = bgp_note_msg_length(note) ;
  msg        = note->msg_buff ;

  memset(  &msg[BGP_MH_MARKER], 0xFF, BGP_MH_MARKER_L) ;
  store_ns(&msg[BGP_MH_LENGTH], msg_length) ;
  store_b( &msg[BGP_MH_TYPE],   BGP_MT_NOTIFICATION);

  store_b(&msg[BGP_MH_BODY + BGP_NOM_CODE],    note->code) ;
  store_b(&msg[BGP_MH_BODY + BGP_NOM_SUBCODE], note->subcode) ;

  qassert(note->data == (note->msg_buff + BGP_NOM_MIN_L)) ;

  *p_msg_length = msg_length ;
  return msg ;
} ;

/*------------------------------------------------------------------------------
 * Get the length of a complete NOTIFICATION message (if any)
 *
 * NB: we silently curtail this to the maximum that will fit into such a
 *     message.
 */
extern uint
bgp_note_msg_length(bgp_note note)
{
  uint msg_length ;

  if (note != NULL)
    msg_length = BGP_NOM_MIN_L + note->length ;
  else
    msg_length = 0 ;

  if (msg_length > BGP_MSG_MAX_L)
    msg_length = BGP_MSG_MAX_L ;

  return msg_length ;
} ;

/*------------------------------------------------------------------------------
 * Get the length of the data portion of a NOTIFICATION (if any)
 *
 * NB: we silently curtail this to the maximum that will fit into such a
 *     message.
 */
extern uint
bgp_note_data_length(bgp_note note)
{
  uint data_length ;

  if (note != NULL)
    data_length = note->length ;
  else
    data_length = 0 ;

  if (data_length > (BGP_MSG_MAX_L - BGP_NOM_MIN_L))
    data_length = BGP_MSG_MAX_L - BGP_NOM_MIN_L ;

  return data_length ;
} ;

/*------------------------------------------------------------------------------
 * Put a NOTIFICATION message to the given sock_fd.
 *
 * Take no notice of errors or other niceties -- we don't care !
 */
extern void
bgp_note_put(int sock_fd, bgp_note note)
{
  ptr_t msg ;
  uint  msg_length ;

  msg = bgp_note_message(note, &msg_length) ;

  if ((sock_fd >= 0) && (msg != NULL))
    write(sock_fd, msg, msg_length) ;
} ;

/*==============================================================================
 * Notifications and human readable stuff.
 */

/*------------------------------------------------------------------------------
 * Render the given notification as a string.
 */
extern bgp_note_string_t
bgp_note_string(bgp_note note)
{
  bgp_note_string_t QFB_QFS(st, qfs) ;
  map_direct_p subcode_map ;

  qfs_put_str(qfs, map_direct_with_value(bgp_notify_msg_map, note->code).str) ;
  subcode_map = bgp_notify_subcode_msg_map(note->code) ;
  qfs_put_str(qfs, map_direct_with_value(subcode_map, note->subcode).str) ;

  if (note->length == 0)
    qfs_put_str(qfs, " -- no data") ;
  else
    {
      qfs_printf(qfs, " -- %d: 0x", note->length) ;
      qfs_put_n_hex(qfs, note->data, note->length, pf_lc | pf_space) ;
    } ;

  qfs_term_string(qfs, "...", 3 + 1) ;

  return st ;
} ;
