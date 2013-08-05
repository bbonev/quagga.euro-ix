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
 * A bgp_notify structure encapsulates the contents of a BGP NOTIFICATION
 * message.
 */

/*==============================================================================
 * Create/Destroy bgp_notify
 */
static void bgp_notify_now_need(bgp_notify notification, uint need) ;

/*------------------------------------------------------------------------------
 * Allocate and initialise new notification
 *
 * Can add data later if required.
 *
 * NB: returns a 'NOT received' notification.
 */
extern bgp_notify
bgp_notify_new(bgp_nom_code_t code, bgp_nom_subcode_t subcode)
{
  bgp_notify notification ;

  notification = XCALLOC(MTYPE_BGP_NOTIFY, sizeof(bgp_notify_t)) ;

  /* Zeroizing sets:
   *
   *   * received               -- false    -- not yet
   *
   *   * code                   -- X        -- set below
   *   * subcode                -- X        -- set below
   *
   *   * data                   -- NULL     -- none, yet
   *   * length                 -- 0        -- none, yet
   *   * size                   -- 0        -- none, yet
   *
   *   * msg_buff               -- 0        -- none, yet
   *
   *   * embedded               -- 0's      -- nicely cleared out
   */
  notification->code     = code ;
  notification->subcode  = subcode ;

  return notification ;
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
extern bgp_notify
bgp_notify_new_need(bgp_nom_code_t code, bgp_nom_subcode_t subcode, uint need)
{
  bgp_notify notification ;

  notification = bgp_notify_new(code, subcode) ;
  bgp_notify_now_need(notification, need) ;

  return notification ;
} ;

/*------------------------------------------------------------------------------
 * Need enough space for 'need' bytes of notification data.
 *
 * Tidies up, so that everything in buffer from the given 'need' onwards is
 * zeroized -- assuming that was tidy before any new allocation.
 *
 * NB: when a notification is initialised, the size is set zero.  Here we
 *     will set things up to use the embedded buffer, if it is big enough.
 *
 *     Note that we set up to use the embedded buffer even if need == 0.
 */
static void
bgp_notify_now_need(bgp_notify notification, uint need)
{
  uint zero_to ;

  if (notification->size == 0)
    {
      notification->msg_buff = notification->embedded ;
      notification->data     = notification->embedded   + BGP_NOM_MIN_L ;
      notification->size     = bgp_notify_embedded_size - BGP_NOM_MIN_L ;
    } ;

  if (notification->size >= need)
    {
      qassert(notification->length <= notification->size) ;
      zero_to = notification->length ;
    }
  else
    {
      ptr_t msg_buff ;
      uint  full_size ;

      msg_buff  = notification->msg_buff ;
      full_size = uround_up_up(need + BGP_NOM_MIN_L, 32) ;

      if (msg_buff != notification->embedded)
        msg_buff = XREALLOC(MTYPE_TMP, msg_buff, full_size) ;
      else
        {
          msg_buff = XMALLOC(MTYPE_TMP, full_size) ;
          memcpy(msg_buff, notification->embedded, bgp_notify_embedded_size) ;
        } ;

      notification->msg_buff = msg_buff ;
      notification->data     = msg_buff  + BGP_NOM_MIN_L ;
      notification->size     = full_size - BGP_NOM_MIN_L ;

      zero_to = notification->size ;
  } ;

  if ((need < zero_to) && (zero_to <= notification->size))
    memset(notification->data + need, 0, zero_to - need) ;
} ;

/*------------------------------------------------------------------------------
 * Allocate and initialise new notification, complete with data
 *
 * Can specify an expected amount of data -- copes with len == 0 (and data may
 * be NULL iff len == 0).
 *
 * NB: returns a 'NOT received' notification.
 */
extern bgp_notify
bgp_notify_new_with_data(bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                                     const void* data, uint len)
{
  bgp_notify notification ;

  notification = bgp_notify_new_need(code, subcode, len) ;
  bgp_notify_append_data(notification, data, len) ;

  return notification ;
} ;

/*------------------------------------------------------------------------------
 * Free notification structure
 *
 * Does nothing if there is no structure.
 */
extern bgp_notify
bgp_notify_free(bgp_notify notification)
{
  if (notification != NULL)
    {
      if ((notification->msg_buff != NULL) &&
                             (notification->msg_buff != notification->embedded))
        XFREE(MTYPE_BGP_NOTIFY, notification->msg_buff) ;

      XFREE(MTYPE_BGP_NOTIFY, notification) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Duplicate existing notification (if any)
 */
extern bgp_notify
bgp_notify_dup(bgp_notify notification)
{
  bgp_notify duplicate ;

  if (notification == NULL)
    return NULL ;

  duplicate = bgp_notify_new_need(notification->code, notification->subcode,
                                                         notification->length) ;
  duplicate->received = notification->received ;

  if (notification->length != 0)
    {
      duplicate->length   = notification->length ;
      memcpy(duplicate->data, notification->data, duplicate->length) ;
    } ;

  return duplicate ;
} ;

/*------------------------------------------------------------------------------
 * Unset pointer to notification and free any existing notification structure.
 *
 * Does nothing if there is no structure.
 */
extern void
bgp_notify_unset(bgp_notify* p_notification)
{
  *p_notification = bgp_notify_free(*p_notification) ;
} ;

/*------------------------------------------------------------------------------
 * Unset pointer to notification and return the pointer value.
 *
 * Returns NULL if there is no structure.
 */
extern bgp_notify
bgp_notify_take(bgp_notify* p_notification)
{
  bgp_notify take = *p_notification ;    /* take anything that's there   */
  *p_notification = NULL ;
  return take ;
} ;

/*------------------------------------------------------------------------------
 * Set pointer to notification
 *
 * Frees any existing notification at the destination.
 *
 * NB: copies the source pointer -- so must be clear about responsibility
 *     for the notification structure.
 */
extern void
bgp_notify_set(bgp_notify* p_dst, bgp_notify src)
{
  if (*p_dst != src)            /* empty operation if already set !     */
    {
      bgp_notify_free(*p_dst) ;
      *p_dst = src ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set pointer to notification to a *copy* of the source.
 *
 * Frees any existing notification at the destination unless points at src !
 */
extern void
bgp_notify_set_dup(bgp_notify* p_dst, bgp_notify src)
{
  if (*p_dst != src)
    bgp_notify_free(*p_dst) ;   /* avoid freeing what we're duplicating */

  *p_dst = bgp_notify_dup(src) ;
} ;

/*------------------------------------------------------------------------------
 * Set pointer to notification and unset source pointer
 *
 * Frees any existing notification at the destination.
 *
 * NB: responsibility for the notification structure passes to the destination.
 */
extern void
bgp_notify_set_mov(bgp_notify* p_dst, bgp_notify* p_src)
{
  bgp_notify_set(p_dst, *p_src) ;
  *p_src = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set new Code and Subcode and discard and data accumulated so far.
 *
 * NB: does not change the received state of the notification.
 */
extern bgp_notify
bgp_notify_reset(bgp_notify notification, bgp_nom_code_t code,
                                                      bgp_nom_subcode_t subcode)
{
  if (notification == NULL)
    return bgp_notify_new(code, subcode) ;

  notification->code    = code ;
  notification->subcode = subcode ;
  notification->length  = 0 ;

  return notification ;
} ;

/*------------------------------------------------------------------------------
 * Set a default Code and Subcode.
 */
extern bgp_notify
bgp_notify_default(bgp_notify notification, bgp_nom_code_t code,
                                                      bgp_nom_subcode_t subcode)
{
  if (notification == NULL)
    return bgp_notify_new(code, subcode) ;

  return notification ;
} ;

/*------------------------------------------------------------------------------
 * Duplicate or Create a new default Code and Subcode.
 */
extern bgp_notify
bgp_notify_dup_default(bgp_notify notification, bgp_nom_code_t code,
                                                      bgp_nom_subcode_t subcode)
{
  if (notification == NULL)
    return bgp_notify_new(code, subcode) ;

  return bgp_notify_dup(notification) ;
} ;

/*==============================================================================
 * Appending stuff to a notification
 */

/*------------------------------------------------------------------------------
 * Append data to given notification (if any)
 *
 * Copes with zero length append (and data may be NULL if len == 0).
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_notify
bgp_notify_append_data(bgp_notify notification, const void* data, uint len)
{
  uint new_length ;

  if (notification == NULL)
    return NULL ;

  new_length = notification->length + len ;

  bgp_notify_now_need(notification, new_length) ;

  if (len > 0)
    memcpy(notification->data + notification->length, data, len) ;

  notification->length = new_length ;

  return notification ;
} ;

/*------------------------------------------------------------------------------
 * Append one byte to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_notify
bgp_notify_append_b(bgp_notify notification, uint8_t b)
{
  return bgp_notify_append_data(notification, &b, 1) ;
} ;

/*------------------------------------------------------------------------------
 * Append one word (uint16_t), in network byte order to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_notify
bgp_notify_append_w(bgp_notify notification, uint16_t w)
{
  w = htons(w) ;
  return bgp_notify_append_data(notification, &w, 2) ;
} ;

/*------------------------------------------------------------------------------
 * Append one long (uint32_t), in network byte order to notification (if any)
 *
 * Returns:  address of the notification -- as given.
 *
 * NB: does nothing if no notification !
 */
extern bgp_notify
bgp_notify_append_l(bgp_notify notification, uint32_t l)
{
  l = htonl(l) ;
  return bgp_notify_append_data(notification, &l, 4) ;
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
bgp_notify_message(bgp_notify notification, uint* p_msg_length)
{
  uint  msg_length ;
  ptr_t msg ;

  if (notification == NULL)
    {
      *p_msg_length = 0 ;
      return NULL ;
    } ;

  /* Make sure we have notification->msg_buff & notification->data set up.
   */
  bgp_notify_now_need(notification, notification->length) ;

  msg_length = bgp_notify_msg_length(notification) ;
  msg        = notification->msg_buff ;

  memset(  &msg[BGP_MH_MARKER], 0xFF, BGP_MH_MARKER_L) ;
  store_ns(&msg[BGP_MH_LENGTH], msg_length) ;
  store_b( &msg[BGP_MH_TYPE],   BGP_MT_NOTIFICATION);

  store_b(&msg[BGP_MH_BODY + BGP_NOM_CODE],    notification->code) ;
  store_b(&msg[BGP_MH_BODY + BGP_NOM_SUBCODE], notification->subcode) ;

  qassert(notification->data == (notification->msg_buff + BGP_NOM_MIN_L)) ;

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
bgp_notify_msg_length(bgp_notify notification)
{
  uint msg_length ;

  if (notification != NULL)
    msg_length = BGP_NOM_MIN_L + notification->length ;
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
bgp_notify_data_length(bgp_notify notification)
{
  uint data_length ;

  if (notification != NULL)
    data_length = notification->length ;
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
bgp_notify_put(int sock_fd, bgp_notify notification)
{
  ptr_t msg ;
  uint  msg_length ;

  msg = bgp_notify_message(notification, &msg_length) ;

  if ((sock_fd >= 0) && (msg != NULL))
    write(sock_fd, msg, msg_length) ;
} ;

/*==============================================================================
 * Notifications and human readable stuff.
 */

/*------------------------------------------------------------------------------
 * Render the given notification as a string.
 */
extern bgp_notify_string_t
bgp_notify_string(bgp_notify notification)
{
  bgp_notify_string_t QFB_QFS(st, qfs) ;
  map_direct_p subcode_map ;

  qfs_put_str(qfs, map_direct_with_value(bgp_notify_msg_map,
                                                     notification->code).str) ;
  subcode_map = bgp_notify_subcode_msg_map(notification->code) ;
  qfs_put_str(qfs, map_direct_with_value(subcode_map,
                                                   notification->subcode).str) ;

  if (notification->length == 0)
    qfs_put_str(qfs, " -- no data") ;
  else
    {
      qfs_printf(qfs, " -- %d: 0x", notification->length) ;
      qfs_put_n_hex(qfs, notification->data, notification->length,
                                                             pf_lc | pf_space) ;
    } ;

  qfs_term_string(qfs, "...", 3 + 1) ;

  return st ;
} ;
