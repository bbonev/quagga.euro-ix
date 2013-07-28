/* BGP Notification state handling -- header
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * Recast for pthreaded bgpd: Copyright (C) Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_NOTIFY_H
#define _QUAGGA_BGP_NOTIFY_H

#include "lib/misc.h"
#include "bgpd/bgp_common.h"

#include "lib/qfstring.h"

/*==============================================================================
 * BGP NOTIFICATION message codes.
 */
typedef uint8_t bgp_nom_code_t ;
typedef uint8_t bgp_nom_subcode_t ;

/*==============================================================================
 * Structure for notification.
 *
 * Note that vast majority of notification handling concerns notifications that
 * are *sent* to the far end.  Occasionally a notification will be received.
 *
 * It is *screamingly* convenient to have enough space for the complete
 * NOTIFICATION message in the bgp_notify -- so can write directly from here.
 */
enum { bgp_notify_embedded_size  = ROUND_UP(BGP_NOM_MIN_L + 40, 8) } ;

typedef struct bgp_notify  bgp_notify_t ;

struct bgp_notify
{
  bool              received ;

  bgp_nom_code_t    code ;
  bgp_nom_subcode_t subcode ;

  ptr_t             data ;              /* pointer to data portion      */
  uint              length ;            /* as given                     */
  uint              size ;              /* of *data*                    */

  ptr_t             msg_buff ;

  byte              embedded[bgp_notify_embedded_size] ;
} ;

/*------------------------------------------------------------------------------
 * qfstring for showing the state of notifications
 */
QFB_T(100) bgp_notify_string_t ;

/*==============================================================================
 * Functions
 */
extern bgp_notify bgp_notify_new(bgp_nom_code_t code,
                                 bgp_nom_subcode_t subcode) ;
extern bgp_notify bgp_notify_new_need(bgp_nom_code_t code,
                                 bgp_nom_subcode_t subcode, uint need) ;
extern bgp_notify bgp_notify_new_with_data(bgp_nom_code_t code,
                                           bgp_nom_subcode_t subcode,
                                                   const void* data, uint len) ;
extern bgp_notify bgp_notify_free(bgp_notify notification) ;
extern bgp_notify bgp_notify_dup(bgp_notify notification) ;
extern void bgp_notify_unset(bgp_notify* p_notification) ;
extern bgp_notify bgp_notify_take(bgp_notify* p_notification) ;
extern void bgp_notify_set(bgp_notify* p_dst, bgp_notify src) ;
extern void bgp_notify_set_dup(bgp_notify* p_dst, bgp_notify src) ;
extern void bgp_notify_set_mov(bgp_notify* p_dst, bgp_notify* p_src) ;

extern bgp_notify bgp_notify_reset(bgp_notify notification,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern bgp_notify bgp_notify_default(bgp_notify notification,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;

extern bgp_notify bgp_notify_append_data(bgp_notify notification,
                                                   const void* data, uint len) ;
extern bgp_notify bgp_notify_append_b(bgp_notify notification, uint8_t b) ;
extern bgp_notify bgp_notify_append_w(bgp_notify notification, uint16_t w) ;

extern bgp_notify bgp_notify_append_l(bgp_notify notification, uint32_t l) ;

extern ptr_t bgp_notify_message(bgp_notify notification, uint* p_msg_length) ;
extern uint bgp_notify_msg_length(bgp_notify notification) ;
extern uint bgp_notify_data_length(bgp_notify notification) ;
extern void bgp_notify_put(int sock_fd, bgp_notify notification) ;
extern bgp_notify_string_t bgp_notify_string(bgp_notify notification) ;

#endif /* _QUAGGA_BGP_NOTIFY_H */
