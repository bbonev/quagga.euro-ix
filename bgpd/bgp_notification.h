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

#ifndef _QUAGGA_BGP_NOTIFICATION_H
#define _QUAGGA_BGP_NOTIFICATION_H

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
 * NOTIFICATION message in the bgp_note -- so can write directly from here.
 */
enum { bgp_notify_embedded_size  = ROUND_UP(BGP_NOM_MIN_L + 40, 8) } ;

typedef struct bgp_note  bgp_note_t ;

struct bgp_note
{
  bool              received ;

  bgp_nom_code_t    code ;
  bgp_nom_subcode_t subcode ;

  /* When a bgp_note is initialised, the data/size/msg_buff point into the
   * embedded area.
   *
   * If more is required, the data/size/msg_buff will refer to some allocated
   * memory, and will not revert back.
   */
  ptr_t             data ;              /* pointer to data portion      */
  uint              length ;            /* as given                     */
  uint              size ;              /* of *data*                    */

  ptr_t             msg_buff ;          /* pointer to message           */

  byte              embedded[bgp_notify_embedded_size] ;
} ;

/*------------------------------------------------------------------------------
 * qfstring for showing the state of notifications
 */
QFB_T(100) bgp_note_string_t ;

/*==============================================================================
 * Functions
 */
extern bgp_note bgp_note_new(bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern bgp_note bgp_note_new_need(bgp_nom_code_t code,
                                         bgp_nom_subcode_t subcode, uint need) ;
extern bgp_note bgp_note_new_with_data(bgp_nom_code_t code,
                                           bgp_nom_subcode_t subcode,
                                                   const void* data, uint len) ;
extern bgp_note bgp_note_reset(bgp_note note) ;
extern bgp_note bgp_note_free(bgp_note note) ;
extern bgp_note bgp_note_copy(bgp_note dst, bgp_note src) ;
extern bgp_note bgp_note_dup(bgp_note note) ;

extern bgp_note bgp_note_set(bgp_note note,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern bgp_note bgp_note_default(bgp_note note,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern bgp_note bgp_note_dup_default(bgp_note note,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;

extern ptr_t bgp_note_prep_data(bgp_note note, uint want) ;
extern bgp_note bgp_note_append_data(bgp_note note,
                                                   const void* data, uint len) ;
extern bgp_note bgp_note_append_b(bgp_note note, uint8_t b) ;
extern bgp_note bgp_note_append_w(bgp_note note, uint16_t w) ;

extern bgp_note bgp_note_append_l(bgp_note note, uint32_t l) ;

extern ptr_t bgp_note_message(bgp_note note, uint* p_msg_length) ;
extern uint bgp_note_msg_length(bgp_note note) ;
extern uint bgp_note_data_length(bgp_note note) ;
extern void bgp_note_put(int sock_fd, bgp_note note) ;
extern bgp_note_string_t bgp_note_string(bgp_note note) ;

#endif /* _QUAGGA_BGP_NOTIFICATION_H */
