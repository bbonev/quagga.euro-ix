/* BGP MRT definitions
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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
#ifndef _QUAGGA_BGP_MRT_H
#define _QUAGGA_BGP_MRT_H

#include <misc.h>

/*==============================================================================
 * Definitions following RFC6396 -- Oct-2011
 */

/* MRT message types
 */
enum MRT_MT_TYPES {
   MRT_MT_NULL              =  0,       /* deprecated   */
   MRT_MT_START             =  1,       /* deprecated   */
   MRT_MT_DIE               =  2,       /* deprecated   */
   MRT_MT_I_AM_DEAD         =  3,       /* deprecated   */
   MRT_MT_PEER_DOWN         =  4,       /* deprecated   */
   MRT_MT_BGP               =  5,       /* deprecated   */
   MRT_MT_RIP               =  6,       /* deprecated   */
   MRT_MT_IDRP              =  7,       /* deprecated   */
   MRT_MT_RIPNG             =  8,       /* deprecated   */
   MRT_MT_BGP4PLUS          =  9,       /* deprecated   */
   MRT_MT_BGP4PLUS_01       = 10,       /* deprecated   */

   MRT_MT_OSPFv2            = 11,
   MRT_MT_TABLE_DUMP        = 12,       /* BGP routing table dump       */
   MRT_MT_TABLE_DUMP_V2     = 13,       /* BGP routing table dump, v2   */
   MRT_MT_BGP4MP            = 16,       /* BGP4 with MP extensions      */
   MRT_MT_BGP4MP_ET         = 17,       /* as above with Extended Times */
   MRT_MT_ISIS              = 32,
   MRT_MT_ISIS_ET           = 33,       /* as above with Extended Times */
   MRT_MT_OSPFv3            = 48,
   MRT_MT_OSPFv3_ET         = 49,       /* as above with Extended Times */
} ;

/* MRT Common Header and other sizes
 */
enum
{
  MRT_COMMON_HEADER_SIZE  = 12,         /* Timestamp(4), Type(2), Subtype(2)
                                         * Length(4)
                                         * NB: length excludes header   */
  MRT_BGP4MP_HEADER_SIZE  = 44          /* Peer AS(4), Local AS(4),
                                         * Interface Index(2),
                                         * Address Family(2),
                                         * Peer IP(16), Local IP(16)    */
} ;

/* MRT subtypes of MRT_MT_BGP4MP
 */
enum MRT_MT_BGP4MP_SUBTYPES
{
  MRT_MST_BGP4MP_STATE_CHANGE      = 0,
  MRT_MST_BGP4MP_MESSAGE           = 1,

  MRT_MST_BGP4MP_ENTRY             = 2, /* deprecated   */
  MRT_MST_BGP4MP_SNAPSHOT          = 3, /* deprecated   */

  MRT_MST_BGP4MP_MESSAGE_AS4       = 4,
  MRT_MST_BGP4MP_STATE_CHANGE_AS4  = 5,

  MRT_MST_BGP4MP_MESSAGE_LOCAL     = 6,
  MRT_MST_BGP4MP_MESSAGE_AS4_LOCAL = 7,
} ;

/* MRT subtypes of MRT_MT_TABLE_DUMP_V2
 */
enum MRT_MT_TABLE_DUMP_V2_SUBTYPES
{
  MRT_MST_TDV2_PEER_INDEX_TABLE    = 1,
  MRT_MST_TDV2_RIB_IPV4_UNICAST    = 2,
  MRT_MST_TDV2_RIB_IPV4_MULTICAST  = 3,
  MRT_MST_TDV2_RIB_IPV6_UNICAST    = 4,
  MRT_MST_TDV2_RIB_IPV6_MULTICAST  = 5,
  MRT_MST_TDV2_RIB_GENERIC         = 6,
} ;

/* Values for MRT_MST_TDV2_PEER_INDEX_TABLE message
 */
enum
{
  MRT_TDV2_PEER_INDEX_TABLE_IPV4   = 0,
  MRT_TDV2_PEER_INDEX_TABLE_IPV6   = 1,
  MRT_TDV2_PEER_INDEX_TABLE_AS2    = 0,
  MRT_TDV2_PEER_INDEX_TABLE_AS4    = 2,
} ;

/* Values for FSM states
 */
enum
{
  MRT_FSM_UNDEF        = 0,     /* Not defined in the standard  */

  MRT_FSM_Idle         = 1,
  MRT_FSM_Connect      = 2,
  MRT_FSM_Active       = 3,
  MRT_FSM_OpenSent     = 4,
  MRT_FSM_OpenConfirm  = 5,
  MRT_FSM_Established  = 6,
} ;

/* Values for AFI in BGP4MP messages
 */
enum
{
  MRT_AFI_IPv4         = 1,
  MRT_AFI_IPv6         = 2,
} ;

#endif /* _QUAGGA_BGP_MRT_H */
