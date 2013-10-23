/* BGP Open State -- header
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

#ifndef _QUAGGA_BGP_OPEN_STATE_H
#define _QUAGGA_BGP_OPEN_STATE_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_run.h"

#include "lib/vector.h"
#include "lib/ring_buffer.h"

/*==============================================================================
 * BGP Open State.
 *
 * This structure encapsulates all the information that may be sent/received
 * in a BGP OPEN Message.
 *
 */
typedef struct bgp_cap_unknown  bgp_cap_unknown_t ;
typedef struct bgp_cap_unknown* bgp_cap_unknown ;

struct bgp_cap_unknown                /* to capture unknown capability      */
{
  uint8_t       code ;
  bgp_size_t    length ;
  uint8_t       value[] ;
} ;

typedef struct bgp_cap_mp_ext  bgp_cap_mp_ext_t ;
typedef struct bgp_cap_mp_ext* bgp_cap_mp_ext ;

struct bgp_cap_mp_ext
{
  bool    seen ;
} ;

typedef struct bgp_cap_gr  bgp_cap_gr_t ;
typedef struct bgp_cap_gr* bgp_cap_gr ;

struct bgp_cap_gr
{
  bool  seen ;
  bool  has_preserved ;
} ;

typedef struct bgp_cap_orf_mode  bgp_cap_orf_mode_t ;
typedef struct bgp_cap_orf_mode* bgp_cap_orf_mode ;

struct bgp_cap_orf_mode
{
  bgp_form_t form ;
  uint8_t    mode ;
} ;

typedef bgp_cap_orf_mode_t bgp_cap_orf_mode_v[BGP_CAP_ORF_ORFT_T_MAX + 1] ;

typedef struct bgp_cap_orf  bgp_cap_orf_t ;
typedef struct bgp_cap_orf* bgp_cap_orf ;

struct bgp_cap_orf
{
  uint count ;
  bgp_cap_orf_mode_v  types ;
} ;

typedef struct bgp_cap_afi_safi  bgp_cap_afi_safi_t ;
typedef struct bgp_cap_afi_safi* bgp_cap_afi_safi ;
typedef const struct bgp_cap_afi_safi* bgp_cap_afi_safi_c ;

struct bgp_cap_afi_safi
{
  qafx_t    qafx ;              /* qafx_other => unknown afi/safi
                                 * qafx_undef => reserved afi and/or safi */
  iAFI_SAFI_t mp ;

  /* Registering afi/safi from BGP_CAN_MP_EXT
   */
  bgp_cap_mp_ext_t mp_ext ;

  /* Registering afi/safi from BGP_CAN_G_RESTART
   */
  bgp_cap_gr_t  gr ;

  /* Registering afi/safi from BGP_CAN_ORF and BGP_CAN_ORF_pre
   */
  bgp_cap_orf_t orf ;
} ;

typedef struct bgp_open_state    bgp_open_state_t ;
typedef const  bgp_open_state_t* bgp_open_state_c ;

struct bgp_open_state
{
  bgp_sargs     sargs ;

  as2_t         my_as2 ;        /* OPEN Message: "My Autonomous System" */

  vector_t      afi_safi[1] ;   /* various afi/safi capabilities        */
  vector_t      unknowns[1] ;   /* list of bgp_cap_unknown              */
} ;

/*------------------------------------------------------------------------------
 * Auxiliary structure for bgp_open_make_cap_orf()
 */
typedef struct bgp_open_orf_type  bgp_open_orf_type_t ;
typedef struct bgp_open_orf_type* bgp_open_orf_type ;

struct bgp_open_orf_type
{
  uint8_t   type ;

  qafx_set_t sm ;
  qafx_set_t rm ;
} ;

/*==============================================================================
 *
 */
extern bgp_open_state bgp_open_state_init_new(bgp_open_state state) ;
extern bgp_open_state bgp_open_state_reset(bgp_open_state state) ;
extern bgp_open_state bgp_open_state_free(bgp_open_state state) ;
extern bgp_open_state bgp_open_state_set_mov(bgp_open_state dst,
                                                        bgp_open_state* p_src) ;

extern bgp_sargs bgp_sargs_init_new(bgp_sargs sargs) ;
extern bgp_sargs bgp_sargs_reset(bgp_sargs sargs) ;
extern void bgp_sargs_suppress(bgp_sargs sargs) ;
extern bgp_sargs bgp_sargs_copy(bgp_sargs dst, bgp_sargs_c src) ;
extern bgp_sargs bgp_sargs_dup(bgp_sargs_c src) ;
extern bgp_sargs bgp_sargs_free(bgp_sargs sargs) ;

extern void bgp_open_state_unknown_add(bgp_open_state state, uint8_t code,
                                               void* value, bgp_size_t length) ;
extern int bgp_open_state_unknown_count(bgp_open_state state) ;

extern bgp_cap_unknown bgp_open_state_unknown_cap(bgp_open_state state,
                                                               unsigned index) ;
extern bgp_cap_afi_safi bgp_open_state_afi_safi_find(bgp_open_state state,
                                                                 iAFI_SAFI mp) ;
extern uint bgp_open_state_afi_safi_count(bgp_open_state state) ;
extern bgp_cap_afi_safi bgp_open_state_afi_safi_cap(bgp_open_state state,
                                                                       uint i) ;
extern void bgp_open_state_afi_safi_drop(bgp_open_state state, uint i) ;

extern void bgp_peer_open_state_receive(bgp_peer peer);

extern void bgp_open_make_cap_option(blower sbr, blower br, bool one_option) ;
extern void bgp_open_make_cap_as4(blower br, as_t my_as, bool wrap) ;
extern void bgp_open_make_cap_mp_ext(blower br, qafx_set_t mp, bool wrap) ;
extern void bgp_open_make_cap_r_refresh(blower br, bgp_form_t form, bool wrap) ;
extern void bgp_open_make_cap_end(blower sbr, blower br, bool one_option) ;

extern bool bgp_open_prepare_orf_type(bgp_open_orf_type orf_type, uint8_t orft,
                       bgp_orf_caps modes, bgp_form_t form, qafx_set_t can_af) ;
extern void bgp_open_make_cap_orf(blower br, uint8_t cap_code, uint count,
                    bgp_open_orf_type_t types[], qafx_set_t can_af, bool wrap) ;
extern void bgp_open_make_cap_gr(blower br, bgp_sargs_gr cap_gr,
                                                 qafx_set_t can_af, bool wrap) ;

#endif /* QUAGGA_BGP_OPEN_STATE_H */
