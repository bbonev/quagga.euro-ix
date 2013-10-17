/* BGP Daemon -- header.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * Recast: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGPD_H
#define _QUAGGA_BGPD_H

#include "misc.h"

#include "bgpd/bgp_common.h"

#include "qpnexus.h"
#include "workqueue.h"
#include "privs.h"
#include "list_util.h"

/*==============================================================================
 * This is the bacic running state for bgp.
 *
 * This references both the bgp_inst objects, which contain the configuration,
 * and any currently running bgp_run objects, which contain running instances.
 */

/*------------------------------------------------------------------------------
 * BGP master for system wide configurations and variables.
 */
typedef enum bgp_option bgp_option_t ;
enum bgp_option
{
  /* Command-line options -- ie not changed by configuration/CLI
   */
  BGP_OPT_NO_FIB                = BIT(0),

  BGP_OPT_LEGACY_IPV4_DEFAULT   = BIT(1),
  BGP_OPT_LEGACY_GROUPS         = BIT(2),

  /* Other options -- may be changed by configuration/CLI
   */
  BGP_OPT_MULTIPLE_INSTANCE     = BIT(8),
  BGP_OPT_CONFIG_CISCO          = BIT(9),
} ;

typedef struct bgp_env bgp_env_t ;
struct bgp_env
{
  /* We support a number of separate instances -- but usually only have one !
   */
  struct dl_base_pair(bgp_inst) bgps ;

  struct dl_base_pair(bgp_run) bruns ;

  uint  bgp_count ;
  uint  brun_count ;

  struct thread_master *master; /* BGP thread master.                   */

  char*    addresses ;          /* Listener address & port number       */
  char*    port_str ;

  time_t   start_time;          /* BGP start time.                      */

  bgp_option_t options;         /* Various BGP global configuration.    */

  bool  reading_config ;        /* in the process of reading config.    */
  bool  as2_speaker ;           /* Do not announce AS4                  */

  uint  peer_linger_count ;     /* Peers lingering in pDeleting         */

  wq_base_t     fg_wq ;
  wq_base_t     bg_wq ;
};

/*==============================================================================
 *
 */
/* BGP versions.
 */
enum { BGP_VERSION_4       =   4 } ;

/* Default BGP port number.
 */
enum { BGP_PORT_DEFAULT    = 179 } ;

/* BGP timers default values
 */
enum bgp_timer_defaults
{
#ifndef BGP_IDLE_HOLD_MAX
  BGP_DEFAULT_IDLE_HOLD_MAX_SECS   = 120,
#else
  BGP_DEFAULT_IDLE_HOLD_MAX_SECS   = BGP_IDLE_HOLD_MAX + 0,
#endif

#ifndef BGP_IDLE_HOLD_MIN
  BGP_DEFAULT_IDLE_HOLD_MIN_SECS   =   5,
#else
  BGP_DEFAULT_IDLE_HOLD_MIN_SECS   = BGP_IDLE_HOLD_MIN + 0,
#endif

  BGP_INIT_START_TIMER             =   5,
  BGP_ERROR_START_TIMER            =  30,
  BGP_DEFAULT_HOLDTIME             = 180,
  BGP_DEFAULT_KEEPALIVE            =  60,
  BGP_DEFAULT_ASORIGINATE          =  15,
  BGP_DEFAULT_EBGP_MRAI            =  30,
  BGP_DEFAULT_CBGP_MRAI            =  30,
  BGP_DEFAULT_IBGP_MRAI            =   5,
  BGP_CLEAR_CONNECT_RETRY          =  20,
  BGP_DEFAULT_CONNECT_RETRY        = 120,
  BGP_DEFAULT_ACCEPT_RETRY         = 240,
  BGP_DEFAULT_OPENHOLDTIME         = 240,

  BGP_DEFAULT_RESTART_TIME         = 120,       /* Graceful Restart */
  BGP_DEFAULT_STALEPATH_TIME       = 360,
} ;

enum bgp_local_pref
{
  BGP_DEFAULT_LOCAL_PREF           = 100
} ;

/* Default configuration settings for bgpd.
 */
#define BGP_VTY_PORT                 2605
#define BGP_DEFAULT_CONFIG     "bgpd.conf"

/* Check AS path loop when we send NLRI.  */
/* #define BGP_SEND_ASPATH_CHECK */

/*------------------------------------------------------------------------------
 * Globals.
 */
extern bgp_env   bm ;

extern qpn_nexus cli_nexus;
extern qpn_nexus be_nexus;
extern qpn_nexus re_nexus;

extern struct zebra_privs_t bgpd_privs ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_terminate (bool, bool);
extern void bgp_reset (void);

extern void bgp_zclient_reset (void);                      /* See bgp_zebra ! */

extern void bgp_master_init (void);

extern void bgp_init (void);

extern bgp_ret_t bgp_option_set (bgp_option_t);
extern bgp_ret_t bgp_option_unset (bgp_option_t);


extern bool bgp_name_match(chs_c name1, chs_c name2) ;

Inline bool bgp_option_check (bgp_option_t flag)
{
  return (bm->options & flag);
}

#endif /* _QUAGGA_BGPD_H */
