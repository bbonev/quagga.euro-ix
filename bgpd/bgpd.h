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
#include "vector.h"
#include "name_index.h"

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
  BGP_OPT_AS2_SPEAKER           = BIT(1),

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

  uint  peer_linger_count ;     /* Peers lingering in pDeleting         */

  wq_base_t     fg_wq ;
  wq_base_t     bg_wq ;
};

/*------------------------------------------------------------------------------
 * BGP instance structure.
 */
typedef struct bgp_inst bgp_inst_t ;

struct bgp_inst
{
  bgp_env       parent_env ;

  struct dl_list_pair(bgp_inst) bgp_list ;

  /* The the 'view' name is an essential part of the bgp_inst, and *cannot* be
   * changed once the bgp_inst has been created.
   */
  bgp_nref      name;

  /* The run-time state of the instance, and all the running peers.
   */
  bgp_run       brun ;

  /* BGP Peers and Groups -- configuration
   *
   * All the peers and groups associated with this bgp instance.  The vectors
   * are held in group-name and peer-ip order:
   *
   *   * to find a group within a view, does a vector_bsearch() in this vector.
   *
   *   * for output of configuration etc, the output is in order.
   */
  vector_t      groups[1] ;     /* bgp_peer -- group    */
  vector_t      peers[1] ;      /* bgp_peer -- peer     */

  /* The configuration for this bgp_inst.
   */
  bgp_bconfig   c ;
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

extern const bgp_defaults_t bgp_default_defaults ;

/*==============================================================================
 * Prototypes.
 */
extern void bgp_terminate (bool, bool);
extern void bgp_reset (void);

extern void bgp_zclient_reset (void);                      /* See bgp_zebra ! */

extern void bgp_master_init (void);
extern void bgp_init (void);

extern bgp_ret_t bgp_option_set (bgp_option_t);
extern bgp_ret_t bgp_option_unset (bgp_option_t);
Inline bool bgp_option_check (bgp_option_t flag) ;

Inline time_t bgp_clock(void) ;
Inline time_t bgp_wall_clock(time_t mono) ;

extern bgp_nref bgp_nref_get(chs_c name) ;
extern bgp_nref bgp_nref_inc(bgp_nref nref) ;
extern bgp_nref bgp_nref_dec(bgp_nref nref) ;
extern void bgp_nref_set(bgp_nref* p_nref, chs_c name) ;
extern void bgp_nref_copy(bgp_nref* p_nref, bgp_nref nref) ;

Inline chs_c bgp_nref_name(bgp_nref nref) ;

extern bool bgp_name_match(chs_c name1, chs_c name2) ;

/*==============================================================================
 * Inlines
 */

/*------------------------------------------------------------------------------
 * Is the given option set ?
 */
Inline bool
bgp_option_check (bgp_option_t flag)
{
  return (bm->options & flag);
} ;

/*------------------------------------------------------------------------------
 * Get the name associated with the given nref.
 *
 * NB: this assumes that the mutex around the setting of the nref means that
 *     the nref value is visible to all threads after it is first set.
 */
Inline chs_c
bgp_nref_name(bgp_nref nref)
{
  return ni_nref_name(nref) ;
} ;

/*------------------------------------------------------------------------------
 * For many purposes BGP requires a CLOCK_MONOTONIC type time, in seconds.
 */
Inline time_t
bgp_clock(void)
{
  return qt_get_mono_secs() ;
} ;

/*------------------------------------------------------------------------------
 * For some purposes BGP requires a Wall Clock version of a time returned by
 * bgp_clock() above.
 *
 * This is calculated from the current Wall Clock, the current bgp_clock and
 * the bgp_clock time of some moment in the past.
 *
 * The fundamental problem is that the Wall Clock *may* (just may) be altered
 * by the operator or automatically, if the system clock is wrong.  So there
 * are, potentially, two versions of a past moment:
 *
 *   1) according to the Wall Clock at the time.
 *
 *   2) according to the Wall Clock now.
 *
 * There doesn't seem to be a good way of selecting between these if they are
 * different... Here we take (2), which (a) doesn't require us to fetch and
 * store both bgp_clock() and Wall Clock times every time we record the time
 * of some event, and (b) assumes that if the Wall Clock has been adjusted,
 * it was wrong before.  This can still cause confusion, because the Wall
 * Clock time calculated now may differ from any logged Wall Clock times !!
 */
Inline time_t
bgp_wall_clock(time_t mono)
{
  return time(NULL) - (bgp_clock() - mono) ;
} ;

#endif /* _QUAGGA_BGPD_H */
