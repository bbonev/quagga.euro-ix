/* BGP message definition header.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGPD_H
#define _QUAGGA_BGPD_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_notification.h"

#include "thread.h"
#include "plist.h"
#include "qtime.h"
#include "privs.h"
#include "ihash.h"
#include "sockunion.h"
#include "workqueue.h"

/*------------------------------------------------------------------------------
 * BGP master for system wide configurations and variables.
 */
enum bgp_option_bits
{
  BGP_OPT_NO_FIB                = BIT(0),
  BGP_OPT_MULTIPLE_INSTANCE     = BIT(1),
  BGP_OPT_CONFIG_CISCO          = BIT(2),
} ;
typedef byte bgp_option_bits_t ;        /* NB: <= 8 bits defined        */

struct bgp_master
{
  struct list *bgp ;            /* BGP instance list.                   */

  struct thread_master *master; /* BGP thread master.                   */

  char*    addresses ;          /* Listener address & port number       */
  char*    port_str ;

  time_t   start_time;          /* BGP start time.                      */

  bgp_option_bits_t options;    /* Various BGP global configuration.    */

  bool  reading_config ;        /* in the process of reading config.    */
  bool  as2_speaker ;           /* Do not announce AS4                  */

  uint  peer_linger_count ;     /* Peers lingering in pDeleting         */

  wq_base_t     fg_wq ;
  wq_base_t     bg_wq ;
};

/*------------------------------------------------------------------------------
 * BGP instance structure.
 */
enum bgp_config_bits
{
  BGP_CONFIG_ROUTER_ID      = BIT(0),
  BGP_CONFIG_CLUSTER_ID     = BIT(1),
  BGP_CONFIG_CONFEDERATION  = BIT(2),
} ;
typedef uint16_t bgp_config_bits_t ;    /* NB: <= 16 bits defined       */

enum bgp_flag_bits
{
  BGP_FLAG_ALWAYS_COMPARE_MED       = BIT( 0),
  BGP_FLAG_DETERMINISTIC_MED        = BIT( 1),
  BGP_FLAG_MED_MISSING_AS_WORST     = BIT( 2),
  BGP_FLAG_MED_CONFED               = BIT( 3),
  BGP_FLAG_NO_DEFAULT_IPV4          = BIT( 4),
  BGP_FLAG_NO_CLIENT_TO_CLIENT      = BIT( 5),
  BGP_FLAG_ENFORCE_FIRST_AS         = BIT( 6),
  BGP_FLAG_COMPARE_ROUTER_ID        = BIT( 7),
  BGP_FLAG_ASPATH_IGNORE            = BIT( 8),
  BGP_FLAG_IMPORT_CHECK             = BIT( 9),
  BGP_FLAG_NO_FAST_EXT_FAILOVER     = BIT(10),
  BGP_FLAG_LOG_NEIGHBOR_CHANGES     = BIT(11),
  BGP_FLAG_GRACEFUL_RESTART         = BIT(12),
  BGP_FLAG_ASPATH_CONFED            = BIT(13),
} ;
typedef uint16_t bgp_flag_bits_t ;      /* NB: <= 16 bits defined       */

enum bgp_af_flag_bits
{
  BGP_CONFIG_DAMPING    = BIT(0),
} ;
typedef uint8_t bgp_af_flag_bits_t ;    /* NB: <= 8 bits defined        */

typedef struct bgp bgp_inst_t ;

struct bgp
{
  /* AS number of this BGP instance.
   */
  as_t  my_as;

  /* Name of this BGP instance.
   */
  char* name;

  /* Reference count to allow bgp_peer_delete to finish after bgp_delete
   */
  uint  lock;

  /* Self peer.
   */
  bgp_peer      peer_self;

  /* BGP Peers and Groups.
   *
   * All the peers and groups associated with this bgp instance.
   *
   * The lists are held in IP/Name order.
   */
  struct list *peer;
  struct list *group;

  /* BGP router identifier.
   */
  in_addr_t  router_id;

  /* BGP route reflector cluster ID.
   */
  in_addr_t  cluster_id ;

  /* BGP confederation information.
   *
   * The ebgp_as is:  bgp->my_as, unless bgp->confed_id is set, when it is that.
   *
   * So bgp->ebgp_as is the effective as for eBGP sessions (NB: that *excludes*
   * sessions to Confederation peers in different Member ASes).
   *
   * check_confed_id is set iff:  confed_id != BGP_ASN_NULL
   *                         and: confed_id != bgp->my_as
   *
   * check_confed_id_all is set iff: confed_id not in confed_peers.
   *
   * What check_confed_id means is that for iBGP and for cBGP, we can check
   * that the AS-PATH on incoming routes does NOT contain the confed_id.
   *
   * NB: the confed_id *may* be the same as the bgp->my_as.
   *
   * NB: the confed_peers *will* exclude the bgp->my_as, but not necessarily the
   *     confed_id !
   */
  as_t    ebgp_as ;

  as_t    confed_id ;           /* BGP_ASN_NULL <=> no CONFED   */
  asn_set confed_peers;

  bool    check_confed_id ;
  bool    check_confed_id_all ;

  /* BGP configuration.
   */
  bgp_config_bits_t config;

  /* BGP flags.
   */
  bgp_flag_bits_t flags;

  /* BGP Per AF flags
   */
  bgp_af_flag_bits_t af_flags[qafx_count];

  /* Static route configuration.
   */
  bgp_table route[qafx_count];

  /* Aggregate address configuration.
   */
  bgp_table aggregate[qafx_count];

  /* BGP routing information bases -- one per AFI/SAFI and one for Main/RS.
   */
  bgp_rib  rib[qafx_count][rib_type_count];

  /* BGP redistribute
   */
  bool     redist[AFI_MAX][ZEBRA_ROUTE_MAX];
  bool     redist_metric_set[AFI_MAX][ZEBRA_ROUTE_MAX];
  uint32_t redist_metric[AFI_MAX][ZEBRA_ROUTE_MAX];

  struct
  {
    char *name;
    struct route_map *map;
  } rmap[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP distance configuration.
   */
  byte distance_ebgp;
  byte distance_ibgp;
  byte distance_local;

  /* BGP default local-preference, MEDs and weight.
   */
  uint32_t default_local_pref;
  uint32_t default_med ;
  uint32_t default_weight ;

  /* BGP default timers.
   */
  uint32_t default_holdtime ;
  uint32_t default_keepalive ;
  uint32_t default_connect_retry_secs ;
  uint32_t default_accept_retry_secs ;
  uint32_t default_open_hold_secs ;

  uint32_t default_ibgp_mrai ;
  uint32_t default_cbgp_mrai ;          /* usually same as eBGP */
  uint32_t default_ebgp_mrai ;

  /* BGP graceful restart
   */
  uint32_t restart_time;
  uint32_t stalepath_time;
} ;

/* BGP peer-group support.
 */
typedef struct peer_group peer_group_t ;

struct peer_group
{
  char*     name;

  bgp_inst  bgp;                /* Does not own a lock          */

  struct list* peer ;           /* Peer-group client list.      */
  struct list* members ;        /* Peer-group client list.      */

  bgp_peer conf ;               /* the configuration            */
};



#define PEER_PASSWORD_MINLEN    (1)
#define PEER_PASSWORD_MAXLEN    (80)

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

/* Max TTL value.
 */
enum { TTL_MAX  = MAXTTL } ;    /* MAXTTL from netinet/ip.h     */

/* BGP uptime string length.
 */
enum { BGP_UPTIME_LEN   = 25 } ;

/* Default configuration settings for bgpd.
 */
#define BGP_VTY_PORT                          2605
#define BGP_DEFAULT_CONFIG             "bgpd.conf"

/* Check AS path loop when we send NLRI.  */
/* #define BGP_SEND_ASPATH_CHECK */

/* The sort of peer is a key property of the peer:
 *
 *   * BGP_PEER_UNSPECIFIED -- for group configuration where the remote-as is
 *                             not set.
 *
 *   * BGP_PEER_IBGP     -- remote peer is in the same AS as us (bpg->my_as),
 *                          which may be a CONFED Member AS.
 *
 *   * BGP_PEER_CBGP     -- peer is in same AS as us (bgp->my_as),
 *                          ant that AS is a (different) CONFED Member AS
 *
 *   * BGP_PEER_EBGP     -- peer is in a different AS to us (bgp->my_as)
 *                          and that is not a CONFED Member AS (if any)
 *
 * The CONFED thing is a bit of a tangle.  Suppose we have AS99, and we
 * configure that as a Confederation with 3 Member ASN: 65001, 65002 and
 * 65003.  And suppose we are in the 65001 Member AS, then we have:
 *
 *   router bgp 65001                           -- so bgp->my_as      == 65001
 *    bgp confederation identifier 99           -- so bgp->confed_id  == 99
 *    bgp confereration_peers 65002 65003
 *
 * We have a set of CONFED Member ASes, which includes my_as.
 *
 * When we speak to other routers in 65001, that is within our CONFED member AS
 * and is iBGP, and we preserve confed stuff in the path.  We OPEN connections
 * as AS65001.
 *
 * When we speak to other routers in 65002 or 65003, that is "cBGP"... which
 * almost eBGP, but we maintain the confed stuff in the path.  We OPEN
 * connections as AS65001.
 *
 * When we speak to other routers outside our confederation, that is eBGP, and
 * we strip any confed stuff from the path.  We OPEN connections as AS99 (the
 * bgp->confed_id).  IN bgp->ebgp_as we keep a copy of bgp->my_as or
 * bgp->confed_id, to give the ASN to peer as for eBGP in all cases (unless
 * have change_local_as... which is another story).
 */
typedef enum
{
  BGP_PEER_UNSPECIFIED,
  BGP_PEER_IBGP,
  BGP_PEER_CBGP,
  BGP_PEER_EBGP,
} bgp_peer_sort_t ;

/* Flag for peer_clear_soft().
 */
typedef enum
{
  BGP_CLEAR_HARD,
  BGP_CLEAR_SOFT_OUT,
  BGP_CLEAR_SOFT_IN,
  BGP_CLEAR_SOFT_BOTH,
  BGP_CLEAR_SOFT_IN_ORF_PREFIX,
  BGP_CLEAR_SOFT_RSCLIENT
} bgp_clear_type_t ;

/* BGP error codes,
 */
enum BGP_RET_CODE
{
  BGP_SUCCESS                            =   0,
  BGP_ERR_INVALID_VALUE                  =  -1,
  BGP_ERR_INVALID_FLAG                   =  -2,
  BGP_ERR_INVALID_AS                     =  -3,
  BGP_ERR_INVALID_BGP                    =  -4,
  BGP_ERR_PEER_GROUP_MEMBER              =  -5,
  BGP_ERR_MULTIPLE_INSTANCE_USED         =  -6,
  BGP_ERR_PEER_GROUP_MEMBER_EXISTS       =  -7,
  BGP_ERR_PEER_BELONGS_TO_GROUP          =  -8,
  BGP_ERR_PEER_GROUP_AF_UNCONFIGURED     =  -9,
  BGP_ERR_PEER_GROUP_NO_REMOTE_AS        = -10,
  BGP_ERR_PEER_GROUP_CANT_CHANGE         = -11,
  BGP_ERR_PEER_GROUP_MISMATCH            = -12,
  BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT = -13,
  BGP_ERR_MULTIPLE_INSTANCE_NOT_SET      = -14,
  BGP_ERR_AS_MISMATCH                    = -15,
  BGP_ERR_PEER_INACTIVE                  = -16,
  BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER  = -17,
  BGP_ERR_PEER_GROUP_HAS_THE_FLAG        = -18,
  BGP_ERR_PEER_FLAG_CONFLICT_1           = -19,
  BGP_ERR_PEER_FLAG_CONFLICT_2           = -20,
  BGP_ERR_PEER_FLAG_CONFLICT_3           = -21,
  BGP_ERR_PEER_GROUP_SHUTDOWN            = -22,
  BGP_ERR_PEER_FILTER_CONFLICT           = -23,
  BGP_ERR_NOT_INTERNAL_PEER              = -24,
  BGP_ERR_REMOVE_PRIVATE_AS              = -25,
  BGP_ERR_AF_UNCONFIGURED                = -26,
  BGP_ERR_SOFT_RECONFIG_UNCONFIGURED     = -27,
  BGP_ERR_INSTANCE_MISMATCH              = -28,
  BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP = -29,
  BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS   = -30,
  BGP_ERR_TCPSIG_FAILED                  = -31,
  BGP_ERR_PEER_EXISTS                    = -32,
  BGP_ERR_NO_EBGP_MULTIHOP_WITH_GTSM     = -33,
  BGP_ERR_NO_IBGP_WITH_TTLHACK           = -34,
  BGP_ERR_MAX                            = -35,
} ;
typedef enum BGP_RET_CODE bgp_ret_t ;

/*------------------------------------------------------------------------------
 * Globals.
 */
extern struct bgp_master *bm ;

extern qpn_nexus cli_nexus;
extern qpn_nexus bgp_nexus;
extern qpn_nexus routing_nexus;

extern struct zebra_privs_t bgpd_privs ;

/*------------------------------------------------------------------------------
 * For many purposes BGP requires a CLOCK_MONOTONIC type time, in seconds.
 */
Inline time_t
bgp_clock(void)
{
  return qt_get_mono_secs() ;
}

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

/*------------------------------------------------------------------------------
 * When reading and writing packets using stream buffers, we set the stream
 * to be a little larger than the maximum size of message.  Don't really expect
 * messages to overflow, and if they do, not by much -- so most of the time
 * we will know how badly the stream overflowed.
 */
enum { BGP_STREAM_SIZE = BGP_MSG_MAX_L * 5 / 4 } ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_terminate (bool, bool);
extern void bgp_reset (void);

extern void bgp_zclient_reset (void);                      /* See bgp_zebra ! */
extern int bgp_nexthop_set (union sockunion *, union sockunion *,
                     struct bgp_nexthop *, struct peer *); /* See bgp_zebra ! */

extern bgp_inst bgp_get_default (void);
extern bgp_inst bgp_lookup (as_t, const char *);
extern bgp_inst bgp_lookup_by_name (const char *);
extern bgp_inst bgp_lookup_vty(vty vty, const char *name) ;

extern int bgp_config_write (struct vty *);
extern void bgp_config_write_family_header (struct vty *, qafx_t, int *);

extern void bgp_master_init (void);

extern void bgp_init (void);
extern void bgp_route_map_cmd_init (void);
extern void bgp_route_map_init (void);

extern bgp_ret_t bgp_option_set (uint);
extern bgp_ret_t bgp_option_unset (uint);
extern bool bgp_option_check (uint);

extern bgp_ret_t bgp_get (bgp_inst*, as_t*, const char*);
extern bgp_ret_t bgp_delete (bgp_inst);

extern void bgp_flag_set (bgp_inst, uint);
extern void bgp_flag_unset (bgp_inst, uint);
extern bool bgp_flag_check (bgp_inst, uint);

extern bgp_inst bgp_lock (bgp_inst bgp) ;
extern bgp_inst bgp_unlock (bgp_inst bgp);

extern bgp_ret_t bgp_router_id_set (bgp_inst bgp, in_addr_t router_id,
                                                                     bool set) ;
extern bgp_ret_t bgp_cluster_id_set (bgp_inst bgp, in_addr_t cluster_id,
                                                                     bool set) ;

extern bgp_ret_t bgp_confederation_id_set (bgp_inst bgp, as_t as);
extern bgp_ret_t bgp_confederation_id_unset (bgp_inst bgp);
extern bool bgp_confederation_peers_check (bgp_inst bgp, as_t as);

extern bgp_ret_t bgp_confederation_peers_add (bgp_inst bgp, as_t asn);
extern bgp_ret_t bgp_confederation_peers_remove (bgp_inst bgp, as_t asn);
extern bgp_ret_t bgp_confederation_peers_scan(bgp_inst bgp) ;

extern bgp_ret_t bgp_timers_set (bgp_inst bgp, uint holdtime, uint keepalive);
extern bgp_ret_t bgp_timers_unset (bgp_inst bgp);
extern bgp_ret_t bgp_connect_retry_time_set (bgp_inst bgp,
                                                      uint connect_retry_secs) ;
extern bgp_ret_t bgp_connect_retry_time_unset (bgp_inst bgp) ;
extern bgp_ret_t bgp_accept_retry_time_set (bgp_inst bgp,
                                                      uint accept_retry_secs) ;
extern bgp_ret_t bgp_accept_retry_time_unset (bgp_inst bgp) ;
extern bgp_ret_t bgp_open_hold_time_set (bgp_inst bgp, uint openholdtime) ;
extern bgp_ret_t bgp_open_hold_time_unset (bgp_inst bgp) ;
extern bgp_ret_t bgp_mrai_set (bgp_inst bgp, uint ibgp_mrai, uint cbgp_mrai,
                                                             uint ebgp_mrai) ;
extern bgp_ret_t bgp_mrai_unset (bgp_inst bgp) ;

extern bgp_ret_t bgp_default_local_preference_set (bgp_inst, uint32_t);
extern bgp_ret_t bgp_default_local_preference_unset (bgp_inst);

extern void program_terminate_if_all_disabled(void);

#endif /* _QUAGGA_BGPD_H */
