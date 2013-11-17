/* BGP Peer -- header
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_PEER_H
#define _QUAGGA_BGP_PEER_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_notification.h"

#include "lib/plist.h"
#include "lib/list_util.h"

/*==============================================================================
 *
 */

enum bgp_route_map_types
{
  RMAP_IN       = 0,
  RMAP_OUT      = 1,
  RMAP_IMPORT   = 2,
  RMAP_EXPORT   = 3,
  RMAP_RS_IN    = 4,
  RMAP_MAX      = 5,
} ;

/*==============================================================================
 *
 */

/* Next hop self address. */
struct bgp_nexthop
{
  struct interface* ifp;
  struct in_addr    v4;
#ifdef HAVE_IPV6
  struct in6_addr  v6_global;
  struct in6_addr  v6_local;
#endif /* HAVE_IPV6 */
};

/* BGP filter structure. */
struct bgp_filter
{
  /* Distribute-list.  */
  struct
  {
    char *name;
    struct access_list *alist;
  } dlist[FILTER_MAX];

  /* Prefix-list.  */
  struct
  {
#if 1
    prefix_list_ref ref ;
#else
    char *name;
    struct prefix_list *plist;
#endif
  } plist[FILTER_MAX];

  /* Filter-list.  */
  struct
  {
    char *name;
    struct as_list *aslist;
  } aslist[FILTER_MAX];

  /* Route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } map[RMAP_MAX];

  /* Unsuppress-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } usmap;
};

/*==============================================================================
 * struct peer  -- the BGP neighbor structure.
 *
 *
 *
 */

enum PEER_DOWN {
  PEER_DOWN_first            =  0,

  PEER_DOWN_NULL             =  0, /* Not a PEER_DOWN                   */

  /* Session taken down at this end for some unspecified reason         */

  PEER_DOWN_UNSPECIFIED,

  /* Configuration changes that cause a session to be reset.            */

  PEER_DOWN_CONFIG_CHANGE,         /* Unspecified config change         */

  PEER_DOWN_RID_CHANGE,            /* 'bgp router-id'                      */
  PEER_DOWN_REMOTE_AS_CHANGE,      /* 'neighbor remote-as'                 */
  PEER_DOWN_LOCAL_AS_CHANGE,       /* 'neighbor local-as'                  */
  PEER_DOWN_CLID_CHANGE,           /* 'bgp cluster-id'                     */
  PEER_DOWN_CONFED_ID_CHANGE,      /* 'bgp confederation identifier'       */
  PEER_DOWN_CONFED_PEER_CHANGE,    /* 'bgp confederation peer'             */
  PEER_DOWN_RR_CLIENT_CHANGE,      /* 'neighbor route-reflector-client'    */
  PEER_DOWN_RS_CLIENT_CHANGE,      /* 'neighbor route-server-client'       */
  PEER_DOWN_UPDATE_SOURCE_CHANGE,  /* 'neighbor update-source'             */
  PEER_DOWN_AF_ACTIVATE,           /* 'neighbor activate'                  */
  PEER_DOWN_RMAP_BIND,             /* 'neighbor peer-group'                */
  PEER_DOWN_RMAP_UNBIND,           /* 'no neighbor peer-group'             */
  PEER_DOWN_DONT_CAPABILITY,       /* 'neighbor dont-capability-negotiate' */
  PEER_DOWN_OVERRIDE_CAPABILITY,   /* 'neighbor override-capability'       */
  PEER_DOWN_STRICT_CAP_MATCH,      /* 'neighbor strict-capability-match'   */
  PEER_DOWN_CAPABILITY_CHANGE,     /* 'neighbor capability'                */
  PEER_DOWN_PASSIVE_CHANGE,        /* 'neighbor passive'                   */
  PEER_DOWN_MULTIHOP_CHANGE,       /* 'neighbor multihop'                  */
  PEER_DOWN_AF_DEACTIVATE,         /* 'no neighbor activate'               */
  PEER_DOWN_PASSWORD_CHANGE,       /* password changed                     */
  PEER_DOWN_ALLOWAS_IN_CHANGE,     /* allowas-in change                    */

  /* Other actions that cause a session to be reset                     */

  PEER_DOWN_USER_SHUTDOWN,         /* 'neighbor shutdown'               */
  PEER_DOWN_USER_RESET,            /* 'clear ip bgp'                    */
  PEER_DOWN_NEIGHBOR_DELETE,       /* neighbor delete                   */

  PEER_DOWN_INTERFACE_DOWN,        /* interface reported to be down     */

  /* Errors and problems that cause a session to be reset               */

  PEER_DOWN_MAX_PREFIX,            /* max prefix limit exceeded         */

  PEER_DOWN_HEADER_ERROR,          /* error in BGP Message header       */
  PEER_DOWN_OPEN_ERROR,            /* error in BGP OPEN message         */
  PEER_DOWN_UPDATE_ERROR,          /* error in BGP UPDATE message       */
  PEER_DOWN_HOLD_TIMER,            /* HoldTimer expired                 */
  PEER_DOWN_FSM_ERROR,             /* error in FSM sequence             */
  PEER_DOWN_DYN_CAP_ERROR,         /* error in Dynamic Capability       */

  /* Things the far end can do to cause a session to be reset           */

  PEER_DOWN_NOTIFY_RECEIVED,       /* notification received             */
  PEER_DOWN_CLOSE_SESSION,         /* tcp session close                 */
  PEER_DOWN_NSF_CLOSE_SESSION,     /* NSF tcp session close             */

  /* Number of down causes                                              */
  PEER_DOWN_count
} ;

typedef enum PEER_DOWN peer_down_t ;




struct peer
{
  /* BGP structure.  */
  struct bgp *bgp;

  /* reference count, primarily to allow bgp_process'ing of route_node's
   * to be done after a struct peer is deleted.
   *
   * named 'lock' for hysterical reasons within Quagga.
   */
  int lock;

  /* BGP peer group.  */
  struct peer_group *group;
  u_char af_group[AFI_MAX][SAFI_MAX];

  /* Peer's remote AS number. */
  as_t as;

  /* Peer's local AS number. */
  as_t local_as;

  /* Peer's Change local AS number. */
  as_t change_local_as;

  /* Remote router ID. */
  struct in_addr remote_id;

  /* Local router ID. */
  struct in_addr local_id;

  /* Peer specific RIB when configured as route-server-client.  */
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];

  /* Collection of routes originated by peer                    */
  struct bgp_info* routes[AFI_MAX][SAFI_MAX] ;

  /* Collection of adj_in routes                                */
  struct bgp_adj_in* adj_ins[AFI_MAX][SAFI_MAX] ;

  /* Collection of adj_out routes -- base of sdl-list           */
  struct bgp_adj_out* adj_outs[AFI_MAX][SAFI_MAX] ;

  /* Packet receive buffer. */
  struct stream *ibuf;

  struct stream_fifo *obuf;
  struct stream *work;

  /* Status of the peer. */
  bgp_peer_state_t state;       /* current state                        */
  bgp_peer_state_t ostate;      /* old state                            */

  /* Peer index, used for dumping TABLE_DUMP_V2 format */
  uint16_t table_dump_index;

  /* Peer information */
  bgp_peer_index_entry  index_entry ;
  bgp_session  session ;        /* Current session                      */

  int   ttl ;                   /* TTL of TCP connection to the peer.   */
  bool  gtsm ;                  /* ttl set by neighbor xxx ttl_security */

  char *desc;                   /* Description of the peer.             */
  unsigned short port;          /* Destination port for peer            */
  char *host;                   /* Printable address of the peer.       */
  union sockunion su;           /* Sockunion address of the peer.       */
  time_t uptime;                /* Last Up/Down time                    */
  time_t readtime;              /* Last read time                       */
  time_t resettime;             /* Last reset time                      */

  unsigned int ifindex;         /* ifindex of the BGP connection.       */
  char *ifname;                 /* bind interface name.                 */
  char *update_if;
  union sockunion *update_source;
  struct zlog *log;

  union sockunion *su_local;    /* Sockunion of local address.          */
  union sockunion *su_remote;   /* Sockunion of remote address.         */
  int shared_network;           /* Is this peer shared same network.    */
  struct bgp_nexthop nexthop;   /* Nexthop                              */

  /* Peer address family configuration. */
  u_char afc[AFI_MAX][SAFI_MAX];
  u_char afc_nego[AFI_MAX][SAFI_MAX];
  u_char afc_adv[AFI_MAX][SAFI_MAX];
  u_char afc_recv[AFI_MAX][SAFI_MAX];

  /* Capability flags (reset in bgp_stop) */
  u_int16_t cap;
#define PEER_CAP_REFRESH_ADV                (1 << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_OLD_RCV            (1 << 1) /* refresh old received */
#define PEER_CAP_REFRESH_NEW_RCV            (1 << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV                (1 << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV                (1 << 4) /* dynamic received */
#define PEER_CAP_RESTART_ADV                (1 << 5) /* restart advertised */
#define PEER_CAP_RESTART_RCV                (1 << 6) /* restart received */
#define PEER_CAP_AS4_ADV                    (1 << 7) /* as4 advertised */
#define PEER_CAP_AS4_RCV                    (1 << 8) /* as4 received */

#define PEER_CAP_SUPPRESSED                 (1 << 9) /* none sent       */

#define PEER_CAP_AS4_BOTH (PEER_CAP_AS4_ADV + PEER_CAP_AS4_RCV)
#define PEER_CAP_AS4_USE(peer) \
  (((peer)->cap & PEER_CAP_AS4_BOTH) == PEER_CAP_AS4_BOTH)

  /* Capability flags (reset in bgp_stop) */
  u_int16_t af_cap[AFI_MAX][SAFI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1 << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1 << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1 << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1 << 3) /* receive-mode received */
#define PEER_CAP_ORF_PREFIX_SM_OLD_RCV      (1 << 4) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_OLD_RCV      (1 << 5) /* receive-mode received */
#define PEER_CAP_RESTART_AF_RCV             (1 << 6) /* graceful restart afi/safi received */
#define PEER_CAP_RESTART_AF_PRESERVE_RCV    (1 << 7) /* graceful restart afi/safi F-bit received */

  /* Global configuration flags. */
  u_int32_t flags;
#define PEER_FLAG_PASSIVE                   (1 << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1 << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1 << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1 << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1 << 4) /* strict-match */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1 << 5) /* dynamic capability */
#define PEER_FLAG_DISABLE_CONNECTED_CHECK   (1 << 6) /* disable-connected-check */
#define PEER_FLAG_LOCAL_AS_NO_PREPEND       (1 << 7) /* local-as no-prepend */

  /* NSF mode (graceful restart) */
  u_char nsf[AFI_MAX][SAFI_MAX];

  /* Per AF configuration flags. */
  u_int32_t af_flags[AFI_MAX][SAFI_MAX];
#define PEER_FLAG_SEND_COMMUNITY            (1 << 0) /* send-community */
#define PEER_FLAG_SEND_EXT_COMMUNITY        (1 << 1) /* send-community ext. */
#define PEER_FLAG_NEXTHOP_SELF              (1 << 2) /* next-hop-self */
#define PEER_FLAG_REFLECTOR_CLIENT          (1 << 3) /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT            (1 << 4) /* route-server-client */
#define PEER_FLAG_SOFT_RECONFIG             (1 << 5) /* soft-reconfiguration */
#define PEER_FLAG_AS_PATH_UNCHANGED         (1 << 6) /* transparent-as */
#define PEER_FLAG_NEXTHOP_UNCHANGED         (1 << 7) /* transparent-next-hop */
#define PEER_FLAG_MED_UNCHANGED             (1 << 8) /* transparent-next-hop */
#define PEER_FLAG_DEFAULT_ORIGINATE         (1 << 9) /* default-originate */
#define PEER_FLAG_REMOVE_PRIVATE_AS         (1 << 10) /* remove-private-as */
#define PEER_FLAG_ALLOWAS_IN                (1 << 11) /* set allowas-in */
#define PEER_FLAG_ORF_PREFIX_SM             (1 << 12) /* orf capability send-mode */
#define PEER_FLAG_ORF_PREFIX_RM             (1 << 13) /* orf capability receive-mode */
#define PEER_FLAG_MAX_PREFIX                (1 << 14) /* maximum prefix */
#define PEER_FLAG_MAX_PREFIX_WARNING        (1 << 15) /* maximum prefix warning-only */
#define PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED   (1 << 16) /* leave link-local nexthop unchanged */

  /* MD5 password */
  char *password;

  /* default-originate route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } default_rmap[AFI_MAX][SAFI_MAX];

  /* Peer status flags. */
  u_int16_t sflags;
#define PEER_STATUS_REAL_PEER         (1 << 0) /* not group conf or peer_self */
#define PEER_STATUS_PREFIX_OVERFLOW   (1 << 1) /* prefix-overflow             */
#define PEER_STATUS_GROUP             (1 << 3) /* peer-group conf             */
#define PEER_STATUS_NSF_MODE          (1 << 4) /* NSF aware peer              */
#define PEER_STATUS_NSF_WAIT          (1 << 5) /* wait comeback peer          */

  /* Peer status af flags (reset in bgp_stop) */
  u_int16_t af_sflags[AFI_MAX][SAFI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND   (1 << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH  (1 << 1) /* wait refresh received peer */
#define PEER_STATUS_DEFAULT_ORIGINATE (1 << 2) /* default-originate peer */
#define PEER_STATUS_PREFIX_THRESHOLD  (1 << 3) /* exceed prefix-threshold */
#define PEER_STATUS_PREFIX_LIMIT      (1 << 4) /* exceed prefix-limit */
#define PEER_STATUS_EOR_SEND          (1 << 5) /* end-of-rib send to peer */
#define PEER_STATUS_EOR_RECEIVED      (1 << 6) /* end-of-rib received from peer */

  /* Default attribute value for the peer.
   */
  u_int32_t config;
#define PEER_CONFIG_WEIGHT            (1 << 0) /* Default weight.       */
#define PEER_CONFIG_TIMER             (1 << 1) /* keepalive & holdtime  */
#define PEER_CONFIG_CONNECT           (1 << 2) /* connect               */
#define PEER_CONFIG_ROUTEADV          (1 << 3) /* route advertise       */

  uint16_t  weight;
  uint32_t  holdtime;
  uint32_t  keepalive;
  uint32_t  connect;
  uint32_t  routeadv;

  /* Timer and other values
   */
  uint32_t  v_start;
  uint32_t  v_connect;
  uint32_t  v_holdtime;
  uint32_t  v_keepalive;
  uint32_t  v_asorig;
  uint32_t  v_routeadv;
  uint32_t  v_pmax_restart;
  uint32_t  v_gr_restart;

  /* Threads.                                           */
  struct thread *t_withdraw ;
  struct thread *t_routeadv;
  struct thread *t_pmax_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;

  /* BGP state count                                    */
  u_int32_t established;
  u_int32_t dropped;

  /* Synchronization list and time.                     */
  struct bgp_synchronize *sync[AFI_MAX][SAFI_MAX];
  time_t synctime;

  bool   do_updates ;

  /* Send prefix count.                                 */
  unsigned long scount[AFI_MAX][SAFI_MAX];

  /* Filter structure.                                  */
  struct bgp_filter filter[AFI_MAX][SAFI_MAX];

  /* ORF Prefix-list                                    */
  struct prefix_list *orf_plist[AFI_MAX][SAFI_MAX];

  /* Prefix count.                                      */
  unsigned long pcount[AFI_MAX][SAFI_MAX];

  /* Max prefix count.                                  */
  unsigned long pmax[AFI_MAX][SAFI_MAX];
  u_char pmax_threshold[AFI_MAX][SAFI_MAX];
  u_int16_t pmax_restart[AFI_MAX][SAFI_MAX];
#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

  /* allowas-in.                                        */
  char allowas_in[AFI_MAX][SAFI_MAX];

  /* peer reset cause                                   */
  peer_down_t last_reset;

  bgp_notify notification ;

  /* The kind of route-map Flags.                       */
  u_int16_t rmap_type;
#define PEER_RMAP_TYPE_IN             (1 << 0) /* neighbor route-map in       */
#define PEER_RMAP_TYPE_OUT            (1 << 1) /* neighbor route-map out      */
#define PEER_RMAP_TYPE_NETWORK        (1 << 2) /* network route-map           */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1 << 3) /* redistribute route-map      */
#define PEER_RMAP_TYPE_DEFAULT        (1 << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_NOSET          (1 << 5) /* not allow to set commands   */
#define PEER_RMAP_TYPE_IMPORT         (1 << 6) /* neighbor route-map import   */
#define PEER_RMAP_TYPE_EXPORT         (1 << 7) /* neighbor route-map export   */
#define PEER_RMAP_TYPE_RS_IN          (1 << 8) /* neighbor route-map rs-in    */
} ;


#define BGP_TIMER_ON(T,F,V)                     \
  do {                                          \
    if (!(T) && (peer->state != bgp_peer_pDeleting))    \
      THREAD_TIMER_ON(master,(T),(F),peer,(V)); \
  } while (0)

#define BGP_TIMER_OFF(T)                        \
  do {                                          \
    if (T)                                      \
      THREAD_TIMER_OFF(T);                      \
  } while (0)

#if 0
#define BGP_EVENT_ADD(P,E)                      \
  do {                                          \
    if ((P)->state != bgp_peer_pDeleting)                       \
      thread_add_event (master, bgp_event, (P), (E)); \
  } while (0)

#define BGP_EVENT_FLUSH(P)                      \
  do {                                          \
    assert (peer);                              \
    thread_cancel_event (master, (P));          \
  } while (0)

/* Prototypes. */
extern int bgp_event (struct thread *);
extern int bgp_stop (struct peer *peer);
#if 0
extern void bgp_timer_set (struct peer *);
#endif
extern void bgp_fsm_change_status (struct peer *peer, int status);

#endif

extern const char *peer_down_str[];

/*==============================================================================
 *
 */

extern void bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag);
extern void bgp_peer_enable(bgp_peer peer);
extern void bgp_peer_down(bgp_peer peer, peer_down_t why_down) ;
extern void bgp_peer_down_error(bgp_peer peer,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern void bgp_peer_down_error_with_data (bgp_peer peer,
                              bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                         const u_int8_t* data, size_t datalen) ;
extern void bgp_peer_clearing_completed(bgp_peer peer) ;
extern bgp_peer bgp_peer_new (struct bgp *bgp);
extern bgp_peer bgp_peer_create (sockunion su, struct bgp *bgp, as_t local_as,
                                        as_t remote_as, afi_t afi, safi_t safi);
extern bgp_peer bgp_peer_lock (bgp_peer peer) ;
extern bgp_peer bgp_peer_unlock (bgp_peer peer) ;
extern int bgp_peer_delete (bgp_peer peer);
extern sockunion bgp_peer_get_ifaddress(bgp_peer peer, const char* ifname,
                                                               sa_family_t af) ;
extern void bgp_withdraw_schedule(bgp_peer peer) ;

#endif /* _QUAGGA_BGP_PEER_H */

