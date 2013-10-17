/* BGP Peer and Peer-Group Configuration -- Header
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Restructured: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_PEER_CONFIG_H
#define _QUAGGA_BGP_PEER_CONFIG_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_peer_index.h"

#include "filter.h"
#include "plist.h"
#include "sockunion.h"
#include "name_index.h"

/*==============================================================================
 * This deals with the update of peer and peer-group configuration settings.
 */

/*------------------------------------------------------------------------------
 * The structure for each peer.
 *
 * Most bgp_peer structures are "real" peers, but each peer group uses one to
 * hold the group configuration, and each bgp instance uses one for static
 * routes etc.
 *
 * NB: when comparing peers, the value of the peer-type is most significant.
 */
typedef enum peer_type bgp_peer_type_t ;
enum peer_type
{
  PEER_TYPE_NULL        = 0,
  PEER_TYPE_SELF        = 1,           /* holder of statics etc       */
  PEER_TYPE_GROUP       = 2,           /* peer-group conf             */
  PEER_TYPE_REAL        = 3,           /* not group conf or peer_self */
} ;

typedef struct bgp_peer bgp_peer_t ;
typedef struct bgp_peer const* bgp_peer_c ;

struct bgp_peer
{
  /* The bgp instance this belongs to.
   */
  bgp_inst       parent_bgp ;

  /* Peer structures are:
   *
   *   * PEER_TYPE_REAL    -- ordinary "real" peers
   *
   *                          Live on the bgp instance's a list of peers, and
   *                          in the peer index.
   *
   *                          A PEER_TYPE_REAL may be a member of a group, in
   *                          one or more afi/safi.
   *
   *   * PEER_TYPE_GROUP -- where the configuration of a group is stored.
   *
   *                          The parent peer_group structure points here.
   *
   *                          The pointer to the bgp instance is a duplicate
   *                          of the pointer in the peer_group.
   *
   *   * PEER_TYPE_SELF    -- one per bgp instance, for static routes etc.
   */
  bgp_peer_type_t ptype ;

  bgp_peer_id_t   peer_id ;
  uint            group_id ;

  /* The name is:
   *
   *   * PEER_TYPE_REAL         -- "cannonical" form of the neighbor address.
   *
   *   * PEER_TYPE_GROUP   -- the given name of the group
   *
   *   * PEER_TYPE_SELF         -- NULL
   */
  chs_t     name ;              /* name of the peer/group (text)        */
  chs_t     cname ;

  /* For real peers.... TODO
   */
  sockunion_t   su_name[1] ;    /* Name of the peer is address of same  */
  bgp_prun      prun ;

  bool          changed ;
  struct dl_list_pair(bgp_peer) pending ;

  /* The configuration for the peer or the peer-group.
   */
  bgp_pconfig   c ;
};

/*------------------------------------------------------------------------------
 *
 */
typedef enum bgp_peer_or_group bgp_peer_or_group_t ;
enum bgp_peer_or_group
{
  bpog_peer_ip        = BIT(0),
  bpog_group_name     = BIT(1),
  bpog_peer_or_group  = bpog_peer_ip | bpog_group_name,
} ;

/*==============================================================================
 * Peer and Peer-Group Configuration
 * ---------------------------------
 *
 * For each configuration item we have a "set" bit, to signal that the
 * peer/peer-group has setting for the item.  The same bits are used to
 * track changes in configuration -- so that when changes are made to the
 * bgp instance or a peer-group, only those changes need to be propagated
 * across all peers.
 *
 *
 *
 */

/* The pcs_xxxx -- names of the configuration items which are general for a
 * peer or peer-group -- that is, they apply to the peer or peer-group as a
 * whole.
 */
typedef enum bgp_pc_setting  bgp_pc_setting_t ;
enum bgp_pc_setting
{
  /* These first settings are simple "flag" values.
   */
  pcs_SHUTDOWN                 = 0,

  /* For current Quagga these have "flag" semantics -- see bgp_cpnf.c
   */
  pcs_PASSIVE,                  /* ) interact with each other           */
  pcs_ACTIVE,                   /* )                                    */

  pcs_DONT_CAPABILITY,          /* )                                    */
  pcs_OVERRIDE_CAPABILITY,      /* ) interact with each other           */
  pcs_STRICT_CAP_MATCH,         /* )                                    */

  pcs_DYNAMIC_CAPABILITY,       /* ) interact with each other           */
  pcs_DYNAMIC_CAPABILITY_DEP,   /* )                                    */

  pcs_DISABLE_CONNECTED_CHECK,

  pcs_count_of_flags,

  /* The qafx for which the peer-group or peer is configured.
   *
   * NB: these are NOT inherited from any peer-group to which a peer may be
   *     bound.
   */
  pcs_qafx_first        = pcs_count_of_flags,
  pcs_qafx_last         = pcs_qafx_first + (qafx_last - qafx_first),

  /* These settings are for more general values
   *
   * Description does not affect the running state !  Nor does the group value
   * affect any peer.
   */
  pcs_description,

  /* pcs_group        is set "on" when the peer is a group-member for general
   *                  configuration.
   *
   * pcs_remote_as    is set "on" where the peer-group or peer has an explicit
   *                  remote-as setting.
   *
   *                  a peer-group need not have a setting.
   *
   *                  a peer MUST have a setting, or be bound to a peer-group
   *                  which does.
   */
  pcs_group,
  pcs_remote_as,

  /* "value" semantics -- see bgp_config.c
   */
  pcs_weight,
  pcs_password,
  pcs_update_source,

  /* multi-hop and ttl_security have basically "value" semantics, except:
   *
   *   * may not set/unset multi-hop if peer/group or any group member has
   *     ttl_security set.
   *
   *   * may not set/unset ttl_security if peer/group or any group member has
   *     multi-hop set.
   *
   * The problem is that changing between the two has quite serious effects on
   * the peer... so cannot simply force a group member to follow the group
   * if the member is (say) multi-hop and the group is (say) ttl_security.
   */
  pcs_multihop,
  pcs_ttl_security,

  /* "group value" semantics -- see bgp_config.c
   */
  pcs_timers,
  pcs_change_local_as,
  pcs_connect_retry,

  /* "peer value" semantics: group may not have a value.
   */
  pcs_port,
  pcs_mrai,

  pcs_count_of_settings
};

CONFIRM(pcs_count_of_settings <= 64) ;

typedef uint64_t bgp_pc_set_t ;
#define pcs_bit(n) BIT64(n)
#define pcs_qafx_bit(q) pcs_bit(pcs_qafx_first + (q) - qafx_first)

#define pcs_qafx_mask (pcs_bit(pcs_qafx_last + 1) - pcs_bit(pcs_qafx_first))
CONFIRM((pcs_qafx_last + 1) < 64) ;

/*------------------------------------------------------------------------------
 * The pconf structure.
 *
 * This captures all the values which are set by configuration for a peer.
 *
 * The effective configuration for a peer is a combination of the peer's
 * own configuration, any group of which it is a member and the bgp instance
 * of which it is a member.
 *
 * It is explicitly intended that a change in configuration may be detected
 * by comparing two pconf structures
 *
 * Some of the elements of a pconf are "names".  Those are implemented as
 * pointers to a
 *
 */
#if 0
/* The peer_flag_t are configuration flags for the entire peer.
 */
typedef enum bgp_pflag bgp_pflag_t ;
enum bgp_pflag
{
  PEER_FLAG_NOTHING                  = 0,

  PEER_FLAG_SHUTDOWN                 = BIT(pcs_SHUTDOWN),
  PEER_FLAG_PASSIVE                  = BIT(pcs_PASSIVE),
  PEER_FLAG_ACTIVE                   = BIT(pcs_ACTIVE),
  PEER_FLAG_DONT_CAPABILITY          = BIT(pcs_DONT_CAPABILITY),
  PEER_FLAG_OVERRIDE_CAPABILITY      = BIT(pcs_OVERRIDE_CAPABILITY),
  PEER_FLAG_STRICT_CAP_MATCH         = BIT(pcs_STRICT_CAP_MATCH),
  PEER_FLAG_DYNAMIC_CAPABILITY       = BIT(pcs_DYNAMIC_CAPABILITY),
  PEER_FLAG_DYNAMIC_CAPABILITY_DEP   = BIT(pcs_DYNAMIC_CAPABILITY_DEP),
  PEER_FLAG_DISABLE_CONNECTED_CHECK  = BIT(pcs_DISABLE_CONNECTED_CHECK),
} ;
#endif


typedef enum bgp_pconfig_type bgp_pconfig_type_t ;
enum bgp_pconfig_type
{
  BGP_CFT_NULL          = 0,

  BGP_CFT_PEER          = 1,    /* genuine peer                 */
  BGP_CFT_GROUP         = 2,    /* peer-group conf              */
  BGP_CFT_MEMBER        = 3,    /* peer-group-member            */
} ;

typedef struct bgp_pconfig  bgp_pconfig_t ;
typedef struct bgp_pconfig const* bgp_pconfig_c ;

struct bgp_pconfig
{
  bgp_peer  parent_peer ;       /* parent bgp_peer object       */

  char*     desc ;

  /* BGP_CFT_PEER has:   gc             -- NULL -- no group association
   *                     members        -- NULL
   *
   * BGP_CFT_GROUP has:  gc             -- NULL -- no group association !
   *                     members        -- vector of members -- bgp_paf_config
   *
   * BGP_CFT_MEMBER has: gc             -- configuration of group is member of,
   *                     members        -- NULL
   */
  bgp_pconfig_type_t    ctype ;

  bgp_pconfig   gc ;
  vector        members ;       /* bgp_pconfig  */

  /* All peers have a remote-as, some peer-groups do.
   *
   * Where a peer-group has a remote-as, all peers follow that -- in this case
   * a group member may not have its own remote-as.  For the group member, the
   * setting is "off", but the remote-as value is valid (and is a copy of the
   * group's value).
   */
  as_t          remote_as ;

  /* The bit-vector of items for which this configuration has a setting, and
   * a bit-vector of items which are set "on".
   */
  bgp_pc_set_t  set ;
  bgp_pc_set_t  set_on ;

  /* Values which are generally inherited from the bgp instance, but which
   * may be set on a per peer/peer-group basis.
   */
  uint16_t port ;

  uint  local_pref;
  uint  med ;
  uint  weight ;

  uint  holdtime_secs ;
  uint  keepalive_secs ;
  uint  connect_retry_secs ;
  uint  accept_retry_secs ;
  uint  open_hold_secs ;

  uint  mrai_secs ;

  /* Other peer/peer-group level stuff
   *
   * TODO setting for mp_ext on per peer basis ?
   * TODO setting for as4 on a per peer basis ?
   * TODO setting for route refresh on a per peer basis ?
   */
  as_t      change_local_as ;
  bool      change_local_as_prepend ;

  ttl_t     ttl ;               /* 1..TTL_MAX                           */
  bool      gtsm ;              /* set GTSM if possible                 */

  nref_c    password ;
  nref_c    update_source ;

  /* The afc specific stuff.
  */
  qafx_set_t    af_configured ;

  bgp_paf_config afc[qafx_count] ;
} ;

Inline bool
pcs_is_set(bgp_pconfig pc, bgp_pc_setting_t pcs)
{
  return (pc->set & pcs_bit(pcs)) ;
} ;

Inline bool
pcs_is_on(bgp_pconfig pc, bgp_pc_setting_t pcs)
{
  return (pc->set & pc->set_on & pcs_bit(pcs)) ;
} ;

Inline bool
pcs_is_off(bgp_pconfig pc, bgp_pc_setting_t pcs)
{
  return (pc->set & ~pc->set_on & pcs_bit(pcs)) ;
} ;

Inline bool
pcs_qafx_config(bgp_pconfig pc, qafx_t qafx)
{
  return (pc->set & pc->set_on & pcs_qafx_bit(pcs_qafx_bit(qafx))) ;
} ;

Inline qafx_set_t
pcs_qafxs(bgp_pconfig pc)
{
  return ((pc->set_on & pc->set) >> pcs_qafx_first) & qafx_known_bits ;

  confirm((pcs_qafx_bit(qafx_first) >> pcs_qafx_first) == qafx_first_bit) ;
}

/*------------------------------------------------------------------------------
 * The AFI/SAFI Specific configuration.
 */
typedef enum bgp_pafc_setting  bgp_pafc_setting_t ;
enum bgp_pafc_setting
{
  /* These first settings are simple "flag" values.
   *
   * "flag" semantics
   */
  pafcs_SOFT_RECONFIG           = 0,
  pafcs_NEXTHOP_LOCAL_UNCHANGED,

  /* "group flag" semantics -- see bgp_config.c.
   */
  pafcs_RSERVER_CLIENT,
  pafcs_REFLECTOR_CLIENT,
  pafcs_SEND_COMMUNITY,
  pafcs_SEND_EXT_COMMUNITY,
  pafcs_NEXTHOP_SELF,
  pafcs_NEXTHOP_UNCHANGED,
  pafcs_AS_PATH_UNCHANGED,
  pafcs_REMOVE_PRIVATE_AS,
  pafcs_MED_UNCHANGED,
  pafcs_DEFAULT_ORIGINATE,

  pafcs_ORF_SEND,               // TODO
  pafcs_ORF_RECV,               // TODO

  pafcs_count_of_flags,

  /* Group membership.
   */
  pafcs_group                   = pafcs_count_of_flags,

  /* These settings are for more general values
   *
   * "value" semantics
   */
  pafcs_max_prefix,
  pafcs_allow_as_in,
  pafcs_dlist_in,
  pafcs_plist_in,
  pafcs_aslist_in,
  pafcs_rmap_in,
  pafcs_rmap_inx,
  pafcs_rmap_export,

  /* "group value" semantics
   */
  pafcs_default_rmap,
  pafcs_dlist_out,
  pafcs_plist_out,
  pafcs_aslist_out,
  pafcs_rmap_import,
  pafcs_rmap_out,
  pafcs_us_rmap,

  pafcs_count_of_settings
};

CONFIRM(pafcs_count_of_settings <= 64) ;

typedef uint64_t bgp_pafc_set_t ;
#define pafcs_bit(n) BIT64(n)

#if 0
typedef enum bgp_paf_flag bgp_paf_flag_t ;
enum bgp_paf_flag
{
  PEER_AFF_NOTHING                 = 0,

  /* These are configuration flags, for per afi/safi configuration stuff.
   */
  PEER_AFF_SOFT_RECONFIG            = BIT(pafcs_SOFT_RECONFIG),
  PEER_AFF_RSERVER_CLIENT           = BIT(pafcs_RSERVER_CLIENT),
  PEER_AFF_REFLECTOR_CLIENT         = BIT(pafcs_REFLECTOR_CLIENT),
  PEER_AFF_SEND_COMMUNITY           = BIT(pafcs_SEND_COMMUNITY),
  PEER_AFF_SEND_EXT_COMMUNITY       = BIT(pafcs_SEND_EXT_COMMUNITY),
  PEER_AFF_NEXTHOP_SELF             = BIT(pafcs_NEXTHOP_SELF),
  PEER_AFF_NEXTHOP_UNCHANGED        = BIT(pafcs_NEXTHOP_UNCHANGED),
  PEER_AFF_NEXTHOP_LOCAL_UNCHANGED  = BIT(pafcs_NEXTHOP_LOCAL_UNCHANGED),
  PEER_AFF_AS_PATH_UNCHANGED        = BIT(pafcs_AS_PATH_UNCHANGED),
  PEER_AFF_REMOVE_PRIVATE_AS        = BIT(pafcs_REMOVE_PRIVATE_AS),
  PEER_AFF_MED_UNCHANGED            = BIT(pafcs_MED_UNCHANGED),
  PEER_AFF_DEFAULT_ORIGINATE        = BIT(pafcs_DEFAULT_ORIGINATE),
} ;
#endif

typedef struct bgp_paf_config  bgp_paf_config_t ;
typedef struct bgp_paf_config const* bgp_paf_config_c ;

struct bgp_paf_config
{
  bgp_pconfig   parent_pconf ;
  qafx_t        qafx ;

  /* The pconfig-type, gafc and members are used for group membership
   * at the address family level -- in the same way as the main config.
   */
  bgp_pconfig_type_t    ctype ;

  bgp_paf_config gafc ;
  vector        members ;               /* bgp_paf_config       */

  /* The configuration settings.
   */
  bgp_pafc_set_t    set ;
  bgp_pafc_set_t    set_on ;

  uint          allow_as_in ;

  nref_c        filter_set[bfs_count] ;

  prefix_max_t  pmax ;
};

Inline bool
pafcs_is_set(bgp_paf_config pafc, bgp_pafc_setting_t pafcs)
{
  return (pafc->set & pafcs_bit(pafcs)) ;
} ;

Inline bool
pafcs_is_on(bgp_paf_config pafc, bgp_pafc_setting_t pafcs)
{
  return (pafc->set & pafc->set_on & pafcs_bit(pafcs)) ;
} ;

/*==============================================================================
 * Prototypes.
 */
extern bool bgp_peer_config_write (vty vty, bgp_peer peer, bool done_peer) ;

extern bgp_ret_t bgp_peer_create_peer(bgp_inst bgp, sockunion su, as_t as,
                                                               bgp_peer group) ;
extern bgp_ret_t bgp_peer_create_group(bgp_inst bgp, chs_c g_str) ;

extern bgp_ret_t bgp_peer_delete (bgp_peer peer);

extern bgp_ret_t bgp_peer_as_set(bgp_peer peer, as_t as, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_group_set(bgp_peer peer, bgp_peer group, qafx_t qafx,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_af_set(bgp_peer peer, qafx_t qafx, bgp_sc_t bsc) ;

extern bgp_peer_sort_t bgp_peer_as_sort(bgp_inst bgp, as_t asn) ;

extern bgp_ret_t bgp_peer_sex(chs_c p_str, sockunion su,
                                                      bgp_peer_or_group_t bpg) ;
extern bgp_peer bgp_peer_lookup_su(bgp_inst bgp, sockunion su) ;
extern bgp_peer bgp_peer_lookup_group(bgp_inst bgp, chs_c g_str) ;
extern bool bgp_peer_ipv4_default(bgp_peer peer) ;

extern bgp_ret_t bgp_peer_flag_modify(bgp_peer peer,
                                           bgp_pc_setting_t pcs, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_af_flag_modify(bgp_peer peer, qafx_t qafx,
                                       bgp_pafc_setting_t pafcs, bgp_sc_t bsc) ;

extern bgp_ret_t bgp_peer_multihop_set (bgp_peer peer, ttl_t ttl,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_ttl_security_hops_set (bgp_peer peer, ttl_t ttl,
                                                                  bgp_sc_t bsc);
extern bgp_ret_t bgp_peer_description_set (bgp_peer peer, chs_c desc);
extern bgp_ret_t bgp_peer_update_source_if_set (bgp_peer peer, chs_c ifname);
extern bgp_ret_t bgp_peer_update_source_addr_set (bgp_peer peer, chs_c addr,
                                                                  sockunion su);
extern bgp_ret_t bgp_peer_update_source_unset (bgp_peer peer);
extern bgp_ret_t bgp_peer_interface_set (bgp_peer peer, chs_c ifname,
                                                                  bgp_sc_t bsc);
extern bgp_ret_t bgp_peer_default_originate_set (bgp_peer peer, qafx_t qafx,
                                                chs_c rmap_name, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_port_set (bgp_peer peer, uint16_t port, bgp_sc_t bsc);
extern bgp_ret_t bgp_peer_weight_set (bgp_peer peer, uint weight, bgp_sc_t bsc);
extern bgp_ret_t bgp_peer_timers_set (bgp_peer peer, uint keepalive,
                                                 uint holdtime, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_timers_connect_set (bgp_peer peer,
                                        uint connect_retry_secs, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_advertise_interval_set (bgp_peer peer, uint mrai_secs,
                                                                  bgp_sc_t bsc);
extern bgp_ret_t bgp_peer_allow_as_in_set (bgp_peer peer, qafx_t qafx,
                                                     uint allow, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_local_as_set (bgp_peer peer, as_t asn, bool no_prepend,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_password_set (bgp_peer peer, chs_c password,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_maximum_prefix_set (bgp_peer peer, qafx_t qafx,
                 uint32_t max, byte thresh_pc, bool warning, uint16_t restart,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_peer_filter_set(bgp_peer peer, qafx_t qafx,
                         bgp_pafc_setting_t setting, chs_c name, bgp_sc_t bsc) ;

extern void bgp_peer_distribute_update (access_list alist) ;
extern void bgp_peer_prefix_list_update (prefix_list plist) ;
extern void bgp_peer_aslist_update (void) ;

#endif /* _QUAGGA_BGP_PEER_CONFIG_H */
