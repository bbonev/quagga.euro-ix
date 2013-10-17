/* BGP Common -- functions
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

#ifndef _QUAGGA_BGP_COMMON_H
#define _QUAGGA_BGP_COMMON_H

#include "misc.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ip.h>

#include "bgpd/bgp.h"
#include "qafi_safi.h"

/*==============================================================================
 * Here are a number of "incomplete" declarations, which allow a number of
 * bgpd structures to refer to each other.
 */
typedef struct bgp_env*         bgp_env ;
typedef struct bgp_inst*        bgp_inst ;
typedef struct bgp_run*         bgp_run ;
typedef struct bgp_bconfig*     bgp_bconfig ;
typedef struct bgp_baf_config*  bgp_baf_config ;
typedef struct bgp_args*        bgp_args ;
typedef struct bgp_rcontext*    bgp_rcontext ;
typedef struct bgp_rib*         bgp_rib ;
typedef struct bgp_lcontext*    bgp_lcontext ;
typedef struct bgp_peer*        bgp_peer ;
typedef struct bgp_prun*        bgp_prun ;
typedef struct bgp_prib*        bgp_prib ;
typedef struct bgp_session*     bgp_session ;
typedef struct bgp_connection*  bgp_connection ;
typedef struct bgp_cops*        bgp_cops ;
typedef const struct bgp_cops*  bgp_cops_c ;
typedef struct bgp_session_args* bgp_session_args ;
typedef struct bgp_acceptor*    bgp_acceptor ;
typedef struct bgp_open_state*  bgp_open_state ;
typedef struct bgp_nexthop*     bgp_nexthop ;
typedef struct bgp_peer_index_entry* bgp_peer_index_entry ;
typedef struct bgp_msg_reader*  bgp_msg_reader ;

typedef struct bgp_note*        bgp_note ;

typedef struct bgp_peer_group*  bgp_peer_group ;
typedef struct bgp_pconfig*     bgp_pconfig ;
typedef struct bgp_paf_config*  bgp_paf_config ;

typedef struct bgp_connection_logging* bgp_connection_logging ;

//typedef struct bgp_event*      bgp_event ;

typedef struct attr_set*        attr_set ;
typedef struct asn_set*         asn_set ;

typedef struct bgp_rib_node*    bgp_rib_node ;
typedef struct bgp_rib_walker*  bgp_rib_walker ;
typedef struct bgp_rib_item*    bgp_rib_item ;

typedef struct route_info*      route_info ;
typedef struct route_extra*     route_extra ;
typedef struct nroute*          nroute ;
typedef struct iroute*          iroute ;
typedef struct zroute*          zroute ;


typedef struct adj_out*         adj_out ;
typedef struct route_in_parcel*  route_in_parcel ;
typedef struct route_out_parcel* route_out_parcel ;

typedef struct route_mpls*      route_mpls ;
typedef struct attr_flux*       attr_flux ;
typedef struct route_flux*      route_flux ;



typedef struct bgp_table*       bgp_table ;
typedef struct bgp_node*        bgp_node ;

/*==============================================================================
 * Miscellaneous common types
 */
typedef uint32_t as_t ;         /* general ASN                  */

/* TTL type and maximum value.
 */
enum { TTL_MAX  = MAXTTL } ;    /* MAXTTL from netinet/ip.h     */
typedef byte ttl_t ;
CONFIRM(TTL_MAX <= (uint)BYTE_MAX) ;

/* Med value and extremes
 */
typedef uint32_t bgp_med_t ;
enum bgp_med
{
  BGP_MED_MIN = 0,
  BGP_MED_MAX = UINT32_MAX,
} ;

/* Port number
 *
 * NB: we use port_t where we have a *host* order port number, and in_port_t
 *     where we have the network order port number.
 */
typedef in_port_t port_t ;

/*==============================================================================
 * Common data types
 */
enum bgp_password_length
{
  BGP_PASSWORD_MIN_LEN    =   1,
  BGP_PASSWORD_MAX_LEN    = 103,        /* 104 divides exactly by 8     */
  BGP_PASSWORD_SIZE       = 104,        /* including the '\0'           */
} ;

typedef char bgp_password_t[BGP_PASSWORD_SIZE] ;
typedef char bgp_ifname_t[IF_NAMESIZE] ;        /* IF_NAMESIZE includes '\0' */

CONFIRM(BGP_ID_NULL == INADDR_ANY) ;
CONFIRM(BGP_ID_NULL == 0) ;     /* BGP_ID_NULL == ntohl(BGP_ID_NULL) !! */

/*------------------------------------------------------------------------------
 * When reading and writing packets using stream buffers, we set the stream
 * to be a little larger than the maximum size of message.  Don't really expect
 * messages to overflow, and if they do, not by much -- so most of the time
 * we will know how badly the stream overflowed.
 */
enum { BGP_STREAM_SIZE = BGP_MSG_MAX_L * 5 / 4 } ;

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Components of configuration.
 */
enum { MAXIMUM_PREFIX_THRESHOLD_DEFAULT = 75 } ;

typedef struct prefix_max  prefix_max_t ;
typedef struct prefix_max* prefix_max ;

struct prefix_max
{
  bool        set ;
  bool        warning ;

  uint        trigger ;

  uint        limit ;
  uint        threshold ;
  uint16_t    thresh_pc ;
  uint16_t    restart ;
} ;

/* Names provided by zebra.h
 */
enum { FILTER_COUNT = FILTER_MAX } ;
CONFIRM(FILTER_COUNT == 2) ;
CONFIRM(FILTER_IN     < 2) ;
CONFIRM(FILTER_OUT    < 2) ;

/* The known route-maps
 */
typedef enum bgp_route_map_types bgp_route_map_types_t ;
enum bgp_route_map_types
{
  RMAP_IN       = 0,
  RMAP_INX      = 1,
  RMAP_OUT      = 2,
  RMAP_IMPORT   = 3,
  RMAP_EXPORT   = 4,

  RMAP_COUNT    = 5,
} ;

/* The complete filter set.
 */
typedef enum bgp_filter_set bgp_filter_set_t ;
enum bgp_filter_set
{
  bfs_first     = 0,

  bfs_dlist         = bfs_first,
  bfs_plist         = bfs_dlist     + FILTER_COUNT,
  bfs_aslist        = bfs_plist     + FILTER_COUNT,
  bfs_rmap          = bfs_aslist    + FILTER_COUNT,
  bfs_us_rmap       = bfs_rmap      + RMAP_COUNT,

  bfs_default_rmap,
  bfs_orf_plist,

  bfs_count,
  bfs_last      = bfs_count - 1,

  bfs_dlist_in      = bfs_dlist     + FILTER_IN,
  bfs_dlist_out     = bfs_dlist     + FILTER_OUT,

  bfs_plist_in      = bfs_plist     + FILTER_IN,
  bfs_plist_out     = bfs_plist     + FILTER_OUT,

  bfs_aslist_in     = bfs_aslist    + FILTER_IN,
  bfs_aslist_out    = bfs_aslist    + FILTER_OUT,

  bfs_rmap_in       = bfs_rmap      + RMAP_IN,
  bfs_rmap_inx      = bfs_rmap      + RMAP_INX,
  bfs_rmap_out      = bfs_rmap      + RMAP_OUT,
  bfs_rmap_import   = bfs_rmap      + RMAP_IMPORT,
  bfs_rmap_export   = bfs_rmap      + RMAP_EXPORT,
} ;

/*==============================================================================
 * The sort of peer is a key property of the peer:
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
typedef enum bgp_peer_sort bgp_peer_sort_t ;
enum bgp_peer_sort
{
  BGP_PEER_UNSPECIFIED  = 0,
  BGP_PEER_IBGP,
  BGP_PEER_CBGP,
  BGP_PEER_EBGP,
} ;

typedef enum bgp_peer_sorts bgp_peer_sorts_t ;
enum bgp_peer_sorts
{
  BGP_PSORTS_NONE       = 0,

  BGP_PSORTS_IBGP_BIT   = BIT(0),
  BGP_PSORTS_CBGP_BIT   = BIT(1),
  BGP_PSORTS_EBGP_BIT   = BIT(2),
} ;

/*==============================================================================
 * Return codes for BGP operations.
 *
 * The
 */
typedef enum BGP_RET_CODE bgp_ret_t ;

enum BGP_RET_CODE
{
  /* General returns.
   */
  BGP_SUCCESS     =  0,         /* tickety-boo                          */

  BGP_WARNING     =  1,         /* not good                             */
  BGP_ERROR,                    /* failed badly                         */

  /* Special purpose "OK" returns
   */
  BGP_OK_PEER_IP,
  BGP_OK_GROUP_NAME,

  /* Error returns of many colours
   */
  BGP_ERR_BUG,

  BGP_ERR_NOT_SUPPORTED,

  BGP_ERR_INVALID_VALUE,
  BGP_ERR_INVALID_FLAG,
  BGP_ERR_INVALID_AS,
  BGP_ERR_INVALID_BGP,

  BGP_ERR_INVALID_IF_NAME,
  BGP_ERR_INVALID_IP_ADDRESS,
  BGP_ERR_INVALID_CLUSTER_ID,
  BGP_ERR_INVALID_ROUTE_TYPE,
  BGP_ERR_INVALID_FAMILY,
  BGP_ERR_INVALID_METRIC,

  BGP_ERR_MULTIPLE_INSTANCE_USED,
  BGP_ERR_MULTIPLE_INSTANCE_NOT_SET,
  BGP_ERR_INSTANCE_MISMATCH,
  BGP_ERR_AS_MISMATCH,

  BGP_ERR_INVALID_PEER_IP,
  BGP_ERR_INVALID_GROUP_NAME,
  BGP_ERR_PEER_NOT_GROUP,
  BGP_ERR_GROUP_NOT_PEER,

  BGP_ERR_AF_NOT_CONFIGURED,
  BGP_ERR_PEER_GROUP_AF_NOT_CONFIGURED,

  BGP_ERR_PEER_EXISTS,
  BGP_ERR_PEER_EXISTS_IN_VIEW,
  BGP_ERR_CANNOT_SET_AS_AND_GROUP,
  BGP_ERR_PEER_NEEDS_REMOTE_AS,
  BGP_ERR_GROUP_NEEDS_REMOTE_AS,
  BGP_ERR_AS_IS_CONFED_ID,

  BGP_ERR_PEER_GROUP_EXISTS,

  BGP_ERR_PEER_CANNOT_SET_AS,
  BGP_ERR_PEER_CANNOT_UNSET_AS,
  BGP_ERR_GROUP_CANNOT_SET_AS,
  BGP_ERR_CANNOT_CHANGE_AS,
  BGP_ERR_CANNOT_BIND_GROUP,

  BGP_ERR_PEER_GROUP_CANNOT_CHANGE,

  BGP_ERR_PEER_FLAG_CONFLICT_1,
  BGP_ERR_PEER_FLAG_CONFLICT_2,
  BGP_ERR_PEER_FLAG_CONFLICT_3,
  BGP_ERR_PEER_GROUP_SHUTDOWN,
  BGP_ERR_PEER_FILTER_CONFLICT,
  BGP_ERR_NOT_INTERNAL_PEER,
  BGP_ERR_REMOVE_PRIVATE_AS,
  BGP_ERR_SOFT_RECONFIG_UNCONFIGURED,
  BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP,
  BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS,
  BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_CONFED_ID,

  BGP_ERR_CONFED_ID_USED_AS_EBGP_PEER,
  BGP_ERR_NO_CBGP_WITH_LOCAL_AS ,
  BGP_ERR_CONFED_ID_USED_AS_LOCAL_AS,
  BGP_ERR_CONFED_PEER_AS_LOCAL_AS,

  BGP_ERR_LOCAL_AS_ALREADY_SET,
  BGP_ERR_TCPSIG_FAILED,
  BGP_ERR_NO_MULTIHOP_WITH_GTSM,
#if 0
  BGP_ERR_NO_IBGP_WITH_TTLHACK,
#endif

  BGP_RET_COUNT,
} ;

/*==============================================================================
 * BGP Arguments -- appear in configuration and in the running state.
 */
typedef struct bgp_args  bgp_args_t ;

struct bgp_args
{
  /* Default port.
   */
  uint16_t port ;

  /* Default metrics
   */
  uint  local_pref;
  uint  med ;
  uint  weight ;

  /* Timer values.
   *
   * The "AcceptRetryTime" is not an RFC value... it is invented here as the
   * time for which the connection accept logic will hold on to an incoming
   * connection waiting for a session to come up and claim it.
   *
   * The "OpenHoldTime" is not given that name in RFC4271, but is the "large"
   * value that the HoldTimer is set to on entry to OpenSent state.  Suggested
   * default value is 4 *minutes*.
   */
  uint  holdtime_secs ;
  uint  keepalive_secs ;
  uint  connect_retry_secs ;
  uint  accept_retry_secs ;
  uint  open_hold_secs ;

  uint  ibgp_mrai_secs ;
  uint  cbgp_mrai_secs ;                /* usually same as eBGP */
  uint  ebgp_mrai_secs ;

  uint  idle_hold_min_secs ;
  uint  idle_hold_max_secs ;

  uint  restart_time_secs ;
  uint  stalepath_time_secs ;

  /* BGP distance configuration.
   */
  byte  distance_ebgp ;
  byte  distance_ibgp ;
  byte  distance_local ;
} ;

/*==============================================================================
 * AFI/SAFI encodings for bgpd
 *
 * This captures the AFI/SAFI combinations that bgpd supports.
 *
 * Note that this defines "qafx" for IPv6 even if do not HAVE_IPV6.
 */
enum
{
  /* Generally, if we don't HAVE_IPV6, we don't have any of the definitions,
   * functions etc. that do IPv6 things.  Occasionally, it is useful to do
   * something different of do or do not have IPv6.
   */
  have_ipv6 =
#ifdef HAVE_IPV6
                  1
#else
                  0
#endif
} ;

/*------------------------------------------------------------------------------
 * A qafx_t identifies a supported AFI/SAFI combination
 *
 * NB: when changing anything here make sure that the various sexing functions
 *     below will still work !
 */
typedef enum qafx_num  qafx_t ;

enum qafx_num
{
  qafx_undef            = -1,   /* No defined AFI/SAFI                  */
  qafx_none             = qafx_undef,   /* "not-an-AFI/SAFI"            */

  qafx_min              = 0,    /* minimum valid qafx                   */

  qafx_first            = 0,    /* all first..last are "real" qafx      */

  qafx_ipv4_unicast     = 0,    /* iAFI = 1, iSAFI = 1                  */
  qafx_ipv4_multicast   = 1,    /* iAFI = 1, iSAFI = 2                  */
  qafx_ipv4_mpls_vpn    = 2,    /* iAFI = 1, iSAFI = 128                */

  qafx_ipv6_unicast     = 3,    /* iAFI = 2, iSAFI = 1                  */
  qafx_ipv6_multicast   = 4,    /* iAFI = 2, iSAFI = 2                  */
  qafx_ipv6_mpls_vpn    = 5,    /* iAFI = 2, iSAFI = 128                */

  qafx_last             = 5,    /* last "real" qafx                     */

  qafx_other            = 6,    /* place-holder: for unknown AFI/SAFI   */

  qafx_max              = 6,    /* maximum qafx                         */
  qafx_count,                   /* number of qafx                       */

  qafx_t_max            = qafx_max
} ;

CONFIRM(qafx_other >  qafx_last) ;
CONFIRM(qafx_other == qafx_max) ;
CONFIRM(qafx_t_max < 256) ;

/*------------------------------------------------------------------------------
 * A qafx_set_t is a set of qafx_bit_t -- a bit-vector
 */
typedef enum qafx_bit   qafx_bit_t ;
typedef      qafx_bit_t qafx_set_t ;

enum qafx_bit
{
  qafx_bits_min           = 0,

  qafx_empty_set          = 0,

  qafx_first_bit          = BIT(qafx_first),
                                /* first..last are all "real" qafx      */

  qafx_ipv4_unicast_bit   = BIT(qafx_ipv4_unicast),
  qafx_ipv4_multicast_bit = BIT(qafx_ipv4_multicast),
  qafx_ipv4_mpls_vpn_bit  = BIT(qafx_ipv4_mpls_vpn),

  qafx_ipv6_unicast_bit   = BIT(qafx_ipv6_unicast),
  qafx_ipv6_multicast_bit = BIT(qafx_ipv6_multicast),
  qafx_ipv6_mpls_vpn_bit  = BIT(qafx_ipv6_mpls_vpn),

  qafx_last_bit           = BIT(qafx_last),

  qafx_other_bit          = BIT(qafx_other),

  qafx_bits_max           = BIT(qafx_count) - 1,

  qafx_known_bits         = BIT((qafx_last + 1)) - qafx_first_bit
} ;

CONFIRM(qafx_known_bits == ( qafx_ipv4_unicast_bit
                           | qafx_ipv4_multicast_bit
                           | qafx_ipv4_mpls_vpn_bit
                           | qafx_ipv6_unicast_bit
                           | qafx_ipv6_multicast_bit
                           | qafx_ipv6_mpls_vpn_bit )) ;

/*------------------------------------------------------------------------------
 * Conversions qafx_num <-> qafx_bit
 *
 * The conversion from qafx_bit -> qafx_num is not built for speed.
 */

/* Get qafx_bit_t for given qafx_t
 *
 * NB: it is a mistake to try to map qafx_undef (FATAL unless NDEBUG).
 */
Inline qafx_bit_t
qafx_bit(qafx_t num)
{
  dassert((num >= qafx_min) && (num <= qafx_max)) ;
  return (1 << num) ;
} ;

/* Get qafx_t for the given qafx_bit_t.
 */
extern qafx_t qafx_num(qafx_bit_t bit) ;


/*==============================================================================
 * Sexing functions for qafx_t
 *
 * NB: these depend critically on the order of values in the qafx_t enum.
 */

/*------------------------------------------------------------------------------
 * Is AFI IPv4 ?
 */
Inline bool
qafx_is_ipv4(qafx_t num)
{
#define QAFX_IS_IPV4(num) \
          ((uint)num <= (uint)qafx_ipv4_mpls_vpn)

  return QAFX_IS_IPV4(num) ;

  confirm(!QAFX_IS_IPV4(qafx_undef)) ;

  confirm(QAFX_IS_IPV4(qafx_ipv4_unicast)) ;
  confirm(QAFX_IS_IPV4(qafx_ipv4_multicast)) ;
  confirm(QAFX_IS_IPV4(qafx_ipv4_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV4(qafx_ipv6_unicast)) ;
  confirm(!QAFX_IS_IPV4(qafx_ipv6_multicast)) ;
  confirm(!QAFX_IS_IPV4(qafx_ipv6_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV4(qafx_other)) ;

#undef QAFX_IS_IPV4
} ;

/*------------------------------------------------------------------------------
 * Is AFI IPv6 ?
 */
Inline bool
qafx_is_ipv6(qafx_t num)
{
#define QAFX_IS_IPV6(num) \
                ((num >= qafx_ipv6_unicast) && (num <= qafx_ipv6_mpls_vpn))

  return QAFX_IS_IPV6(num) ;

  confirm(!QAFX_IS_IPV6(qafx_undef)) ;

  confirm(!QAFX_IS_IPV6(qafx_ipv4_unicast)) ;
  confirm(!QAFX_IS_IPV6(qafx_ipv4_multicast)) ;
  confirm(!QAFX_IS_IPV6(qafx_ipv4_mpls_vpn)) ;

  confirm(QAFX_IS_IPV6(qafx_ipv6_unicast)) ;
  confirm(QAFX_IS_IPV6(qafx_ipv6_multicast)) ;
  confirm(QAFX_IS_IPV6(qafx_ipv6_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV6(qafx_other)) ;

#undef QAFX_IS_IPV6
} ;

/*------------------------------------------------------------------------------
 * Is SAFI Unicast ?
 */
Inline bool
qafx_is_unicast(qafx_t num)
{
  return (num == qafx_ipv4_unicast) || (num == qafx_ipv6_unicast) ;
} ;

/*------------------------------------------------------------------------------
 * Is SAFI Multicast ?
 */
Inline bool
qafx_is_multicast(qafx_t num)
{
  return (num == qafx_ipv4_multicast) || (num == qafx_ipv6_multicast) ;
} ;

/*------------------------------------------------------------------------------
 * Is SAFI MPLS VPN (iSAFI == 128) ?
 */
Inline bool
qafx_is_mpls_vpn(qafx_t num)
{
  return (num == qafx_ipv4_mpls_vpn) || (num == qafx_ipv6_mpls_vpn) ;
} ;


/*==============================================================================
 * Conversions for qafx_t => qAFI, qSAFI, iAFI, iSAFI and pAF
 */

/*------------------------------------------------------------------------------
 * Convert qafx_t to qAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown values to qAFI_undef
 */
extern const qAFI_t qAFI_map[qafx_count] ;

Inline qAFI_t
get_qAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return qAFI_map[num] ;
  else
    return qAFI_undef ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to qSAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown values to qSAFI_undef
 */
extern const qSAFI_t qSAFI_map[qafx_count] ;

Inline qSAFI_t
get_qSAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return qSAFI_map[num] ;
  else
    return qSAFI_undef ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to iAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to iAFI_Reserved
 */
extern const iAFI_t iAFI_map[qafx_count] ;

Inline iAFI_t
get_iAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return iAFI_map[num] ;
  else
    return iAFI_Reserved ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to iSAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to iSAFI_Reserved
 */
extern const iSAFI_t iSAFI_map[qafx_count] ;

Inline iSAFI_t
get_iSAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return iSAFI_map[num] ;
  else
    return iSAFI_Reserved ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to AF_xxx (pAF_t)
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to AF_UNSPEC
 */
extern const sa_family_t sa_family_map[qafx_count] ;

Inline sa_family_t
get_qafx_sa_family(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return sa_family_map[num] ;
  else
    return AF_UNSPEC ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to string
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to AF_UNSPEC
 */
extern const char* qafx_name_map[qafx_max + 1] ;

Inline const char*
get_qafx_name(qafx_t num)
{
  if ((uint)num <= (uint)qafx_max)
    return qafx_name_map[num] ;
  else
    return "??invalid qafx??" ;
} ;

/*==============================================================================
 * Conversions for iAFI/iSAFI => qafx_t
 *             and qAFI/qSAFI => qafx_t
 *
 *             and iAFI/iSAFI => qafx_bit_t
 *             and qAFI/qSAFI => qafx_bit_t
 */
extern qafx_t qafx_from_i(iAFI_t afi, iSAFI_t safi) ;
extern qafx_t qafx_from_q(qAFI_t afi, qSAFI_t safi) ;
extern qafx_bit_t qafx_bit_from_i(iAFI_t afi, iSAFI_t safi) ;
extern qafx_bit_t qafx_bit_from_q(qAFI_t afi, qSAFI_t safi) ;


#endif /* _QUAGGA_BGP_COMMON_H */

