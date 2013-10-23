/* BGP Running Instances and Parameters -- header.
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
#ifndef _QUAGGA_BGP_RUN_H
#define _QUAGGA_BGP_RUN_H

#include "misc.h"

#include "bgpd/bgp_common.h"

#include "qtime.h"
#include "sockunion.h"
#include "list_util.h"
#include "vector.h"
#include "name_index.h"

/*==============================================================================
 * The BGP Run-Time Parameters -- for bgp_run
 */
typedef struct bgp_run_param  bgp_run_param_t ;
struct bgp_run_param
{
  /* BGP AS and confederation information.
   *
   * The 'my_as' is a copy of that in the bgp_inst and *cannot* change !
   *
   * The ebgp_as is: my_as, unless confed_id is set, when it is that.
   *
   * So my_as_ebgp is the effective as for eBGP sessions (NB: that *excludes*
   * sessions to Confederation peers in different Member ASes).
   */
  as_t          my_as ;
  as_t          my_as_ebgp ;

  as_t          confed_id ;     /* BGP_ASN_NULL <=> no CONFED   */

  /* The router_id is set either by configuration, or by other means.  If there
   * is no router_id, then the run-time cannot run !
   *
   * The cluster_eid is the *effective* cluster_id -- ie the configured
   * cluster_id, or (absent that) the router_id.
   */
  in_addr_t     router_id ;
  in_addr_t     cluster_eid ;

  bool  cluster_id_set ;                /* cluster_id is set by config  */

  /* Confed-ID support:
   *
   *   * do_check_confed_id     -- set if there is a confed-id, and that is
   *                               not the same as my-as.
   *
   *                               If set then confed-id == my-ebgp-as.
   *
   *   * do_check_confed_id_all -- set if should include confed-segments in
   *                               check for confed-id.
   */
  bool  do_check_confed_id ;
  bool  do_check_confed_id_all ;

  /* BGP flags.
   */
  bool  no_client_to_client ;           /* bcs_NO_CLIENT_TO_CLIENT      */
  bool  do_enforce_first_as ;           /* bcs_ENFORCE_FIRST_AS         */
  bool  do_import_check ;               /* bcs_IMPORT_CHECK             */
  bool  no_fast_ext_failover ;          /* bcs_NO_FAST_EXT_FAILOVER     */
  bool  do_log_neighbor_changes ;       /* bcs_LOG_NEIGHBOR_CHANGES     */
  bool  do_graceful_restart ;           /* bcs_GRACEFUL_RESTART         */

  /* Running defaults
   */
  bgp_defaults_t    defs ;

  /* Vector of running groups -- for group membership only.
   */
  vector_t      gruns[1] ;      /* bgp_grun objects             */

  /* When a collection of running-parameters is made, this points to the
   * parameters for all configured address families.
   *
   * For the running-parameters in the bgp_brun object, these are auxiliary
   * pointers to the parameters in the bgp_rib objects.
   */
  bgp_rib_param afp[qafx_count] ;
} ;

/*------------------------------------------------------------------------------
 * BGP Run-Time Redistribution parameters.
 *
 * This is very similar to the bgp_redist_config_t -- but need not be identical
 * forever !
 */
typedef struct bgp_redist_param  bgp_redist_param_t ;
struct bgp_redist_param
{
  bool      set ;
  bool      metric_set ;
  uint      metric ;

  bgp_nref  rmap_name ;
};

/*------------------------------------------------------------------------------
 * The BGP Address-Family Run-Time Parameters -- for bgp_rib
 */
typedef struct bgp_rib_param bgp_rib_param_t ;

struct bgp_rib_param
{
  bool  real_rib ;

  /* These flags control various options for route selection, which are
   * (at least conceptually) setable on a per afi/safi basis.
   */
  bool  do_always_compare_med ; /* bcs_ALWAYS_COMPARE_MED       */
  bool  do_deterministic_med ;  /* bcs_DETERMINISTIC_MED
                                   and ! do_always_compare_med  */
  bool  do_confed_compare_med ; /* bcs_MED_CONFED               */
  bool  do_prefer_current ;     /* ! bcs_COMPARE_ROUTER_ID      */
  bool  do_aspath_ignore ;      /* bcs_ASPATH_IGNORE            */
  bool  do_aspath_confed ;      /* bcs_ASPATH_CONFED            */

  bool  do_damping ;            /* bafcs_DAMPING                */

  /* Controlling redistribution of routes -- every address family has
   * these parameters, but only a few use them.
   */
  bgp_redist_param_t redist[redist_type_count] ;
} ;

/*==============================================================================
 * BGP Connection Options Structure
 *
 * This is a discrete structure so that the accept() handling can handle these
 * things without requiring the complete bgp_connection or bgp_session !
 */

/* Whether the connection is prepared to accept and/or connect and/or track.
 *
 * This is the primary control over the connection handling in the BGP Engine,
 * and lives in the connection options as transmitted to the BGP Engine.
 *
 *   * csMayAccept      -- is allowed to accept() a connection
 *
 *   * csMayConnect     -- is allowed to make a connect() connection
 *
 *   * csTrack          -- run the acceptor and track incoming connections
 *
 *                         Ignored if not csMay_Accept !
 *
 *                         This is cleared if the peer is pisDown
 *
 *   * csRun            -- run the session or session acquisition.
 *
 *                         Ignored if not csMay_Accept or csMay_Connect,
 *                         unless a session is established already.
 *
 *                         This is cleared if the peer is not pisRunnable
 *
 * Note that may be csRun without either csMayAccept/Connect.  In particular,
 * once a session is Established, changes to csMayAccept/Connect do not affect
 * the session, but clearing csRun brings it down.
 *
 * When a peer is stopped, will clear csRun, and when it is down, will clear
 * both csRun and csTrack.
 */
typedef enum bgp_conn_state bgp_conn_state_t ;
enum bgp_conn_state
{
  bgp_csDown        = 0,

  bgp_csMayAccept   = BIT(0),
  bgp_csMayConnect  = BIT(1),

  bgp_csMayMask     = bgp_csMayAccept | bgp_csMayConnect,
  bgp_csMayBoth     = bgp_csMayAccept | bgp_csMayConnect,

  bgp_csTrack       = BIT(4),
  bgp_csRun         = BIT(5),

  bgp_csCanTrack    = bgp_csTrack | bgp_csMayAccept,
} ;

typedef struct bgp_cops bgp_cops_t ;

struct bgp_cops
{
  /* For configuration options:
   *
   *   remote_su    = peer->su_name      -- used by connect() and listen()
   *   local_su     = for bind()         -- used by connect()
   *
   *   The local_su is, for example, set by "neighbor xx update-source <addr>".
   *
   *   NB: ifname takes precedence over local_su.
   *
   * For connections once connect() or accept() have succeeded
   *
   *   remote_su    = getpeername()
   *   local_su     = getsockname()
   *
   * NB: these are embedded, so can be copied around etc. without fuss.
   */
  sockunion_t   remote_su ;
  sockunion_t   local_su ;

  /* The port to be used or currently in use.
   */
  in_port_t     port ;

  /* Whether to connections are shutdown/disabled/enabled.
   */
  bgp_conn_state_t  conn_state ;

  /* Flag so can suppress sending NOTIFICATION messages without first
   * sending an OPEN -- just in case, but default is to not send !
   */
  bool      can_notify_before_open ;

  /* Timer intervals for pre-OPEN timers.
   */
  uint      idle_hold_max_secs ;
  uint      connect_retry_secs ;
  uint      accept_retry_secs ;
  uint      open_hold_secs ;

  /* Both connect() and accept() will attempt to set the required ttl/gtsm
   *
   * The ttl and gtsm are configuration options, which are unchanged by
   * attempts to set them.
   *
   * ttl_out and ttl_min are set when a connection is actually made, and
   * reflect what was possible at the time.  They default to TTL_MAX and
   * 0 respectively.
   *
   * If gtsm is true, then ttl_min == 0 => either GTSM not yet set, or
   * failed to set it when we tried.  When gtsm is true, ttl_out is set to
   * TTL_MAX, whether succeeds in setting GTSM or not.
   *
   * NB: if gtsm is requested, the ttl is the maximum number of hops to/from
   *     the remote end.  The ttl set on outgoing packets will be 0xFF.  The
   *     maximum allowed incoming ttl will be 0xFF less the nominal ttl.
   */
  ttl_t     ttl ;               /* 1..TTL_MAX                           */
  bool      gtsm ;              /* set GTSM if possible                 */

  ttl_t     ttl_out ;           /* actual value set                     */
  ttl_t     ttl_min ;           /* actual min_ttl -- 0 <=> not GTSM     */

  /* Both connect() and listen() will apply MD5 password to connections.
   *
   * NB: this is embedded, so can be copied around etc. without fuss.
   */
  bgp_password_t password ;     /* copy of MD5 password                 */

  /* For configuration options:
   *
   *   ifname       = if to bid to, if any -- used by connect()
   *   ifindex      = N/A
   *
   *   The ifname is set, for example, by "neighbor xx update-source <name>"
   *
   *   Note that if the ifname is set, local_su is ignored.
   *
   * For connections once connect() or accept() have succeeded
   *
   *   ifname       = set to the interface name   ) from the getsockname()
   *   ifindex      = set to the interface index  ) address, via certain magic
   *
   * NB: these are embedded, so can be copied around etc. without fuss.
   */
  bgp_ifname_t ifname ;         /* interface to bind to, if any         */

  uint         ifindex ;        /* and its index, if any                */
} ;

/*==============================================================================
 * The Session Arguments -- used by Session, Connection and Open State
 *
 * These arguments affect how the session runs, from when it is first enabled
 * to when it stops.
 *
 * Some of these affect the capability negotiation and some are subject to
 * that negotiation.
 */
typedef struct bgp_sargs_gr  bgp_sargs_gr_t ;
typedef struct bgp_sargs_gr* bgp_sargs_gr ;

struct bgp_sargs_gr
{
  bool   can ;

  bool   restarting ;
  uint   restart_time ;

  qafx_set_t  can_preserve ;
  qafx_set_t  has_preserved ;
} ;

typedef struct bgp_orf_caps  bgp_orf_caps_t ;
typedef struct bgp_orf_caps* bgp_orf_caps ;

struct bgp_orf_caps
{
  bgp_orf_cap_bits_t  af[qafx_count] ;
} ;

/* Some BGP capabilities and messages have RFC and pre-RFC forms.
 *
 * Sometimes see both, or send RFC and/or pre-RFC forms, or track what form(s)
 * are being used.
 */
typedef enum bgp_form bgp_form_t ;

enum bgp_form
{
  bgp_form_none     = 0,
  bgp_form_pre      = 1,
  bgp_form_rfc      = 2,
  bgp_form_both     = 3     /* _rfc and _pre are bits !     */
} ;

/*------------------------------------------------------------------------------
 * Session Arguments affect the state of a session from the moment a
 * connection is made.
 *
 * The OPEN message sent is based on the Session Arguments.  The OPEN message
 * received is (largely) parsed into a set of Session Arguments.  When a
 * session becomes established, the resulting Session Arguments are the
 * intersection of what was configured, what was sent (which may be different
 * -- for example when capabilities are suppressed) and what was received.
 */
typedef struct bgp_sargs bgp_sargs_t ;
typedef const struct bgp_sargs* bgp_sargs_c ;

struct bgp_sargs
{
  as_t          local_as ;      /* ASN here                     */
  in_addr_t     local_id ;      /* BGP-Id here                  */

  as_t          remote_as ;     /* ASN of the peer              */
  in_addr_t     remote_id ;     /* BGP-Id of the peer           */

  /* Whether we can send any capabilities at all and whether can do AS4 and/or
   * MP-Ext.
   *
   * These will, usually all be set !
   */
  bool      can_capability ;
  bool      can_mp_ext ;

  bool      can_as4 ;           /* can be turned off                    */

  /* This is set iff the capabilities have been suppressed.
   *
   * Is set in open_sent->args if required, and copied from there back to the
   * session->args when the session becomes established.
   */
  bool      cap_suppressed ;

  /* These are configuration properties of the peer which are reflected down
   * to the connection.
   *
   * When a session is established, cap_af_override is set true if the override
   * is implemented.  The cap_strict is returned as the state at the time the
   * session was established.
   */
  bool      cap_af_override ;   /* assume other end can do all afi/safi
                                 * this end has active                  */
  bool      cap_strict ;        /* must have all the capabilites we asked
                                 * for.                                 */

  /* The can_af is the set of address families we can support -- whether or
   * not we can advertise those by MP-Ext.
   *
   * If !can_mp_ext, then this is limited to (at most) IPv4/Unicast, unless
   * is cap_af_override.
   */
  qafx_set_t    can_af ;

  /* Support for Route Refresh and Graceful Restart.
   */
  bgp_form_t        can_rr ;
  bgp_sargs_gr_t    gr ;

  /* Support for ORF.
   *
   * The can_orf says whether one or both of the ORF *capabilities* is
   * supported -- RFC or pre-RFC forms.
   *
   * The can_orf_pfx says what ORF types are supported for each qafx.
   */
  bgp_form_t     can_orf ;
  bgp_orf_caps_t can_orf_pfx ;

  bool       can_dynamic ;
  bool       can_dynamic_dep ;

  uint       holdtime_secs ;
  uint       keepalive_secs ;
} ;

/*==============================================================================
 *
 */


/*------------------------------------------------------------------------------
 * Parameters for Running Peer.
 */
typedef struct bgp_prun_param bgp_prun_param_t ;

struct bgp_prun_param
{
  /* We have the name of the peer and its description,
   *
   * The name and the su_name cannot be changed by a change of configuration.
   * (We have copies here, though, so that the run-time is self contained, and
   * when being assembled, the bgp_prun_param is a complete.)
   */
  bgp_nref      name ;          /* copied from config           */
  bgp_nref      cname ;         /* copied from config           */
  bgp_nref      desc ;          /* copied from config           */

  bgp_grun      grun ;          /* Group membership, if any     */

  /* The sort of peer depends on the ASN of the peer, our ASN, CONFED
   * stuff etc.
   *
   *   iBGP: if peer->args.remote_as == bgp->my_as -- whether or not that
   *         is a confederation member AS.
   *
   *   cBGP: if peer->args.remote_as is one of a bgp confederation peer
   *
   *   eBGP:   otherwise
   */
  bgp_peer_sort_t  sort ;

  /* Parameters and flags.
   *
   *   do_enforce_first_as      is a bgp instance option, but could be done on
   *                            a per-peer basis.
   *
   *   do_log_neighbor_changes  is a bgp instance option, but could be done on
   *                            a per-peer basis.
   */
  bool      do_shutdown ;               /* ie pcs_SHUTDOWN              */

  bool      do_enforce_first_as ;
  bool      do_log_neighbor_changes ;

  /* The connection options used in the bgp_prun_param are:
   *
   *   * remote_su              -- the address of the peer -- by configuration
   *
   *   * local_su               -- "neighbor xx update-source <addr>".
   *
   *   * port                   -- for connect() and listen()
   *
   *   * conn_state             -- bgp_csMayAccept   ) the actual "passive" etc
   *                               bgp_csMayConnect  )            configuration
   *
   *   * can_notify_before_open -- per default, or otherwise
   *
   *   * connect_retry_secs     -- per default, or otherwise
   *   * accept_retry_secs      -- per default, or otherwise
   *   * open_hold_secs         -- per default, or otherwise
   *
   *   * ttl                    -- "neighbor xx ebgp-multihop" etc.
   *   * gtsm                   -- "neighbor xx ttl-security hops" etc.
   *
   *   * password               -- "neighbor xx password"
   *
   *   * ifname                 -- "neighbor xx update-source <name>"
   */
  bgp_cops_t    cops_conf ;     /* NB: embedded         */

  /* Peer's configured session arguments
   *
   *   * local_as               -- our ASN for this peering
   *   * local_id               -- copy of router_id
   *
   *     The local_as is what we say in any OPEN we send, and for:
   *
   *       - iBGP == my_as
   *       - cBGP == my_as
   *       - eBGP == my_as_ebgp -- *except* when is change_local_as
   *
   *   * remote_as              -- as set by configuration
   *
   *   * can_capability         -- ! pcs_DONT_CAPABILITY
   *
   *     When constructing session arguments for an OPEN, if !can_capability
   *     will clear down other things.  Here we leave all those "side effects"
   *     to be implemented in one place.
   *
   *   * can_mp_ext             -- true
   *
   *   * can_as4                -- !bm->as2_speaker
   *
   *   * cap_af_override        -- pcs_OVERRIDE_CAPABILITY
   *
   *   * cap_strict             -- pcs_STRICT_CAP_MATCH
   *
   *   * can_af                 -- for peer->args: the enabled address families
   *
   *   * can_rr                 -- bgp_form_both
   *
   *   * gr.can                 -- bcs_GRACEFUL_RESTART
   *
   *   * can_orf                -- bgp_form_both
   *
   *   * can_orf_pfx[]          -- per "neighbor capability orf prefix-list"
   *
   *     Here we register only the RFC types.  As we construct arguments for
   *     session and for open_sent, will expand this to include the pre-RFC
   *     types -- where the pre-RFC capability is advertised.
   *
   *   * can_dynamic            -- false
   *   * can_dynamic_dep        -- false
   *
   *   * holdtime_secs          -- pcs_timers
   *   * keepalive_secs         -- pcs_timers
   */
  bgp_sargs_t  sargs_conf ;     /* NB: embedded         */

  /* change_local_as is set when we are pretending that a previous ASN still
   * exists.
   *
   * For eBGP (not cBGP !) we pretend that the 'change_local_as' AS sits
   * between us (local_as) and the peer.  This allows the peer to believe that
   * they are peering with 'change_local_as' (as it was before).
   *
   * The args.local_as is set to change_local_as (my_as_ebgp), because that is
   * the AS used for the session (and in the OPEN sent).
   */
  as_t          change_local_as ;
  bool          do_local_as_prepend ;

  /* Other flags and running configuration
   */
  bool          do_disable_connected_check ;

  uint16_t      weight ;
  uint          default_local_pref ;
  uint          default_med ;

  uint          mrai_secs ;

  /* When a collection of running-parameters is made, this points to the
   * parameters for all configured address families.
   *
   * For the running-parameters in the bgp_prun object, these are auxiliary
   * pointers to the parameters in the bgp_prib objects.
   */
  bgp_prib_param     afp[qafx_count] ;
} ;

/*------------------------------------------------------------------------------
 * Parameters for Address Family of Running Peer.
 */
typedef struct bgp_prib_param bgp_prib_param_t ;

struct bgp_prib_param
{
  bgp_grun      grun ;          /* Group membership, if any             */

  /* Running flags
   */
  bool          do_soft_reconfig ;
  bool          is_route_server_client ;
  bool          is_route_reflector_client ;
  bool          do_send_community ;
  bool          do_send_ecommunity ;
  bool          do_next_hop_self ;
  bool          do_next_hop_unchanged ;
  bool          do_next_hop_local_unchanged ;

  bool          do_as_path_unchanged ;
  bool          do_remove_private_as ;
  bool          do_med_unchanged ;
  bool          do_default_originate ;

  uint8_t       allow_as_in ;

  /* Filters and route-maps.
    */
  bgp_nref      filter_set[bfs_count] ;

  /* Max prefix count.
   */
  prefix_max_t pmax ;
} ;

/*==============================================================================
 * BGP Instance Run-Time
 */
typedef struct bgp_run  bgp_run_t ;
struct bgp_run
{
  /* The brun has a parent instance.  The running code does not care.
   *
   * The brun is hung off the bgp_env -- so all running instances can be found.
   *
   * The view name is a copy of the value in the instance, and *cannot* change
   * while it and the brun are in existence.
   */
  bgp_inst      parent_inst ;
  struct dl_list_pair(bgp_run) brun_list ;

  chs_c         view_name ;

  /* Route-Contexts by name, if any and the view's rcontext, ditto.
   */
  vhash_table   rc_name_index ;
  bgp_rcontext  rc_view ;

  /* Self and peers -- peers are in name order.
   */
  bgp_prun      prun_self ;
  vector_t      pruns[1] ;      /* bgp_prun                     */

  /* The Run-Time Parameters
   */
  bgp_run_param_t  rp ;

  /* BGP routing information bases -- one per AFI/SAFI.
   */
  bgp_rib       rib[qafx_count] ;
  bool          real_rib ;      /* true <=> install routes      */
} ;

/*==============================================================================
 * Run-Time Group Membership
 */
typedef struct bgp_grun  bgp_grun_t ;

struct bgp_grun
{
  bgp_nref      name ;

  vector_t      prun_members[1] ;       /* bgp_prun objects             */

  vector_t      prib_members[qafx_count][1] ;
                                        /* bgp_prib objects             */
} ;

/*==============================================================================
 * Parameter Assembly -- as assembled from the configuration
 */
typedef struct bgp_assembly  bgp_assembly_t ;

struct bgp_assembly
{
  bgp_inst      parent_bgp ;

  bgp_run_param brp ;

  vector_t      prun_params[1] ;        /* bgp_prun_param objects       */
} ;




/*==============================================================================
 * Prototypes.
 */
extern bgp_run bgp_run_lookup(chs_c view_name) ;

extern bgp_prib bgp_run_get_pribs(bgp_run brun, qafx_t qafx) ;


#endif /* _QUAGGA_BGP_RUN_H */
