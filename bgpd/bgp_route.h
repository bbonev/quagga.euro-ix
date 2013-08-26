/* BGP routing information base
   Copyright (C) 1996, 97, 98, 2000 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_ROUTE_H
#define _QUAGGA_BGP_ROUTE_H

#include "bgp_table.h"
#include "bgp_attr_store.h"
#include "bgp_attr.h"

/*------------------------------------------------------------------------------
 * Ancillary information to struct bgp_info,
 * used for uncommonly used data (aggregation, MPLS, etc.)
 * and lazily allocated to save memory.
 */
typedef struct bgp_info_extra  bgp_info_extra_t ;

struct bgp_info_extra
{
  /* Pointer to damping structure.              */
  struct bgp_damp_info *damp_info;

  /* This route is suppressed with aggregation. */
  int suppress;

  /* Nexthop reachability check.                */
  u_int32_t igpmetric;

  /* MPLS label.                                */
  u_char tag[3];
};

/*------------------------------------------------------------------------------
 * BGP Info Object -- contains one route
 */
enum bgp_info_flags
{
  BGP_INFO_IGP_CHANGED    = BIT( 0),
  BGP_INFO_DAMPED         = BIT( 1),
  BGP_INFO_HISTORY        = BIT( 2),
  BGP_INFO_SELECTED       = BIT( 3),
  BGP_INFO_VALID          = BIT( 4),
  BGP_INFO_ATTR_CHANGED   = BIT( 5),
  BGP_INFO_DMED_TBD       = BIT( 6),
  BGP_INFO_DMED_IGNORE    = BIT( 7),
  BGP_INFO_STALE          = BIT( 8),
  BGP_INFO_REMOVED        = BIT( 9),
  BGP_INFO_COUNTED        = BIT(10),
} ;

/* The bgp_info structure contains the RIB information for each route for
 * a given prefix.
 */
typedef struct bgp_info bgp_info_t ;

struct bgp_info
{
  /* For linked list -- hung off the 'info' entry in the bgp_node for the
   * prefix in its table.
   */
  bgp_node  rn ;
  struct dl_list_pair(bgp_info) info ;

  /* Peer structure -- the source of this route.
   */
  bgp_peer  peer;
  struct dl_list_pair(bgp_info) routes ;

  /* Attribute structure -- stored and locked
   *
   * These are the attributes after any 'in' route-map etc processing, so these
   * are the attributes used for best-path selection.
   *
   * For RS Client ribs, these are the attributes after any 'rs-in', 'export'
   * and 'import' processing.
   */
  attr_set      attr;

  /* Extra information
   */
  bgp_info_extra extra;

  /* Uptime.
   */
  time_t  uptime;

  /* reference count
  */
  uint    lock ;

  /* BGP information status.
   */
  uint16_t flags;

  /* BGP route type.
   */
  byte   type ;                 /* static, RIP, OSPF, BGP etc.  */
  byte   sub_type ;             /* normal, static, etc.         */
};

/*------------------------------------------------------------------------------
 * BGP static route configuration.
 */
typedef struct bgp_static bgp_static_t ;

struct bgp_static
{
  /* Backdoor configuration.                            */
  bool backdoor;

  /* Import check status.                               */
  bool  valid;

  /* IGP metric.                                        */
  uint32_t igpmetric;

  /* IGP nexthop.                                       */
  struct in_addr igpnexthop;

  /* Atomic set reference count (ie cause of pathlimit) */
  uint32_t atomic;

  /* BGP redistribute route-map.                        */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap;

  /* MPLS label.                                        */
  byte  tag[3];
};

/*------------------------------------------------------------------------------
 */
/* Flags which indicate a route is unuseable in some form
 */
#define BGP_INFO_UNUSEABLE (BGP_INFO_HISTORY|BGP_INFO_DAMPED|BGP_INFO_REMOVED)
/* Macro to check BGP information is alive or not.  Sadly,
 * not equivalent to just checking previous, because of the
 * sense of the additional VALID flag.
 */
#define BGP_INFO_HOLDDOWN(BI) \
  (((BI)->flags & (BGP_INFO_VALID | BGP_INFO_UNUSEABLE)) != BGP_INFO_VALID)

#define DISTRIBUTE_IN_NAME(F)   ((F)->dlist[FILTER_IN].name)
#define DISTRIBUTE_IN_LIST(F)   ((F)->dlist[FILTER_IN].alist)
#define DISTRIBUTE_OUT_NAME(F)  ((F)->dlist[FILTER_OUT].name)
#define DISTRIBUTE_OUT_LIST(F)  ((F)->dlist[FILTER_OUT].alist)

#define PREFIX_LIST_IN_LIST(F)  ((F)->plist[FILTER_IN])
#define PREFIX_LIST_IN_NAME(F)  prefix_list_get_name(PREFIX_LIST_IN_LIST(F))
#define PREFIX_LIST_OUT_LIST(F) ((F)->plist[FILTER_OUT])
#define PREFIX_LIST_OUT_NAME(F) prefix_list_get_name(PREFIX_LIST_OUT_LIST(F))

#define FILTER_LIST_IN_NAME(F)  ((F)->aslist[FILTER_IN].name)
#define FILTER_LIST_IN_LIST(F)  ((F)->aslist[FILTER_IN].aslist)
#define FILTER_LIST_OUT_NAME(F) ((F)->aslist[FILTER_OUT].name)
#define FILTER_LIST_OUT_LIST(F) ((F)->aslist[FILTER_OUT].aslist)

#define ROUTE_MAP_IN_NAME(F)     ((F)->map[RMAP_IN].name)
#define ROUTE_MAP_IN(F)          ((F)->map[RMAP_IN].map)
#define ROUTE_MAP_OUT_NAME(F)    ((F)->map[RMAP_OUT].name)
#define ROUTE_MAP_OUT(F)         ((F)->map[RMAP_OUT].map)

#define ROUTE_MAP_IMPORT_NAME(F) ((F)->map[RMAP_IMPORT].name)
#define ROUTE_MAP_IMPORT(F)      ((F)->map[RMAP_IMPORT].map)
#define ROUTE_MAP_EXPORT_NAME(F) ((F)->map[RMAP_EXPORT].name)
#define ROUTE_MAP_EXPORT(F)      ((F)->map[RMAP_EXPORT].map)

#define ROUTE_MAP_RS_IN_NAME(F)  ((F)->map[RMAP_RS_IN].name)
#define ROUTE_MAP_RS_IN(F)       ((F)->map[RMAP_RS_IN].map)

#define UNSUPPRESS_MAP_NAME(F)   ((F)->usmap.name)
#define UNSUPPRESS_MAP(F)        ((F)->usmap.map)

enum bgp_clear_route_type
{
  BGP_CLEAR_ROUTE_NORMAL,
  BGP_CLEAR_ROUTE_MY_RSCLIENT
};

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_route_cmd_init (void);
extern void bgp_route_init (void);
extern void bgp_route_finish (void);


extern bool bgp_update_from_peer(bgp_peer peer, route_in_parcel parcel,
                                                                 bool refresh) ;
extern bool bgp_update_rs_from_peer(peer_rib prib, route_info ri_main,
                                            prefix_id_entry pie, bool process) ;
extern void bgp_process_schedule(bgp_rib rib, bgp_rib_node rn) ;

extern void bgp_announce_all_families (bgp_peer peer, uint delay);
extern void bgp_announce_family(bgp_peer peer, qafx_t qafx, uint delay) ;


extern void bgp_default_originate (bgp_peer peer, qafx_t qafx, bool withdraw) ;
extern void bgp_soft_reconfig_in (bgp_peer peer, qafx_t qafx);
extern void bgp_soft_reconfig_rsclient_in (bgp_peer peer, qafx_t qafx) ;
extern void bgp_check_local_routes_rsclient (bgp_peer rsclient, qafx_t qafx);
extern void bgp_clear_all_routes (bgp_peer peer, bool nsf);
extern void bgp_clear_routes(bgp_peer peer, qafx_t qafx, bool nsf) ;
extern void bgp_clear_rsclient_rib(bgp_peer rsclient, qafx_t qafx) ;
extern void bgp_clear_adj_in (bgp_peer peer, qafx_t qafx);
extern void bgp_clear_stale_route (bgp_peer, qafx_t);

extern struct bgp_info *bgp_info_lock (struct bgp_info *);
extern struct bgp_info *bgp_info_unlock (struct bgp_info *);
extern void bgp_info_add (struct bgp_node *rn, struct bgp_info *ri);
extern void bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri);
extern struct bgp_info_extra *bgp_info_extra_get (struct bgp_info *);
extern void bgp_info_set_flag (struct bgp_node *, struct bgp_info *, u_int32_t);
extern void bgp_info_unset_flag (struct bgp_node *, struct bgp_info *, u_int32_t);

extern bool bgp_maximum_prefix_overflow (peer_rib prib, bool always) ;

extern void bgp_redistribute_add (prefix, ip_union, uint32_t, uchar);
extern void bgp_redistribute_delete (struct prefix *, u_char);
extern void bgp_redistribute_withdraw_all (struct bgp *, qAFI_t, int);

extern void bgp_static_delete (struct bgp *);
extern void bgp_static_update (struct bgp *, prefix p,
                                             struct bgp_static *, qafx_t qafx);
extern void bgp_static_withdraw (struct bgp *, prefix p, qafx_t qafx);

extern int bgp_static_set_vpnv4 (struct vty *vty, const char *,
                          const char *, const char *);
extern int bgp_static_unset_vpnv4 (struct vty *, const char *,
                            const char *, const char *);


extern bool bgp_update (bgp_peer peer, prefix p, attr_set attr, qafx_t qafx,
                   int type, int subtype, const byte* tag, bool soft_reconfig) ;
extern bool bgp_withdraw (bgp_peer peer, prefix p, qafx_t qafx,
                                                       int type, int sub_type) ;

/* for bgp_nexthop and bgp_damp */
extern void bgp_process_dispatch (bgp_inst bgp, bgp_rib_node rn);
extern int bgp_config_write_network (struct vty *, struct bgp *, qafx_t,
                                                                        int *);
extern int bgp_config_write_distance (struct vty *, struct bgp *);

extern void bgp_aggregate_increment (struct bgp *, prefix, struct bgp_info *,
                                                                   qafx_t qafx);
extern void bgp_aggregate_decrement (struct bgp *, prefix, struct bgp_info *,
                                                                   qafx_t qafx);

extern byte bgp_distance_apply (bgp_peer peer, prefix_c p);

extern qAFI_t bgp_node_afi (struct vty* vty) ;
extern qSAFI_t bgp_node_safi (struct vty* vty) ;
extern qafx_t bgp_node_qafx (struct vty* vty) ;

extern void route_vty_out (vty vty, prefix p, route_info ri, bool display);
extern void route_vty_out_tag (vty vty, prefix p, route_info ri, bool display);
extern void route_vty_out_tmp (vty vty, prefix p, attr_set attr, qafx_t qafx) ;

#endif /* _QUAGGA_BGP_ROUTE_H */
