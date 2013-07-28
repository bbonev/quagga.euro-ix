/* Peer-RIB Adj-Out handling -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_ADJ_OUT_H
#define _QUAGGA_BGP_ADJ_OUT_H

#include "lib/misc.h"
#include "lib/list_util.h"
#include "lib/prefix_id.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_attr_store.h"

/*------------------------------------------------------------------------------
 * The adj_out belongs to the out-bound peer, and lives in the peer_rib.
 *
 * The adj_out is an ihash by prefix_id.  So each entry is a pointer to some
 * data structure, and at any time that may be:
 *
 *   0) NULL
 *
 *      This is the "steady state" where we have withdrawn the prefix.
 *
 *      The ihash does not strongly distinguish between entries which are NULL
 *      and entries which do not exist.  If the entry exists it can be
 *      discarded.
 *
 *   1) a stored attribute set.
 *
 *      This is the "steady state" value for not-MPLS SAFI.
 *
 *   2) an MPLS route.
 *
 *      This is the "steady state" value for an MPLS SAFI.
 *
 *      The MPLS stored value comprises a pointer to a stored attribute set,
 *      and the Tag last sent.
 *
 *   3) a route in flux structure.
 *
 *      This is the dynamic state for all SAFI.
 *
 *      This is used where an update (withdraw or announce) is scheduled, and
 *      while an update is "cooling off" after being sent, and before any
 *      further update may be sent.
 *
 * To distinguish which of (1), (2) or (3) are the value, we have to do a
 * certain amount of magic with the layout of (2) and (3) -- based on the
 * fact that (1) starts with a vhash_node !  The layout of the vhash node is:
 *
 *   a) void*
 *   b) uint32_t
 *   c) uint32_t -- reference count and LS bit == "set" bit.
 *
 * Now: stored attributes sets are always "set".  The adj_out NEVER uses not
 * stored attribute sets, but those will always have a zero reference count,
 * and a zero "set" bit.
 *
 * So: we arrange the 'route_mpls' and the 'route_flux' structures such that
 * the uint32_t (c) has B0=0 but non-zero.  To avoid issues with Endian-ness,
 * The layout of these structures has an explicit uint32_t here.
 *
 * We also arrange for the attr_flux to only ever use the "set" bit of the
 * vhash.ref_count -- so that we can use the rest as the schedule-time for the
 * attr_flux !
 */
typedef union adj_out_ptr  adj_out_ptr_t ;

union adj_out_ptr
{
  adj_out     anon ;            /* until know what it is        */
  attr_set    attr ;
  route_mpls  mpls ;
  route_flux  flux ;
} ;

typedef struct adj_out  adj_out_t ;

struct adj_out
{
  void*     p ;
  uint32_t  x ;

  uint32_t  bits ;      /* the adj_out_bits_t   */
};

typedef uint32_t adj_out_bits_t ;

/* An adj_out_ptr may refer to an attr_set, so it must be capable of being
 * mapped to an adj_out_t.
 */
CONFIRM(offsetof(adj_out_t, bits)  == offsetof(attr_set_t, vhash.ref_count)) ;
CONFIRM(sizeof(((adj_out)0)->bits) == sizeof(((attr_set)0)->vhash.ref_count)) ;

enum adj_out_bits
{
  /* The LS 2 bits are common to all things pointed to by an adj_out_ptr,
   * and distinguish those.
   *
   *   B 0.. 1: the 'type'           -- see adj_out_type_t
   *
   *  Where we have aob_flux -- the rest of the "bits" are:
   *
   *   B 2.. 3: the current 'action' -- see route_flux_action_t.
   *
   *   B 4..12: flags
   *
   *   B13..21: the delta
   *
   *   B22..31: the pfifo index
   *
   * To extract the 'action', shift down by aob_action_shift and apply mask.
   *
   * Similarly, to extract the delta and index.
   */
  aob_type_shift     = 0,               /* LS bits                      */
  aob_type_mask      = BIT( 2) - 1,     /*  2 bit field                 */

  aob_action_shift   = 2,               /* above the type               */
  aob_action_mask    = BIT( 2) - 1,     /*  2 bit field                 */

  aob_flags_shift    = 4,               /* above the action             */
  aob_flags_mask     = BIT( 9) - 1,     /*  9 bit field                 */

  aob_mrai_wait      = BIT( 8),
  aob_ex             = BIT(12),

  aob_delta_shift    = 13,
  aob_delta_mask     = BIT( 9) - 1,     /*  9 bit field                 */

  aob_index_shift    = 22,
  aob_index_mask     = BIT(10) - 1,     /* 10 bit field                 */

  aob_index_ex       = aob_index_mask,
  aob_index_max      = aob_index_mask - 1,

  /* We'd like this to be an unsigned enum
   */
  aob_unsigned       = UINT_MAX,
} ;
CONFIRM(aob_index_shift  == (32              - 10)) ;   /* MS  10 bits  */
CONFIRM(aob_delta_shift  == (aob_index_shift  - 9)) ;   /* Next 9 bits  */
CONFIRM(aob_flags_shift  == (aob_delta_shift  - 9)) ;   /* Next 9 bits  */
CONFIRM(aob_action_shift == (aob_flags_shift  - 2)) ;   /* Next 2 bits  */
CONFIRM(aob_type_shift   == (aob_action_shift - 2)) ;   /* LS   2 bits  */

CONFIRM((  ((uint)aob_index_mask   << aob_index_shift)
         + ((uint)aob_delta_mask   << aob_delta_shift)
         + ((uint)aob_flags_mask   << aob_flags_shift)
         + ((uint)aob_action_mask  << aob_action_shift)
         + ((uint)aob_type_mask    << aob_type_shift)  ) == UINT32_MAX) ;

CONFIRM(aob_mrai_wait     & (aob_flags_mask << aob_flags_shift)) ;
CONFIRM(aob_ex            & (aob_flags_mask << aob_flags_shift)) ;

CONFIRM(sizeof(uint) >= sizeof(adj_out_bits_t)) ;

enum
{
  /* We are using time periods to implement relatively short delays.  The
   * aob_delay_max represents the maximum possible delay, and is set to
   * be just over 2 minutes.  Generally the maximum delay is the MRAI, which
   * is 30 seconds by default for eBGP.
   */
  aob_mrai_max            = 120 * 4,    /* more than 2 minutes          */

  aob_batch_delay_ebgp    =   3 * 4,    /* ~ 3 seconds                  */
  aob_announce_delay_ebgp =   2 * 4,    /* ~ 2 seconds                  */

  aob_batch_delay_ibgp    =   3 * 4/2,  /* ~ 1.5 seconds                */
  aob_announce_delay_ibgp =   2 * 2,    /* ~ 1 seconds                  */

  aob_delay_max           = 127 * 4,

  /* Even when things are busy, we expect the ...
   *
   */
  aob_time_slack     =  10 * 4,         /* a little over 10 seconds     */
};

CONFIRM(aob_delay_max   > (QTIME(128) >> bgp_period_shift)) ;

CONFIRM(aob_delay_max  >= aob_mrai_max + aob_batch_delay_ebgp) ;
CONFIRM(aob_delay_max  >= aob_announce_delay_ebgp) ;
CONFIRM(aob_delay_max  >= aob_mrai_max + aob_batch_delay_ibgp) ;
CONFIRM(aob_delay_max  >= aob_announce_delay_ebgp) ;

CONFIRM(aob_delay_max   < (uint)aob_delta_mask) ;
CONFIRM(aob_delay_max   < ((uint)aob_index_mask / 2)) ;

CONFIRM(sizeof(adj_out_bits_t) <= sizeof(uint32_t)) ;

/* The type values are common to all things that the adj_out entry can point
 * to.
 *
 * NB: if aob_attr_set bit is set, the rest of the bits may be anything and
 *     MUST be ignored.
 *
 * NB: an attr_flux object is NOT referred to by an adj_out entry, but
 *     like route_mpls may be pointed to by a route_flux.  Note that we
 *     cannot distinguish an attr_flux from an attr_set -- the route_flux
 *     can tell that from the route_flux_action_t.
 *
 *     The attr_flux object also starts with a vhash_node, and its reference
 *     count field is co-opted to be the adj_out_bits_t for the attr_flux,
 *     at least for the time settings.
 *
 *     The attr_flux object is always "set" from a vhash perspective, same
 *     like the attr_set.  But, unlike the attr_set, the attr_flux does not
 *     use the reference count (since that has been co-opted !).
 *
 * NB: an empty attr_flux object is used to signal End-of-RIB.
 */
typedef enum adj_out_type adj_out_type_t ;
enum adj_out_type
{
  aob_attr_set    = BIT(0),
  aob_attr_flux   = aob_attr_set,

  aob_eor         = 0 * BIT(1),

  aob_mpls        = 0 * BIT(1),
  aob_flux        = 1 * BIT(1),

  aob_type_count,
} ;
CONFIRM(aob_attr_set  == (uint)vhash_ref_count_set) ;
CONFIRM(aob_attr_flux == (uint)vhash_ref_count_set) ;
CONFIRM(aob_type_mask >= (aob_type_count - 1)) ;

/* A route-flux object in aob_flux state has a route_flux_action, indicating
 * which list it is on, inter alia.
 */
typedef enum route_flux_action  route_flux_action_t ;
enum route_flux_action
{
  rf_act_batch    = 0,          /* with aob_flux        */
  rf_act_withdraw = 1,
  rf_act_announce = 2,
  rf_act_mrai     = 3,

  rf_act_count    = 4,
};
CONFIRM(aob_action_mask >= (rf_act_count - 1)) ;

/*------------------------------------------------------------------------------
 * A 'route_mpls' comprises a pointer to either an attribute set, or to an
 * attribute collection, plus an MPLS tag.
 *
 * In "steady state" the adj_out points at the 'route_mpls' (which in turn
 * points at the attribute set -- not NULL).
 *
 * When in flux, the adj_out points to a 'route_flux', which points at the
 * 'route_mpls' (which in turn points at the attribute out marshal).
 */
typedef struct route_mpls  route_mpls_t ;

struct route_mpls
{
  void*         atp ;           /* attr_flux for pending announcement
                                 * attr_set for announced route         */
  mpls_tags_t   tag ;

  uint32_t      bits ;          /* the adj_out_bits_t                   */
} ;

/* An adj_out_ptr may refer to a route_mpls, so it must be capable of being
 * mapped to an adj_out_t.
 */
CONFIRM(offsetof(route_mpls_t, bits)  == offsetof(adj_out_t, bits)) ;
CONFIRM(sizeof(((route_mpls)0)->bits) == sizeof(((adj_out)0)->bits)) ;

/*------------------------------------------------------------------------------
 * A 'route_flux' manages a route while a new update is pending, and for a
 * while after that (to support MinRouteAdvertisementTimer).
 *
 * When an update is pending, the attr pointer refers to an attr_flux either
 * directly or via a route_mpls.  The route_flux object will live on the
 * rf_act_announce fifo.
 *
 * When a withdraw is pending, the attr pointer is NULL, and the route_flux
 * object will live on the rf_act_withdraw fifo.
 *
 * When the route has been announced, the attr pointer is NULL, or points to
 * the attribute set last announced either directly or via a route_mpls.  The
 * route_flux object will live on the ra_out_cool fifo, until the cooling
 * time expires.
 */
typedef struct route_flux  route_flux_t ;

struct route_flux
{
  void*         current ;       /* NULL => nothing
                                 * attr_set for not MPLS
                                 * route_mpls for MPLS.                 */
  prefix_id_t   pfx_id ;

  uint32_t      bits ;          /* the adj_out_bits_t   */

  void*         pending ;       /* if not MPLS:
                                 *   NULL => withdraw or nothing pending
                                 *   attr_set  -- unless rf_act_announce
                                 *   attr_flux -- for rf_act_announce
                                 * if MPLS -> route_mpls (at all times)
                                 *   the route_mpls->atp is as above.   */

  struct dl_list_pair(route_flux) list ;
} ;

/* An adj_out_ptr may refer to a route_mpls, so it must be capable of being
 * mapped to an adj_out_t.
 */
CONFIRM(offsetof(route_flux_t, bits)  == offsetof(adj_out_t, bits)) ;
CONFIRM(sizeof(((route_flux)0)->bits) == sizeof(((adj_out)0)->bits)) ;

/*------------------------------------------------------------------------------
 * While marshalling updates, it is necessary to collect together all prefixes
 * which are being advertised with the same attributes.
 *
 * To do that, the peer_rib contains a vhash table for attributes.  The hash
 * table points at attr_flux objects.
 *
 * Each attr_flux object has a fifo, on which all related 'route_flux' items are
 * hung.  Where the attr_flux object has a not-empty fifo, it will live on
 * the adj_out's fifo[rf_act_announce].
 *
 * NB: the
 */
typedef struct attr_flux  attr_flux_t ;
typedef const struct attr_flux* attr_flux_c ;

struct attr_flux
{
  /* Red Tape for the hash
   */
  vhash_node_t  vhash ;

  /* The attributes in question.
   *
   * NB: this pointer "owns" a lock on the stored attribute set.
   *
   *     Pointers to the bgp_adv_attr own a lock on the vhash node.  They do
   *     not have their own lock on the attributes.
   *
   * NB: the attributes here are the attributes *after* any 'out' route-map.
   */
  attr_set attr ;

  /* When the 'fifo' is not empty, this sits on the adj_out
   */
  struct dl_list_pair(attr_flux) list ;

  /* Base of fifo of route_flux objects which share these attributes.
   */
  struct dl_base_pair(route_flux) fifo ;
} ;

CONFIRM(offsetof(attr_flux_t, vhash) == 0) ;     /* see vhash.h  */

/* An attr_flux must be distinguishable from an attr_set, so it must be capable
 * of being mapped to an adj_out_t.
 */
CONFIRM(offsetof(adj_out_t, bits)  == offsetof(attr_flux_t, vhash.ref_count)) ;
CONFIRM(sizeof(((adj_out)0)->bits) == sizeof(((attr_flux)0)->vhash.ref_count)) ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_adj_out_init(peer_rib prib) ;
extern void bgp_adj_out_discard(peer_rib prib) ;
extern void bgp_adj_out_set_stale(peer_rib prib, uint delay) ;

extern void bgp_adj_out_update (peer_rib prib, prefix_id_entry pie,
                                            attr_set attr, mpls_tags_t tag) ;
extern void bgp_adj_out_eor(peer_rib prib) ;

Inline bool bgp_adj_out_have_withdraw(peer_rib prib) ;
Inline bool bgp_adj_out_have_announce(peer_rib prib) ;

extern route_out_parcel bgp_adj_out_next_withdraw(peer_rib prib,
                                                      route_out_parcel parcel) ;
extern route_out_parcel bgp_adj_out_done_withdraw(peer_rib prib,
                                                      route_out_parcel parcel) ;
extern route_out_parcel bgp_adj_out_first_announce(peer_rib prib,
                                                      route_out_parcel parcel) ;
extern route_out_parcel bgp_adj_out_next_announce(peer_rib prib,
                                                      route_out_parcel parcel) ;
extern void bgp_adj_out_done_announce(peer_rib prib, route_out_parcel parcel) ;

/*------------------------------------------------------------------------------
 *
 */
Inline bool
bgp_adj_out_have_withdraw(peer_rib prib)
{
  return (prib->withdraw_queue.head != NULL) ;
}

/*------------------------------------------------------------------------------
 *
 */
Inline bool
bgp_adj_out_have_announce(peer_rib prib)
{
  return (prib->withdraw_queue.head != NULL) ;
}

#endif /* _QUAGGA_BGP_ADJ_OUT_H */
