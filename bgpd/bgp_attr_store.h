/* BGP attributes store -- Header.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman (substantially rewritten)
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
#ifndef _QUAGGA_BGP_ATTR_STORE_H
#define _QUAGGA_BGP_ATTR_STORE_H

#include "misc.h"

#include "vhash.h"
#include "name_map.h"
#include "vty.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_unknown.h"
#include "bgpd/bgp_cluster.h"
#include "bgpd/bgp_mplsvpn.h"

/*==============================================================================
 * BGP attribute structure
 */

/* For attributes where need to know whether the attribute is set or not, and
 * that cannot be determined from its value.
 */
enum attr_bits
{
  atb_local_pref            = BIT( 0),
  atb_med                   = BIT( 1),
  atb_atomic_aggregate      = BIT( 2),  /* presence/absence is it       */
  atb_originator_id         = BIT( 3),
  atb_reflected             = BIT( 4),  /* one bit of state             */
} ;

typedef byte  attr_bits_t ;     /* NB: <= 8 bits !              */

/* Extra value to signal unknown/unset origin
 *
 * Real ORIGIN values are BGP_ATT_ORG_MIN (0) .. BGP_ATT_ORG_MAX, inclusive.
 */
CONFIRM(BGP_ATT_ORG_MIN == 0) ;
enum { BGP_ATT_ORG_UNSET = BGP_ATT_ORG_MAX + 1 } ;

/* Next-Hop Types
 */
enum attr_next_hop_type
{
  nh_none       = 0,

  nh_ipv4,

  nh_ipv6_1,            /* "global" address only                */
  nh_ipv6_2,            /* "global" and link-local addresses    */

  nh_max
} ;

CONFIRM(nh_max <= 256) ;
typedef byte nh_type_t ;

typedef struct attr_next_hop  attr_next_hop_t ;
typedef struct attr_next_hop* attr_next_hop ;

struct attr_next_hop
{
  nh_type_t       type ;
  union ip_next_hop
    {
      in_addr_t         v4 ;
      struct in_addr    in_addr ;
      in6_addr_pair_t   v6 ;
    } ip ;
} ;

enum { BGP_ATTR_DEFAULT_WEIGHT = 32768 } ;

/* The complete attributes.
 *
 * To initialise an attr_set_t, zeroize it.
 */
typedef struct attr_set  attr_set_t ;
typedef const struct attr_set* attr_set_c ;

struct attr_set
{
  /* The attributes are held in a vhash and whether is stored.
   *
   * NB: the leading part of the attribute set is to do with the organisation
   *     of the attribute store, and does *not* form part of the value, and is
   *     not part of the hash.
   *
   * NB: when an attribute set is stored, it is *always* stored as "set".
   *
   *     This means that attribute sets are NOT automatically destroyed when
   *     their use count reduces to zero:
   *
   *       * when things are busy, it is probably worth saving the memory
   *         management overhead -- so this is deferred to quieter moments.
   *
   *       * it is possible, particularly for Route Server but also while
   *         converging at start-up, that some attribute sets may be created,
   *         destroyed and recreated.  Deferring actual destruction helps.
   *
   *       * there is a massive KLUDGE in the adj_out area, which uses the
   *         fact that a stored attribute set *always* has the "set" bit !!
   *
   *         See .... TODO ...........................................................
   */
  vhash_node_t    vhash ;

  /* Which attributes and sub-attribute sets we have here
   *
   * NB: this is the start of the attributes value.  Everything from, and
   *     including, the flags is part of the hash.
   *
   * NB: when initialising a new set of attributes, it is essential to zeroize
   *     all of this.
   */
  attr_bits_t     have ;                /*<-<-<-<-<-<-<-<-<-<-<-*/

  /* The attributes
   *
   * For any given set of attributes we have one address family type of
   * next_hop.  If none is set, the next_hop->type will be nh_none, and the
   * rest of the value is zero.  Note that some care must be taken when
   * setting/changing a next_hop value, to ensure that all parts which are
   * not set are set to zero.
   *
   * All of these are initialised by being set to zero, except for 'origin'
   * which is set to BGP_ATT_ORG_UNSET.
   */
  uint8_t         origin ;              /* BGP_ATT_ORG_UNSET if not set      */

  uint16_t        weight;               /* zero => none (or zero)            */

  uint32_t        med ;                 /* zero unless atb_med               */
  uint32_t        local_pref ;          /* zero unless atb_local_pref        */

  in_addr_t       originator_id ;       /* zero unless atb_originator_id     */

  as_t            aggregator_as ;       /* BGP_ASN_NULL <=> none             */
  in_addr_t       aggregator_ip ;       /* zero if none                      */

  /* The next-hop and the tags are an integral part of the attributes.
   *
   * When an MPLS prefix is advertised, the next-hop identifies the origin PE
   * router which understands how to deliver packets to that MPLS prefix.  The
   * tag tells the origin PE router which VPN (or VRF) an incoming packet is
   * destined for.  So, some distant PE router pushes the tag and forwards the
   * result towards the origin PE by pushing a further tag to implement the
   * "tunnel" across the provider's network.
   *
   * On an incoming set of attributes the next-hop and the tags are, therefore
   * closely linked -- even though the tags arrive with the prefix and the
   * next-hop attribute does not carry a tag.
   */
  attr_next_hop_t next_hop ;            /* all zero if none set              */
  mpls_tags_t     tags ;

  /* The sub-attributes
   *
   * NB: the attribute set cannot be stored until all the sub-attributes have
   *     been.  Once a sub-attribute has been stored, its *address* is a
   *     proxy name for the sub-attribute, and is used as part of the hash
   *     for the entire set, and when comparing attribute sets for equality.
   *
   * All of these are initialised to NULL, except asp which is set to
   * as_path_empty_asp.
   */
  as_path         asp ;
  attr_community  community ;           /* NULL <=> empty/absent             */
  attr_unknown    transitive ;          /* NULL <=> empty/absent             */
  attr_ecommunity ecommunity ;          /* NULL <=> empty/absent             */
  attr_cluster    cluster ;             /* NULL <=> empty/absent             */
} ;

CONFIRM(offsetof(attr_set_t, vhash) == 0) ;      /* see vhash.h  */

enum
{
  attr_set_value_offset  = offsetof(attr_set_t, have),
  attr_set_value_size    = sizeof(attr_set_t) - attr_set_value_offset,
};

Inline void*
attr_set_value(attr_set set)
{
  return ((char*)set) + attr_set_value_offset ;
} ;

Inline const void*
attr_set_value_c(attr_set_c set)
{
  return ((const char*)set) + attr_set_value_offset ;
} ;

/*------------------------------------------------------------------------------
 * When operating on attribute sets, uses an "attribute pair", comprising the
 * original attribute set and the working attribute set -- the working set
 * starts as the original set, and then any changes to the attributes affect
 * the working set, only.
 *
 * For the sub-attributes, bits in the 'new' field in the attribute pair are
 * set when the respective sub-attribute in the working set is changed.
 */
typedef struct attr_pair  attr_pair_t ;
typedef struct attr_pair* attr_pair ;

enum attr_new_bits
{
  atnb_as_path               = BIT( 0),
  atnb_community             = BIT( 1),
  atnb_ecommunity            = BIT( 2),
  atnb_cluster               = BIT( 3),
  atnb_transitive            = BIT( 4),

  atnb_all   = (atnb_as_path      |
                atnb_community    |
                atnb_ecommunity   |
                atnb_cluster      |
                atnb_transitive
               )
};
typedef enum attr_new_bits attr_new_bits_t ;

struct attr_pair
{
  /* "stored" points to a stored attribute set -- NULL if none.
   *
   * The stored set (if any) is *read* *only*.
   *
   * This pointer is counted in the attribute set's reference count, so
   * attribute set pair set up and tear down has to deal with that.
   *
   * NB: all sub-attributes will be stored attributes.
   *
   *     The reference count of a sub-attribute accounts for the pointer in
   *     the attribute set *only*.
   */
  attr_set     stored ;

  /* "working" points to a working attribute set
   *
   * This will either be the same as the stored set, or be a brand new set
   * which is in construction.  A set in construction will zero reference
   * count *and* not be "set" (in vhash terms).
   */
  attr_set     working ;

  /* When a new working set is created, sub-attributes are simply copied from
   * the stored set -- without locking.  The 'new' set of sub attributes is
   * emptied.
   *
   * When new sub-attribute values are set in the working set, they will
   * be registered as 'new' and will be:
   *
   *   * existing stored values, which will locked as they are placed in the
   *     working set
   *
   *   * brand new values, not stored, which are completely unlocked.
   *
   * If a sub-attribute is unset in the working set, if it was a simple copy
   * of the original attribute, then the old pointer is discarded; if a new
   * value has been set, then a stored value needs to be unlocked, and an
   * unstored value needs to be freed.  In all cases the sub-attribute is
   * cleared from the 'have' set and the 'new' set.
   *
   * So, when the working set is stored or discarded, the 'new' state and
   * whether a sub-attribute is stored are used to decide how to deal with
   * each one.
   */
  attr_new_bits_t  new ;

  /* When a new working set is created, the working pointer points to this
   * "scratch" set.
   *
   * This means that only need to malloc an actual set if the set created is
   * (a) stored and (b) does not already exist.
   */
  attr_set_t scratch[1] ;
} ;

/*==============================================================================
 * Functions.
 */
extern void bgp_attr_start(void) ;
extern void bgp_attr_finish(void) ;
extern uint bgp_attr_count (void);
extern void bgp_attr_show_all (struct vty *vty) ;

Inline attr_set bgp_attr_lock(attr_set set) ;
Inline attr_set bgp_attr_unlock(attr_set set) ;

extern attr_set bgp_attr_pair_load_new(attr_pair pair) ;
extern attr_set bgp_attr_pair_load(attr_pair pair, attr_set set) ;
extern attr_set bgp_attr_pair_load_default(attr_pair pair, byte origin) ;
extern attr_set bgp_attr_pair_store(attr_pair pair) ;
extern attr_set bgp_attr_pair_assign(attr_pair pair) ;
extern attr_set bgp_attr_pair_unload(attr_pair pair) ;

extern attr_set bgp_attr_pair_set_as_path(attr_pair pair, as_path asp) ;
extern attr_set bgp_attr_pair_set_community(attr_pair pair,
                                                          attr_community comm) ;
extern attr_set bgp_attr_pair_set_ecommunity(attr_pair pair,
                                                         attr_ecommunity ecomm);
extern attr_set bgp_attr_pair_set_cluster(attr_pair pair, attr_cluster clust) ;
extern attr_set bgp_attr_pair_set_transitive(attr_pair pair, attr_unknown unk) ;

extern attr_set bgp_attr_pair_set_next_hop(attr_pair pair, nh_type_t type,
                                                               const void* ip) ;
extern attr_set bgp_attr_pair_set_local_pref(attr_pair pair,
                                                          uint32_t local_pref) ;
extern attr_set bgp_attr_pair_default_local_pref(attr_pair pair,
                                                          uint32_t local_pref) ;
extern attr_set bgp_attr_pair_clear_local_pref(attr_pair pair,
                                                          uint32_t local_pref) ;
extern attr_set bgp_attr_pair_set_weight(attr_pair pair, uint16_t weight) ;
extern attr_set bgp_attr_pair_set_med(attr_pair pair, uint32_t med) ;
extern attr_set bgp_attr_pair_default_med(attr_pair pair, uint32_t med) ;
extern attr_set bgp_attr_pair_clear_med(attr_pair pair, uint32_t med) ;
extern attr_set bgp_attr_pair_set_origin(attr_pair pair, uint origin) ;
extern attr_set bgp_attr_pair_clear_origin(attr_pair pair) ;
extern attr_set bgp_attr_pair_set_atomic_aggregate(attr_pair pair, bool flag) ;
extern attr_set bgp_attr_pair_set_originator_id(attr_pair pair, bgp_id_t id) ;
extern attr_set bgp_attr_pair_clear_originator_id(attr_pair pair) ;
extern attr_set bgp_attr_pair_set_reflected(attr_pair pair, bool reflected) ;
extern attr_set bgp_attr_pair_set_aggregator(attr_pair pair, as_t as,
                                                                 in_addr_t ip) ;
extern attr_set bgp_attr_set_tags(attr_set attr, mpls_tags_t tags) ;

/* An empty set of attributes, set up in bgp_attr_start() and discarded in
 * bgp_attr_finish().  This set of attributes is never put into the vhash
 * table, but its reference count may be incremented/decremented in the usual
 * way.
 *
 * The bgp_attr_null is completely empty and MUST NOT be used as anything
 * except as a placeholder for no attributes at all.
 */
extern attr_set bgp_attr_null ;

/*==============================================================================
 * The Inlines
 */

/*------------------------------------------------------------------------------
 * Increase the reference count on the given set of attributes.
 *
 * MUST be a stored set !!
 *
 * Returns: the attribute set
 *
 * So can:   foo->set = bgp_attr_unlock(bar->set) ;
 */
Inline attr_set
bgp_attr_lock(attr_set set)
{
  qassert(vhash_is_set(set)) ;

  vhash_inc_ref(set) ;

  return set ;
} ;

/*------------------------------------------------------------------------------
 * Reduce the reference count on the given set of attributes.
 *
 * MUST be a stored set and MUST have a non-zero reference count.
 *
 * Attributes may vanish at some time in the future if the reference count
 * becomes zero.
 *
 * Returns:  NULL
 *
 * So can:   foo->set = bgp_attr_unlock(foo->set) ;
 *
 * NB: does NOT immediately discard a set of attributes whose reference count
 *     hits zero.  That is left for "garbage collection".
 *
 *     The bgp_attr_null "dummy" set of attributes can be bgp_attr_lock() and
 *     bgp_attr_unlock(), but will not be garbage collected.
 */
Inline attr_set
bgp_attr_unlock(attr_set set)
{
  qassert(vhash_is_set(set) && vhash_has_references(set)) ;

  vhash_dec_ref_simple(set) ;

  return NULL ;
} ;

#endif /* _QUAGGA_BGP_ATTR_STORE_H */
