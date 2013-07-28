/* BGP Cluster Attribute handling -- Header
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_CLUSTER_H
#define _QUAGGA_BGP_CLUSTER_H

#include "misc.h"
#include "qlump.h"

/*==============================================================================
 * Cluster attributes comprise:
 *
 *   * CLUSTER_LIST    -- list of 32-bit values
 *
 * The CLUSTER_LIST is held as a qlump of 4 byte entries, with an embedded body
 * of 6 entries, which should easily be enough for almost any network.
 *
 * The qlump length is the length of the CLUSTER_LIST.
 */
typedef bgp_id_t cluster_id_t ;

enum { cluster_list_embedded_size = 6 } ;

enum attr_cluster_state
{
  clst_null         = 0,        /* nothing set, no encoding etc.        */

  clst_string       = BIT(1),

  clst_limit,
} ;
CONFIRM(clst_limit <= 256) ;

typedef byte attr_cluster_state_t ;

typedef       struct attr_cluster  attr_cluster_t ;
typedef       struct attr_cluster* attr_cluster ;
typedef const struct attr_cluster* attr_cluster_c ;

struct attr_cluster
{
  /* Red tape for storing cluster attributes
   */
  vhash_node_t vhash ;

  bool      stored ;

  /* State
   */
  attr_cluster_state_t state ;

  /* String equivalent of the cluster list -- valid if clst_string
   */
  qstring_t   str ;             /* embedded qstring             */

  /* list qlump and embedded body
   *
   * NB: the cluster_id_t's are held in Network Order -- they are bgp_id_t.
   */
  qlump_t   list ;

  cluster_id_t embedded_list[cluster_list_embedded_size] ;
} ;

CONFIRM(offsetof(attr_cluster_t, vhash) == 0) ; /* see vhash.h  */

/*------------------------------------------------------------------------------
 * For output of cluster list attribute, which always goes with a prepended
 * cluster-id
 */
typedef struct attr_cluster_out  attr_cluster_out_t ;
typedef struct attr_cluster_out* attr_cluster_out ;

struct attr_cluster_out
{
  byte*      part[2] ;
  uint       len[2] ;

  /* NB: we do something a little dirty here...
   *
   *     ... the attribute red tape is written into the buf[] so that it
   *         immediately precedes the cluster_id.
   *
   *     ... it is possible that the alignment of the cluster_id could
   *         introduce space space between buf[] and the cluster_id, so
   *         we set the start of the attribute header by counting *back*
   *         from the address of the cluster_id !!!
   *
   * So: do NOT separate buf[] and cluster_id, and do NOT change the order !!
   */
  byte       buf[4] ;                   /* Attribute header + 1 prepend */
  cluster_id_t  cluster_id ;            /* to prepend                   */
} ;

/*==============================================================================
 */
extern void attr_cluster_start(void) ;
extern void attr_cluster_finish(void) ;

extern attr_cluster attr_cluster_new(uint n) ;
extern attr_cluster attr_cluster_store(attr_cluster clust) ;
extern attr_cluster attr_cluster_free(attr_cluster clust) ;
Inline void attr_cluster_lock(attr_cluster clust) ;
Inline attr_cluster attr_cluster_release(attr_cluster clust) ;

extern attr_cluster attr_cluster_set(const byte* p, uint count) ;
extern void attr_cluster_out_prepare(attr_cluster_out out, attr_cluster clust) ;

extern bool attr_cluster_check(attr_cluster clust, cluster_id_t id) ;
extern uint attr_cluster_length(attr_cluster clust) ;
extern const char* attr_cluster_str (attr_cluster clust) ;

/*------------------------------------------------------------------------------
 * Functions to increase the reference count and to release an attr_cluster.
 */
Private vhash_table attr_cluster_vhash ;

/*------------------------------------------------------------------------------
 * Increase the reference count on the given attr_cluster
 *
 * NB: clust may NOT be NULL and MUST be stored
 */
Inline void
attr_cluster_lock(attr_cluster clust)
{
  qassert((clust != NULL) && (clust->stored)) ;

  vhash_inc_ref(clust) ;
} ;

/*------------------------------------------------------------------------------
 * Release the given attr_cluster (if any):
 *
 *   * do nothing if NULL
 *
 *   * if is stored, reduce the reference count.
 *
 *   * if is not stored, free it.
 *
 * Returns:  NULL
 */
Inline attr_cluster
attr_cluster_release(attr_cluster clust)
{
  if (clust != NULL)
    {
      if (clust->stored)
        vhash_dec_ref(clust, attr_cluster_vhash) ;
      else
        attr_cluster_free(clust) ;
    } ;

  return NULL ;
} ;

#endif /* _QUAGGA_BGP_CLUSTER_H */
