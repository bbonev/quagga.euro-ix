/* BGP Peer Index
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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
#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_peer_config.h"

#include "lib/vhash.h"
#include "lib/vector.h"
#include "lib/qpthreads.h"
#include "lib/sockunion.h"
#include "lib/memory.h"
#include "lib/list_util.h"

/*==============================================================================
 * BGP Peer Index and its Mutex
 *
 * When peers are created, they are registered in the bgp_peer_su_index.  When
 * they are destroyed, they are removed.  This is done by the Routing Engine.
 *
 * The Peer Index is used by the Routing Engine to lookup peers either by
 * name (IP address) or by peer_id.
 *
 * The BGP Engine needs to know what to do when a listening socket accepts a
 * connection, so the Peer Index is used by the BGP Engine to lookup the
 * session by its name.
 */
typedef struct bgp_peer_index_entry  bgp_peer_index_entry_t ;
typedef struct bgp_peer_index_entry* bgp_peer_index_entry ;
typedef struct bgp_peer_index_entry const* bgp_peer_index_entry_c ;

struct bgp_peer_index_entry
{
  /* When registered, the entry is in the IP address hash.
   */
  vhash_node_t  vhash ;

  /* When not registered and not in use, the entry lives on the free list.
   */
  bgp_peer_index_entry  next_free ;

  /* The "name" of the peer is set when the index entry is created, and
   * not cleared until the entry is destroyed.  When the entry is registered,
   * the "name" is what it is registered as.
   *
   * The "id" is intrinsic to the entry.
   */
  sockunion_t   su_name[1] ;
  bgp_peer_id_t id ;

  /* Pointer to the configured peer
   */
  bgp_peer      peer ;

  /* Pointers to running peer and session to which this applies.
   *
   * These are set when the index entry is created, which is just after the
   * peer and its session are created.
   */
  bgp_prun      prun ;
  bgp_session   session ;
} ;

CONFIRM(offsetof(bgp_peer_index_entry_t, vhash) == 0) ; /* see vhash.h  */

/*------------------------------------------------------------------------------
 * The BGP Peer Index comprises a vhash_table for looking up peers "by name"
 * and a vector for looking up peers "by peer_id".  Both structures point to
 * struct bgp_peer_index_entry entries.
 */

static vhash_table  bgp_peer_su_index = NULL ;  /* lookup by 'name'     */
static vector_t     bgp_peer_id_index[1] ;      /* lookup by peer-id    */

static qpt_mutex    bgp_peer_index_mutex = NULL ;

CONFIRM(bgp_peer_id_null == 0) ;

#if 0
enum { bgp_peer_id_unit  = 64 } ;       /* allocate many at a time      */

typedef struct bgp_peer_id_table_chunk  bgp_peer_id_table_chunk_t ;
typedef struct bgp_peer_id_table_chunk* bgp_peer_id_table_chunk ;

struct bgp_peer_id_table_chunk
{
  bgp_peer_id_table_chunk  next ;

  bgp_peer_index_entry_t entries[bgp_peer_id_unit] ;
} ;
#endif

inline static void BGP_PEER_INDEX_LOCK(void)
{
  qpt_mutex_lock(bgp_peer_index_mutex) ;
} ;

inline static void BGP_PEER_INDEX_UNLOCK(void)
{
  qpt_mutex_unlock(bgp_peer_index_mutex) ;
} ;

static struct dl_base_pair(bgp_peer_index_entry) bgp_peer_id_free
                                                             = { NULL, NULL } ;
/* The vhash table magic
 */
static vhash_equal_func bgp_peer_su_index_equal ;
static vhash_new_func   bgp_peer_su_index_new ;
static vhash_free_func  bgp_peer_su_index_free ;

static const vhash_params_t peer_index_vhash_params =
{
  .hash         = sockunion_vhash_hash,
  .equal        = bgp_peer_su_index_equal,
  .new          = bgp_peer_su_index_new,
  .free         = bgp_peer_su_index_free,
  .orphan       = vhash_orphan_null,
  .table_free   = vhash_table_free_parent,
} ;

/* Forward references
 */
static void bgp_peer_id_table_free_entry(bgp_peer_index_entry peer_ie,
                                                             bgp_peer_id_t id) ;

/*------------------------------------------------------------------------------
 * Initialise the bgp_peer_su_index.
 *
 * This must be done before any peers are configured !
 */
extern void
bgp_peer_index_init(void)
{
  bgp_peer_su_index = vhash_table_new(
          &bgp_peer_su_index,
          50,                     /* start ready for a few sessions     */
          200,                    /* allow to be quite dense            */
          &peer_index_vhash_params) ;

  vector_init_new(bgp_peer_id_index, 50) ;
  vector_push_item(bgp_peer_id_index, NULL) ;
  CONFIRM(bgp_peer_id_null == 0) ;              /* NULL entry   */

  dsl_init(bgp_peer_id_free) ;
} ;

/*------------------------------------------------------------------------------
 * Second stage initialisation.
 *
 * Initialise the bgp_peer_index_mutex.
 */
extern void
bgp_peer_index_init_r(void)
{
  bgp_peer_index_mutex = qpt_mutex_new(qpt_mutex_recursive, "Peer Index") ;
} ;

/*------------------------------------------------------------------------------
 * Shut down the peer index -- freeing all memory and mutex.
 *
 * For shutdown, *only*.
 *
 * NB: assumes is running in the one remaining thread at shutdown
 *
 * NB: it would be a serious mistake to do anything at all with the peer index
 *     after this -- so all listeners should be shut *first*.
 */
extern void
bgp_peer_index_finish(void)
{
  bgp_peer_index_entry    peer_ie ;

  qassert(!qpthreads_active) ;

  /* Ream out and discard vhash table -- gives back the peer_ids which are in
   * use.  The chunks of entries are freed en masse, below.
   */
  bgp_peer_su_index = vhash_table_reset(bgp_peer_su_index) ;

  /* Ream out the peer id vector -- checking that all entries are empty and
   * freeing same.
   */
  while ((peer_ie = vector_ream(bgp_peer_id_index, keep_it)) != NULL)
    {
      qassert(peer_ie->peer == NULL) ;
      XFREE(MTYPE_BGP_PEER_ID_ENTRY, peer_ie) ;
    } ;

  /* Set utterly empty and discard mutex.
   */
  dsl_init(bgp_peer_id_free) ;

  bgp_peer_index_mutex = qpt_mutex_destroy(bgp_peer_index_mutex) ;
} ;

/*------------------------------------------------------------------------------
 * Register a peer in the peer index.
 *
 * For use by the Routeing Engine.
 *
 * Registering the entry sets it 'held'.
 *
 * Returns:  the peer-id  -- bgp_peer_id_null <=> already registered !
 */
extern bgp_peer_id_t
bgp_peer_index_register(bgp_peer peer)
{
  bgp_peer_index_entry peer_ie ;
  bool          added ;
  bgp_peer_id_t id ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  /* Add entry to the vhash_table -- creates entry and allocates id.
   */
  peer_ie = vhash_lookup(bgp_peer_su_index, peer->su_name, &added) ;

  if (added)
    {
      peer_ie->peer = peer ;
      id = peer_ie->id ;

      vhash_set_held(peer_ie) ;
    }
  else
    {
      id = bgp_peer_id_null ;
    } ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->-->*/

  return id ;
} ;

/*------------------------------------------------------------------------------
 * Lookup a peer configuration -- do nothing if does not exist
 *
 * For use by the Routeing Engine.
 *
 * Returns:  the bgp_peer -- NULL if not found.
 */
extern bgp_peer
bgp_peer_index_peer_lookup(sockunion su)
{
  bgp_peer_index_entry peer_ie ;
  bgp_peer peer ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  peer_ie = vhash_lookup(bgp_peer_su_index, su, NULL) ;

  if (peer_ie != NULL)
    peer = peer_ie->peer ;
  else
    peer = NULL ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->-->*/

  return peer ;
} ;

/*------------------------------------------------------------------------------
 * Lookup a peer running state -- do nothing if does not exist
 *
 * For use by the Routeing Engine.
 *
 * Returns:  the bgp_prun -- NULL if not found.
 */
extern bgp_prun
bgp_peer_index_prun_lookup(sockunion su)
{
  bgp_peer_index_entry peer_ie ;
  bgp_prun prun ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  peer_ie = vhash_lookup(bgp_peer_su_index, su, NULL) ;

  if (peer_ie != NULL)
    prun = peer_ie->prun ;
  else
    prun = NULL ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->-->*/

  return prun ;
} ;

/*------------------------------------------------------------------------------
 * Lookup a peer's session -- do nothing if does not exist
 *
 * For use by the BGP Engine.
 *
 * Returns:  the bgp_session -- NULL if not found.
 *
 * NB: caller is BGP Engine, so the pointer from the peer index entry to the
 *     session is stable, because the BGP Engine is responsible for the session,
 *     once it is created.
 */
extern bgp_session
bgp_peer_index_session_lookup(sockunion su)
{
  bgp_peer_index_entry peer_ie ;
  bgp_session          session ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  peer_ie = vhash_lookup(bgp_peer_su_index, su, NULL) ;

  if (peer_ie != NULL)
    session = peer_ie->session ;
  else
    session = NULL ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->-->*/

  return session ;
} ;

/*------------------------------------------------------------------------------
 * Deregister a peer from the peer index -- for use by the Routeing Engine.
 *
 * NB: it is a FATAL error to deregister a peer which is not registered.
 */
extern void
bgp_peer_index_deregister(bgp_peer peer)
{
  bgp_peer_index_entry peer_ie ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  peer_ie = vector_get_item(bgp_peer_id_index, peer->peer_id) ;
  assert((peer_ie != NULL) && (peer_ie->peer == peer)
                           && (peer->peer_id == peer_ie->id)) ;

  peer_ie->peer = NULL ;
  peer->peer_id = bgp_peer_id_null ;

  vhash_clear_held(peer_ie) ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Create a new entry in the bgp_peer_su_index, for the given sockunion.
 *
 * Allocates the next peer_id -- creating more if required.
 *
 * NB: requires the BGP_PEER_INDEX_LOCK()
 */
static vhash_item
bgp_peer_su_index_new(vhash_table table, vhash_data_c data)
{
  bgp_peer_index_entry peer_ie ;
  bgp_peer_id_t        id ;
  sockunion_c          su ;

  su = data ;

  /* Allocate bgp_peer_index_entry complete with peer_id.
   */
  peer_ie = dsl_pop(&peer_ie, bgp_peer_id_free, next_free) ;

  if (peer_ie == NULL)
    {
      peer_ie = XCALLOC(MTYPE_BGP_PEER_ID_ENTRY,
                                               sizeof(bgp_peer_index_entry_t)) ;
      vector_push_item(bgp_peer_id_index, peer_ie) ;
      peer_ie->id = vector_last(bgp_peer_id_index) ;
    } ;

  id = peer_ie->id ;

  assert(vector_get_item(bgp_peer_id_index, id) == peer_ie) ;

  /* For completeness -- empty out the entry.
   *
   *   * vhash              -- set on exit
   *
   *   * next_free          -- NULL
   *
   *   * su_name            -- set below -- embedded !
   *   * id                 -- preserved !
   *
   *   * peer               -- NULL
   *   * prun               -- NULL
   *   * session            -- NULL
   */
  memset(peer_ie, 0, sizeof(bgp_peer_index_entry_t)) ;
  peer_ie->id = id ;

  /* Copy in the name of the entry before it is added to the vhash.
   */
  sockunion_copy(peer_ie->su_name, su) ;

  return peer_ie ;
} ;

/*------------------------------------------------------------------------------
 * Give back the peer_id -- the vhash_item is a bgp_peer_index_entry
 *
 * NB: requires the BGP_PEER_INDEX_LOCK()
 */
static vhash_item
bgp_peer_su_index_free(vhash_item item, vhash_table table)
{
  bgp_peer_index_entry peer_ie ;

  peer_ie = item ;
  qassert((peer_ie->peer == NULL) && (peer_ie->prun == NULL)
                                  && (peer_ie->session == NULL)) ;

  bgp_peer_id_table_free_entry(peer_ie, peer_ie->id) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function -- vhash_equal_func
 */
static int
bgp_peer_su_index_equal(vhash_item_c item, vhash_data_c data)
{
  bgp_peer_index_entry_c peer_ie ;
  sockunion_c            su_name ;

  peer_ie = item ;
  su_name = data ;

  return sockunion_cmp(peer_ie->su_name, su_name) ;
} ;

/*==============================================================================
 * Extending the bgp_peer_id_table and adding free entries to it.
 */

/*------------------------------------------------------------------------------
 * Free the given peer index entry and release its peer_id.
 *
 * NB: requires the BGP_PEER_INDEX_LOCK()
 */
static void
bgp_peer_id_table_free_entry(bgp_peer_index_entry peer_ie, bgp_peer_id_t id)
{
  assert((peer_ie != NULL) &&
                            ((uint)id < vector_get_length(bgp_peer_id_index))) ;
  assert(vector_get_item(bgp_peer_id_index, id) == peer_ie) ;

  /* Clear down the bgp_peer_index_entry:
   *
   *   * vhash              -- empty
   *
   *   * next_free          -- set below;
   *
   *   * su_name            -- emptied out
   *   * id                 -- preserved !
   *
   *   * peer               -- NULL (should already be !)
   *   * prun               -- NULL (should already be !)
   *   * session            -- NULL (should already be !)
   */
  memset(peer_ie, 0, sizeof(bgp_peer_index_entry_t)) ;
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;

  peer_ie->id = id ;

  /* Now stick on the list of free id
   */
  dsl_append(bgp_peer_id_free, peer_ie, next_free) ;
} ;

