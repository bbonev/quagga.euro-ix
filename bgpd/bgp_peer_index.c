/* BGP Peer Index -- header
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

#include "lib/zassert.h"

#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_peer_index.h"

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
 * connection, which can happen whether there is a peer or a session active for
 * the incoming address.  To handle incoming stuff "between sessions" each
 * configured peer has an "acceptor" object.  When a session is running, the
 * acceptor and the session interact.  When a session is not running, the
 * acceptor runs autonomously.
 *
 * The BGP Engine needs to:
 *
 *   * know whether a peer is configured for a given address.
 *
 *     When a peer is configured it is immediately entered into the index, and
 *     an acceptor object is created for it.
 *
 *     When a peer is dismantled, it is removed from the index.  However,
 *     the index entry may live on (pointing at moribund peer) if:
 *
 *       a) there is a session running for the peer -- the session will
 *          be in the process of being closed down.
 *
 *       b) the acceptor for this instance of the peer is yet to be
 *          destroyed.
 *
 *     because the BGP Engine is responsible for closing the session and/or
 *     shutting down the acceptor.
 *
 *   * know whether a peer is enabled for accept(), for when a connection
 *     arrives.
 *
 *   * be able to "track" an inbound connection while a session is not "up".
 *
 *   * manage connection options (eg password) for accept() and connect()
 *     sockets.
 *
 * The Routeing Engine needs:
 *
 *   * a Peer Index entry for each configured peer -- so needs to create and
 *     destroy those entries.
 *
 *   * a means to manage connection options, and signal changes to the BGP
 *     Engine.
 */
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
   * the "name" is what it is registered as.  (Note that it is possible for
   * more than one entry to have the same "name", but not possible for more
   * than one entry with the same name to be registered.  After an entry
   * is de-registered it continues in existence while the BGP Engine needs
   * it.)
   *
   * The "id" is intrinsic to the entry.
   *
   * These are read-only.
   */
  sockunion     su_name ;       /* the "name".                          */
  bgp_peer_id_t id ;            /* the id                               */

  /* Pointers to peer and session to which this applies.
   *
   * These are set when the index entry is created, which is at the same time
   * as the peer and its session are created.
   *
   * These are cleared, under the peer index mutex when the peer is deleted (by
   * the Routeing Engine), and when the session is deleted (by the BGP Engine).
   *
   * The peer will be deleted first, and at that moment the entry is removed
   * from the "name" hash... so the name can be re-registered, but the
   * peer-id and session pointer live on.  The session will be deleted later,
   * and at that moment the entry and the peer-id can be released.
   *
   * [In fact, the way this is done is that the first of RE/BE to delete
   *  peer/session removes the entry from the "name" hash, and the second
   *  frees the index entry all together and releases the peer-id.
   *
   *  When the index entry is created, it is "set" as belonging to the peer,
   *  but with a reference count, belonging to the session.]
   */
  bgp_peer      peer ;
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

enum { bgp_peer_id_unit  = 64 } ;       /* allocate many at a time      */

typedef struct bgp_peer_id_table_chunk  bgp_peer_id_table_chunk_t ;
typedef struct bgp_peer_id_table_chunk* bgp_peer_id_table_chunk ;

struct bgp_peer_id_table_chunk
{
  bgp_peer_id_table_chunk  next ;

  bgp_peer_index_entry_t entries[bgp_peer_id_unit] ;
} ;

inline static void BGP_PEER_INDEX_LOCK(void)
{
  qpt_mutex_lock(bgp_peer_index_mutex) ;
} ;

inline static void BGP_PEER_INDEX_UNLOCK(void)
{
  qpt_mutex_unlock(bgp_peer_index_mutex) ;
} ;

static bgp_peer_id_t           bgp_peer_id_count = 0 ;

static bgp_peer_id_table_chunk bgp_peer_id_table = NULL ;

static struct dl_base_pair(bgp_peer_index_entry) bgp_peer_id_free
                                                             = { NULL, NULL } ;
/* Forward references
 */
static void bgp_peer_id_table_free_entry(bgp_peer_index_entry peer_ie,
                                                             bgp_peer_id_t id) ;
static void bgp_peer_id_table_make_ids(void) ;

/* The vhash table magic
 */
static vhash_equal_func bgp_peer_su_index_equal ;
static vhash_new_func   bgp_peer_su_index_new ;
static vhash_free_func  bgp_peer_su_index_free ;

static const vhash_params_t peer_index_vhash_params =
{
  .hash   = sockunion_vhash_hash,
  .equal  = bgp_peer_su_index_equal,
  .new    = bgp_peer_su_index_new,
  .free   = bgp_peer_su_index_free,
  .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * Initialise the bgp_peer_su_index.
 *
 * This must be done before any peers are configured !
 */
extern void
bgp_peer_index_init(void* parent)
{
  bgp_peer_su_index = vhash_table_new(
          parent,
          50,                     /* start ready for a few sessions     */
          200,                    /* allow to be quite dense            */
          &peer_index_vhash_params) ;

  vector_init_new(bgp_peer_id_index, bgp_peer_id_unit) ;

  /* Initialise table entirely empty
   */
  bgp_peer_id_table     = NULL ;
  dsl_init(bgp_peer_id_free) ;

  bgp_peer_id_count = 0 ;
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
  bgp_peer_id_table_chunk chunk ;

  qassert(!qpthreads_active) ;

  /* Ream out and discard vhash table -- gives back the peer_ids which are in
   * use.  The chunks of entries are freed en masse, below.
   */
  bgp_peer_su_index = vhash_table_reset(bgp_peer_su_index, free_it) ;

  /* Ream out the peer id vector -- checking that all entries are empty
   */
  while ((peer_ie = vector_ream(bgp_peer_id_index, keep_it)) != NULL)
    {
      qassert(peer_ie->peer == NULL) ;


    } ;

  /* Discard the empty chunks of entries
   */
  while (bgp_peer_id_table != NULL)
    {
      chunk = bgp_peer_id_table ;
      bgp_peer_id_table = chunk->next ;
      XFREE(MTYPE_BGP_PEER_ID_TABLE, chunk) ;
    } ;

  /* Set utterly empty and discard mutex.
   */
  bgp_peer_id_table     = NULL ;
  dsl_init(bgp_peer_id_free) ;

  bgp_peer_id_count = 0 ;

  bgp_peer_index_mutex = qpt_mutex_destroy(bgp_peer_index_mutex) ;
} ;

/*------------------------------------------------------------------------------
 * Register a peer and its session in the peer index.
 *
 * For use by the Routeing Engine.
 *
 * NB: peer and session must point at each other already.
 *
 * NB: it is a FATAL error to register a peer for an address which is already
 *     registered.
 */
extern void
bgp_peer_index_register(bgp_peer peer, bgp_session session)
{
  bgp_peer_index_entry peer_ie ;
  bool   added ;

  qassert((peer != NULL) && (session != NULL)) ;
  qassert((peer == session->peer) && (session == peer->session)) ;
  qassert(peer->peer_ie    == NULL) ;
  qassert(session->peer_ie == NULL) ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  /* Add entry to the vhash_table -- creates entry and allocates id.
   */
  peer_ie = vhash_lookup(bgp_peer_su_index, peer->su_name, &added) ;

  assert(added) ;               /* really do not know what to do if not */

  /* Point entry at peer and session and vice versa and fix "set" and ref_count
   */
  peer->peer_ie    = peer_ie ;
  peer_ie->peer    = peer ;
  vhash_set(peer_ie) ;

  session->peer_ie = peer_ie ;
  peer_ie->session = session ;
  vhash_inc_ref(peer_ie) ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->-->*/
} ;

/*------------------------------------------------------------------------------
 * Lookup a peer's session -- do nothing if does not exist
 *
 * For use by the BGP Engine.
 *
 * Returns the bgp_session -- NULL if not found.
 *
 * NB: caller is BGP Engine, so the pointer from the peer index entry to the
 *     session is stable, because the BGP Engine is responsible for the session,
 *     once it is created.
 */
extern bgp_session
bgp_peer_index_seek_session(sockunion su)
{
  bgp_peer_index_entry peer_ie ;
  bgp_session          session ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<*/

  peer_ie = vhash_lookup(bgp_peer_su_index, su, NULL /* don't add */) ;
  session = (peer_ie != NULL) ? peer_ie->session : NULL ;

  BGP_PEER_INDEX_UNLOCK() ;  /*>->->->->->->->->->->->->->->->->->->->->->->->*/

  return session ;
} ;

/*------------------------------------------------------------------------------
 * Deregister a peer from the peer index -- for use by the Routeing Engine.
 *
 * Clears the peer->peer_ie pointer.
 *
 * NB: the peer_id MUST not be in use anywhere in the Routeing Engine !
 *
 * NB: it is a FATAL error to deregister a peer which is not registered.
 */
extern void
bgp_peer_index_deregister_peer(bgp_peer peer)
{
  bgp_peer_index_entry peer_ie ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  peer_ie = peer->peer_ie ;
  if (peer_ie != NULL)
    {
      qassert(peer_ie->peer == peer) ;
      qassert(vhash_is_set(peer_ie)) ;

      peer->peer_ie = NULL ;
      peer_ie->peer = NULL ;

      vhash_unset_delete(peer_ie, bgp_peer_su_index) ;
    } ;

  BGP_PEER_INDEX_UNLOCK() ;  /*->->->->->->->->->->->->->->->->->->->->->->->*/
} ;

/*------------------------------------------------------------------------------
 * Deregister a session from the peer index -- for use by the BGP Engine.
 *
 * NB: the peer index entry peer_id is still in use (anywhere at all)
 *
 * NB: it is a FATAL error to deregister a peer which is not registered.
 */
extern void
bgp_peer_index_deregister_session(bgp_session session)
{
  bgp_peer_index_entry peer_ie ;

  BGP_PEER_INDEX_LOCK() ;    /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  peer_ie = session->peer_ie ;
  if (peer_ie != NULL)
    {
      qassert(peer_ie->session == session) ;
      qassert(vhash_has_references(peer_ie)) ;

      session->peer_ie = NULL ;
      peer_ie->session = NULL ;

      vhash_dec_ref(peer_ie, bgp_peer_su_index) ;
    } ;

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
  if (dsl_head(bgp_peer_id_free) == NULL)
    bgp_peer_id_table_make_ids() ;

  peer_ie = dsl_pop(&peer_ie, bgp_peer_id_free, next_free) ;
  assert(vector_get_item(bgp_peer_id_index, peer_ie->id) == peer_ie) ;

  /* For completeness -- empty out the entry.
   *
   *   * vhash              -- set on exit
   *
   *   * next_free          -- NULL
   *
   *   * su_name            -- set below
   *   * id                 -- preserved !
   *
   *   * peer               -- NULL
   *   * session            -- NULL
   */
  id = peer_ie->id ;
  memset(peer_ie, 0, sizeof(bgp_peer_index_entry_t)) ;
  peer_ie->id = id ;

  /* Copy in the name of the entry before it is added to the vhash.
   */
  peer_ie->su_name = sockunion_dup(su) ;        /* set the "name"       */

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
  qassert((peer_ie->peer == NULL) && (peer_ie->session == NULL)) ;

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
  assert((peer_ie != NULL) && (id < bgp_peer_id_count)) ;
  assert(vector_get_item(bgp_peer_id_index, id) == peer_ie) ;

  /* Clear down the bgp_peer_index_entry:
   *
   *   * vhash              -- empty
   *
   *   * next_free          -- set below;
   *
   *   * su_name            -- discard existing name and set NULL
   *   * id                 -- preserved !
   *
   *   * peer               -- NULL (should already be !)
   *   * session            -- NULL (should already be !)
   */
  sockunion_free(peer_ie->su_name) ;

  memset(peer_ie, 0, sizeof(bgp_peer_index_entry_t)) ;
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;

  peer_ie->id = id ;

  /* Now stick on the list of free id
   */
  dsl_append(bgp_peer_id_free, peer_ie, next_free) ;
} ;

/*------------------------------------------------------------------------------
 * Make a new set of free bgp_peer_ids.
 *
 * NB: requires the BGP_PEER_INDEX_LOCK()
 */
static void
bgp_peer_id_table_make_ids(void)
{
  bgp_peer_id_t           id_new ;
  bgp_peer_id_table_chunk chunk ;
  bgp_peer_index_entry    peer_ie ;

  chunk = XCALLOC(MTYPE_BGP_PEER_ID_TABLE, sizeof(bgp_peer_id_table_chunk_t)) ;

  chunk->next = bgp_peer_id_table ;
  bgp_peer_id_table = chunk ;

  peer_ie = &chunk->entries[0] ;

  id_new = bgp_peer_id_count ;
  bgp_peer_id_count += bgp_peer_id_unit ;

  /* Special case to avoid id == 0 being used.  Is not set in vector.
   *
   * NB: the entry has already been zeroized, so:
   *
   *   * vhash              -- empty
   *   * next_free          -- NULL
   *   * su_name            -- NULL
   *   * id                 -- bgp_peer_id_null
   *   * peer               -- NULL
   *   * session            -- NULL
   */
  if (id_new == 0)
    {
      confirm(bgp_peer_id_null == 0) ;

      peer_ie += 1 ;            /* step past id == 0            */
      id_new  += 1 ;            /* avoid setting id == 0 free   */
    } ;

  /* Complete the creation of the new chunk of peer_ids by "freeing" all the
   * new entries.
   *
   * NB: the entry has already been zeroized, so:
   *
   *   * su_name            -- NULL
   *
   * Adds entry to the id_index *first*, because bgp_peer_id_table_free_entry()
   * checks that !
   */
  while (id_new < bgp_peer_id_count)
    {
      vector_set_item(bgp_peer_id_index, id_new, peer_ie) ;

      bgp_peer_id_table_free_entry(peer_ie, id_new) ;

      peer_ie += 1 ;
      id_new  += 1 ;
    } ;
} ;

