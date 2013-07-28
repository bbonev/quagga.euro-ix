/* Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * 24-Nov-2009  -- substantially re-cast to speed up the handling of very
 *                 large prefix-lists (10,000+ entries).
 *                 Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#include "plist.h"
#include "command.h"
#include "memory.h"
#include "log.h"
#include "vhash.h"
#include "vector.h"
#include "qfstring.h"
#include "avl.h"

/* This implements ip prefix-list functions.
 *
 * A prefix-list is referred to by name, where a name is an arbitrary string,
 * case-sensitive.  When showing prefix-lists the names are sorted
 * "alphabetically", except for any digit sections, which sort numerically.
 * Note that leading zeros are significant... "01" is not the same as "1",
 * and sorts after it.
*/

enum prefix_flags
{
  PFLAG_TYPE = BIT(0),

  PFLAG_SEEN = BIT(3),  /* used for debug walk of tree etc      */

  PFLAG_ANY  = BIT(4),  /* prefix declared as 'any'             */
  PFLAG_LE   = BIT(5),  /* explicit 'le'                        */
  PFLAG_GE   = BIT(6),  /* explicit 'ge'                        */
  PFLAG_SEQ  = BIT(7),  /* explicit sequence number             */

  PFLAGS_MAX = PFLAG_TYPE | PFLAG_ANY | PFLAG_LE | PFLAG_GE | PFLAG_SEQ,
} ;
CONFIRM(PREFIX_DENY   == (PREFIX_DENY   & PFLAG_TYPE)) ;
CONFIRM(PREFIX_PERMIT == (PREFIX_PERMIT & PFLAG_TYPE)) ;

typedef enum prefix_flags prefix_flags_t ;
CONFIRM(PFLAGS_MAX <= UINT8_MAX) ;      /* fits in a byte !     */

typedef struct prefix_master  prefix_master_t ;
typedef struct prefix_master* prefix_master ;

typedef const struct prefix_list* prefix_list_c ;

typedef struct prefix_list_entry  prefix_list_entry_t ;
typedef struct prefix_list_entry* prefix_list_entry ;
typedef const struct prefix_list_entry* prefix_list_entry_c ;

typedef struct prefix_list_node  prefix_list_node_t ;
typedef struct prefix_list_node* prefix_list_node ;

/*------------------------------------------------------------------------------
 * Master structure of prefix_list.
 *
 * Each address family has it's own distinct set of prefix lists.  (Including
 * the fake qAFI_ORF_PREFIX "family".)
 *
 * This means that a prefix_list name is local to an address family, but
 * global wrt router instances.
 *
 * The vhash_table allows prefix-list to be looked up by name.
 *
 * A prefix-list comes into existence when some property of the prefix list is
 * set, or when it is referred to by some user of the prefix-list.  It is
 * destroyed when the list is "unconfigured" (not "set") *and* there are no
 * more references.  Note that when a list is not "set" (eg "no ip prefix-list
 * FRED") it will be empty, but there may still be users of the (now empty)
 * prefix-list.  If the list is "reconfigured", then all existing users of the
 * prefix-list will see the new prefix-list.  The name is key !
 */
struct prefix_master
{
  vhash_table table ;           /* table of prefix_list by name.              */

  bool seqnum_flag ;            /* ip prefix-list sequence-number state.      */

  prefix_list   recent ;        /* the latest update.                         */

  void (*add_hook) (prefix_list) ;
                                /* executed when new prefix_list is added.    */
  void (*delete_hook) (prefix_list) ;
                                /* executed when a prefix_list is deleted.    */
};

/*------------------------------------------------------------------------------
 * A prefix-list entry.
 *
 * NB: all entries have the same afi as the parent prefix-list.
 *
 * FWIW: the flags, pl, ge and le are all bytes, and the seq is 4 bytes, so
 *       that collection is eqivalent to a 64-bit address.
 */
struct prefix_list_entry
{
  prefix_list_entry  next ;     /* in sequence number order     */

  uint32_t      seq ;

  byte          flags ;         /* prefix_flags_t               */

  prefix_len_t  pl ;
  prefix_len_t  ge ;
  prefix_len_t  le ;

  ip_union_pair_t pair[1] ;     /* prefix as start..end range   */

  ulong  refcnt ;
  ulong  hitcnt ;
} ;

/*------------------------------------------------------------------------------
 * Each prefix_list is described by one of these.
 *
 * When these are created, they are created empty, with a default 'any' entry
 * which gives PREFIX_DENY.
 */
struct prefix_list
{
  /* Lives in a vhash by name, and we have a pointer to the vhash_table.
   */
  vhash_node_t  vhash ;
  vhash_table   table ;         /* has a reference to the table         */

  /* Context for the prefix-list
   */
  prefix_master master ;        /* parent table: scope of this list.    */

  /* Value of the prefix-list
   */
  char*      name ;
  char*      desc ;             /* ip prefix-list description           */

  vector_t   index[1] ;         /* embedded vector: by sequence number  */

  prefix_list_node  root ;      /* first node in tree: by value         */
  avl_tree_params_c params ;

  prefix_list_entry_t  any ;    /* 'next' points to first 'any' entry
                                 * 'seq'  set to max possible           */

  uint rangecount ;             /* XXX TODO: discover what this is for ??
                                 *           Is not changed anywhere !! */

  qAFI_t     afi ;              /* address family for all prefixes
                                 * this is the *real* address family, so
                                 * not "qAFI_ORF_PREFIX" or similar.    */
} ;

CONFIRM(offsetof(prefix_list_t, vhash) == 0) ;  /* see vhash.h  */

/*------------------------------------------------------------------------------
 * prefix-list tree and tree-node
 *
 * Note that for the node to exist there MUST be at least one entry on the
 * list of prefix list entries, and that entry contains the addr_pair which
 * is the value of the node as far as the tree is concerned.
 */
struct prefix_list_node
{
  avl_node_t   avl ;            /* embedded                             */

  prefix_list_entry entries ;   /* list, in sequence number order       */

  prefix_list_node  sub_root ;  /* if any                               */
} ;

CONFIRM(offsetof(prefix_list_node_t, avl) == avl_node_offset) ;

/* The parameters for an IPv4 tree
 */
static avl_new_func prefix_list_avl_new_node ;
static avl_cmp_func prefix_list_ipv4_cmp_node ;

static const avl_tree_params_t prefix_list_ipv4_tree_params =
  {
    .new  = prefix_list_avl_new_node,
    .cmp  = prefix_list_ipv4_cmp_node,
  } ;

/* The parameters for an IPv6 tree
 */
static avl_cmp_func prefix_list_ipv6_cmp_node ;

static const avl_tree_params_t prefix_list_ipv6_tree_params =
  {
    .new  = prefix_list_avl_new_node,
    .cmp  = prefix_list_ipv6_cmp_node,
  } ;

/*------------------------------------------------------------------------------
 * Static array of prefix_master structures.
 */
static prefix_master_t prefix_masters[qAFI_ORF_PREFIX + 1] ;

CONFIRM(qAFI_ORF_PREFIX == (qAFI_max + 1)) ;

/* For real afi, the choice is strictly limited, and includes IPv6
 * only if HAVE_IPV6 !
 */
#ifdef HAVE_IPV6
#define assert_afi_real(a) assert(((a) == qAFI_IP) || ((a) == qAFI_IP6))
#else
#define assert_afi_real(a) assert((a) == qAFI_IP)
#endif

/*------------------------------------------------------------------------------
 * Map afi to prefix_master.
 *
 * Maps qAFI_IP and qAFI_IPV6 (if HAVE_IPV6) always.
 *
 * Maps qAFI_ORF_PREFIX (pseudo AFI) if required.
 *
 * Note: there is no ipv6 master if not HAVE_IPV6.
 *
 * Returns address of prefix_master, or NULL if unknown afi.
 */
static inline prefix_master
prefix_master_get(uint afi, bool map_orf_prefix)
{
  switch (afi)
  {
    case qAFI_ORF_PREFIX:
      if (!map_orf_prefix)
        return NULL ;

      fall_through ;

    case qAFI_IP:
#ifdef HAVE_IPV6
    case qAFI_IP6:
#endif
      return &prefix_masters[afi] ;

    default:
      return NULL;
  } ;
} ;

/*------------------------------------------------------------------------------
 * Return string of prefix_list_type.
 */
static const char *
prefix_list_type_str (prefix_list_entry pe)
{
  switch (pe->flags & PFLAG_TYPE)
    {
    case PREFIX_PERMIT:
      return "permit";
    case PREFIX_DENY:
      return "deny";
    default:
      return "";
    }
}

/*------------------------------------------------------------------------------
 * Map afi to name of same: "ip" or "ipv6".  Implied assert_afi_real().
 */
static const char*
prefix_afi_name_str(afi_t afi)
{
  switch (afi)
  {
    case AFI_IP:
      return "ip" ;
#ifdef HAVE_IPV6
    case AFI_IP6:
      return "ipv6" ;
#endif
    default:
      zabort("invalid address family") ;
      return "?" ;
  } ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Map afi to maximum prefix length.  Implied assert_afi_real().
 */
static inline uint
prefix_max_length(qAFI_t afi)
{
  switch (afi)
  {
    case qAFI_IP:
      return IPV4_MAX_BITLEN ;
#ifdef HAVE_IPV6
    case qAFI_IP6:
      return IPV6_MAX_BITLEN ;
#endif
    default:
      zabort("invalid address family") ;
      return 0 ;
  } ;
} ;
#endif

/*==============================================================================
 * Operations on prefix_master and the vhash stuff
 */
static vhash_equal_func  prefix_list_vhash_equal ;
static vhash_new_func    prefix_list_vhash_new ;
static vhash_free_func   prefix_list_vhash_free ;
static vhash_orphan_func prefix_list_vhash_orphan ;

static const vhash_params_t prefix_list_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = prefix_list_vhash_equal,
  .new    = prefix_list_vhash_new,
  .free   = prefix_list_vhash_free,
  .orphan = prefix_list_vhash_orphan,
} ;

static void prefix_list_flush(prefix_list plist) ;

/*------------------------------------------------------------------------------
 * Initialise all the masters and set-up the ones we use.
 */
extern void
prefix_list_init (void)
{
  uint afi ;

  memset(prefix_masters, 0, sizeof(prefix_masters)) ;

  for (afi = 0 ; afi <= qAFI_ORF_PREFIX ; ++afi)
    {
      prefix_master pm ;

      pm = prefix_master_get(afi, true /* map qAFI_ORF_PREFIX */) ;

      if (pm != NULL)
        {
          pm->table = vhash_table_new(pm, 50, 200, &prefix_list_vhash_params) ;
          vhash_table_set_parent(pm->table, pm) ;
          pm->seqnum_flag = true ;      /* Default      */
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Shut down all the masters we use.
 */
extern void
prefix_list_reset (free_keep_b free)
{
  uint afi ;

  for (afi = 0 ; afi <= qAFI_ORF_PREFIX ; ++afi)
    {
      prefix_master pm ;

      pm = prefix_master_get(afi, true /* map qAFI_ORF_PREFIX */) ;

      if (pm != NULL)
        {
          vhash_table_reset(pm->table, free) ;

          if (free)
            pm->table = NULL ;

          pm->seqnum_flag = true ;      /* restore default    */

          pm->recent = NULL ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * The add_hook and delete_hook functions.
 *
 * These are used:
 *
 *   a. to keep references to prefix lists up to date -- so when a prefix-list
 *      comes in to being, a name reference can now refer to the actual list;
 *      and when a prefix-list is destroyed, any pointer to it can be discarded.
 *
 *      The prefix_list_set_ref() etc mechanism replaces this.
 *
 *   b. to flag when a prefix-list has changed, so that any implications of
 *      that change can be worked through.
 *
 *      This could be improved... TBA TODO
 */

/* Set add hook function.
 *
 * This function is called every time a prefix entry is inserted.
 */
extern void
prefix_list_add_hook (void (*func)(prefix_list plist))
{
  uint afi ;

  for (afi = 0 ; afi <= qAFI_ORF_PREFIX ; ++afi)
    {
      prefix_master pm ;

      pm = prefix_master_get(afi, true /* map qAFI_ORF_PREFIX */) ;

      if (pm != NULL)
        pm->add_hook = func;
    } ;
} ;

/* Set delete hook function.
 *
 * This function is called every time a prefix entry is deleted and if the
 * entire prefix-list is deleted.
 *
 * NB: it is passed the plist which may may no longer have a value, and may
 *     be about to be freed.  In this case the name in the plist is valid,
 *     but prefix_list_lookup() will not find a plist of that name !
 */
extern void
prefix_list_delete_hook (void (*func)(prefix_list plist))
{
  uint afi ;

  for (afi = 0 ; afi <= qAFI_ORF_PREFIX ; ++afi)
    {
      prefix_master pm ;

      pm = prefix_master_get(afi, true /* map qAFI_ORF_PREFIX */) ;

      if (pm != NULL)
        pm->delete_hook = func;
    } ;
} ;

/*==============================================================================
 * Basic constructors and destructors for prefix_list.
 */
static prefix_list_entry prefix_list_entry_free (prefix_list_entry pe) ;

/*------------------------------------------------------------------------------
 * Construct a new prefix_list -- vhash_new_func
 *
 * NB: does not fully initialise the new prefix-list: prefix_list_tree_reset()
 *     will complete the job -- see prefix_list_need()
 */
static vhash_item
prefix_list_vhash_new(vhash_table table, vhash_data_c data)
{
  prefix_list  new ;
  const char*  name = data ;

  new = XCALLOC (MTYPE_PREFIX_LIST, sizeof(prefix_list_t)) ;

  /* Zeroizing has set:
   *
   *   * vhash          -- all zero   -- not that this matters
   *   * table          -- X          -- set below
   *   * master         -- X          -- set below
   *
   *   * name           -- X          -- set below
   *   * desc           -- NULL       -- none
   *
   *   * index          -- empty vector -- confirm() below
   *
   *   * root           -- NULL       -- tree is empty
   *   * params         -- NULL       -- *invalid*, pro tem
   *   * any            -- all zeros  -- *incomplete*, pro tem
   *
   *   * rangecount     -- 0          -- use unknown
   *
   *   * afi            -- 0          -- *invalid*, pro tem
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;

  new->table  = vhash_table_inc_ref(table) ;
  new->master = table->parent ;
  new->name   = XSTRDUP(MTYPE_PREFIX_LIST_STR, name) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Complete the initialisation of an empty prefix-list.
 *
 * Sets the given 'afi' and the tree parameters to suit.
 *
 * Empties out the 'any' structure, which is used in prefix_list_apply(), and
 * (in particular) sets:
 *
 *   any.next   -- NULL          -- no 'any' prefix-list entries.
 *
 *   any.seq    -- UINT32_MAX    -- the default prefix-list entry
 *   any.flags  -- PREFIX_DENY   -- default result
 */
static void
prefix_list_tree_reset(prefix_list plist, qAFI_t afi)
{
  plist->afi = afi ;

  switch (afi)
    {
      case AFI_IP:
        plist->params = &prefix_list_ipv4_tree_params ;
        break ;
#ifdef HAVE_IPV6
      case AFI_IP6:
        plist->params = &prefix_list_ipv6_tree_params ;
        break ;
#endif
      default:
        zabort("invalid address family") ;
    } ;

  /* Zeroizing the 'any' structure sets:
   *
   *   * next                  -- NULL     -- no 'any' prefix-list entries.
   *
   *   * seq                   -- X        -- set below
   *
   *   * flags                 -- PREFIX_DENY
   *
   *   * pl                    )
   *   * ge                    )  all zero -- see use in prefix_list_apply()
   *   * le                    )
   *   * pair                  )
   *
   *   * refcnt                -- 0        -- never used
   *   * hitcnt                -- 0        -- never used
   */
  memset(&plist->any, 0, sizeof(prefix_list_entry_t)) ;

  confirm(PREFIX_DENY == 0) ;

  plist->any.seq = UINT32_MAX ;
} ;

/*------------------------------------------------------------------------------
 * Comparison -- vhash_cmp_func
 */
static int
prefix_list_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  prefix_list_c plist = item ;
  const char*   name  = data ;

  return strcmp(plist->name, name) ;
} ;

/*------------------------------------------------------------------------------
 * Free prefix-list -- vhash_free_func
 *
 * Makes sure that the prefix-list is empty, first.
 */
static vhash_item
prefix_list_vhash_free(vhash_item item, vhash_table table)
{
  prefix_list plist = item ;

  qassert(plist->table == table) ;

  prefix_list_flush(plist) ;            /* make sure    */
  vhash_table_dec_ref(table) ;

  XFREE (MTYPE_PREFIX_LIST_STR, plist->name) ;
  XFREE (MTYPE_PREFIX_LIST, plist) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Orphan prefix-list -- vhash_orphan_func
 *
 * Makes sure that the prefix-list is empty and unset.
 */
static vhash_item
prefix_list_vhash_orphan(vhash_item item, vhash_table table)
{
  prefix_list plist = item ;

  qassert(plist->table == table) ;

  prefix_list_flush(plist) ;

  return vhash_unset(plist, table) ;
} ;

/*------------------------------------------------------------------------------
 * Returns true <=> prefix list is empty, and no description even
 *
 * A NULL plist is an empty plist !
 */
static bool
prefix_list_is_empty(prefix_list plist)
{
  return (plist == NULL) ||
              ( (vector_end(plist->index) == 0) && (plist->desc == NULL) ) ;
} ;

/*==============================================================================
 * Operations on prefix_lists
 */
static prefix_list prefix_list_seek(prefix_master pm, const char *name) ;
static prefix_list prefix_list_need(prefix_master pm, qAFI_t afi,
                                                             const char *name) ;
static void prefix_list_tree_flush(prefix_list_node* p_root) ;
static void prefix_list_verify(prefix_list plist, bool show) ;

/*------------------------------------------------------------------------------
 * Lookup prefix_list by afi and name -- if afi is known, and name not NULL.
 *
 * Does not create.
 *
 * Tolerates unknown afi and allows "fake" afi (eg. qAFI_ORF_PREFIX).
 *
 * Returns:  NULL <=> not found or is not set
 *           otherwise is address of prefix_list
 *
 * NB: returns NULL if the prefix-list exists but is empty (no description and
 *     no prefix_list entries <=> not "set").
 */
extern prefix_list
prefix_list_lookup(qAFI_t q_afi, const char *name)
{
  prefix_master pm ;

  pm  = prefix_master_get(q_afi, true /* accept qAFI_ORF_PREFIX */) ;

  if ((name == NULL) || (pm == NULL))
    return NULL;

  return prefix_list_seek(pm, name) ;
} ;

/*------------------------------------------------------------------------------
 * Find prefix list for the given q_AFI_t and name -- create if required.
 *
 * Unlike prefix_list_lookup(), if no such prefix-list exists, then a new,
 * empty prefix-list is created.
 *
 * Also unlike prefix_list_lookup(), returns the prefix-list even if it is
 * empty (no description and no prefix_list entries <=> not "set").
 *
 * NB: rejects the qAFI_ORF_PREFIX "extension".
 *
 * Returns:  address of prefix-list (NULL if afi unknown or name NULL)
 */
extern prefix_list
prefix_list_find(qAFI_t q_afi, const char *name)
{
  prefix_master pm ;

  pm  = prefix_master_get(q_afi, false /* real qAFI_t only */) ;

  if ((name == NULL) || (pm == NULL))
    return NULL;

  return prefix_list_need(pm, q_afi, name) ;
} ;

/*------------------------------------------------------------------------------
 * Get a reference to the prefix list for the given q_AFI_t of the given name.
 *
 * In any case, this returns the address of the prefix list, set or not,
 * with the reference count incremented.
 *
 * NB: rejects the qAFI_ORF_PREFIX "extension".
 *
 * Returns:  address of prefix-list (NULL if afi unknown or name NULL)
 */
extern prefix_list
prefix_list_get_ref(qAFI_t q_afi, const char *name)
{
  return prefix_list_set_ref(prefix_list_find(q_afi, name)) ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given prefix list (if any).
 *
 * If prefix-list is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  prefix-list as given
 */
extern prefix_list
prefix_list_set_ref(prefix_list plist)
{
  if (plist != NULL)
    return vhash_inc_ref(plist) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given prefix list (if any).
 *
 * If prefix-list is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  NULL
 */
extern prefix_list
prefix_list_clear_ref(prefix_list plist)
{
  if (plist != NULL)
    vhash_dec_ref(plist, plist->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return name of plist -- will be NULL if plist is NULL
 */
extern const char*
prefix_list_get_name(prefix_list plist)
{
  return (plist != NULL) ? plist->name : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return whether prefix_list is "set" -- that is, some value has been set.
 *
 * Will not be "set" if is NULL.
 *
 * For prefix-list, the value may be just the description.
 */
extern bool
prefix_list_is_set(prefix_list plist)
{
  qassert(vhash_is_set(plist) == !prefix_list_is_empty(plist)) ;

  return vhash_is_set(plist) ;
} ;

/*------------------------------------------------------------------------------
 * Return whether prefix_list is "active".
 *
 * Will not be "active" if is NULL.
 *
 * Will be "active" iff there is at least one entry in the prefix-list.
 */
extern bool
prefix_list_is_active(prefix_list plist)
{
  return (plist != NULL) ? vector_end(plist->index) != 0
                         : false ;
} ;

/*------------------------------------------------------------------------------
 * Seek prefix_list by name in give prefix master.  Does NOT create.
 *
 * Returns:  NULL <=> not found OR is not "set"
 *           otherwise is address of prefix_list
 *
 * NB: returns NULL if the prefix-list exists but is empty (no description and
 *     no prefix_list entries <=> not "set").
 */
static prefix_list
prefix_list_seek(prefix_master pm, const char *name)
{
  prefix_list plist ;

  plist = vhash_lookup(pm->table, name, NULL /* don't add */) ;

  if (plist == NULL)
    return NULL ;

  qassert(vhash_is_set(plist) == !prefix_list_is_empty(plist)) ;

  return vhash_is_set(plist) ? plist : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Need prefix_list -- create an empty one if required.
 *
 * If required, sets the "set" status -- which indicates that the prefix-list
 * is not empty.
 */
static prefix_list
prefix_list_need(prefix_master pm, qAFI_t afi, const char *name)
{
  prefix_list plist ;
  bool added ;

  assert((pm != NULL) && (name != NULL)) ;

  plist = vhash_lookup(pm->table, name, &added) ;  /* creates if required */

  if (added)
    {
      prefix_list_tree_reset(plist, afi) ;      /* complete initialisation */

      if (qdebug)
        prefix_list_verify(plist, false /* not show_tree */) ;
    } ;

  return plist ;
} ;

/*------------------------------------------------------------------------------
 * Delete prefix_list.
 *
 * If the prefix-list has any remaining entries or any remaining description,
 * discard them.  Clear the "set" state.
 *
 * Invoke the delete_hook() if any.
 *
 * If there are no references, delete the prefix-list.  Otherwise, leave it to
 * be deleted when the reference count falls to zero, or leave it to have a
 * value redefined at some future date.
 */
static void
prefix_list_delete (prefix_list plist)
{
  vhash_inc_ref(plist) ;        /* want to hold onto the plist pro tem. */

  prefix_list_flush(plist) ;    /* hammer the value and clear "set"     */

  /* prefix-list no longer has a value
   *
   * If we need to tell the world, we pass the (now empty) plist to the
   * call-back.
   */
  if (plist->master->delete_hook != NULL)
    plist->master->delete_hook(plist);

  /* Now, if there are no references to the prefix-list, it is time for it
   * to go.
   */
   vhash_dec_ref(plist, plist->table) ;         /* now may disappear    */
} ;

/*------------------------------------------------------------------------------
 * Flush all contents of prefix_list, leaving it completely empty.
 *
 * Retains all the red-tape.  Releases the prefix-list entries and description.
 *
 * NB: does not touch the reference count BUT clears the "set" state WITHOUT
 *     freeing the prefix-list.
 */
static void
prefix_list_flush(prefix_list plist)
{
  prefix_list_entry pe ;
  uint i ;

  if (qdebug)
    prefix_list_verify(plist, false /* not show_tree */) ;

  /* Free all the prefix_list_entries, then free the vector they live in.
   */
  for (VECTOR_ITEMS(plist->index, pe, i))
    prefix_list_entry_free(pe) ;

  vector_reset(plist->index, 0) ;

  /* Dismantle the tree, whose nodes now have dangling references to the
   * one-time prefix-entries
   */
  prefix_list_tree_flush(&plist->root) ;

  /* Tidy up the rest of the tree state
   */
  prefix_list_tree_reset(plist, plist->afi) ;

  /* If there is a description, release that now.
   */
  if (plist->desc != NULL)
    XFREE (MTYPE_PREFIX_LIST_STR, plist->desc) ; /* sets plist->desc NULL */

  /* No longer have a recently changed prefix-list
   */
  plist->master->recent = NULL ;

  /* Clear the "set" state -- but do NOT delete, even if reference count == 0
   */
  vhash_clear_set(plist) ;

  if (qdebug)
    prefix_list_verify(plist, false /* not show_tree */) ;
} ;

/*==============================================================================
 * Operations on prefix_list_entry
 */
static prefix_list_entry prefix_list_entry_find_val(prefix_list plist,
                                                     prefix_list_entry_c temp) ;
static vector_index_t prefix_list_entry_lookup_seq(prefix_list plist, uint seq,
                                                                  int* result) ;
static prefix_list_entry prefix_list_entry_tree_delete(prefix_list plist,
                                                         prefix_list_entry px) ;
static prefix_list_entry prefix_list_entry_seek(prefix_list plist,
                       prefix_list_entry_c temp,
                           prefix_list_node** pp_root, prefix_list_node* p_pn) ;
static prefix_list_entry prefix_list_entry_node_delete(prefix_list plist,
                      prefix_list_entry px,
                             prefix_list_node* pp_root, prefix_list_node p_pn) ;

/*------------------------------------------------------------------------------
 * Initialise prefix_list entry -- cleared to zeros.
 *
 * Zeroizing sets:
 *
 *   * next                -- NULL     -- not on any list, yet
 *
 *   * seq                 -- X        -- *unset*
 *                                        but note that BGP ORF can use 0 !
 *
 *   * flags               -- PREFIX_DENY
 *
 *   * pl                  -- X        )
 *   * ge                  -- X        )  *unset*
 *   * le                  -- X        )
 *
 *   * pair                -- all zero -- *unset*
 *
 *   * refcnt              -- 0
 *   * hitcnt              -- 0
 *
 * NB: this is NOT a valid entry -- some items are *unset*
 */
static prefix_list_entry
prefix_list_entry_init(prefix_list_entry pe)
{
  confirm(PREFIX_DENY == 0) ;

  return memset(pe, 0, sizeof(prefix_list_entry_t));
}

/*------------------------------------------------------------------------------
 * Create new prefix list entry, whose contents are a copy of the given 'temp'
 *
 * The new entry is zeroized (to be tidy) and then we have:
 *
 *   * next         -- NULL
 *
 *   * seq          )
 *   * flags        )
 *   * pl           )  copied
 *   * ge           )
 *   * le           )
 *   * pair         )
 *
 *   * refcnt       -- 0
 *   * hitcnt       -- 0
 */
static prefix_list_entry
prefix_list_entry_new (prefix_list_entry_c temp)
{
  prefix_list_entry pe ;

  pe = XCALLOC(MTYPE_PREFIX_LIST_ENTRY, sizeof(prefix_list_entry_t)) ;

  pe->seq   = temp->seq ;
  pe->flags = temp->flags ;
  pe->pl    = temp->pl ;
  pe->ge    = temp->ge ;
  pe->le    = temp->le ;
  memcpy(pe->pair, temp->pair, sizeof(ip_union_pair_t)) ;

  return pe ;
}

/*------------------------------------------------------------------------------
 * Free given prefix list entry
 */
static prefix_list_entry
prefix_list_entry_free (prefix_list_entry pe)
{
  XFREE (MTYPE_PREFIX_LIST_ENTRY, pe);
  return NULL ;
}

/*------------------------------------------------------------------------------
 * Fill prefix from given prefix-list entry and qAFI.
 */
static void
prefix_list_prefix_fill(prefix pfx, prefix_list_entry pe, qAFI_t afi)
{
  prefix_from_pair_range(pfx, pe->pair, afi2family(afi)) ;

  qassert(pe->pl == pfx->prefixlen) ;
} ;

/*------------------------------------------------------------------------------
 * Sequence comparison function -- used in prefix_list_entry_lookup_seq
 */
static int
prefix_seq_cmp(const uint** seq, const struct prefix_list_entry** pe)
{
  if (**seq != (*pe)->seq)
    return (**seq < (*pe)->seq) ? -1 : + 1 ;
  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Complete prefix list entry from given prefix
 *
 * Checks that the prefix length is valid -- rejects if not.
 *
 * Sets the prefix list entry range pair and copies the prefix length.  If the
 * prefix address is invalid (ie there are '1' bits beyond the prefix length)
 * it is forced valid (by clearing those '1's to '0's).
 *
 * Checks or completes ge and/or le settings -- set defaults as required.
 *
 *   -- sets the implied le for "any" or ge, if no explicit le set
 *
 *   -- checks le & ge and updates as required the filter.
 *
 * Note that filter requires le = ge = prefix-length for an exact match.
 *
 * Returns:  CMD_SUCCESS -- it's OK
 *           CMD_WARNING -- something amiss with the pl, ge and/or le setting
 *
 * Cisco say:
 *
 *   If ge: must be <= maximum prefix length and > actual prefix length
 *    else: set to prefix length
 *
 *   If le: must be <= maximum prefix length and > actual prefix length
 *    else: if ge or any set to maximum prefix length
 *    else: set to prefix length
 *
 *   If both ge and le: must have length < ge < le <= maximum
 *
 * But Cisco will apparently allow: length < ge <= le <= maximum
 *
 * We allow:  pl <= ge <= le <= maximum
 */
static cmd_ret_t
prefix_list_entry_complete(prefix_list_entry pe, prefix pfx)
{
  uint pl_max, pl ;

  pl_max = prefix_bit_len(pfx) ;
  pl     = pfx->prefixlen ;

  /* Check that the prefix length is valid.
   */
  if (pl > pl_max)
    return CMD_WARNING ;

  /* Set the prefix list prefix address range and the prefix length
   */
  prefix_to_pair_range_tidy(pe->pair, pfx) ;
  pe->pl = pl ;

  /* If we had ge, check in range, otherwise set to pl.
   */
  if (pe->flags & PFLAG_GE)
    {
      if ( !( (pl <= pe->ge) && (pe->ge <= pl_max) ) )
        return CMD_WARNING ;
    }
  else
    pe->ge = pl ;

  /* If we had le, check in range, otherwise set as required.
   *
   * Note that if had ge, then we've checked that already, otherwise
   * we have set ge = pl -- so can check ge <= le.
   */
  if (pe->flags & PFLAG_LE)
    {
      if ( !( (pe->ge <= pe->le) && (pe->le <= pl_max) ) )
        return CMD_WARNING ;
    }
  else
    pe->le = (pe->flags & (PFLAG_ANY | PFLAG_GE)) ? pl_max : pl ;

  return CMD_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Insert prefix_list_entry or replace an existing one, if we can.
 *
 * The given 'temp' is a complete new entry, except that if PFLAG_SEQ is set,
 * the next sequence number will be allocated.
 *
 * May NOT insert or replace if an entry already exists with the same value,
 * (where the value excludes the sequence number and type).
 *
 * Except that, if a sequence number is given, it is (trivially) possible to
 * "replace" an entry with the same sequence number and value -- possibly
 * updating the type.
 *
 * The prefix_list_entry is then put in the list by sequence number, replacing
 * any existing entry.
 *
 * Returns:  CMD_SUCCESS  -- OK
 *           CMD_WARNING  -- Nope: entry with same value exists (with
 *                                 different sequence and possibly type).
 *
 * NB: can only fail if an entry already exists.  So, the prefix-list cannot be
 *     empty on return !
 */
static cmd_ret_t
prefix_list_entry_insert(prefix_list plist, prefix_list_entry temp)
{
  prefix_list_entry pe ;
  vector_index_t i ;
  int rider ;

  if (qdebug)
    prefix_list_verify(plist, false /* not show_tree */) ;

  /* Whatever else happens, the result is not empty and hence is "set"
   */
  vhash_set(plist) ;

  /* If do not have a sequence number, allocate next -- in steps of 5.
   *
   * If last sequence number is not a multiple of 5, rounds up to multiple
   * and then adds 5 -- eg 3 -> 10 (not 5).
   *
   * NB: if we do not have a sequence number, then we set temp->seq to a
   *     number which is guaranteed not to be in use.
   */
  if (!(temp->flags & PFLAG_SEQ))
    {
      uint last_seq ;

      qassert(temp->seq == 0) ;

      last_seq = 0 ;

      i = vector_end(plist->index) ;
      if (i != 0)
        {
          pe = vector_get_item(plist->index, i - 1) ;
          last_seq = pe->seq ;
        } ;

      temp->seq = (((last_seq + 5 - 1) / 5) * 5) + 5 ;
    } ;

  /* Add entry unless one with this value currently exists.
   *
   * For this purpose the value *excludes* the sequence number and the type
   * of entry.
   */
  pe = prefix_list_entry_find_val(plist, temp) ;

  /* Either added entry or found an existing one.
   *
   * If sequence numbers differ, then have found an existing clashing value.
   * Set the temp->seq and temp->type to those we found.
   */
  if (pe->seq != temp->seq)
    {
      temp->seq   = pe->seq ;
      temp->flags = (temp->flags & ~PFLAG_TYPE) | (pe->flags & PFLAG_TYPE) ;

      return CMD_WARNING ;
    } ;

  /* Now we need to worry about the sequence number index.
   *
   * This is trivial if the sequence number is not currently in use.
   */
  i = prefix_list_entry_lookup_seq(plist, pe->seq, &rider) ;

  if (rider != 0)
    vector_insert_item_here(plist->index, i, rider, pe) ;
  else
    {
      /* The sequence number is in use.
       *
       * If the existing entry is the same as the one we have:
       *
       *   * if the type is the same, then the existing entry is identical to
       *     that specified by 'temp', and there is nothing more to be done
       *     (the prefix-list is unchanged).
       *
       *   * if the type differs, then the existing entry is identical to
       *     that specified by 'temp' in all other respects, and we need only
       *     update the type and run the 'add_hook'.
       *
       * If the existing entry is different to the one we have:
       *
       *   * we are replacing an entry with a new one with a different
       *     value (and possibly a different type).
       *
       *     The existing entry must be deleted from the tree, and the index
       *     updated.
       *
       *     Note that for a brief moment we have had two entries with the
       *     same sequence numbers in the tree.  It is just possible that the
       *     two entries were attached to the same node in the tree -- if the
       *     new and old entries have the same prefix.
       */
      prefix_list_entry px ;

      px = vector_get_item(plist->index, i) ;

      if (px == pe)
        {
          if ((pe->flags & PFLAG_TYPE) == (temp->flags & PFLAG_TYPE))
            return CMD_SUCCESS ;

          pe->flags ^= PFLAG_TYPE ;
        }
      else
        {
          vector_set_item(plist->index, i, pe) ;
          prefix_list_entry_tree_delete(plist, px) ;
        } ;
    } ;

  if (qdebug)
    prefix_list_verify(plist, false /* not show_tree */) ;

  /* Run hook function.
   */
  if (plist->master->add_hook != NULL)
    plist->master->add_hook(plist) ;

  plist->master->recent = plist;

  return CMD_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Delete prefix_list_entry, if we can.
 *
 * To delete an entry the caller must specify the exact value of an existing
 * entry.  If a sequence number is specified, that entry must exist, and its
 * value must exactly match the given value.  If no sequence number is
 * specified, an entry must exist with exactly the given value.
 *
 * Returns:  CMD_SUCCESS  -- OK
 *           CMD_WARNING  -- entry not found.
 */
static cmd_ret_t
prefix_list_entry_delete (prefix_list plist, prefix_list_entry pe_seek)
{
  prefix_list_node*  p_root ;
  prefix_list_node   pn ;
  prefix_list_entry  pe ;
  vector_index_t i ;
  int rider ;

  if (qdebug)
    prefix_list_verify(plist, false /* not show_tree */) ;

 /* If pe_seek is an 'any', p_root and pn are set NULL
   */
  pe = prefix_list_entry_seek(plist, pe_seek, &p_root, &pn) ;

  if (pe == NULL)
    return CMD_WARNING ;

  i = prefix_list_entry_lookup_seq(plist, pe->seq, &rider) ;
  qassert(rider == 0) ;

  if (rider == 0)
    {
      prefix_list_entry px ;

      px = vector_delete_item(plist->index, i) ;
      qassert(px == pe) ;
    } ;

  /* An 'any' entry will have pn == NULL
   */
  prefix_list_entry_node_delete(plist, pe, p_root, pn) ;

  if (prefix_list_is_empty(plist))      /* NB: empty => no description  */
    prefix_list_delete (plist) ;        /* invokes delete hook          */
  else
    {
      if (qdebug)
        prefix_list_verify(plist, false /* not show_tree */) ;

      if (plist->master->delete_hook != NULL)
        plist->master->delete_hook(plist) ;

      plist->master->recent = plist ;
    } ;

  return CMD_SUCCESS ;
} ;

/*==============================================================================
 * Operations on prefix_list entry in vector by sequence number
 */

/*------------------------------------------------------------------------------
 * Lookup prefix_list_entry by its sequence number.  Returns index of an entry
 * in the prefix_list, and sets:
 *
 *   result <  0 -- not found.  index returned is of first entry in the
 *                              prefix list, and this sequence number comes
 *                              before it.  (Or list is empty.)
 *   result == 0 -- found.      index is of the entry found.
 *   result >  0 -- not found.  index returned is of the entry with the largest
 *                              sequence number smaller than the given one.
 */
static vector_index_t
prefix_list_entry_lookup_seq(prefix_list plist, uint seq, int* result)
{
  return vector_bsearch(plist->index, (vector_bsearch_cmp*)prefix_seq_cmp,
                                                                 &seq, result) ;
} ;

/*==============================================================================
 * Operations on prefix_list_entry in avl tree
 */
static prefix_list_node prefix_list_node_lookup(prefix_list plist,
            prefix_list_entry_c temp, bool adding, prefix_list_node** pp_root) ;
static prefix_list_node prefix_list_node_make_subtree(prefix_list plist,
                           prefix_list_entry_c temp, prefix_list_node* p_root,
                                                          prefix_list_node px) ;

/*------------------------------------------------------------------------------
 * Create a new node
 */
static prefix_list_node
prefix_list_node_new(void)
{
  /* Zeroizing a new prefix_list_node sets:
   *
   *  * avl               -- all zeros, not that this matters
   *
   *  * entries           -- NULL   -- no entries, yet
   *
   *  * sub_tree          -- NULL   -- empty subtree
   */
  return XCALLOC(MTYPE_PREFIX_LIST_NODE, sizeof(prefix_list_node_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Free a node
 *
 * Returns:  NULL
 */
static prefix_list_node
prefix_list_node_free(prefix_list_node pn)
{
  if (pn != NULL)
    XFREE(MTYPE_PREFIX_LIST_NODE, pn) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Create a new node -- avl tree call-back
 *
 * If the given 'arg' is NULL, create and return a brand new node.
 *
 * If the given 'arg' is not NULL, it is a node which was prepared earlier, so
 * return that.
 *
 * Returns:  avl_item ready to be inserted into an avl tree
 *
 * NB: the prefix-list node does not contain the key value.  A prefix-list
 *     node MUST point at at least one prefix-list entry and each one conains
 *     the same key value.
 *
 *     When a brand new node is created, it is created with an empty list of
 *     prefix-list entries -- it is ESSENTIAL that an entry is added to that
 *     list *before* any further tree operations are attempted.
 */
static avl_item prefix_list_avl_new_node(avl_key_c key, void* arg)
{
  if (arg == NULL)
    return (avl_item)prefix_list_node_new() ;

  return (avl_item)arg ;
} ;

/*------------------------------------------------------------------------------
 * Compare given IPv4 key and item -- avl tree call-back
 *
 * The key is an ip_union_pair.  The item is a prefix_list_node, which points
 * at (at least one) a prefix_list entry, which contains an ip_union_pair.
 *
 * The ip_union_pair contains the start [0] and end [1] of a range of IPv4
 * addresses.  The comparison returns:
 *
 *   -1 <=> the key range is all to the left of the item range
 *
 *    0 <=> the key and item ranges overlap in some way
 *
 *   +1 <=> the key range is all to the right of the item range
 *
 * NB: for an address range, the components of an ip_union_pair are held in
 *     HOST order, to simplify comparison !
 */
static int prefix_list_ipv4_cmp_node(avl_key_c key, avl_item item)
{
  ip_union_pair_c k, n ;

  k = key ;
  n = ((prefix_list_node)item)->entries->pair ;

  if (k->ipv4[1] < n->ipv4[0])
    return -1 ;                 /* key belongs to left of given item    */

  if (k->ipv4[0] > n->ipv4[1])
    return +1 ;                 /* key belongs to right of given item   */

  return 0 ;                    /* overlap of some kind.                */
} ;

/*------------------------------------------------------------------------------
 * Compare given IPv6 key and item -- avl tree call-back
 *
 * The key is an ip_union_pair.  The item is a prefix_list_node, which points
 * at (at least one) a prefix_list entry, which contains an ip_union_pair.
 *
 * The ip_union_pair contains the start [0] and end [1] of a range of IPv6
 * addresses.  The comparison returns:
 *
 *   -1 <=> the key range is all to the left of the item range
 *
 *    0 <=> the key and item ranges overlap in some way
 *
 *   +1 <=> the key range is all to the right of the item range
 *
 * NB: for an address range, the components of an ip_union_pair are held in
 *     HOST order, to simplify comparison !
 *
 *     An IPv6 ip_union_pair is arranged as two uint64_t, which are held in
 *     Network Order wrt each other.
 */
static int prefix_list_ipv6_cmp_node(avl_key_c key, avl_item item)
{
  ip_union_pair_c k, n ;

  k = key ;
  n = ((prefix_list_node)item)->entries->pair ;

  if (k->ipv6[1].n64[0] < n->ipv6[0].n64[0])
    return -1 ;                 /* key belongs to left of given item    */

  if (k->ipv6[0].n64[0] > n->ipv6[1].n64[0])
    return +1 ;                 /* key belongs to right of given item   */

  if (k->ipv6[1].n64[1] < n->ipv6[0].n64[1])
    return -1 ;                 /* key belongs to left of given item    */

  if (k->ipv6[0].n64[1] > n->ipv6[1].n64[1])
    return +1 ;                 /* key belongs to right of given item   */

  return 0 ;                    /* overlap of some kind.                */
} ;

/*------------------------------------------------------------------------------
 * Find prefix_list_entry by its value in the prefix-list tree.
 *
 * The entry is specified by the given 'temp' entry, which MUST include the
 * sequence number to be used if it is necessary to add a new entry.
 *
 * For the look-up the value is: prefix-range and prefix-length, plus the ge
 * and le ...so may return as "found", an existing entry with any sequence
 * number and with either deny or permit type.
 *
 * Returns:  existing or new entry.
 *
 * Note that if the sequence number and type of the entry returned are the same
 * as in the given 'temp', the caller cannot tell if the value returned is a
 * pre-existing or a new entry.
 *
 * NB: does nothing with the sequence number index.
 *
 *     It is possible for this function to create an entry with the same
 *     sequence number as an existing entry -- but not with the same value
 *     as an existing entry.  (The new entry may even be attached to the same
 *     tree node.)
 */
static prefix_list_entry
prefix_list_entry_find_val(prefix_list plist, prefix_list_entry_c temp)
{
  prefix_list_node*  p_root ;
  prefix_list_node   pn ;
  prefix_list_entry  pe ;
  prefix_list_entry* pp ;

  /* Look-up node for the 'temp' -- create if required.
   *
   * For 'any' prefixes, we don't have a node, but have a separate list of
   * all such -- prefix_list_node_lookup() returns NULL.
   */
  pn = prefix_list_node_lookup(plist, temp, true /* add */, &p_root) ;

  pp = (pn == NULL) ? &plist->any.next : &pn->entries ;

  /* Seek the entry equivalent to 'temp'.
   *
   * Since we are on the required node, we have the required range (and prefix
   * length) so looking only for the right ge and le values.
   *
   * If have create a new node the list of entries will be empty.
   */
  pe = *pp ;
  while (pe != NULL)
    {
      qassert(pe->pl == temp->pl) ;

      if ((pe->ge == temp->ge) && (pe->le == temp->le))
        return pe ;

      pe = pe->next ;
    } ;

  /* Create a prefix-list entry and add it to the given node, in sequence
   * number order.
   *
   * NB: if finds an equal sequence number, adds *after* it.  This should
   *     never happen -- but in the case of the 'any' this is sort of
   *     consistent with an explicit sequence number of UINT32_MAX coming
   *     *after* the implicit, default entry.
   */
  pe = prefix_list_entry_new(temp) ;

  while (1)
    {
      prefix_list_entry ps ;

      ps = *pp ;
      if ((ps == NULL) || (pe->seq < ps->seq))
        {
          *pp = pe ;
          pe->next = ps ;
          return pe ;
        } ;

      pp = &ps->next ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Seek prefix_list_entry by its value in the prefix-list tree.
 *
 * The entry is specified by the given 'temp' entry.
 *
 * In this case the value *includes* the prefix_entry type *and* the sequence
 * number if one is specified.
 *
 * Does NOT add an entry.
 *
 * Returns:  existing entry, of any -- NULL if not found.
 *
 * If an existing entry is returned:
 *
 *   *p_pn    is set to the address of the node that the entry was found in.
 *
 *            NB: NULL for 'any' prefix.
 *
 *   *pp_root is set to point at the root of the tree (or sub-tree) in which
 *            the node exists.
 *
 *            NB: NULL for 'any' prefix
 *
 * These may be used to delete the entry.
 */
static prefix_list_entry
prefix_list_entry_seek(prefix_list plist, prefix_list_entry_c temp,
                             prefix_list_node** pp_root, prefix_list_node* p_pn)
{
  prefix_list_node   pn ;
  prefix_list_entry  pe ;

  /* Look-up node for the 'temp'.
   */
  pn = prefix_list_node_lookup(plist, temp, false /* do not add */, pp_root) ;
  *p_pn = pn ;

  if ((pn == NULL) && (temp->pl != 0))
    return NULL ;

  /* Seek the entry equivalent to 'temp'.
   *
   * Since we are on the required node, we have the required range (and prefix
   * length) so looking only for the right ge and le values.
   */
   ;
  for (pe = (pn == NULL) ? plist->any.next : pn->entries ;
                                                     pe != NULL ; pe = pe->next)
    {
      qassert(pe->pl == temp->pl) ;
      qassert(plist->params->cmp(temp->pair, pn) == 0) ;

      if (pe->ge != temp->ge)
        continue ;

      if (pe->le != temp->le)
        continue ;

      if ((pe->flags & PFLAG_TYPE) != (temp->flags & PFLAG_TYPE))
        continue ;

      if ((temp->flags & PFLAG_SEQ) && (pe->seq != temp->seq))
        continue ;

      break ;
    } ;

  return pe ;
} ;

/*------------------------------------------------------------------------------
 * Look-up node and tree in which entry given by temp should appear -- create
 * a new node if required.
 *
 * Returns:  address of node -- NULL if not found and not required to add.
 *
 * Sets *pp_root to point at the root of the tree or sub-tree that the node
 * is in.
 */
static prefix_list_node
prefix_list_node_lookup(prefix_list plist, prefix_list_entry_c temp,
                                       bool adding, prefix_list_node** pp_root)
{
  prefix_list_node* p_root ;
  prefix_list_node  pn ;

  if (temp->pl == 0)
    {
      *pp_root = NULL ;
      return NULL ;
    } ;

  p_root = &plist->root ;

  while (1)
    {
      prefix_list_entry pe ;

      if (adding)
        pn = avl_lookup_add((avl_item*)p_root, *p_root, temp->pair,
                                                          plist->params, NULL) ;
      else
        pn = avl_lookup((avl_item*)p_root, *p_root, temp->pair, plist->params) ;

      if (pn == NULL)
        {
          qassert(!adding) ;
          break ;               /* not found and not adding     */
        } ;

      /* If the prefix-list node has an empty list of entries, then have just
       * created a node.
       *
       * If have just created a node, that means that there was no match for
       * the prefix range, so no sub-tree stuff to worry about.
       */
      pe = pn->entries ;

      if (pe == NULL)
        {
          qassert(adding) ;
          break ;               /* added new entry              */
        } ;

      /* We have found an existing node.
       *
       * If that is an exact match for the prefix range, we are done.
       */
       if (temp->pl == pe->pl)
        break ;                 /* exact match                  */

      /* If the prefix we are looking for is a sub-prefix of the one we have
       * just found, we need to recurse into the sub-tree.
       */
      if (temp->pl > pe->pl)
        {
          p_root = &pn->sub_root ;
          continue ;
        } ;

      /* The prefix we are looking for is a super-prefix of what we have just
       * found.
       *
       * If we are not adding, we are done -- not found.
       *
       * If we are required to add, the node we have found AND any children
       * for which the new node is a super-prefix, need to be moved to a
       * new node's sub-tree... this is the down-side of the tree mechanism.
       */
      if (adding)
        pn = prefix_list_node_make_subtree(plist, temp, p_root, pn) ;
      else
        pn = NULL ;

      break ;
    } ;

  *pp_root = p_root ;
  return pn ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given entry from the tree and free it.
 *
 * Does nothing if px is NULL or if does not find in the tree.
 *
 * If the entry is the only entry in the node, removes the node from its tree
 * and frees the node as well.
 *
 * Returns:  NULL
 *
 * NB: does not do anything at all with the sequence number index.
 */
static prefix_list_entry
prefix_list_entry_tree_delete(prefix_list plist, prefix_list_entry px)
{
  prefix_list_node*  p_root ;
  prefix_list_node   pn ;

  if (px == NULL)
    return NULL ;               /* do nothing with NULL entry   */

  /* Look for node in tree which this entry should be hung from.
   *
   * Note that this sets pn and p_root NULL if px is 'any'.
   */
  pn = prefix_list_node_lookup(plist, px, false /* do not add */, &p_root) ;

  return prefix_list_entry_node_delete(plist, px, p_root, pn) ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given entry from its node and free it.
 *
 * Does nothing if px is NULL or not found on the node's list.
 *
 * If the entry is the only entry in the node, removes the node from its tree
 * and frees the node as well.
 *
 * For the special case of an 'any' prefix, both 'pn' and 'p_root' are NULL,
 * and 'px' is removed from the special 'any' list.
 *
 * Returns:  NULL
 *
 * NB: does nothing at all with the sequence number index.
 */
static prefix_list_entry
prefix_list_entry_node_delete(prefix_list plist, prefix_list_entry px,
                                  prefix_list_node* p_root, prefix_list_node pn)
{
  prefix_list_entry* pp ;

  if (px == NULL)
    return NULL ;               /* do nothing if entry NULL     */

  /* Look for entry in its node
   */
  if (px->pl == 0)
    {
      qassert(pn == NULL) ;
      pp = &plist->any.next ;
      pn = NULL ;               /* safety first                 */
    }
  else
    {
      if (pn == NULL)
        return NULL ;           /* safety first                 */

      pp = &pn->entries ;
    } ;

  while (1)
    {
      prefix_list_entry pe ;

      pe = *pp ;

      if (pe == px)
        break ;                 /* found entry attached to node */

      if (pe == NULL)
        return NULL ;           /* do nothing if node not found */

      pp = &pe->next ;
    } ;

  /* Found entry in node -- so remove and free it.
   */
  *pp = px->next ;

  prefix_list_entry_free(px) ;

  /* If the node no longer has any entries, remove the node from its tree.
   *
   * If the node has a sub-tree, the contents of that subtree must be moved up
   * to the node's tree -- the inverse of prefix_list_node_make_subtree().
   *
   * Then free the node.
   */
  if ((pn != NULL) && (pn->entries == NULL))
    {
      prefix_list_node psn, seek ;
      prefix_list_node s_root ;

      seek = (prefix_list_node)(pn->avl.parent) ;
      avl_remove((avl_item*)p_root, pn) ;

      s_root = pn->sub_root ;                   /* grab sub_tree        */
      while ((psn = avl_tree_ream((avl_item*)&s_root)) != NULL)
        {
          prefix_list_node pnn ;

          pnn = avl_lookup_add((avl_item*)p_root, seek,
                                       psn->entries->pair, plist->params, psn) ;
          qassert(pnn == psn) ;
        } ;

      XFREE(MTYPE_PREFIX_LIST_NODE, pn) ;       /* discard node         */
    } ;

  /* Return NULL as promised
   */
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * We need to create a new node and add it to its tree -- where the new node
 * encloses one or more existing nodes, which must be moved into the new
 * node's sub-tree.
 *
 * Called with the root of the tree/sub-tree in which the node 'px' has been
 * found, which is to be the first node in a new sub-true in a new node for
 * the address range given by temp.
 *
 * Returns:  the new node which has been added to the tree, enclosing all nodes
 *           which have been moved to the new node's sub-tree
 *
 * NB: the new node does not yet have any entries !
 */
static prefix_list_node
prefix_list_node_make_subtree(prefix_list plist, prefix_list_entry_c temp,
                                  prefix_list_node* p_root, prefix_list_node px)
{
  prefix_list_node pn ;

  qassert(px->entries != NULL) ;

  pn = prefix_list_node_new() ;

  /* The process of creating a sub-tree starts with the given first node
   * to be moved to the sub-tree.
   *
   * Then tries to insert the new node in the main tree, starting the search
   * for the insertion point at the parent (in the original tree) of the node
   * we have just moved.
   *
   * The magic of this is that if finds another node that needs to be moved,
   * returns that instead of inserting the new node.  So we loop until the
   * new node is successfully inserted -- which means that all nodes which
   * match the new node have been moved to the new node's sub-tree.
   *
   * The difference between finding an existing node and inserting the new one
   * is that an existing node must have at least one prefix-list-entry.
   */
  do
    {
      avl_item seek ;

      seek = px->avl.parent ;   /* if node being removed has a parent, then
                                 * tries to reduce lookup by starting from
                                 * here.                                */

      qassert(px->entries->pl > temp->pl) ;
      qassert(px != pn) ;

      avl_remove((avl_item*)p_root, px) ;       /* Remove from tree     */

      avl_lookup_add((avl_item*)&pn->sub_root, NULL, px->entries->pair,
                                                            plist->params, px) ;
                               /* Add to sub-tree                       */
      px = avl_lookup_add((avl_item*)p_root, seek, temp->pair, plist->params,
                                                                           pn) ;
                               /* Add new node or find another to move  */
    }
  while (px->entries != NULL) ;

  qassert(px == pn) ;

  return pn ;
} ;

/*------------------------------------------------------------------------------
 * Flush tree of nodes whose root is *p_root.
 *
 * Flushes all sub-trees.
 *
 * NB: does nothing with any prefix-entries which the tree and any sub-trees
 *     may be pointing to.
 */
static void
prefix_list_tree_flush(prefix_list_node* p_root)
{
  prefix_list_node ream ;
  prefix_list_node pn ;

  ream = *p_root ;
  *p_root = NULL ;

  while ((pn = avl_tree_ream((avl_item*)&ream)) != NULL)
    {
      if (pn->sub_root != NULL)
        prefix_list_tree_flush(&pn->sub_root) ;

      pn->entries = NULL ;              /* forget entries       */
      prefix_list_node_free(pn) ;
    } ;
} ;

/*==============================================================================
 * Prefix List Use.
 */
static prefix_list_entry prefix_list_apply_recurse(prefix_list plist,
                               prefix_list_entry pf, prefix_list_node* p_root,
                                                              prefix_len_t pl) ;
static uint prefix_list_verify_tree(prefix_list_node root, ip_union_pair limits,
                                         uint pl_min, uint pl_max, qAFI_t afi,
                                                                    bool show) ;
static void prefix_list_verify_show_entry(prefix_list_entry pe, qAFI_t afi) ;

enum { qdebug_prefix_list_show_entry = true } ;
#include <stdio.h>

/*------------------------------------------------------------------------------
 * Apply a prefix_list to the given prefix.
 *
 * If the plist is NULL or the prefix-list is empty, will return PREFIX_DENY.
 *
 * NB: does not check the prefix or the prefix length against each other, or
 *     against the sa_family, or against the prefix-list qAFI !
 *
 * Returns:  PREFIX_DENY or PREFIX_PERMIT
 */
extern prefix_list_type_t
prefix_list_apply (prefix_list plist, const void* object)
{
  prefix_len_t      pl ;
  prefix_list_entry pe, pf ;

  if (plist == NULL)
    return PREFIX_DENY ;

  pf = &plist->any ;
  qassert(pf->seq >= UINT32_MAX) ;

  prefix_to_pair_range(pf->pair, (prefix_c)object) ;
  pl = ((prefix_c)object)->prefixlen ;

  pf = prefix_list_apply_recurse(plist, pf, &plist->root, pl) ;

  /* If there are any 'any' entries, process those against best match so far.
   */
  pe = plist->any.next ;
  if (pe != NULL)
    {
      uint32_t  seq ;

      seq = pf->seq ;           /* best, so far                 */
      do
        {
          if (seq < pe->seq)
            break ;             /* quit if not better           */

          pe->refcnt += 1 ;

          if ((pl >= pe->ge) && (pl <= pe->le))
            {
              pf = pe ;
              break ;           /* return better match          */
            } ;

          pe = pe->next ;       /* keep going                   */
        }
      while (pe != NULL) ;
    } ;

  pf->hitcnt += 1 ;

  confirm(PREFIX_DENY   == (PREFIX_DENY   & PFLAG_TYPE)) ;
  confirm(PREFIX_PERMIT == (PREFIX_PERMIT & PFLAG_TYPE)) ;

  return pf->flags & PFLAG_TYPE ;
} ;

/*------------------------------------------------------------------------------
 * Search given tree and sub-trees for best match to given prefix.
 *
 * On entry 'pf' contains: pf->seq     0xFF...FF
 *                         pf->flags   default result = PREFIX_DENY
 *
 *                         pf->pair  ) the prefix being matched to
 *                         pf->pl    )
 *
 * Will recurse down into sub-trees, where there are any and while the pf->pl
 * greater than the current level's prefix-length.
 *
 * When reaches the deepest level, 'pf' contains the best result, so far.
 * Walks the entries at the deepest level, and returns the best match -- which
 * may be the original 'pf'.
 *
 * On the way back up, 'pf' points to the best result so far, and that is
 * tested against all entries at each level.
 *
 * The depth first approach examines the most specific possible matches first.
 * Where does match, expect any less specific matches to have smaller sequence
 * numbers... for if not, they are redundant !
 */
static prefix_list_entry
prefix_list_apply_recurse(prefix_list plist, prefix_list_entry pf,
                                      prefix_list_node* p_root, prefix_len_t pl)
{
  prefix_list_node  pn ;

  pn = avl_lookup((avl_item)p_root, *p_root, pf->pair, plist->params) ;

  if (pn != NULL)
    {
      prefix_list_entry pe ;
      uint seq ;

      pe = pn->entries ;        /* first entry at current level */
      qassert(pl >= pe->pl) ;   /* otherwise could not match !  */

      /* Recurse as required to deepest point possible
       */
      if ((pl > pe->pl) && (pn->sub_root != NULL))
        pf = prefix_list_apply_recurse(plist, pf, &pn->sub_root, pl) ;

      /* We now have 'pf' is best result so far.
       *
       * Note that stops considering prefix-list entries as soon as finds a
       * sequence number *greater*than* the best so far -- which copes with
       * the initial state of pf->seq, which is UINT32_MAX.
       */
      seq = pf->seq ;           /* best, so far                 */
      do
        {
          if (seq < pe->seq)
            break ;             /* quit if not better           */

          pe->refcnt += 1 ;

          if ((pl >= pe->ge) && (pl <= pe->le))
            return pe ;         /* return better match          */

          pe = pe->next ;       /* keep going                   */
        }
      while (pe != NULL) ;
    } ;

  return pf ;
} ;

/*------------------------------------------------------------------------------
 * Verify contents of prefix-list
 */
static void
prefix_list_verify(prefix_list plist, bool show)
{
  uint              index_count, tree_count ;
  prefix_t          pfx[1] ;
  ip_union_pair_t   limits[1] ;
  vector_index_t    i ;
  prefix_list_entry pe ;
  uint              seq, pl_max ;

  if (plist == NULL)
    return ;

  qassert((plist->afi == qAFI_ipv4) || (plist->afi == qAFI_ipv6)) ;

  prefix_default(pfx, afi2family(plist->afi)) ;

  /* Make sure that start with all known entries not "seen"
   */
  seq = 0 ;
  index_count = vector_end(plist->index) ;

  if (show && qdebug_prefix_list_show_entry)
    fprintf(stderr, "%s prefix-list '%s' %u entries:\n",
                    prefix_afi_name_str(plist->afi), plist->name, index_count) ;

  for (i = 0 ; i < index_count ; ++i)
    {
      pe = vector_get_item(plist->index, i) ;
      qassert(pe != NULL) ;

      qassert((pe->seq > seq) || (i == 0)) ;
      seq = pe->seq ;

      pe->flags &= ~PFLAG_SEEN ;
    } ;

  /* Walk the 'any' list, if any.
   *
   * The default 'any' entry must have 'seq' == maximum and be PREFIX_DENY.
   *
   * Any other 'any' entries must all be 0.0.0.0/0 or ::/0, and must have
   * valid ge/le and must be in ascending sequence number order.
   */
  prefix_to_pair_range_tidy(limits, pfx) ;
  pl_max = prefix_bit_len(pfx) ;

  pe = &plist->any ;

  qassert(pe->seq == UINT32_MAX) ;
  qassert((pe->flags & PFLAG_TYPE) == PREFIX_DENY) ;

  tree_count = 0 ;
  while ((pe = pe->next) != NULL)
    {
      if (show && qdebug_prefix_list_show_entry)
        prefix_list_verify_show_entry(pe, plist->afi) ;

      qassert(!(pe->flags & PFLAG_SEEN)) ;
      pe->flags |= PFLAG_SEEN ;

      tree_count += 1 ;

      qassert(pe->seq <= UINT32_MAX) ;

      if (pe != plist->any.next)
        qassert(pe->seq > seq) ;

      qassert(pe->pl == 0) ;
      qassert(memcmp(pe->pair, limits, sizeof(ip_union_pair_t)) == 0) ;

      qassert(pe->pl <= pe->ge) ;
      qassert(pe->ge <= pe->le) ;
      qassert(pe->le <= pl_max) ;

      seq = pe->seq ;
    } ;

  /* Walk the tree and any sub-trees and verify that everything is in order.
   */
  tree_count += prefix_list_verify_tree(plist->root, limits, 1, pl_max,
                                                             plist->afi, show) ;

  /* Check that the tree_count and the index agree.
   */
  qassert(tree_count == index_count) ;

  /* Check that all entries have been visited, and clear the PFLAG_SEEN.
   */
  for (i = 0 ; i < index_count ; ++i)
    {
      pe = vector_get_item(plist->index, i) ;
      qassert(pe != NULL) ;

      qassert(pe->flags &= ~PFLAG_SEEN) ;
      pe->flags &= ~PFLAG_SEEN ;
    } ;

  /* If there is at least one entries or there is a description, then should be
   * "set", otherwise, not.
   */
  if ((index_count != 0) || (plist->desc != NULL))
    qassert(vhash_is_set(plist)) ;
  else
    qassert(!vhash_is_set(plist)) ;
} ;

/*------------------------------------------------------------------------------
 * Verify contents of prefix-list tree and all its sub-trees
 */
static uint
prefix_list_verify_tree(prefix_list_node root, ip_union_pair limits,
                                uint pl_min, uint pl_max, qAFI_t afi, bool show)
{
  prefix_list_node pn ;
  ip_union_pair_t  prev ;
  uint count ;

  count = 0 ;
  pn = avl_get_first(root) ;

  memset(&prev, 0, sizeof(ip_union_pair_t)) ;

  while (pn != NULL)
    {
      prefix_list_entry pe, pf ;
      uint seq ;

      /* Examine the first entry, and check that is within the bounds given
       * byte 'limits', 'pl_min' and 'pl_max', and that is greater than the
       * previous node (if any).
       */
      pf = pn->entries ;
      qassert(pf != NULL) ;
      qassert((pl_min <= pf->pl) && (pf->pl <= pl_max)) ;

      switch (afi)
        {
          case qAFI_ipv4:
            qassert(pf->pair->ipv4[0] >= limits->ipv4[0]) ;
            qassert(pf->pair->ipv4[1] <= limits->ipv4[1]) ;

            qassert((pf->pair->ipv4[0] > prev.ipv4[1]) || (count == 0)) ;
            break ;

#ifdef HAVE_IPV6
          case qAFI_ipv6:
            if (pf->pair->ipv6[0].n64[0] != limits->ipv6[0].n64[0])
              qassert(pf->pair->ipv6[0].n64[0] >  limits->ipv6[0].n64[0]) ;
            else
              qassert(pf->pair->ipv6[0].n64[1] >= limits->ipv6[0].n64[1]) ;

            if (pf->pair->ipv6[1].n64[0] != limits->ipv6[1].n64[0])
              qassert(pf->pair->ipv6[1].n64[0] <  limits->ipv6[1].n64[0]) ;
            else
              qassert(pf->pair->ipv6[1].n64[1] <= limits->ipv6[1].n64[1]) ;
            break ;

            if (pf->pair->ipv6[0].n64[0] != prev.ipv6[1].n64[0])
              qassert((pf->pair->ipv6[0].n64[0] > prev.ipv6[1].n64[0])
                                                              || (count == 0)) ;
            else
              qassert((pf->pair->ipv6[0].n64[1] > prev.ipv6[1].n64[1])
                                                              || (count == 0)) ;
#endif
          default:
            qassert(false) ;
        } ;

      /* Now walk the entries and count, checking that:
       *
       *   * entries are in ascending sequence number order
       *
       *   * entries have the same 'pl' and 'pair'
       *
       *   * entries have valid 'ge' and 'le' values.
       */
      seq = pf->seq ;
      pe = pf ;
      do
        {
          if (show && qdebug_prefix_list_show_entry)
            prefix_list_verify_show_entry(pe, afi) ;

          qassert(!(pe->flags & PFLAG_SEEN)) ;
          pe->flags |= PFLAG_SEEN ;

          count += 1 ;

          qassert(pe->seq <= UINT32_MAX) ;

          if (pe != pf)
            {
              qassert(pe->seq > seq) ;
              qassert(pe->pl == pf->pl) ;
              qassert(memcmp(pe->pair, pf->pair,
                                                sizeof(ip_union_pair_t)) == 0) ;
            } ;

          qassert(pe->pl <= pe->ge) ;
          qassert(pe->ge <= pe->le) ;
          qassert(pe->le <= pl_max) ;

          seq = pe->seq ;
          pe  = pe->next ;
        }
      while (pe != NULL) ;

      /* If there is a sub-tree, recurse into that.
       */
      if (pn->sub_root != NULL)
        {
          if (show && qdebug_prefix_list_show_entry)
            fprintf(stderr, " sub-tree:\n") ;

          count += prefix_list_verify_tree(pn->sub_root, pf->pair, pf->pl + 1,
                                                            pl_max, afi, show) ;
          if (show && qdebug_prefix_list_show_entry)
            fprintf(stderr, " continue:\n") ;
        } ;

      /* Next node must be > this one.
       */
      prev = *pf->pair ;
      pn = avl_get_next(pn) ;
    } ;

  return count ;
} ;

/*------------------------------------------------------------------------------
 * If required, output the given prefix-list entry to stderr.
 */
static void
prefix_list_verify_show_entry(prefix_list_entry pe, qAFI_t afi)
{
  if (qdebug_prefix_list_show_entry)
    {
      prefix_t pfx[1] ;

      prefix_from_pair_range(pfx, pe->pair, afi2family(afi)) ;

      fprintf(stderr, "  %s seq=%u %s ge=%u le=%u\n", spfxtoa(pfx).str,
                            pe->seq, prefix_list_type_str(pe), pe->ge, pe->le) ;
    } ;
} ;

/*==============================================================================
 * BGP ORF prefix-list support
 */

/*------------------------------------------------------------------------------
 * Fill given bgp_orf_name -- given address of peer and qafx
 */
extern void
prefix_bgp_orf_name_set(bgp_orf_name name, sockunion su, uint16_t qafx)
{
  qf_str_t qfs ;

  sockunion2str(su, name, bgp_orf_name_len) ;

  qfs_init_as_is(qfs, name, bgp_orf_name_len) ;

  qfs_put_ch(qfs, '-') ;
  qfs_put_unsigned(qfs, qafx, pf_int_dec, 0, 0) ;

  qfs_term(qfs) ;
} ;

/*------------------------------------------------------------------------------
 * Get the i'th BGP ORF prefix from the given list, copy its value to the given
 * orf_prefix_value structure.
 *
 * Returns:  true <=> i'th entry exists
 */
extern bool
prefix_bgp_orf_get(orf_prefix_value orfpv, prefix_list plist, vector_index_t i)
{
  prefix_list_entry pe ;

  if (!plist || i >= plist->index->end)
    return false ;

  pe = vector_slot(plist->index, i);
  orfpv->seq  = pe->seq;
  orfpv->ge   = pe->ge;
  orfpv->le   = pe->le;
  prefix_list_prefix_fill(&orfpv->pfx, pe, plist->afi) ;
  orfpv->type = pe->flags & PFLAG_TYPE ;
  confirm(PREFIX_DENY   == (PREFIX_DENY   & PFLAG_TYPE)) ;
  confirm(PREFIX_PERMIT == (PREFIX_PERMIT & PFLAG_TYPE)) ;

  return true ;
}

/*------------------------------------------------------------------------------
 * Set or Unset a BGP ORF entry.
 */
extern cmd_ret_t
prefix_bgp_orf_set (bgp_orf_name name, qAFI_t afi, orf_prefix_value orfpv,
                                                                       bool set)
{
  prefix_master       pm ;
  prefix_list         plist ;
  prefix_list_entry_t temp ;
  cmd_ret_t ret ;

  assert_afi_real(afi) ;
  qassert(afi = family2afi(orfpv->pfx.family)) ;

  /* Transfer the values from the orf_prefix to the temp entry
   */
  prefix_list_entry_init(&temp) ;

  temp.flags = orfpv->type & PFLAG_TYPE ;
  confirm(PREFIX_DENY   == (PREFIX_DENY   & PFLAG_TYPE)) ;
  confirm(PREFIX_PERMIT == (PREFIX_PERMIT & PFLAG_TYPE)) ;

  temp.seq     = orfpv->seq ;     /* NB: U32 and may be zero      */
  if (orfpv->ge)
    {
      temp.flags |= PFLAG_GE ;
      temp.ge     = orfpv->ge ;
    }
  if (orfpv->le)
    {
      temp.flags |= PFLAG_LE ;
      temp.le     = orfpv->le ;
    }

  /* Complete the entry we've constructed, and check prefix, ge and le.
   */
  ret = prefix_list_entry_complete(&temp, &orfpv->pfx) ;
  if (ret != CMD_SUCCESS)
    return ret ;

  /* Now insert or delete
   */
  pm = &prefix_masters[qAFI_ORF_PREFIX] ;

  if (set)
    {
      plist = prefix_list_need(pm, afi, name) ;
      return prefix_list_entry_insert(plist, &temp) ;
    }
  else
    {
      plist = prefix_list_seek(pm, name) ;

      if (plist == NULL)
        return CMD_WARNING ;

      return prefix_list_entry_delete(plist, &temp) ;
    }
}

/*------------------------------------------------------------------------------
 * Remove all entries from the given orf list
 */
extern void
prefix_bgp_orf_remove_all (bgp_orf_name name)
{
  prefix_bgp_orf_delete(prefix_list_lookup (qAFI_ORF_PREFIX, name)) ;
}

/*------------------------------------------------------------------------------
 * Delete given orf list
 *
 * If the prefix-list has any remaining entries or any remaining description,
 * discard them.  Clear the "set" state.
 *
 * Invoke the delete_hook() if any.
 *
 * If there are no references, free the prefix-list.  Otherwise, leave it to
 * be freed when the reference count falls to zero, or leave it to have a
 * value redefined at some future date.
 */
extern prefix_list
prefix_bgp_orf_delete(prefix_list plist)
{
  if (plist != NULL)
    prefix_list_delete (plist) ;

  return NULL ;
} ;

/*==============================================================================
 * Common printing operations
 */

/*------------------------------------------------------------------------------
 * Print: "(ip|ipv6) prefix-list NAME" <post>
 */
static void
vty_prefix_list_name_print(struct vty* vty, struct prefix_list* plist,
                                                              const char* post)
{
  vty_out(vty, "%s prefix-list %s%s", prefix_afi_name_str(plist->afi),
                                                            plist->name, post) ;
} ;

/*------------------------------------------------------------------------------
 * Print: "(ip|ipv6) prefix-list NAME: 99 entries" <post>
 */
static void
vty_prefix_list_name_count_print(struct vty* vty, struct prefix_list* plist,
                                                               const char* post)
{
  vty_prefix_list_name_print(vty, plist, "") ;
  vty_out(vty, ": %d entries%s", vector_end(plist->index), post);
} ;

/*------------------------------------------------------------------------------
 * Print: "(ip|ipv6) prefix-list NAME" UNDEFINED<post>
 */
static void
vty_prefix_list_undefined_print(struct vty* vty, afi_t afi, const char* name,
                                                              const char* post)
{
  vty_out(vty, "%s prefix-list %s UNDEFINED%s", prefix_afi_name_str(afi),
                                                                  name, post) ;
} ;

/*------------------------------------------------------------------------------
 * Print: <indent>"Description: xxxx"<post>, if there is a description
 */
static void
vty_prefix_list_desc_print(struct vty* vty, struct prefix_list* plist,
                                                int indent, const char* post)
{
  if (plist->desc)
    vty_out (vty, "%sDescription: %s\n", VTY_SPACES(indent), plist->desc) ;
}

/* Size of buffer to hold either IPv4 or IPv6 string.           */
#ifndef INETX_ADDRSTRLEN
# if INET_ADDRSTRLEN < INET6_ADDRSTRLEN
#  define INETX_ADDRSTRLEN INET6_ADDRSTRLEN
# else
#  define INETX_ADDRSTRLEN INET_ADDRSTLEN
# endif
#endif

/*------------------------------------------------------------------------------
 * Print value of given prefix_list_entry:
 *
 *     "[seq 999 ](permit|deny) (any|XXXXX/999)[ ge 99][ le 99]"
 *                       "[ '('hit count: 999, refcount: 999')']" "\n"
 *
 *  where: sequence number is included if "with_seq" specified
 *         ge and/or le are included if explicitly set
 *         the hit count and refcount are included if "with_stats" specified
 */
static void
vty_prefix_list_value_print(struct vty* vty, prefix_list_entry pe, qAFI_t afi,
                                                 bool with_seq, bool with_stats)
{
  if (with_seq)
    vty_out(vty, "seq %d ", pe->seq) ;

  vty_out(vty, "%s ", prefix_list_type_str(pe)) ;

  if (pe->flags & PFLAG_ANY)
    vty_out(vty, "any");
  else
    {
      prefix_t pfx[1] ;
      prefix_list_prefix_fill(pfx, pe, afi) ;

      vty_out(vty, "%s", spfxtoa(pfx).str) ;
    } ;

  if (pe->flags & PFLAG_GE)
    vty_out(vty, " ge %d", pe->ge);
  if (pe->flags & PFLAG_LE)
    vty_out(vty, " le %d", pe->le);

  if (with_stats)
    vty_out (vty, " (hit count: %lu, refcount: %lu)", pe->hitcnt, pe->refcnt);

  vty_out(vty, "\n") ;
}

/*------------------------------------------------------------------------------
 *
 */
static void __attribute__ ((unused))
prefix_list_print (prefix_list plist)
{
  prefix_list_entry pe ;
  vector_index_t i ;
  struct vty* vty = NULL ;

  if (plist == NULL)
    return;

  vty_prefix_list_name_count_print(vty, plist, VTY_NEWLINE) ;

  for (VECTOR_ITEMS(plist->index, pe, i))
    {
      vty_out_indent(vty, 2) ;
      vty_prefix_list_value_print(vty, pe, plist->afi, true /* seq */,
                                                       true /* stats */) ;
    }
}

/*==============================================================================
 * vty prefix_list operations.
 */

/*------------------------------------------------------------------------------
 * Look up given prefix_list -- complain if not found.
 *
 * NB: is not found if is not "set".
 */
static struct prefix_list*
vty_prefix_list_lookup(struct vty *vty, afi_t afi, const char* name)
{
  struct prefix_list* plist = prefix_list_lookup(afi, name);
  if (plist == NULL)
    vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
  return plist ;
} ;

/*------------------------------------------------------------------------------
 * Process parameters for (ip|ipv6) prefix-list and no (ip|ipv6) prefix-list
 *
 * Fills in the given prefix_list_entry structure, ready for looking up,
 * inserting or deleting prefix_list_entry.
 *
 * Checks parameters for validity/legality.
 *
 * Returns a CMD_xxxx return code.  CMD_SUCCESS => OK !
 */
static cmd_ret_t
vty_prefix_list_process(struct vty *vty, struct prefix_list_entry* pe,
                        afi_t afi, const char *seq_str, const char *type_str,
                        const char *prefix_str,
                        const char *ge_str, const char *le_str)
{
  cmd_ret_t ret ;
  prefix_t  pfx[1] ;

  assert_afi_real(afi) ;        /* require real (and supported) afi     */

  prefix_list_entry_init(pe) ;  /* clears everything, including flags   */

  /* Sequence number
   */
  if (seq_str)
    {
      pe->flags |= PFLAG_SEQ ;
      pe->seq = atol(seq_str) ;
    } ;

  /* Check filter type
   */
  switch (*type_str)
    {
      case 'p':
        pe->flags |= (PREFIX_PERMIT & PFLAG_TYPE) ;
        break ;

      case 'd':
        pe->flags |= (PREFIX_DENY   & PFLAG_TYPE) ;
        break ;

      default:
        vty_out (vty, "%% prefix type must be permit or deny%s", VTY_NEWLINE);
        return CMD_WARNING;
    } ;

  /* Watch out for "any"
   */
  if (strncmp ("any", prefix_str, strlen (prefix_str)) == 0)
    pe->flags |= PFLAG_ANY ;

  /* Process the prefix.
   */
  switch (afi)
    {
      case qAFI_IP:
        if (pe->flags & PFLAG_ANY)
          prefix_str = "0.0.0.0/0" ;
        ret = str2prefix_ipv4 (prefix_str, (struct prefix_ipv4*)pfx);
        if (ret <= 0)
          {
            vty_out (vty, "%% Malformed IPv4 prefix%s", VTY_NEWLINE);
            return CMD_WARNING;
          }
        break ;

#ifdef HAVE_IPV6
      case qAFI_IP6:
        if (pe->flags & PFLAG_ANY)
          prefix_str = "::/0" ;
        ret = str2prefix_ipv6 (prefix_str, (struct prefix_ipv6*)pfx);
        if (ret <= 0)
          {
            vty_out (vty, "%% Malformed IPv6 prefix%s", VTY_NEWLINE);
            return CMD_WARNING;
          }
        break ;
#endif /* HAVE_IPV6 */

      default:
        vty_out (vty, "%% ??BUG?? unknown 'afi'%s", VTY_NEWLINE);
        return CMD_ERROR;
    } ;

  /* ge and le number
   */
  if (ge_str)
    {
      pe->ge = strtoul_s(ge_str) ;
      pe->flags |= PFLAG_GE ;
    }

  if (le_str)
    {
      pe->le = strtoul_s(le_str);
      pe->flags |= PFLAG_LE ;
    } ;

  /* Complete the entry we've constructed, and check prefix, ge and le.
   */
  ret = prefix_list_entry_complete(pe, pfx) ;

  if (ret != CMD_SUCCESS)
    vty_out (vty, "%% Invalid prefix range for %s, make sure: "
                                                "len <= ge-value <= le-value%s",
                        prefix_str, VTY_NEWLINE);

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Install a prefix_list_entry.
 *
 * Deals with all of ip prefix-list and ipv6 prefix-list commands.
 *
 * The arguments are:
 *
 *   afi        -- mandatory: qAFI_IP or qAFI_IP6
 *
 *   name       -- mandatory: name of the prefix-list (!)
 *
 *   seq_str    -- optional: NULL if no sequence number
 *
 *   type_str   -- mandatory: 'd' or 'p' for "deny"/"permit"
 *
 *   prefix_str -- mandatory: prefix in question -- may be "any"
 *
 *   ge_str     -- optional: NULL if no ge value
 *
 *   le_str     -- optional: NULL if no le value
 *
 * See vty_prefix_list_process()
 */
static int
vty_prefix_list_install (struct vty *vty, qAFI_t afi, const char *name,
                         const char *seq_str, const char *type_str,
                         const char *prefix_str,
                         const char *ge_str, const char *le_str)
{
  prefix_master pm ;
  prefix_list_entry_t temp ;
  int ret;

  assert_afi_real(afi) ;        /* UI stuff should ensure this */
  pm = prefix_master_get(afi, false /* real qAFI_t only */) ;

  /* Do the grunt work on the parameters.
   *
   * Completely fill in the temp prefix_list_entry structure.
   */
  ret = vty_prefix_list_process(vty, &temp, afi, seq_str, type_str,
                                                  prefix_str, ge_str, le_str) ;
  if (ret == CMD_SUCCESS)
    {
      /* Insert into the list, unless list contains an entry which is the same
       * apart from the sequence number.
       *
       * Creates the prefix-list if required.
       *
       * If fails, sets the sequence no. in temp to the sequence number found.
       *
       * Note that cannot at this stage fail if the plist is empty, so we don't
       * need to worry about deleting the plist if it does fail.
       */
      prefix_list plist ;

      plist = prefix_list_need(pm, afi, name) ;

      ret = prefix_list_entry_insert(plist, &temp);

      if (ret != CMD_SUCCESS)
        {
          vty_out (vty, "%% Insertion failed - prefix-list entry exists:\n") ;
          vty_out_indent(vty, 2) ;
          vty_prefix_list_value_print(vty, &temp, plist->afi,
                                                           true  /* seq    */,
                                                           false /* stats  */) ;
        } ;
    } ;

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Remove a prefix_list_entry.
 */
static int
vty_prefix_list_uninstall(struct vty *vty, afi_t afi, const char *name,
                          const char *seq_str, const char *type_str,
                          const char *prefix_str,
                          const char *ge_str, const char *le_str)
{
  prefix_list plist ;
  prefix_list_entry_t temp ;
  int ret;

  assert_afi_real(afi) ;        /* UI should guarantee this.    */

  /* Seek prefix_list with name -- error if not found.
   */
  plist = vty_prefix_list_lookup(vty, afi, name);
  if (plist == NULL)
    return CMD_WARNING ;

  /* Only prefix-list name specified, delete the entire prefix-list and its
   * description.
   */
  if ((seq_str == NULL) && (type_str == NULL) && (prefix_str == NULL)
                        && (ge_str == NULL) && (le_str == NULL))
    {
      prefix_list_delete (plist);
      return CMD_SUCCESS;
    }

  /* We must have, at a minimum, both the type and prefix here
   */
  if ((type_str == NULL) || (prefix_str == NULL))
    {
      vty_out (vty, "%% Both prefix and type required\n");
      return CMD_WARNING;
    }

  /* Deleting an individual entry -- if the parameters are valid and the
   * entry in question exists.
   */
  ret = vty_prefix_list_process(vty, &temp, afi, seq_str, type_str,
                                                   prefix_str, ge_str, le_str) ;
  if (ret == CMD_SUCCESS)
    {
      ret = prefix_list_entry_delete (plist, &temp);

      if (ret != CMD_SUCCESS)
        vty_out (vty, "%% Cannot find specified prefix-list entry\n") ;
    } ;

  return ret;
}

/*------------------------------------------------------------------------------
 * Set prefix-list description
 */
static cmd_ret_t
vty_prefix_list_desc_set (struct vty *vty, qAFI_t afi, const char *name,
                                                                    char* desc)
{
  prefix_master pm ;
  prefix_list   plist;

  assert_afi_real(afi) ;        /* UI stuff should ensure this */
  pm = prefix_master_get(afi, false /* real qAFI_t only */) ;

  /* Get prefix_list with name.   Make new list if required.
   */
  plist = prefix_list_need(pm, afi, name) ;

  if (plist->desc != NULL)
    XFREE (MTYPE_PREFIX_LIST_STR, plist->desc) ;

  plist->desc = XSTRDUP(MTYPE_PREFIX_LIST_STR, desc) ;
  vhash_set(plist) ;                    /* Has description => is "set"  */

  XFREE(MTYPE_TMP, desc) ;
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Clear prefix-list description
 */
static cmd_ret_t
vty_prefix_list_desc_unset (struct vty *vty, qAFI_t afi, const char *name)
{
  prefix_list plist ;

  plist = vty_prefix_list_lookup(vty, afi, name);
  if (plist == NULL)
    return CMD_WARNING ;

  if (plist->desc != NULL)
    XFREE (MTYPE_PREFIX_LIST_STR, plist->desc) ; /* sets plist->desc NULL */

  if (prefix_list_is_empty(plist))
    prefix_list_delete(plist) ;         /* delete list if all gone now  */

  return CMD_SUCCESS;
}

enum display_type
{
  normal_display,
  summary_display,
  detail_display,
  sequential_display,
  longer_display,
  first_match_display,
};

/*------------------------------------------------------------------------------
 * Show given prefix_list
 */
static void
vty_show_prefix_entry (struct vty *vty, prefix_list plist, prefix_master pm,
                                              enum display_type dtype, uint seq)
{
  if (qdebug)
    prefix_list_verify(plist, true /* Show Tree */) ;

  /* Print the name of the protocol */
  if (zlog_default)
      vty_out (vty, "%s: ", zlog_get_proto_name(NULL));

  if (dtype == normal_display)
    {
      vty_prefix_list_name_count_print(vty, plist, VTY_NEWLINE) ;
      vty_prefix_list_desc_print(vty, plist, 3, VTY_NEWLINE) ;
    }
  else if (dtype == summary_display || dtype == detail_display)
    {
      struct prefix_list_entry* p_f = vector_get_first_item(plist->index) ;
      struct prefix_list_entry* p_l = vector_get_last_item(plist->index) ;

      vty_prefix_list_name_print(vty, plist, ":") ;
      vty_out(vty, VTY_NEWLINE) ;

      vty_prefix_list_desc_print(vty, plist, 3, VTY_NEWLINE) ;

      vty_out (vty, "   count: %u, range entries: %u, sequences: %u - %u%s",
               vector_end(plist->index), plist->rangecount,
               p_f ? p_f->seq : 0,
               p_l ? p_l->seq : 0,
               VTY_NEWLINE);
    } ;

  if (dtype != summary_display)
    {
      struct prefix_list_entry* pe ;
      vector_index_t i ;
      bool with_seq   = pm->seqnum_flag ;
      bool with_stats = (dtype == detail_display) ||
                        (dtype == sequential_display) ;

      for (VECTOR_ITEMS(plist->index, pe, i))
        {
          if ((dtype == sequential_display) && (pe->seq != seq))
            continue;

          vty_out_indent(vty, 3);
          vty_prefix_list_value_print(vty, pe, plist->afi, with_seq,
                                                           with_stats) ;
        }
    }
}

/*------------------------------------------------------------------------------
 * Comparison function for sorting an extract from the prefix-lists
 */
static int
prefix_list_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb)
{
  prefix_list_c a = *pa ;
  prefix_list_c b = *pb ;

  return strcmp_mixed(a->name, b->name ) ;
} ;

/*------------------------------------------------------------------------------
 * Show given prefix list in given afi, or all prefix lists in given afi.
 */
static int
vty_show_prefix_list (struct vty *vty, qAFI_t afi, const char *name,
                      const char *seq_str, enum display_type dtype)
{
  prefix_list   plist;
  prefix_master pm;
  uint seq = 0;

  pm = prefix_master_get(afi, false /* real qAFI_t only */) ;
  if (pm == NULL)
    return CMD_WARNING;

  if (seq_str)
    seq = strtoul_s(seq_str);

  if (name)
    {
      /* Note that asking after an unknown prefix_list is an error.
       */
      plist = vty_prefix_list_lookup(vty, afi, name);
      if (plist == NULL)
        return CMD_WARNING;

      vty_show_prefix_entry (vty, plist, pm, dtype, seq);
    }
  else
    {
      vector extract ;
      vector_index_t i ;

      if (dtype == detail_display || dtype == summary_display)
        {
          if (pm->recent)
            vty_out (vty, "Prefix-list with the last deletion/insertion: %s%s",
                                                pm->recent->name, VTY_NEWLINE) ;
        }

      /* Extract a vector of all prefix_lists, in name order.
       */
      extract = vhash_table_extract(pm->table, NULL, NULL, false,
                                                         prefix_list_sort_cmp) ;

      for (VECTOR_ITEMS(extract, plist, i))
        {
          if (prefix_list_is_set(plist))
            vty_show_prefix_entry(vty, plist, pm, dtype, seq);
          else
            vty_prefix_list_undefined_print(vty, afi, plist->name, VTY_NEWLINE);
        }

      vector_free(extract) ;    /* throw away temporary vector */
    }

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 *
 */
static int
vty_show_prefix_list_prefix (struct vty *vty, afi_t afi, const char *name,
                                    const char *pfx_str, enum display_type type)
{
  prefix_list       plist;
  prefix_list_entry pe ;
  vector_index_t i ;
  prefix_t pfx[1];
  int  ret;
  bool match;
  bool with_stats ;

  /* Error if cannot find prefix list.
   */
  plist = vty_prefix_list_lookup(vty, afi, name);
  if (plist == NULL)
    return CMD_WARNING;

  ret = str2prefix (pfx_str, pfx);
  if (ret <= 0)
    {
      vty_out (vty, "%% prefix is malformed\n");
      return CMD_WARNING;
    }

  with_stats = (type == normal_display) || (type == first_match_display) ;

  for (VECTOR_ITEMS(plist->index, pe, i))
    {
      prefix_t pe_pfx[1];

      match = false ;

      prefix_list_prefix_fill(pe_pfx, pe, plist->afi) ;

      if     ((type == normal_display || type == first_match_display))
        match = prefix_same(pfx, pe_pfx) ;
      else if (type == longer_display)
        match = prefix_match(pfx, pe_pfx) ;

      if (match)
        {
          vty_out_indent(vty, 3);
          vty_prefix_list_value_print(vty, pe, plist->afi, true /* seq */,
                                                           with_stats) ;
          if (type == first_match_display)
            break ;
        }
    }
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Lookup given ORF prefix list, and show and/or count entries.
 *
 * Outputs contents (if any) to given vty -- unless that is NULL.
 *
 * Returns:  number of entries in the given prefix-list -- 0 not found
 */
extern int
prefix_bgp_show_prefix_list (struct vty *vty, char *name)
{
  prefix_list plist ;

  plist = prefix_list_lookup (qAFI_ORF_PREFIX, name);
  if (! plist)
    return 0;

  if (vty != NULL)
    {
      prefix_list_entry pe ;
      vector_index_t i ;

      vty_prefix_list_name_count_print(vty, plist, VTY_NEWLINE) ;

      for (VECTOR_ITEMS(plist->index, pe, i))
        {
          vty_out_indent(vty, 3) ;
          vty_prefix_list_value_print(vty, pe, plist->afi, true /* seq   */,
                                                           true /* stats */) ;
        }
    } ;

  return vector_end(plist->index);
}

/*------------------------------------------------------------------------------
 * Clear hit counters in all prefix_list_entries:
 *
 *   a) in all prefix_lists  -- name NULL
 *   b) in given prefix list -- prefix NULL
 *   c) that match given prefix, in given prefix_list
 */
static int
vty_clear_prefix_list (struct vty *vty, afi_t afi, const char *name,
                                                   const char *pfx_str)
{
  prefix_master pm;
  prefix_list   plist;
  int ret;
  prefix_t pfx[1] ;
  prefix_list_entry pe ;
  vector_index_t i ;

  pm = prefix_master_get (afi, false /* real qAFI_t only */);
  if (pm == NULL)
    return CMD_WARNING ;                /* impossible   */

  if (name == NULL)
    {
      vhash_walker_t walk[1] ;

      vhash_walk_start(pm->table, walk) ;
      while ((plist = vhash_walk_next(walk)) != NULL)
        {
          for (VECTOR_ITEMS(plist->index, pe, i))
            pe->hitcnt = 0 ;
        } ;
    }
  else
    {
      /* Error if cannot find prefix list.
       */
      plist = vty_prefix_list_lookup(vty, afi, name);
      if (plist == NULL)
        return CMD_WARNING;

      if (pfx_str != NULL)
        {
          ret = str2prefix (pfx_str, pfx);
          if (ret <= 0)
            {
              vty_out (vty, "%% prefix is malformed%s", VTY_NEWLINE);
              return CMD_WARNING;
            }
        }

      for (VECTOR_ITEMS(plist->index, pe, i))
        {
          if (pfx_str != NULL)
            {
              prefix_t pe_pfx[1];

              prefix_list_prefix_fill(pe_pfx, pe, plist->afi) ;

              if (!prefix_match(pe_pfx, pfx))
                continue ;
            } ;

          pe->hitcnt = 0;
        } ;
    } ;
  return CMD_SUCCESS;
}

/*==============================================================================
 * The CLI
 */
DEFUN (ip_prefix_list,
       ip_prefix_list_cmd,
       "ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], NULL,
                                  argv[1], argv[2], NULL, NULL);
}

DEFUN (ip_prefix_list_ge,
       ip_prefix_list_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], NULL, argv[1],
                                 argv[2], argv[3], NULL);
}

DEFUN (ip_prefix_list_ge_le,
       ip_prefix_list_ge_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], NULL, argv[1],
                                  argv[2], argv[3], argv[4]);
}

DEFUN (ip_prefix_list_le,
       ip_prefix_list_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], NULL, argv[1],
                                  argv[2], NULL, argv[3]);
}

DEFUN (ip_prefix_list_le_ge,
       ip_prefix_list_le_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], NULL, argv[1],
                                  argv[2], argv[4], argv[3]);
}

DEFUN (ip_prefix_list_seq,
       ip_prefix_list_seq_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                  argv[3], NULL, NULL);
}

DEFUN (ip_prefix_list_seq_ge,
       ip_prefix_list_seq_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                  argv[3], argv[4], NULL);
}

DEFUN (ip_prefix_list_seq_ge_le,
       ip_prefix_list_seq_ge_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                  argv[3], argv[4], argv[5]);
}

DEFUN (ip_prefix_list_seq_le,
       ip_prefix_list_seq_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                  argv[3], NULL, argv[4]);
}

DEFUN (ip_prefix_list_seq_le_ge,
       ip_prefix_list_seq_le_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                  argv[3], argv[5], argv[4]);
}

DEFUN (no_ip_prefix_list_all,
       no_ip_prefix_list_all_cmd,
       "no ip prefix-list WORD",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, NULL,
                                    NULL, NULL, NULL);
}

DEFUN (no_ip_prefix_list,
       no_ip_prefix_list_cmd,
       "no ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, argv[1],
                                    argv[2], NULL, NULL);
}

DEFUN (no_ip_prefix_list_ge,
       no_ip_prefix_list_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, argv[1],
                                    argv[2], argv[3], NULL);
}

DEFUN (no_ip_prefix_list_ge_le,
       no_ip_prefix_list_ge_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, argv[1],
                                    argv[2], argv[3], argv[4]);
}

DEFUN (no_ip_prefix_list_le,
       no_ip_prefix_list_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, argv[1],
                                    argv[2], NULL, argv[3]);
}

DEFUN (no_ip_prefix_list_le_ge,
       no_ip_prefix_list_le_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], NULL, argv[1],
                                    argv[2], argv[4], argv[3]);
}

DEFUN (no_ip_prefix_list_seq,
       no_ip_prefix_list_seq_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                    argv[3], NULL, NULL);
}

DEFUN (no_ip_prefix_list_seq_ge,
       no_ip_prefix_list_seq_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                    argv[3], argv[4], NULL);
}

DEFUN (no_ip_prefix_list_seq_ge_le,
       no_ip_prefix_list_seq_ge_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                    argv[3], argv[4], argv[5]);
}

DEFUN (no_ip_prefix_list_seq_le,
       no_ip_prefix_list_seq_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                    argv[3], NULL, argv[4]);
}

DEFUN (no_ip_prefix_list_seq_le_ge,
       no_ip_prefix_list_seq_le_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP, argv[0], argv[1], argv[2],
                                    argv[3], argv[5], argv[4]);
}

DEFUN (ip_prefix_list_sequence_number,
       ip_prefix_list_sequence_number_cmd,
       "ip prefix-list sequence-number",
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_masters[qAFI_IP].seqnum_flag = true ;
  return CMD_SUCCESS;
}

DEFUN (no_ip_prefix_list_sequence_number,
       no_ip_prefix_list_sequence_number_cmd,
       "no ip prefix-list sequence-number",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_masters[qAFI_IP].seqnum_flag = false ;
  return CMD_SUCCESS;
}

DEFUN (ip_prefix_list_description,
       ip_prefix_list_description_cmd,
       "ip prefix-list WORD description .LINE",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  return vty_prefix_list_desc_set (vty, qAFI_IP, argv[0],
                                                    argv_concat(argv, argc, 1));
} ;

DEFUN (no_ip_prefix_list_description,
       no_ip_prefix_list_description_cmd,
       "no ip prefix-list WORD description",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, qAFI_IP, argv[0]);
}

ALIAS (no_ip_prefix_list_description,
       no_ip_prefix_list_description_arg_cmd,
       "no ip prefix-list WORD description .LINE",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ip_prefix_list,
       show_ip_prefix_list_cmd,
       "show ip prefix-list",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, qAFI_IP, NULL, NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name,
       show_ip_prefix_list_name_cmd,
       "show ip prefix-list WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, argv[0], NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name_seq,
       show_ip_prefix_list_name_seq_cmd,
       "show ip prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, argv[0], argv[1],
                                                           sequential_display) ;
}

DEFUN (show_ip_prefix_list_prefix,
       show_ip_prefix_list_prefix_cmd,
       "show ip prefix-list WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP, argv[0], argv[1],
                                                               normal_display) ;
}

DEFUN (show_ip_prefix_list_prefix_longer,
       show_ip_prefix_list_prefix_longer_cmd,
       "show ip prefix-list WORD A.B.C.D/M longer",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, qAFI_IP, argv[0], argv[1],
                                                               longer_display) ;
}

DEFUN (show_ip_prefix_list_prefix_first_match,
       show_ip_prefix_list_prefix_first_match_cmd,
       "show ip prefix-list WORD A.B.C.D/M first-match",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, qAFI_IP, argv[0], argv[1],
                                                           first_match_display);
}

DEFUN (show_ip_prefix_list_summary,
       show_ip_prefix_list_summary_cmd,
       "show ip prefix-list summary",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, NULL, NULL, summary_display);
}

DEFUN (show_ip_prefix_list_summary_name,
       show_ip_prefix_list_summary_name_cmd,
       "show ip prefix-list summary WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, argv[0], NULL, summary_display);
}


DEFUN (show_ip_prefix_list_detail,
       show_ip_prefix_list_detail_cmd,
       "show ip prefix-list detail",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, NULL, NULL, detail_display);
}

DEFUN (show_ip_prefix_list_detail_name,
       show_ip_prefix_list_detail_name_cmd,
       "show ip prefix-list detail WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP, argv[0], NULL, detail_display);
}

DEFUN (clear_ip_prefix_list,
       clear_ip_prefix_list_cmd,
       "clear ip prefix-list",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, qAFI_IP, NULL, NULL);
}

DEFUN (clear_ip_prefix_list_name,
       clear_ip_prefix_list_name_cmd,
       "clear ip prefix-list WORD",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, qAFI_IP, argv[0], NULL);
}

DEFUN (clear_ip_prefix_list_name_prefix,
       clear_ip_prefix_list_name_prefix_cmd,
       "clear ip prefix-list WORD A.B.C.D/M",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_clear_prefix_list (vty, qAFI_IP, argv[0], argv[1]);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_prefix_list,
       ipv6_prefix_list_cmd,
       "ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], NULL,
                                  argv[1], argv[2], NULL, NULL);
}

DEFUN (ipv6_prefix_list_ge,
       ipv6_prefix_list_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                 argv[2], argv[3], NULL);
}

DEFUN (ipv6_prefix_list_ge_le,
       ipv6_prefix_list_ge_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                  argv[2], argv[3], argv[4]);
}

DEFUN (ipv6_prefix_list_le,
       ipv6_prefix_list_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                  argv[2], NULL, argv[3]);
}

DEFUN (ipv6_prefix_list_le_ge,
       ipv6_prefix_list_le_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                  argv[2], argv[4], argv[3]);
}

DEFUN (ipv6_prefix_list_seq,
       ipv6_prefix_list_seq_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                  argv[3], NULL, NULL);
}

DEFUN (ipv6_prefix_list_seq_ge,
       ipv6_prefix_list_seq_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                  argv[3], argv[4], NULL);
}

DEFUN (ipv6_prefix_list_seq_ge_le,
       ipv6_prefix_list_seq_ge_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                  argv[3], argv[4], argv[5]);
}

DEFUN (ipv6_prefix_list_seq_le,
       ipv6_prefix_list_seq_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                  argv[3], NULL, argv[4]);
}

DEFUN (ipv6_prefix_list_seq_le_ge,
       ipv6_prefix_list_seq_le_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                  argv[3], argv[5], argv[4]);
}

DEFUN (no_ipv6_prefix_list_all,
       no_ipv6_prefix_list_all_cmd,
       "no ipv6 prefix-list WORD",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, NULL,
                                    NULL, NULL, NULL);
}

DEFUN (no_ipv6_prefix_list,
       no_ipv6_prefix_list_cmd,
       "no ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                    argv[2], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_ge,
       no_ipv6_prefix_list_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                    argv[2], argv[3], NULL);
}

DEFUN (no_ipv6_prefix_list_ge_le,
       no_ipv6_prefix_list_ge_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                    argv[2], argv[3], argv[4]);
}

DEFUN (no_ipv6_prefix_list_le,
       no_ipv6_prefix_list_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                    argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_prefix_list_le_ge,
       no_ipv6_prefix_list_le_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], NULL, argv[1],
                                    argv[2], argv[4], argv[3]);
}

DEFUN (no_ipv6_prefix_list_seq,
       no_ipv6_prefix_list_seq_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                    argv[3], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge,
       no_ipv6_prefix_list_seq_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                    argv[3], argv[4], NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge_le,
       no_ipv6_prefix_list_seq_ge_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                    argv[3], argv[4], argv[5]);
}

DEFUN (no_ipv6_prefix_list_seq_le,
       no_ipv6_prefix_list_seq_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                    argv[3], NULL, argv[4]);
}

DEFUN (no_ipv6_prefix_list_seq_le_ge,
       no_ipv6_prefix_list_seq_le_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, qAFI_IP6, argv[0], argv[1], argv[2],
                                    argv[3], argv[5], argv[4]);
}

DEFUN (ipv6_prefix_list_sequence_number,
       ipv6_prefix_list_sequence_number_cmd,
       "ipv6 prefix-list sequence-number",
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_masters[qAFI_IP6].seqnum_flag = true ;
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_prefix_list_sequence_number,
       no_ipv6_prefix_list_sequence_number_cmd,
       "no ipv6 prefix-list sequence-number",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_masters[qAFI_IP6].seqnum_flag = false ;
  return CMD_SUCCESS;
}

DEFUN (ipv6_prefix_list_description,
       ipv6_prefix_list_description_cmd,
       "ipv6 prefix-list WORD description .LINE",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  return vty_prefix_list_desc_set (vty, qAFI_IP6, argv[0],
                                                    argv_concat(argv, argc, 1));
}

DEFUN (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_cmd,
       "no ipv6 prefix-list WORD description",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, qAFI_IP6, argv[0]);
}

ALIAS (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_arg_cmd,
       "no ipv6 prefix-list WORD description .LINE",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ipv6_prefix_list,
       show_ipv6_prefix_list_cmd,
       "show ipv6 prefix-list",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, qAFI_IP6, NULL, NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name,
       show_ipv6_prefix_list_name_cmd,
       "show ipv6 prefix-list WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, argv[0], NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name_seq,
       show_ipv6_prefix_list_name_seq_cmd,
       "show ipv6 prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, argv[0], argv[1],
                                                           sequential_display);
}

DEFUN (show_ipv6_prefix_list_prefix,
       show_ipv6_prefix_list_prefix_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_show_prefix_list_prefix (vty, qAFI_IP6, argv[0], argv[1], normal_display);
}

DEFUN (show_ipv6_prefix_list_prefix_longer,
       show_ipv6_prefix_list_prefix_longer_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M longer",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, qAFI_IP6, argv[0], argv[1], longer_display);
}

DEFUN (show_ipv6_prefix_list_prefix_first_match,
       show_ipv6_prefix_list_prefix_first_match_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M first-match",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, qAFI_IP6, argv[0], argv[1],
                                                          first_match_display);
}

DEFUN (show_ipv6_prefix_list_summary,
       show_ipv6_prefix_list_summary_cmd,
       "show ipv6 prefix-list summary",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, NULL, NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_summary_name,
       show_ipv6_prefix_list_summary_name_cmd,
       "show ipv6 prefix-list summary WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, argv[0], NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_detail,
       show_ipv6_prefix_list_detail_cmd,
       "show ipv6 prefix-list detail",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, NULL, NULL, detail_display);
}

DEFUN (show_ipv6_prefix_list_detail_name,
       show_ipv6_prefix_list_detail_name_cmd,
       "show ipv6 prefix-list detail WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, qAFI_IP6, argv[0], NULL, detail_display);
}

DEFUN (clear_ipv6_prefix_list,
       clear_ipv6_prefix_list_cmd,
       "clear ipv6 prefix-list",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, qAFI_IP6, NULL, NULL);
}

DEFUN (clear_ipv6_prefix_list_name,
       clear_ipv6_prefix_list_name_cmd,
       "clear ipv6 prefix-list WORD",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, qAFI_IP6, argv[0], NULL);
}

DEFUN (clear_ipv6_prefix_list_name_prefix,
       clear_ipv6_prefix_list_name_prefix_cmd,
       "clear ipv6 prefix-list WORD X:X::X:X/M",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_clear_prefix_list (vty, qAFI_IP6, argv[0], argv[1]);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Configuration output
 */

/*------------------------------------------------------------------------------
 * Configuration write function.
 */
static int
config_write_prefix_afi (afi_t afi, struct vty *vty)
{
  prefix_list        plist;
  prefix_list_entry  pe;
  prefix_master      pm;
  int write ;
  vector extract ;
  vector_index_t i, ipe ;

  write = 0;

  pm = prefix_master_get (afi, false /* real qAFI_t only */);
  if (pm == NULL)
    return write ;

  /* Setting for all prefix-list
   */
  if (! pm->seqnum_flag)
    vty_out (vty, "no %s prefix-list sequence-number\n"
                  "!\n", prefix_afi_name_str(afi)) ;

  /* Extract a vector of all prefix_lists, in name order.
   */
  extract = vhash_table_extract(pm->table, NULL, NULL, false,
                                                         prefix_list_sort_cmp) ;

  for (VECTOR_ITEMS(extract, plist, i))
    {
      if (prefix_list_is_set(plist))
        {
          vty_out_vtysh_config_group(vty, "prefix-list %s %s",
                                       afitoa_lc(plist->afi).str, plist->name) ;

          if (plist->desc)
            {
              vty_prefix_list_name_print(vty, plist, "") ;
              vty_out (vty, " description %s\n", plist->desc) ;
              write++ ;
            }

          for (VECTOR_ITEMS(plist->index, pe, ipe))
            {
              vty_prefix_list_name_print(vty, plist, " ") ;
              vty_prefix_list_value_print(vty, pe, plist->afi, pm->seqnum_flag,
                                                            false /* stats */) ;
              write++ ;
            }

          vty_out_vtysh_config_group_end(vty) ;
        }
      else
        {
          vty_out(vty, "!! ") ;
          vty_prefix_list_undefined_print(vty, afi, plist->name, VTY_NEWLINE) ;
          write++ ;
        } ;
    } ;

  vector_free(extract) ;        /* discard temporary vector */

  return write;
} ;

static int
config_write_prefix_ipv4 (struct vty *vty)
{
  return config_write_prefix_afi (AFI_IP, vty);
}

CMD_INSTALL_TABLE(static, plist_ipv4_cmd_table,
                                             RIPD | OSPFD | BGPD | ZEBRA) =
{
  { VIEW_NODE,       &show_ip_prefix_list_cmd                           },
  { VIEW_NODE,       &show_ip_prefix_list_name_cmd                      },
  { VIEW_NODE,       &show_ip_prefix_list_name_seq_cmd                  },
  { VIEW_NODE,       &show_ip_prefix_list_prefix_cmd                    },
  { VIEW_NODE,       &show_ip_prefix_list_prefix_longer_cmd             },
  { VIEW_NODE,       &show_ip_prefix_list_prefix_first_match_cmd        },
  { VIEW_NODE,       &show_ip_prefix_list_summary_cmd                   },
  { VIEW_NODE,       &show_ip_prefix_list_summary_name_cmd              },
  { VIEW_NODE,       &show_ip_prefix_list_detail_cmd                    },
  { VIEW_NODE,       &show_ip_prefix_list_detail_name_cmd               },

  { ENABLE_NODE,     &show_ip_prefix_list_cmd                           },
  { ENABLE_NODE,     &show_ip_prefix_list_name_cmd                      },
  { ENABLE_NODE,     &show_ip_prefix_list_name_seq_cmd                  },
  { ENABLE_NODE,     &show_ip_prefix_list_prefix_cmd                    },
  { ENABLE_NODE,     &show_ip_prefix_list_prefix_longer_cmd             },
  { ENABLE_NODE,     &show_ip_prefix_list_prefix_first_match_cmd        },
  { ENABLE_NODE,     &show_ip_prefix_list_summary_cmd                   },
  { ENABLE_NODE,     &show_ip_prefix_list_summary_name_cmd              },
  { ENABLE_NODE,     &show_ip_prefix_list_detail_cmd                    },
  { ENABLE_NODE,     &show_ip_prefix_list_detail_name_cmd               },
  { ENABLE_NODE,     &clear_ip_prefix_list_cmd                          },
  { ENABLE_NODE,     &clear_ip_prefix_list_name_cmd                     },
  { ENABLE_NODE,     &clear_ip_prefix_list_name_prefix_cmd              },

  { CONFIG_NODE,     &ip_prefix_list_cmd                                },
  { CONFIG_NODE,     &ip_prefix_list_ge_cmd                             },
  { CONFIG_NODE,     &ip_prefix_list_ge_le_cmd                          },
  { CONFIG_NODE,     &ip_prefix_list_le_cmd                             },
  { CONFIG_NODE,     &ip_prefix_list_le_ge_cmd                          },
  { CONFIG_NODE,     &ip_prefix_list_seq_cmd                            },
  { CONFIG_NODE,     &ip_prefix_list_seq_ge_cmd                         },
  { CONFIG_NODE,     &ip_prefix_list_seq_ge_le_cmd                      },
  { CONFIG_NODE,     &ip_prefix_list_seq_le_cmd                         },
  { CONFIG_NODE,     &ip_prefix_list_seq_le_ge_cmd                      },

  { CONFIG_NODE,     &no_ip_prefix_list_all_cmd                         },
  { CONFIG_NODE,     &no_ip_prefix_list_cmd                             },
  { CONFIG_NODE,     &no_ip_prefix_list_ge_cmd                          },
  { CONFIG_NODE,     &no_ip_prefix_list_ge_le_cmd                       },
  { CONFIG_NODE,     &no_ip_prefix_list_le_cmd                          },
  { CONFIG_NODE,     &no_ip_prefix_list_le_ge_cmd                       },
  { CONFIG_NODE,     &no_ip_prefix_list_seq_cmd                         },
  { CONFIG_NODE,     &no_ip_prefix_list_seq_ge_cmd                      },
  { CONFIG_NODE,     &no_ip_prefix_list_seq_ge_le_cmd                   },
  { CONFIG_NODE,     &no_ip_prefix_list_seq_le_cmd                      },
  { CONFIG_NODE,     &no_ip_prefix_list_seq_le_ge_cmd                   },

  { CONFIG_NODE,     &ip_prefix_list_description_cmd                    },
  { CONFIG_NODE,     &no_ip_prefix_list_description_cmd                 },
  { CONFIG_NODE,     &no_ip_prefix_list_description_arg_cmd             },
  { CONFIG_NODE,     &ip_prefix_list_sequence_number_cmd                },
  { CONFIG_NODE,     &no_ip_prefix_list_sequence_number_cmd             },

  CMD_INSTALL_END
} ;

#ifdef HAVE_IPV6

static int
config_write_prefix_ipv6 (struct vty *vty)
{
  return config_write_prefix_afi (AFI_IP6, vty);
}

CMD_INSTALL_TABLE(static, plist_ipv6_cmd_table,
                                            RIPNGD | OSPF6D | BGPD | ZEBRA) =
{
  { VIEW_NODE,       &show_ipv6_prefix_list_cmd                         },
  { VIEW_NODE,       &show_ipv6_prefix_list_name_cmd                    },
  { VIEW_NODE,       &show_ipv6_prefix_list_name_seq_cmd                },
  { VIEW_NODE,       &show_ipv6_prefix_list_prefix_cmd                  },
  { VIEW_NODE,       &show_ipv6_prefix_list_prefix_longer_cmd           },
  { VIEW_NODE,       &show_ipv6_prefix_list_prefix_first_match_cmd      },
  { VIEW_NODE,       &show_ipv6_prefix_list_summary_cmd                 },
  { VIEW_NODE,       &show_ipv6_prefix_list_summary_name_cmd            },
  { VIEW_NODE,       &show_ipv6_prefix_list_detail_cmd                  },
  { VIEW_NODE,       &show_ipv6_prefix_list_detail_name_cmd             },

  { ENABLE_NODE,     &show_ipv6_prefix_list_cmd                         },
  { ENABLE_NODE,     &show_ipv6_prefix_list_name_cmd                    },
  { ENABLE_NODE,     &show_ipv6_prefix_list_name_seq_cmd                },
  { ENABLE_NODE,     &show_ipv6_prefix_list_prefix_cmd                  },
  { ENABLE_NODE,     &show_ipv6_prefix_list_prefix_longer_cmd           },
  { ENABLE_NODE,     &show_ipv6_prefix_list_prefix_first_match_cmd      },
  { ENABLE_NODE,     &show_ipv6_prefix_list_summary_cmd                 },
  { ENABLE_NODE,     &show_ipv6_prefix_list_summary_name_cmd            },
  { ENABLE_NODE,     &show_ipv6_prefix_list_detail_cmd                  },
  { ENABLE_NODE,     &show_ipv6_prefix_list_detail_name_cmd             },
  { ENABLE_NODE,     &clear_ipv6_prefix_list_cmd                        },
  { ENABLE_NODE,     &clear_ipv6_prefix_list_name_cmd                   },
  { ENABLE_NODE,     &clear_ipv6_prefix_list_name_prefix_cmd            },

  { CONFIG_NODE,     &ipv6_prefix_list_cmd                              },
  { CONFIG_NODE,     &ipv6_prefix_list_ge_cmd                           },
  { CONFIG_NODE,     &ipv6_prefix_list_ge_le_cmd                        },
  { CONFIG_NODE,     &ipv6_prefix_list_le_cmd                           },
  { CONFIG_NODE,     &ipv6_prefix_list_le_ge_cmd                        },
  { CONFIG_NODE,     &ipv6_prefix_list_seq_cmd                          },
  { CONFIG_NODE,     &ipv6_prefix_list_seq_ge_cmd                       },
  { CONFIG_NODE,     &ipv6_prefix_list_seq_ge_le_cmd                    },
  { CONFIG_NODE,     &ipv6_prefix_list_seq_le_cmd                       },
  { CONFIG_NODE,     &ipv6_prefix_list_seq_le_ge_cmd                    },

  { CONFIG_NODE,     &no_ipv6_prefix_list_all_cmd                       },
  { CONFIG_NODE,     &no_ipv6_prefix_list_cmd                           },
  { CONFIG_NODE,     &no_ipv6_prefix_list_ge_cmd                        },
  { CONFIG_NODE,     &no_ipv6_prefix_list_ge_le_cmd                     },
  { CONFIG_NODE,     &no_ipv6_prefix_list_le_cmd                        },
  { CONFIG_NODE,     &no_ipv6_prefix_list_le_ge_cmd                     },
  { CONFIG_NODE,     &no_ipv6_prefix_list_seq_cmd                       },
  { CONFIG_NODE,     &no_ipv6_prefix_list_seq_ge_cmd                    },
  { CONFIG_NODE,     &no_ipv6_prefix_list_seq_ge_le_cmd                 },
  { CONFIG_NODE,     &no_ipv6_prefix_list_seq_le_cmd                    },
  { CONFIG_NODE,     &no_ipv6_prefix_list_seq_le_ge_cmd                 },

  { CONFIG_NODE,     &ipv6_prefix_list_description_cmd                  },
  { CONFIG_NODE,     &no_ipv6_prefix_list_description_cmd               },
  { CONFIG_NODE,     &no_ipv6_prefix_list_description_arg_cmd           },
  { CONFIG_NODE,     &ipv6_prefix_list_sequence_number_cmd              },
  { CONFIG_NODE,     &no_ipv6_prefix_list_sequence_number_cmd           },

  CMD_INSTALL_END
} ;

#endif /* HAVE_IPV6 */

extern void
prefix_list_cmd_init (void)
{
  cmd_install_node_config_write(PREFIX_NODE, config_write_prefix_ipv4);
  cmd_install_table(plist_ipv4_cmd_table) ;

#ifdef HAVE_IPV6
  cmd_install_node_config_write(PREFIX_IPV6_NODE, config_write_prefix_ipv6);
  cmd_install_table(plist_ipv6_cmd_table) ;
#endif /* HAVE_IPV6 */
}
