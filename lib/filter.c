/* Route filtering function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include "prefix.h"
#include "filter.h"
#include "memory.h"
#include "command.h"
#include "command_parse.h"
#include "sockunion.h"
#include "buffer.h"
#include "log.h"
#include "vhash.h"

/*------------------------------------------------------------------------------
 * Master structure of access_list.
 */
typedef struct access_master  access_master_t ;
typedef struct access_master* access_master ;

struct access_master
{
  vhash_table table ;           /* table of access_list by name.        */

  /* Hook function which is executed when new access_list is added.
   */
  void (*add_hook)(access_list);

  /* Hook function which is executed when access_list is deleted.
   */
  void (*delete_hook)(access_list);
};

/*------------------------------------------------------------------------------
 * Access list
 */
typedef struct access_list_entry  access_list_entry_t ;
typedef struct access_list_entry* access_list_entry ;

typedef const struct access_list* access_list_c ;

enum filter_form
{
  form_unknown    = 0,
  form_zebra,
  form_cisco_standard,
  form_cisco_extended,
} ;
typedef enum filter_form filter_form_t ;

struct access_list
{
  /* Lives in a vhash by name, and we have a pointer to the vhash_table.
   */
  vhash_node_t  vhash ;
  vhash_table   table ;         /* has a reference to the table */

  /* Context for the access-list
   */
  access_master master ;        /* scope for the access-list    */

  /* Value of the access-list
   */
  char*  name ;
  char*  remark ;

  filter_form_t form ;

  struct dl_base_pair(access_list_entry) base ;
};

CONFIRM(offsetof(access_list_t, vhash) == 0) ;  /* see vhash.h  */

/*------------------------------------------------------------------------------
 * The access-list entries
 */
typedef struct filter_cisco  filter_cisco_t ;
typedef struct filter_cisco* filter_cisco ;

struct filter_pair
{
  in_addr_t addr ;              /* masked down  */
  in_addr_t wild ;
  in_addr_t mask ;              /* = ~wild      */
} ;

struct filter_cisco
{
  struct filter_pair addr ;
  struct filter_pair mask;
};

typedef struct filter_zebra  filter_zebra_t ;
typedef struct filter_zebra* filter_zebra ;

struct filter_zebra
{
  int exact;

  struct prefix prefix;
};

/* Access list entry
 */
struct access_list_entry
{
  struct dl_list_pair(access_list_entry) list ;

  enum filter_type type;        /* DENY, PERMIT etc.            */

  union
    {
      filter_cisco_t cisco ;
      filter_zebra_t zebra ;
    } filter ;
};

/*------------------------------------------------------------------------------
 * Static declarations of the access_masters
 */
static access_master_t access_masters[qAFI_count] ;

inline static access_master
access_master_get(qAFI_t afi)
{
  switch (afi)
    {
      case qAFI_IP:
#ifdef HAVE_IPV6
      case qAFI_IP6:
#endif
        return &access_masters[afi] ;

      default:
        return NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return string for filter_type.
 */
static const char *
access_list_entry_type_str(enum filter_type type)
{
  switch (type)
    {
    case FILTER_PERMIT:
      return "permit";
      break;
    case FILTER_DENY:
      return "deny";
      break;
    case FILTER_DYNAMIC:
      return "dynamic";
      break;
    default:
      return "??BUG??";
      break;
    }
} ;

/*------------------------------------------------------------------------------
 * Return string for afi type.
 */
static const char *
access_list_afi_str(qAFI_t afi)
{
  switch (afi)
    {
    case qAFI_IP:
      return "ip";
      break;

#ifdef HAVE_IPV6
    case qAFI_IP6:
      return "ipv6";
      break;
#endif

    default:
      return "??BUG??";
      break;
    }
} ;

/*==============================================================================
 * Access-List master operations and vhash stuff.
 */
static vhash_equal_func  access_list_vhash_equal ;
static vhash_new_func    access_list_vhash_new ;
static vhash_free_func   access_list_vhash_free ;
static vhash_orphan_func access_list_vhash_orphan ;

static const vhash_params_t access_list_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = access_list_vhash_equal,
  .new    = access_list_vhash_new,
  .free   = access_list_vhash_free,
  .orphan = access_list_vhash_orphan,
} ;

static void access_list_flush(access_list alist) ;

/*------------------------------------------------------------------------------
 * Initialise all the masters and set-up the ones we use.
 */
extern void
access_list_init (void)
{
  qAFI_t afi ;

  memset(access_masters, 0, sizeof(access_masters)) ;

  for (afi = qAFI_first ; afi <= qAFI_last ; ++afi)
    {
      access_master am ;

      am = access_master_get(afi) ;

      if (am != NULL)
        {
          am->table = vhash_table_new(am, 50, 200, &access_list_vhash_params) ;
          vhash_table_set_parent(am->table, am) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Shut down all the masters we use.
 */
extern void
access_list_reset(free_keep_b free)
{
  qAFI_t afi ;

  for (afi = qAFI_first ; afi <= qAFI_last ; ++afi)
    {
      access_master am ;

      am = access_master_get(afi) ;

      if (am != NULL)
        {
          vhash_table_reset(am->table, free) ;

          if (free)
            am->table = NULL ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * The add_hook and delete_hook functions.
 *
 * These are used:
 *
 *   a. to keep references to access-lists up to date -- so when an access-list
 *      comes in to being, a name reference can now refer to the actual list;
 *      and when an access-list is destroyed, any pointer to it can be
 *      discarded.
 *
 *      The access_list_set_ref() etc mechanism replaces this.
 *
 *   b. to flag when an access-list has changed, so that any implications of
 *      that change can be worked through.
 *
 *      This could be improved... TBA TODO
 */

/* Set add hook function.
 *
 * This function is called every time an access-list entry is inserted.
 */
extern void
access_list_add_hook (void (*func)(access_list))
{
  qAFI_t afi ;

  for (afi = qAFI_first ; afi <= qAFI_last ; ++afi)
    {
      access_master am ;

      am = access_master_get(afi) ;

      if (am != NULL)
        am->add_hook = func ;
    } ;
}

/* Set delete hook function.
 *
 * This function is called every time an access-list entry is deleted.
 */
extern void
access_list_delete_hook (void (*func) (struct access_list *access))
{
  qAFI_t afi ;

  for (afi = qAFI_first ; afi <= qAFI_last ; ++afi)
    {
      access_master am ;

      am = access_master_get(afi) ;

      if (am != NULL)
        am->delete_hook = func ;
    } ;
} ;

/*==============================================================================
 * Basic constructors and destructors for access_list.
 */
static void access_list_entry_free (access_list_entry ae) ;

/*------------------------------------------------------------------------------
 * Allocate new access_list structure.
 */
static vhash_item
access_list_vhash_new(vhash_table table, vhash_data_c data)
{
  access_list  new ;
  const char*  name = data ;

  new = XCALLOC (MTYPE_ACCESS_LIST, sizeof(access_list_t)) ;

  /* Zeroizing has set:
   *
   *   * vhash                -- all zero   -- not that this matters
   *   * table                -- X          -- set below
   *   * master               -- X          -- set below
   *
   *   * name                 -- X          -- set below
   *   * remark               -- NULL       -- none
   *
   *   * form                 -- form_unknown -- must be set when an entry is
   *                                             added
   *
   *   * base                  -- NULLs     -- empty list
   */
  confirm(form_unknown == 0) ;

  new->table  = vhash_table_inc_ref(table) ;
  new->master = table->parent ;
  new->name   = XSTRDUP(MTYPE_ACCESS_LIST_STR, name) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Comparison -- vhash_cmp_func
 */
static int
access_list_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  access_list_c alist = item ;
  const char*   name  = data ;

  return strcmp(alist->name, name) ;
} ;

/*------------------------------------------------------------------------------
 * Free allocated access_list.
 */
static vhash_item
access_list_vhash_free (vhash_item item, vhash_table table)
{
  access_list alist = item ;

  access_list_flush(alist) ;            /* make sure            */
  vhash_table_dec_ref(alist->table) ;

  XFREE(MTYPE_ACCESS_LIST_STR, alist->name) ;
  XFREE(MTYPE_ACCESS_LIST, alist);

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Orphan access-list -- vhash_orphan_func
 *
 * Makes sure that the access-list is empty and unset.
 */
static vhash_item
access_list_vhash_orphan(vhash_item item, vhash_table table)
{
  access_list alist = item ;

  access_list_flush(alist) ;

  return vhash_unset(alist, alist->table) ;
} ;

/*------------------------------------------------------------------------------
 * Is the access-list empty ?
 *
 * Is empty if there are no entries ADN there is no remark set
 */
static bool
access_list_is_empty (access_list alist)
{
  return (ddl_head(alist->base) == NULL) && (alist->remark == NULL) ;
}

/*==============================================================================
 * Operations on access_lists
 */

/*------------------------------------------------------------------------------
 * Lookup access-list by afi and name -- do not create.
 *
 * Returns:  address of access-list
 *           NULL <=> not found OR is not "set"
 *
 * NB: returns NULL if the access-list exists but is empty (no description and
 *     no access_list entries <=> not "set").
 */
extern access_list
access_list_lookup (qAFI_t afi, const char *name)
{
  access_master am ;
  access_list   alist ;

  if (name == NULL)
    return NULL;

  am = access_master_get (afi);
  if (am == NULL)
    return NULL;

  alist = vhash_lookup(am->table, name, NULL /* don't add */) ;

  if (alist == NULL)
    return NULL ;

  qassert(vhash_is_set(alist) == !access_list_is_empty(alist)) ;

  return vhash_is_set(alist) ? alist : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Find access-list by afi and name  -- create (if afi valid and name not NULL).
 *
 * Returns:  address of access-list -- may be new, empty access-list
 *           but NULL if afi invalid or name NULL.
 *
 * NB: returns with alist->form == form_unknown, which must be fixed when the
 *     first entry is added.
 *
 *     The form of entries is the same for all entries in a given access-list.
 *     We treat this as if it is decided when the first entry is added.
 */
extern access_list
access_list_find (qAFI_t afi, const char *name)
{
  access_master am ;
  access_list alist ;
  bool added ;

  if (name == NULL)
    return NULL;

  am = access_master_get (afi);
  if (am == NULL)
    return NULL;

  alist = vhash_lookup(am->table, name, &added) ;  /* creates if required */

  if (qdebug)
    {
      if (added)
        qassert(ddl_head(alist->base) == NULL) ;

      if (ddl_head(alist->base) == NULL)
        qassert(alist->form == form_unknown) ;
      else
        qassert(alist->form != form_unknown) ;
    } ;

  return alist ;
} ;

/*------------------------------------------------------------------------------
 * Get a reference to the access list for the given q_AFI_t of the given name.
 *
 * In any case, this returns the address of the access list, set or not,
 * with the reference count incremented.
 *
 * NB: rejects the AFI_ORF_PREFIX "extension".
 *
 * Returns:  address of access-list (NULL if afi unknown or name NULL)
 */
extern access_list
access_list_get_ref(qAFI_t q_afi, const char *name)
{
  return access_list_set_ref(access_list_find(q_afi, name)) ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given access list (if any).
 *
 * If access-list is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  access-list as given
 */
extern access_list
access_list_set_ref(access_list alist)
{
  if (alist != NULL)
    return vhash_inc_ref(alist) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given access list (if any).
 *
 * If access-list is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  NULL
 */
extern access_list
access_list_clear_ref(access_list alist)
{
  if (alist != NULL)
    vhash_dec_ref(alist, alist->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return name of alist -- will be NULL if alist is NULL
 */
extern const char*
access_list_get_name(access_list alist)
{
  return (alist != NULL) ? alist->name : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return whether access_list is "set" -- that is, some value has been set.
 *
 * Will not be "set" if is NULL.
 *
 * For access-list, the value may be just the remark.
 */
extern bool
access_list_is_set(access_list alist)
{
  qassert(vhash_is_set(alist) == !access_list_is_empty(alist)) ;

  return vhash_is_set(alist) ;
} ;

/*------------------------------------------------------------------------------
 * Return whether access_list is "active".
 *
 * Will not be "active" if is NULL.
 *
 * Will be "active" iff there is at least one entry in the access-list.
 */
extern bool
access_list_is_active(access_list alist)
{
  return (alist != NULL) ? ddl_head(alist->base) != NULL
                         : false ;
} ;

/*------------------------------------------------------------------------------
 * Delete access_list.
 *
 * If the access-list has any remaining entries or any remaining remark,
 * discard them.  Clear the "set" state.
 *
 * Invoke the delete_hook() if any.
 *
 * If there are no references, delete the access-list.  Otherwise, leave it to
 * be deleted when the reference count falls to zero, or leave it to have a
 * value redefined at some future date.
 */
static void
access_list_delete (access_list alist)
{
  vhash_inc_ref(alist) ;        /* want to hold onto the alist pro tem. */

  access_list_flush(alist) ;    /* hammer the value and clear "set"     */

  /* access-list no longer has a value
   *
   * If we need to tell the world, we pass the (now empty) alist to the
   * call-back.
   */
  if (alist->master->delete_hook != NULL)
    alist->master->delete_hook(alist);

  /* Now, if there are no references to the access-list, it is time for it
   * to go.
   */
   vhash_dec_ref(alist, alist->table) ;         /* now may disappear    */
} ;

/*------------------------------------------------------------------------------
 * Flush all contents of access_list, leaving it completely empty.
 *
 * Retains all the red-tape.  Releases the access-list entries and remark
 *
 * NB: does not touch the reference count BUT clears the "set" state WITHOUT
 *     freeing the access-list.
 */
static void
access_list_flush(access_list alist)
{
  while (1)
    {
      access_list_entry ae ;

      ae = ddl_pop(&ae, alist->base, list) ;

      if (ae == NULL)
        break ;

      access_list_entry_free(ae) ;
    } ;

  alist->form = form_unknown ;

  if (alist->remark)
    XFREE (MTYPE_ACCESS_LIST_STR, alist->remark) ; /* sets alist->remark NULL */

  /* Clear the "set" state -- but do NOT delete, even if reference count == 0
   */
  vhash_clear_set(alist) ;
} ;

/*==============================================================================
 * Access List Use.
 */
inline static bool filter_match_cisco_standard(filter_cisco filter,
                                                                 prefix_c pfx) ;
inline static bool filter_match_cisco_extended(filter_cisco filter,
                                                                 prefix_c pfx) ;
inline static bool filter_match_zebra (filter_zebra filter, prefix_c pfx) ;

/*------------------------------------------------------------------------------
 * Apply access list (if any) to object (which should be struct prefix *).
 */
extern enum filter_type
access_list_apply (access_list alist, const void* object)
{
  access_list_entry ae ;
  prefix_c  pfx ;

  pfx = (prefix_c) object;

  ae = (alist != NULL) ? ddl_head(alist->base) : NULL ;
  while (ae != NULL)
    {
      switch (alist->form)
        {
          case form_zebra:
            if (filter_match_zebra (&ae->filter.zebra, pfx))
              return ae->type ;
            break ;

          case form_cisco_standard:
            if (filter_match_cisco_standard(&ae->filter.cisco, pfx))
              return ae->type ;
            break ;

          case form_cisco_extended:
            if (filter_match_cisco_extended(&ae->filter.cisco, pfx))
              return ae->type ;
            break ;

          default:
            qassert(false) ;
            return FILTER_DENY ;
        } ;

      ae = ddl_next(ae, list) ;
    } ;

  return FILTER_DENY;
}

/*------------------------------------------------------------------------------
 * Do we have a filter match for a Zebra style filter ?
 *
 * Returns:  true <=> match
 */
inline static bool
filter_match_zebra (filter_zebra filter, prefix_c pfx)
{
  if (filter->prefix.family == pfx->family)
    {
      if (!(filter->exact) || (filter->prefix.prefixlen == pfx->prefixlen))
        return prefix_match (&filter->prefix, pfx);
    } ;

  return false ;
}

/*------------------------------------------------------------------------------
 * Do we have a filter match for a Cisco style "standard" filter ?
 *
 * Returns:  true <=> match
 */
inline static bool
filter_match_cisco_standard(filter_cisco filter, prefix_c pfx)
{
  return (pfx->u.prefix4.s_addr & filter->addr.mask) == filter->addr.addr ;
} ;

/*------------------------------------------------------------------------------
 * Do we have a filter match for a Cisco style "extended" filter ?
 *
 * Returns:  true <=> match
 */
inline static bool
filter_match_cisco_extended(filter_cisco filter, prefix_c pfx)
{
  struct in_addr mask;

  if (!filter_match_cisco_standard(filter, pfx))
    return false ;

  masklen2ip (pfx->prefixlen, &mask);
  return (mask.s_addr & filter->mask.mask) == filter->mask.addr ;
} ;

/*==============================================================================
 * Access-List Entry operations.
 */
static cmd_ret_t vty_access_list_not_found(struct vty *vty, qAFI_t afi,
                                                             const char *name) ;
static cmd_ret_t filter_set_prepare(struct vty *vty, access_list_entry temp,
                                                         const char *type_str) ;
static access_list_entry filter_lookup (access_list alist,
                                                       access_list_entry seek) ;
static cmd_ret_t filter_set_cisco_part(struct vty *vty,
         struct filter_pair* pair, const char *addr_str, const char *mask_str) ;
static cmd_ret_t filter_set_entry (struct vty *vty, afi_t afi, const char* name,
                     add_b adding, filter_form_t form, access_list_entry temp) ;

/*------------------------------------------------------------------------------
 * Allocate new access_list_entry structure.
 */
static access_list_entry
access_list_entry_new (void)
{
  return XCALLOC (MTYPE_ACCESS_ENTRY, sizeof(access_list_entry_t));
}

/*------------------------------------------------------------------------------
 * Free access_list_entry structure.
 */
static void
access_list_entry_free (access_list_entry ae)
{
  XFREE (MTYPE_ACCESS_ENTRY, ae);
}

/*------------------------------------------------------------------------------
 * Create new entry with the given value, and append to the given access-list
 *                                                          -- invoke add_hook()
 *
 * If the access-list is empty, set the form of access_list_entries.
 *
 * If the access-list is not empty, it must already be set to the given form,
 * but we set it anyway.
 */
static void
access_list_filter_add (access_list alist, access_list_entry temp,
                                                             filter_form_t form)
{
  access_list_entry ae ;

  if (qdebug)
    {
      if (ddl_head(alist->base) == NULL)
        qassert(alist->form == form_unknown) ;
      else
        qassert(alist->form == form) ;
    } ;

  alist->form = form ;

  ae = access_list_entry_new() ;
  *ae = *temp ;

  ddl_append(alist->base, ae, list) ;

  vhash_set(alist) ;

  if (alist->master->add_hook != NULL)
    (*alist->master->add_hook)(alist) ;
} ;

/*------------------------------------------------------------------------------
 * Delete given entry from the given access-list -- invoke delete_hook()
 *
 * If there are no entries left, set form_unknown.
 *
 * If the access-list becomes empty, then delete it.
 */
static void
access_list_filter_delete (access_list alist, access_list_entry ae)
{
  /* Hack the entry off the list and free it.
   */
  ddl_del(alist->base, ae, list) ;
  access_list_entry_free (ae);

  /* If there are now no entries, set form to unknown
   */
  if (!access_list_is_active(alist))
    alist->form = form_unknown ;

  /* If access_list becomes empty delete it -- by empty, we mean no entries
   * and no remark.
   *
   * Otherwise, run the delete hook.
   */
  if (access_list_is_empty(alist))
    access_list_delete (alist);
  else if (alist->master->delete_hook != NULL)
    alist->master->delete_hook(alist);
} ;

/*------------------------------------------------------------------------------
 * Delete entire access-list
 */
static cmd_ret_t
vty_no_access_list_all(struct vty *vty, qAFI_t afi, const char* name)
{
  access_list alist ;

  alist = access_list_lookup (afi, name);
  if (alist == NULL)
    return vty_access_list_not_found(vty, afi, name) ;

  access_list_delete (alist);

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Set access-list remark
 */
static cmd_ret_t
vty_access_list_remark_set (struct vty *vty, qAFI_t afi, const char* name,
                                                               char* remark)
{
  access_list alist;

  alist = access_list_find(afi, name) ;

  if (alist->remark != NULL)
    XFREE (MTYPE_ACCESS_LIST_STR, alist->remark) ;

  alist->remark = XSTRDUP(MTYPE_ACCESS_LIST_STR, remark) ;
  vhash_set(alist) ;                    /* Has description => is "set"  */

  XFREE(MTYPE_TMP, remark) ;
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Clear access-list remark
 */
static cmd_ret_t
vty_access_list_remark_unset (struct vty *vty, qAFI_t afi, const char *name)
{
  access_list alist;

  alist = access_list_lookup (afi, name);
  if (alist == NULL)
    return vty_access_list_not_found(vty, afi, name) ;

  if (alist->remark != NULL)
    XFREE (MTYPE_ACCESS_LIST_STR, alist->remark) ; /* sets alist->remark NULL */

  if (access_list_is_empty(alist))
    access_list_delete(alist) ;         /* delete list if all gone now  */

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Show that access list is not there, and return CMD_WARNING.
 */
static cmd_ret_t
vty_access_list_not_found(struct vty *vty, qAFI_t afi, const char *name)
{
  vty_out(vty, "%% %s access list %s not found", access_list_afi_str(afi),
                                                                         name) ;
  return CMD_WARNING;
} ;

/*------------------------------------------------------------------------------
 * Add/Delete Zebra form entry to/from access-list
 *
 * If adding:
 *
 *   * create new access-list if required.
 *
 *   * if entry already exists, quietly leave it where it was in the list
 *
 *   * otherwise, append new entry
 *
 * If deleting:
 *
 *   * complain if access-list does not exist
 *
 *   * if entry exists, remove it
 *
 *   * otherwise, quietly ignore redundant deletion
 */
static cmd_ret_t
filter_set_zebra (struct vty *vty, qAFI_t afi, const char *name,
         add_b adding, const char *type_str, const char *prefix_str, bool exact)
{
  cmd_ret_t ret;
  prefix      p ;
  access_list_entry_t temp[1] ;

  if (all_digit(name))
    {
      vty_out (vty, "%% Zebra form access-list name cannot be all digits\n");
      return CMD_WARNING;
    } ;

  /* Initialise temporary access_list_entry, set permit/deny and exact-ness
   */
  ret = filter_set_prepare(vty, temp, type_str) ;
  if (ret != CMD_SUCCESS)
    return ret ;

  temp->filter.zebra.exact = exact ;

  /* Check string format of prefix and prefixlen and set same
   */
  p = &temp->filter.zebra.prefix ;

  switch (afi)
    {
      case qAFI_IP:
        if(str2prefix_ipv4 (prefix_str, (prefix_ipv4)p) <= 0)
          {
            vty_out (vty, "IP address prefix/prefixlen is malformed\n") ;
            return CMD_WARNING;
          }
        break ;

#ifdef HAVE_IPV6
      case qAFI_IP6:
        if (str2prefix_ipv6 (prefix_str, (prefix_ipv6)p) <= 0)
          {
            vty_out (vty, "IPv6 address prefix/prefixlen is malformed\n") ;
            return CMD_WARNING ;
          } ;
        break ;
#endif /* HAVE_IPV6 */

      default:                  /* impossible ! */
        return CMD_WARNING ;
    } ;

  /* Now Add/Delete entry given by temp
   */
  return filter_set_entry(vty, afi, name, adding, form_zebra, temp) ;
} ;

/*------------------------------------------------------------------------------
 * Add/Delete Cisco form entry to/from access-list
 *
 * If adding:
 *
 *   * create new access-list if required.
 *
 *   * if entry already exists, quietly leave it where it was in the list
 *
 *   * otherwise, append new entry
 *
 * If deleting:
 *
 *   * complain if access-list does not exist
 *
 *   * if entry exists, remove it
 *
 *   * otherwise, quietly ignore redundant deletion
 */
static cmd_ret_t
filter_set_cisco (struct vty *vty, const char *name, add_b adding,
                      const char* type_str,
                        const char* addr_addr_str, const char* addr_mask_str,
                        bool extended,
                        const char* mask_addr_str, const char* mask_mask_str)
{
  cmd_ret_t ret;
  filter_cisco  f ;
  access_list_entry_t temp[1] ;

  /* Initialise temporary access_list_entry, set permit/deny an exact-ness
   */
  ret = filter_set_prepare(vty, temp, type_str) ;
  if (ret != CMD_SUCCESS)
    return ret ;

  /* Set up the various addresses and masks.
   *
   * NB: does NOT cross check the addr and the mask parts of an "extended"
   *     Cisco form.
   */
  f = &temp->filter.cisco ;

  ret = filter_set_cisco_part(vty, &f->addr, addr_addr_str, addr_mask_str) ;

  if ((ret == CMD_SUCCESS) && extended)
    ret = filter_set_cisco_part(vty, &f->mask, mask_addr_str, mask_mask_str) ;

  if (ret != CMD_SUCCESS)
    return ret ;

  /* Now Add/Delete entry given by temp
   */
  return filter_set_entry(vty, qAFI_IP, name, adding,
                   extended ? form_cisco_extended : form_cisco_standard, temp) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise given access_list_entry and set permit/deny as required.
 */
static cmd_ret_t
filter_set_prepare(struct vty *vty, access_list_entry temp,
                                                           const char *type_str)
{
  memset(temp, 0, sizeof(access_list_entry_t)) ;

  switch (type_str[0])
    {
      case 'p':
        temp->type = FILTER_PERMIT;
        break ;

      case 'd':
        temp->type = FILTER_DENY;
        break ;

      default:
        vty_out (vty, "filter type must be [permit|deny]\n") ;
        return CMD_WARNING;
    } ;

  return CMD_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Look for an access-list entry which is the same as the given entry
 */
static access_list_entry
filter_lookup(access_list alist, access_list_entry seek)
{
  access_list_entry ae ;

  for (ae = ddl_head(alist->base) ; ae != NULL ; ae = ddl_next(ae, list))
    {
      if (ae->type != seek->type)
        continue ;

      switch (alist->form)
        {
          case form_zebra:
            if (ae->filter.zebra.exact != seek->filter.zebra.exact)
              continue ;

            if (!prefix_same (&ae->filter.zebra.prefix,
                              &seek->filter.zebra.prefix))
              continue ;

            break ;

          case form_cisco_extended:
            if (ae->filter.cisco.mask.addr != seek->filter.cisco.mask.addr)
              continue ;

            if (ae->filter.cisco.mask.wild != seek->filter.cisco.mask.wild)
              continue ;

            fall_through ;

          case form_cisco_standard:
            if (ae->filter.cisco.addr.addr != seek->filter.cisco.addr.addr)
              continue ;

            if (ae->filter.cisco.addr.wild != seek->filter.cisco.addr.wild)
              continue ;

            break ;

          default:
            return NULL ;
        } ;

      return ae ;
    } ;

  return NULL;
} ;

/*------------------------------------------------------------------------------
 * Set given address/wild pair
 *
 * The wild is, in fact, a wild-card.
 *
 * Checks that the wildcard is valid for the address part.
 *
 * NB: Cisco do NOT require the wild-card to be contiguous 1's !!
 *
 * NB: we reject addr-part that has any bits in common with the wildcard.
 *
 *     This means that does not have to mask the address part when checking.
 *
 *     Also means that does NOT think that: 10.1.2.3  0.0.0.255
 *                          is the same as: 10.1.2.0  0.0.0.255
 */
static cmd_ret_t
filter_set_cisco_part(struct vty *vty, struct filter_pair* pair,
                                    const char *addr_str, const char *mask_str)
{
  int ret ;

  ret = inet_pton(AF_INET, addr_str, &pair->addr) ;
  if (ret <= 0)
    {
      vty_out(vty, "%% malformed address '%s'\n", addr_str) ;
      return CMD_WARNING ;
    } ;

  ret = inet_pton(AF_INET, mask_str, &pair->wild) ;
  if (ret <= 0)
    {
      vty_out(vty, "%% malformed wild-card '%s'\n", mask_str) ;
      return CMD_WARNING ;
    } ;

  if ((pair->addr & pair->wild) != 0)
    {
      vty_out(vty, "%% address '%s' and wild-card '%s' overlap\n",
                                                           addr_str, mask_str) ;
      return CMD_WARNING ;
    } ;

  pair->mask = ~pair->wild ;

  return CMD_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Add/Delete given entry of given form to/from access-list
 *
 * If adding:
 *
 *   * create new access-list if required.
 *
 *   * if entry already exists, quietly leave it where it was in the list
 *
 *   * otherwise, append new entry
 *
 * If deleting:
 *
 *   * complain if access-list does not exist
 *
 *   * if entry exists, remove it
 *
 *   * otherwise, quietly ignore redundant deletion
 */
static cmd_ret_t
filter_set_entry (struct vty *vty, afi_t afi, const char* name, add_b adding,
                                     filter_form_t form, access_list_entry temp)
{
  access_list alist;

  if (adding)
    {
      alist = access_list_find(afi, name);

      if (filter_lookup (alist, temp) == NULL)
        access_list_filter_add (alist, temp, form);
    }
  else
    {
      access_list_entry ae ;

      alist = access_list_lookup(afi, name);

      if (alist == NULL)
        return vty_access_list_not_found(vty, afi, name) ;

      ae = filter_lookup (alist, temp) ;
      if (ae != NULL)
        access_list_filter_delete (alist, ae);
    } ;

  return CMD_SUCCESS;
} ;

/*==============================================================================
 * CLI -- setting access-list
 */

/*------------------------------------------------------------------------------
 * Cisco "standard" form access-list
 */
DEFUN (access_list_standard,
       access_list_standard_cmd,
       "access-list (<1-99>|<1300-1999>) (deny|permit) A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n"
       "Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], argv[3],
                                             false /* standard */, NULL, NULL) ;
} ;

DEFUN (access_list_standard_nomask,
       access_list_standard_nomask_cmd,
       "access-list (<1-99>|<1300-1999>) (deny|permit) A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
}

DEFUN (access_list_standard_host,
       access_list_standard_host_cmd,
       "access-list (<1-99>|<1300-1999>) (deny|permit) host A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A single host address\n"
       "Address to match\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
} ;

DEFUN (access_list_standard_any,
       access_list_standard_any_cmd,
       "access-list (<1-99>|<1300-1999>) (deny|permit) any",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any source host\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], "255.255.255.255",
                                                                      "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
}

DEFUN (no_access_list_standard,
       no_access_list_standard_cmd,
       "no access-list (<1-99>|<1300-1999>) (deny|permit) A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n"
       "Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], argv[3],
                                             false /* standard */, NULL, NULL) ;
}

DEFUN (no_access_list_standard_nomask,
       no_access_list_standard_nomask_cmd,
       "no access-list (<1-99>|<1300-1999>) (deny|permit) A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
}

DEFUN (no_access_list_standard_host,
       no_access_list_standard_host_cmd,
       "no access-list (<1-99>|<1300-1999>) (deny|permit) host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A single host address\n"
       "Address to match\n")
{
 return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
}

DEFUN (no_access_list_standard_any,
       no_access_list_standard_any_cmd,
       "no access-list (<1-99>|<1300-1999>) (deny|permit) any",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any source host\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], "255.255.255.255",
                                                                      "0.0.0.0",
                                             false /* standard */, NULL, NULL) ;
}

/*------------------------------------------------------------------------------
 * Cisco "extended" form access-list
 */
DEFUN (access_list_extended,
       access_list_extended_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                           "ip A.B.C.D A.B.C.D A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], argv[3],
                                  true /* extended */, argv[4], argv[5]) ;
}

DEFUN (access_list_extended_mask_any,
       access_list_extended_mask_any_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                       "ip A.B.C.D A.B.C.D any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], argv[3],
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

DEFUN (access_list_extended_any_mask,
       access_list_extended_any_mask_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                       "ip any A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, argv[2], argv[3]) ;
}

DEFUN (access_list_extended_any_any,
       access_list_extended_any_any_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) ip any any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

DEFUN (access_list_extended_mask_host,
       access_list_extended_mask_host_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                              "ip A.B.C.D A.B.C.D host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], argv[3],
                                  true /* extended */, argv[4], "0.0.0.0") ;
}

DEFUN (access_list_extended_host_mask,
       access_list_extended_host_mask_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                              "ip host A.B.C.D A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, argv[3], argv[4]) ;
}

DEFUN (access_list_extended_host_host,
       access_list_extended_host_host_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                 "ip host A.B.C.D host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, argv[3], "0.0.0.0") ;
}

DEFUN (access_list_extended_any_host,
       access_list_extended_any_host_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) ip any host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, argv[2], "0.0.0.0") ;
}

DEFUN (access_list_extended_host_any,
       access_list_extended_host_any_cmd,
       "access-list (<100-199>|<2000-2699>) (deny|permit) ip host A.B.C.D any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], add, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

DEFUN (no_access_list_extended,
       no_access_list_extended_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                           "ip A.B.C.D A.B.C.D A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], argv[3],
                                  true /* extended */, argv[4], argv[5]) ;
}

DEFUN (no_access_list_extended_mask_any,
       no_access_list_extended_mask_any_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                       "ip A.B.C.D A.B.C.D any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], argv[3],
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

DEFUN (no_access_list_extended_any_mask,
       no_access_list_extended_any_mask_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                       "ip any A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, argv[2], argv[3]) ;
}

DEFUN (no_access_list_extended_any_any,
       no_access_list_extended_any_any_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) ip any any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

DEFUN (no_access_list_extended_mask_host,
       no_access_list_extended_mask_host_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                              "ip A.B.C.D A.B.C.D host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], argv[3],
                                  true /* extended */, argv[4], "0.0.0.0") ;
}

DEFUN (no_access_list_extended_host_mask,
       no_access_list_extended_host_mask_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                              "ip host A.B.C.D A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, argv[3], argv[4]) ;
}

DEFUN (no_access_list_extended_host_host,
       no_access_list_extended_host_host_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                 "ip host A.B.C.D host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, argv[3], "0.0.0.0") ;
}

DEFUN (no_access_list_extended_any_host,
       no_access_list_extended_any_host_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                          "ip any host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "A single destination host\n"
       "Destination address\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], "0.0.0.0",
                                                            "255.255.255.255",
                                  true /* extended */, argv[2], "0.0.0.0") ;
}

DEFUN (no_access_list_extended_host_any,
       no_access_list_extended_host_any_cmd,
       "no access-list (<100-199>|<2000-2699>) (deny|permit) "
                                                          "ip host A.B.C.D any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Any destination host\n")
{
  return filter_set_cisco (vty, argv[0], del, argv[1], argv[2], "0.0.0.0",
                                  true /* extended */, "0.0.0.0",
                                                            "255.255.255.255") ;
}

/*------------------------------------------------------------------------------
 * Zebra form access-list -- IPv4
 */
DEFUN (access_list_zebra,
       access_list_zebra_cmd,
       "access-list WORD (deny|permit) A.B.C.D/M",
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], add, argv[1], argv[2],
                                                        false /* not exact */) ;
}

DEFUN (access_list_zebra_exact,
       access_list_zebra_exact_cmd,
       "access-list WORD (deny|permit) A.B.C.D/M exact-match",
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], add, argv[1], argv[2],
                                                             true /* exact */) ;
}

DEFUN (access_list_zebra_any,
       access_list_zebra_any_cmd,
       "access-list WORD (deny|permit) any",
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], add, argv[1], "0.0.0.0/0",
                                                        false /* not exact */) ;
}

DEFUN (no_access_list_zebra,
       no_access_list_zebra_cmd,
       "no access-list WORD (deny|permit) A.B.C.D/M",
       NO_STR
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], del, argv[1], argv[2],
                                                        false /* not exact */) ;
}

DEFUN (no_access_list_zebra_exact,
       no_access_list_zebra_exact_cmd,
       "no access-list WORD (deny|permit) A.B.C.D/M exact-match",
       NO_STR
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], del, argv[1], argv[2],
                                                             true /* exact */) ;
}

DEFUN (no_access_list_zebra_any,
       no_access_list_zebra_any_cmd,
       "no access-list WORD (deny|permit) any",
       NO_STR
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], del, argv[1], "0.0.0.0/0",
                                                        false /* not exact */) ;
}

/*------------------------------------------------------------------------------
 * Common IPv4 access-list stuff
 */
DEFUN (no_access_list_all,
       no_access_list_all_cmd,
       "no access-list (<1-99>|<100-199>|<1300-1999>|<2000-2699>|WORD)",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list name\n")
{
  return vty_no_access_list_all(vty, qAFI_IP, argv[0]) ;
} ;

DEFUN (access_list_remark,
       access_list_remark_cmd,
       "access-list (<1-99>|<100-199>|<1300-1999>|<2000-2699>|WORD) remark .LINE",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
  return vty_access_list_remark_set(vty, qAFI_IP, argv[0],
                                                   argv_concat(argv, argc, 1)) ;
}

DEFUN (no_access_list_remark,
       no_access_list_remark_cmd,
       "no access-list (<1-99>|<100-199>|<1300-1999>|<2000-2699>|WORD) remark",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n")
{
  return vty_access_list_remark_unset (vty, qAFI_IP, argv[0]);
}

ALIAS (no_access_list_remark,
       no_access_list_remark_arg_cmd,
       "no access-list (<1-99>|<100-199>|<1300-1999>|<2000-2699>|WORD) remark .LINE",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

/*------------------------------------------------------------------------------
 * IPv6 access-list stuff
 */
#ifdef HAVE_IPV6
DEFUN (ipv6_access_list,
       ipv6_access_list_cmd,
       "ipv6 access-list WORD (deny|permit) X:X::X:X/M",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n")
{
  return filter_set_zebra(vty, qAFI_IP6, argv[0], add, argv[1], argv[2],
                                                        false /* not exact */) ;
}

DEFUN (ipv6_access_list_exact,
       ipv6_access_list_exact_cmd,
       "ipv6 access-list WORD (deny|permit) X:X::X:X/M exact-match",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Exact match of the prefixes\n")
{
  return filter_set_zebra(vty, qAFI_IP6, argv[0], add, argv[1], argv[2],
                                                             true /* exact */) ;
}

DEFUN (ipv6_access_list_any,
       ipv6_access_list_any_cmd,
       "ipv6 access-list WORD (deny|permit) any",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefixi to match\n")
{
  return filter_set_zebra(vty, qAFI_IP6, argv[0], add, argv[1], "::/0",
                                                        false /* not exact */) ;
}

DEFUN (no_ipv6_access_list,
       no_ipv6_access_list_cmd,
       "no ipv6 access-list WORD (deny|permit) X:X::X:X/M",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n")
{
  return filter_set_zebra(vty, qAFI_IP6, argv[0], del, argv[1], argv[2],
                                                        false /* not exact */) ;
}

DEFUN (no_ipv6_access_list_exact,
       no_ipv6_access_list_exact_cmd,
       "no ipv6 access-list WORD (deny|permit) X:X::X:X/M exact-match",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Exact match of the prefixes\n")
{
  return filter_set_zebra(vty, qAFI_IP, argv[0], del, argv[1], argv[2],
                                                             true /* exact */) ;
}

DEFUN (no_ipv6_access_list_any,
       no_ipv6_access_list_any_cmd,
       "no ipv6 access-list WORD (deny|permit) any",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefixi to match\n")
{
  return filter_set_zebra(vty, qAFI_IP6, argv[0], del, argv[1], "::/0",
                                                        false /* not exact */) ;
}

DEFUN (no_ipv6_access_list_all,
       no_ipv6_access_list_all_cmd,
       "no ipv6 access-list WORD",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n")
{
  return vty_no_access_list_all(vty, qAFI_IP6, argv[0]) ;
}

DEFUN (ipv6_access_list_remark,
       ipv6_access_list_remark_cmd,
       "ipv6 access-list WORD remark .LINE",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
  return vty_access_list_remark_set(vty, qAFI_IP6, argv[0],
                                                   argv_concat(argv, argc, 1)) ;
}

DEFUN (no_ipv6_access_list_remark,
       no_ipv6_access_list_remark_cmd,
       "no ipv6 access-list WORD remark",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n")
{
  return vty_access_list_remark_unset (vty, qAFI_IP6, argv[0]);
}

ALIAS (no_ipv6_access_list_remark,
       no_ipv6_access_list_remark_arg_cmd,
       "no ipv6 access-list WORD remark .LINE",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

#endif /* HAVE_IPV6 */

/*==============================================================================
 * Mechanics for showing access-list configuration.
 */
static int access_list_sort_cmp(const vhash_item_c* pa,
                                const vhash_item_c* pb) ;
static int access_list_select_cmp(const vhash_item_c* pi, vhash_data_c d)
                                                                        Unused ;

static void write_access_zebra(struct vty *vty, filter_zebra filter) ;
static void write_access_cisco_standard(struct vty *vty, filter_cisco filter) ;
static void write_access_cisco_extended(struct vty *vty, filter_cisco filter) ;
static void access_list_show(struct vty *vty, qAFI_t afi, access_list alist) ;

/*------------------------------------------------------------------------------
 * show access-list command -- show given named access-list, or all lists.
 */
static cmd_ret_t
filter_show (struct vty *vty, qAFI_t afi, const char *name)
{
  access_list   alist ;
  access_master am ;

  am = access_master_get (afi);
  if (am == NULL)
    return CMD_WARNING ;                /* should not happen    */

  /* Print the name of the protocol */
  if (zlog_default)
     vty_out (vty, "%s:\n", zlog_get_proto_name(NULL)) ;

  if (name != NULL)
    {
      alist = access_list_lookup(afi, name) ;

      if (alist != NULL)
        access_list_show (vty, afi, alist) ;
      else
        vty_access_list_not_found(vty, afi, name) ;
    }
  else
    {
      /* Extract a vector of all access_list, in name order.
       */
      vector extract ;
      vector_index_t  i ;

      extract = vhash_table_extract(am->table, NULL, NULL, false,
                                                         access_list_sort_cmp) ;

      for (VECTOR_ITEMS(extract, alist, i))
        {
          if (access_list_is_set(alist))
            access_list_show (vty, afi, alist) ;
        } ;

      vector_free(extract) ;
    } ;

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * show access-list command.
 */
static void
access_list_show (struct vty *vty, qAFI_t afi, access_list alist)
{
  access_list_entry ae ;
  const char* form ;

  switch (alist->form)
    {
      case form_zebra:
        form = "Zebra" ;
        break ;

      case form_cisco_standard:
        form = "Standard" ;
        break ;

      case form_cisco_extended:
        form = "Extended" ;
        break ;

      default:
        form = "??BUG??" ;
        break ;
    } ;

  vty_out (vty, "%s %s access list %s", form, access_list_afi_str(afi),
                                                                  alist->name) ;
  if (alist->remark != NULL)
    vty_out (vty, "  -- %s", alist->remark) ;

  vty_out(vty, "\n") ;

  for(ae = ddl_head(alist->base) ; ae != NULL ; ae = ddl_next(ae, list))
    {
      vty_out (vty, "    %-6s", access_list_entry_type_str(ae->type));

      switch (alist->form)
        {
          case form_zebra:
            write_access_zebra (vty, &ae->filter.zebra) ;
            break ;

          case form_cisco_standard:
            write_access_cisco_standard (vty, &ae->filter.cisco);
            break ;

          case form_cisco_extended:
            write_access_cisco_extended (vty, &ae->filter.cisco);
            break ;

          default:
            vty_out(vty, "??BUG??\n") ;
            break ;
        } ;

      vty_out (vty, "\n") ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function for sorting an extract from the access-lists
 */
static int
access_list_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb)
{
  access_list_c a = *pa ;
  access_list_c b = *pb ;

  return strcmp_mixed(a->name, b->name) ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function for selecting an extract from the access-lists
 */
static int
access_list_select_cmp(const vhash_item_c* pi, vhash_data_c d)
{
  access_list_c alist = *pi ;
  const char*   name  = d ;

  return strcmp_mixed(alist->name, name ) ;
} ;

/*------------------------------------------------------------------------------
 * CLI -- "show" commands
 */
DEFUN (show_ip_access_list,
       show_ip_access_list_cmd,
       "show ip access-list",
       SHOW_STR
       IP_STR
       "List IP access lists\n")
{
  return filter_show (vty, qAFI_IP, NULL);
}

DEFUN (show_ip_access_list_name,
       show_ip_access_list_name_cmd,
       "show ip access-list (<1-99>|<100-199>|<1300-1999>|<2000-2699>|WORD)",
       SHOW_STR
       IP_STR
       "List IP access lists\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n")
{
  return filter_show (vty, qAFI_IP, argv[0]);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_access_list,
       show_ipv6_access_list_cmd,
       "show ipv6 access-list",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n")
{
  return filter_show (vty, qAFI_IP6, NULL);
}

DEFUN (show_ipv6_access_list_name,
       show_ipv6_access_list_name_cmd,
       "show ipv6 access-list WORD",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n"
       "IPv6 zebra access-list\n")
{
  return filter_show (vty, qAFI_IP6, argv[0]);
}
#endif /* HAVE_IPV6 */


/*==============================================================================
 * Writing away access-list configuration.
 */
static void write_access_cisco_extended_part(struct vty *vty,
                                                     struct filter_pair* pair) ;

/*------------------------------------------------------------------------------
 * Write the configuration of all access-lists for the given afi.
 */
static int
config_write_access (struct vty *vty, qAFI_t afi)
{
  access_list       alist ;
  access_master     am ;
  int write ;
  vector extract ;
  vector_index_t  i ;
  const char* tag ;

  write = 0 ;

  am = access_master_get (afi);
  if (am == NULL)
    return write ;

  tag = afi == qAFI_IP ? "" : "ipv6 " ;

  /* Extract a vector of all access_lists, in name order.
   */
  extract = vhash_table_extract(am->table, NULL, NULL, false,
                                                         access_list_sort_cmp) ;

  for (VECTOR_ITEMS(extract, alist, i))
    {
      access_list_entry ae ;

      if (!access_list_is_set(alist))
        continue ;

      if (write == 0)
        vtysh_config_section_start(vty, vct_access_list, "*") ;

      if (alist->remark)
        {
          vty_out (vty, "%saccess-list %s remark %s\n", tag,
                                               alist->name, alist->remark) ;
          write++;
        } ;

      for (ae = ddl_head(alist->base) ; ae != NULL ; ae = ddl_next(ae, list))
        {
          vty_out (vty, "%saccess-list %s %s", tag,
                            alist->name, access_list_entry_type_str(ae->type)) ;

          switch (alist->form)
            {
              case form_zebra:
                write_access_zebra (vty, &ae->filter.zebra) ;
                break ;

              case form_cisco_standard:
                write_access_cisco_standard (vty, &ae->filter.cisco);
                break ;

              case form_cisco_extended:
                vty_out (vty, " ip") ;
                write_access_cisco_extended (vty, &ae->filter.cisco);
                break ;

              default:
                vty_out(vty, "??BUG??") ;
                break ;
            } ;

          vty_out (vty, "\n") ;
          write++;
        } ;

      vty_out_vtysh_config_group_end(vty) ;
    } ;

  return write;
}

/*------------------------------------------------------------------------------
 * The configuration for a Zebra style access-list entry:
 *
 *   either: " any"        -- where prefix length == 0 and !exact
 *       or: " ppp/99"
 *       or: " ppp/99 exact-match"
 */
static void
write_access_zebra (struct vty *vty, filter_zebra filter)
{
  prefix  p;

  p = &filter->prefix;

  if ((p->prefixlen == 0) && !filter->exact)
    vty_out (vty, " any");
  else
    vty_out (vty, " %s%s", spfxtoa(p).str,
                                          filter->exact ? " exact-match" : "") ;
} ;

/*------------------------------------------------------------------------------
 * The configuration for a Cisco style "standard" access-list entry.
 *
 *   either: " any"       -- where www = 255.255.255.255
 *       or: " aaa"       -- where www = 0.0.0.0
 *       or: " aaa www"
 */
static void
write_access_cisco_standard (struct vty *vty, filter_cisco filter)
{
  if (filter->addr.wild == 0xffffffff)
    vty_out (vty, " any");
  else
    {
      vty_out (vty, " %s", siptoa(AF_INET, &filter->addr.addr).str) ;

      if (filter->addr.wild != 0)
        vty_out (vty, " %s", siptoa(AF_INET, &filter->addr.wild).str) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * The configuration for a Cisco style "extended" access-list entry.
 *
 * Writes address part and wild part.
 */
static void
write_access_cisco_extended (struct vty *vty, filter_cisco filter)
{
  write_access_cisco_extended_part(vty, &filter->addr) ;
  write_access_cisco_extended_part(vty, &filter->mask) ;
} ;

/*------------------------------------------------------------------------------
 * The configuration for part of Cisco style "extended" access-list entry.
 *
 *   either: " any"       -- where www = 255.255.255.255
 *       or: " host aaa"  -- where www = 0.0.0.0
 *       or: " aaa www"
 */
static void
write_access_cisco_extended_part(struct vty *vty, struct filter_pair* pair)
{
  if (pair->wild == 0xffffffff)
    vty_out (vty, " any");
  else if (pair->wild == 0)
    vty_out (vty, " host %s", siptoa(AF_INET, &pair->addr).str) ;
  else
    vty_out (vty, " %s %s", siptoa(AF_INET, &pair->addr).str,
                            siptoa(AF_INET, &pair->wild).str);
} ;

/*------------------------------------------------------------------------------
 * Partial parsing of access-list configuration -- for vtysh integrated
 *                                                               configurations.
 *
 * When constructing an integrated vtysh configuration, the lines created
 * above -- see config_write_access() -- must be partially parsed in order to
 * correctly merge the filter lists from two or more daemons into one filter
 * list.
 *
 * Recognises: (ipv6 )?access-list ..name.. remark ....
 *             (ipv6 )?access-list ..name.. ....
 *
 * Sets:       group_name: vX ..name.. 0   -- for remark lines
 *                         vX ..name.. 1   -- for other lines
 *
 *             item_name:  rest of line, concatenated.
 *
 * Expects the groups to be handled as mst_sorted and the contents of the
 * groups to be mst_as_is.
 */
extern cmd_ret_t
access_list_parse_section(vtysh_content_parse cp, cmd_parsed parsed)
{
  cmd_token t ;
  uint      ti, tn ;

  /* Even if the line is blank, there will be at least one token, the eol !
   */
  tn = parsed->num_tokens ;

  ti = 0 ;
  t = cmd_token_get(parsed->tokens, ti) ;

  if (els_cmp_str(t->ot, "ipv6") == 0)
    {
      t = cmd_token_get(parsed->tokens, ++ti) ;
      qs_set_str(cp->new_name, "v6 ") ;
    }
  else
    qs_set_str(cp->new_name, "v4 ") ; ;

  if (els_cmp_str(t->ot, "access-list") != 0)
    {
      cp->error_msg = "unknown first token of 'access-list' line" ;
      return CMD_ERROR ;
    } ;

  ++ti ;                        /* index of the name token              */
  if ((ti + 1) >= tn)
    {
      cp->error_msg = "unknown form of 'access-list' line" ;
      return CMD_ERROR  ;       /* expect name + at least one other     */
    } ;

  t = cmd_token_get(parsed->tokens, ti) ;
  qs_append_els(cp->new_name, t->ot) ;          /* the name             */

  ++ti ;                        /* index of token after the name        */
  t = cmd_token_get(parsed->tokens, ti) ;
  if (els_cmp_str(t->ot, "remark") == 0)
    qs_append_str(cp->new_name, " 0") ;         /* remark group         */
  else
    qs_append_str(cp->new_name, " 1") ;         /* entry group          */

  cp->new_depth = 2 ;
  cp->new_type  = vct_access_list ;

  cp->result = vcp_line | vcp_section ;

  return CMD_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * The IPv4 access-list command table
 */
static int
config_write_access_ipv4 (struct vty *vty)
{
  return config_write_access (vty, AFI_IP);
}

/* Install vty related command.
 */
CMD_INSTALL_TABLE(static, filter_cmd_table, ALL_RDS) =
{
  { ENABLE_NODE,      &show_ip_access_list_cmd                           },
  { ENABLE_NODE,      &show_ip_access_list_name_cmd                      },

  /* Zebra access-list */
  { CONFIG_NODE,      &access_list_zebra_cmd                             },
  { CONFIG_NODE,      &access_list_zebra_exact_cmd                       },
  { CONFIG_NODE,      &access_list_zebra_any_cmd                         },
  { CONFIG_NODE,      &no_access_list_zebra_cmd                          },
  { CONFIG_NODE,      &no_access_list_zebra_exact_cmd                    },
  { CONFIG_NODE,      &no_access_list_zebra_any_cmd                      },

  /* Standard access-list */
  { CONFIG_NODE,      &access_list_standard_cmd                          },
  { CONFIG_NODE,      &access_list_standard_nomask_cmd                   },
  { CONFIG_NODE,      &access_list_standard_host_cmd                     },
  { CONFIG_NODE,      &access_list_standard_any_cmd                      },
  { CONFIG_NODE,      &no_access_list_standard_cmd                       },
  { CONFIG_NODE,      &no_access_list_standard_nomask_cmd                },
  { CONFIG_NODE,      &no_access_list_standard_host_cmd                  },
  { CONFIG_NODE,      &no_access_list_standard_any_cmd                   },

  /* Extended access-list */
  { CONFIG_NODE,      &access_list_extended_cmd                          },
  { CONFIG_NODE,      &access_list_extended_any_mask_cmd                 },
  { CONFIG_NODE,      &access_list_extended_mask_any_cmd                 },
  { CONFIG_NODE,      &access_list_extended_any_any_cmd                  },
  { CONFIG_NODE,      &access_list_extended_host_mask_cmd                },
  { CONFIG_NODE,      &access_list_extended_mask_host_cmd                },
  { CONFIG_NODE,      &access_list_extended_host_host_cmd                },
  { CONFIG_NODE,      &access_list_extended_any_host_cmd                 },
  { CONFIG_NODE,      &access_list_extended_host_any_cmd                 },
  { CONFIG_NODE,      &no_access_list_extended_cmd                       },
  { CONFIG_NODE,      &no_access_list_extended_any_mask_cmd              },
  { CONFIG_NODE,      &no_access_list_extended_mask_any_cmd              },
  { CONFIG_NODE,      &no_access_list_extended_any_any_cmd               },
  { CONFIG_NODE,      &no_access_list_extended_host_mask_cmd             },
  { CONFIG_NODE,      &no_access_list_extended_mask_host_cmd             },
  { CONFIG_NODE,      &no_access_list_extended_host_host_cmd             },
  { CONFIG_NODE,      &no_access_list_extended_any_host_cmd              },
  { CONFIG_NODE,      &no_access_list_extended_host_any_cmd              },
  { CONFIG_NODE,      &access_list_remark_cmd                            },
  { CONFIG_NODE,      &no_access_list_all_cmd                            },
  { CONFIG_NODE,      &no_access_list_remark_cmd                         },
  { CONFIG_NODE,      &no_access_list_remark_arg_cmd                     },

  CMD_INSTALL_END
} ;

/*------------------------------------------------------------------------------
 * The IPv6 access-list command table
 */
#ifdef HAVE_IPV6

static int
config_write_access_ipv6 (struct vty *vty)
{
  return config_write_access (vty, AFI_IP6);
}

CMD_INSTALL_TABLE(static, filter_ipv6_cmd_table, ALL_RDS) =
{
  { ENABLE_NODE,      &show_ipv6_access_list_cmd                         },
  { ENABLE_NODE,      &show_ipv6_access_list_name_cmd                    },

  { CONFIG_NODE,      &ipv6_access_list_cmd                              },
  { CONFIG_NODE,      &ipv6_access_list_exact_cmd                        },
  { CONFIG_NODE,      &ipv6_access_list_any_cmd                          },
  { CONFIG_NODE,      &no_ipv6_access_list_exact_cmd                     },
  { CONFIG_NODE,      &no_ipv6_access_list_cmd                           },
  { CONFIG_NODE,      &no_ipv6_access_list_any_cmd                       },
  { CONFIG_NODE,      &no_ipv6_access_list_all_cmd                       },
  { CONFIG_NODE,      &ipv6_access_list_remark_cmd                       },
  { CONFIG_NODE,      &no_ipv6_access_list_remark_cmd                    },
  { CONFIG_NODE,      &no_ipv6_access_list_remark_arg_cmd                },

  CMD_INSTALL_END
} ;
#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * Initialise all access-list commands -- IPv4 and IPv6
 */
extern void
access_list_cmd_init (void)
{
  cmd_install_node_config_write(ACCESS_NODE, config_write_access_ipv4) ;
  cmd_install_table(filter_cmd_table) ;

#ifdef HAVE_IPV6
  cmd_install_node_config_write(ACCESS_IPV6_NODE, config_write_access_ipv6) ;
  cmd_install_table(filter_ipv6_cmd_table) ;
#endif /* HAVE_IPV6 */
}
