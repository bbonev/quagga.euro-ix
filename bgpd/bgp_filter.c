/* AS path filter list.
   Copyright (C) 1999 Kunihiro Ishiguro

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

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "buffer.h"
#include "vhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_filter.h"

/*==============================================================================
 * AS Path Filter handling
 */

/*------------------------------------------------------------------------------
 * AS path filter master.
 */
typedef struct as_list_master  as_list_master_t ;
typedef struct as_list_master* as_list_master ;

struct as_list_master
{
  vhash_table_t  table[1] ;     /* embedded             */

  /* Hook function which is executed when new access_list is added. */
  void (*add_hook) (void);

  /* Hook function which is executed when access_list is deleted. */
  void (*delete_hook) (void);
};

/*------------------------------------------------------------------------------
 * Element of AS path filter.
 */
typedef struct as_list_entry  as_list_entry_t ;
typedef struct as_list_entry* as_list_entry ;

struct as_list_entry
{
  struct dl_list_pair(as_list_entry) list;

  as_filter_type_t type;

  regex_t* reg ;
  char*    reg_str ;
};

/*------------------------------------------------------------------------------
 * AS path filter list.
 */
typedef const struct as_list* as_list_c ;

struct as_list
{
  vhash_node_t  vhash ;

  char*  name;

  struct dl_base_pair(as_list_entry) base ;
} ;

CONFIRM(offsetof(as_list_t, vhash) == 0) ;      /* see vhash.h  */

/*------------------------------------------------------------------------------
 * Return string form of
 */
static const char*
filter_type_str (as_filter_type_t type)
{
  switch (type)
    {
      case AS_FILTER_PERMIT:
        return "permit";
      case AS_FILTER_DENY:
        return "deny";
      default:
        return "??BUG??";
    } ;
} ;

/*==============================================================================
 * AS-List master operations and vhash stuff.
 */
static vhash_equal_func  as_list_vhash_equal ;
static vhash_new_func    as_list_vhash_new ;
static vhash_free_func   as_list_vhash_free ;
static vhash_orphan_func as_list_vhash_orphan ;

static const vhash_params_t as_list_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = as_list_vhash_equal,
  .new    = as_list_vhash_new,
  .free   = as_list_vhash_free,
  .orphan = as_list_vhash_orphan,
} ;

static void as_list_flush(as_list flist) ;

/* We have one, static as_list_master.
 *
 * Note that the vhash_table is embedded in the master structure, and never
 * freed -- so do not need to worry about all that.
 */
static as_list_master_t as_lists[1] ;

/*------------------------------------------------------------------------------
 * Early morning initialisation of as_list master
 */
extern void
bgp_filter_init (void)
{
  memset(as_lists, 0, sizeof(as_lists)) ;

  vhash_table_init(as_lists->table, NULL, 50, 200, &as_list_vhash_params) ;
} ;

/*------------------------------------------------------------------------------
 * Final termination of route-map master
 */

extern void
bgp_filter_reset (void)
{
  /* Empty out the embedded as-list table.
   */
  vhash_table_reset(as_lists->table, keep_it) ;
} ;

/*------------------------------------------------------------------------------
 * Set the 'add_hook' function.
 */
extern void
as_list_add_hook (void (*func) (void))
{
  as_lists->add_hook = func;
} ;

/*------------------------------------------------------------------------------
 * Set the 'delete_hook' function.
 */
extern void
as_list_delete_hook (void (*func) (void))
{
  as_lists->delete_hook = func;
} ;

/*==============================================================================
 * Basic constructors and destructors for as_list.
 */

/*------------------------------------------------------------------------------
 * Construct a new route-map -- vhash_new_func
 */
static vhash_item
as_list_vhash_new(vhash_table table, vhash_data_c data)
{
  as_list   new ;
  const char* name = data ;

  new = XCALLOC (MTYPE_AS_LIST, sizeof(as_list_t)) ;

  /* Zeroizing has set:
   *
   *   * vhash                -- all zero   -- not that this matters
   *
   *   * name                 -- X          -- set below
   *
   *   * base                 -- NULLs      -- empty list
   */
  new->name = XSTRDUP(MTYPE_AS_FILTER_STR, name) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Comparison -- vhash_cmp_func
 */
static int
as_list_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  as_list_c flist = item ;
  const char* name  = data ;

  return strcmp(flist->name, name) ;
} ;

/*------------------------------------------------------------------------------
 * Free as-list -- vhash_free_func
 *
 * Makes sure that the as-list is empty, first.
 */
static vhash_item
as_list_vhash_free(vhash_item item, vhash_table table)
{
  as_list flist = item ;

  as_list_flush(flist) ;               /* make sure    */

  XFREE (MTYPE_AS_FILTER_STR, flist->name) ;
  XFREE (MTYPE_AS_LIST, flist) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Orphan as-list -- vhash_orphan_func
 *
 * Makes sure that the as-list is empty and unset.
 */
static vhash_item
as_list_vhash_orphan(vhash_item item, vhash_table table)
{
  as_list flist = item ;

  as_list_flush(flist) ;

  return vhash_unset(flist, table) ;
} ;

/*------------------------------------------------------------------------------
 * Returns true <=> route-map is empty
 *
 * A NULL as-list is an empty as-list !
 */
static bool
as_list_is_empty(as_list flist)
{
  if (flist != NULL)
    qassert( ((flist->base.head == NULL) && (flist->base.tail == NULL)) ||
             ((flist->base.head != NULL) && (flist->base.tail != NULL)) ) ;

  return (flist == NULL) || (ddl_head(flist->base) == NULL) ;
} ;

/*==============================================================================
 * Operations on as_lists
 */
static void as_list_entry_free (as_list_entry ae) ;

/*------------------------------------------------------------------------------
 * Lookup as-list of the given name (if any).
 *
 * Does not create.
 *
 * Returns:  NULL <=> not found or is not set
 *           otherwise is address of as_list
 *
 * NB: returns NULL if the as-list exists but is empty (<=> not "set").
 */
extern as_list
as_list_lookup (const char* name)
{
  as_list flist ;

  if (name == NULL)
    return NULL ;

  flist = vhash_lookup(as_lists->table, name, NULL /* don't add */) ;

  if (flist == NULL)
    return NULL ;

  qassert(vhash_is_set(flist) == !as_list_is_empty(flist)) ;

  return vhash_is_set(flist) ? flist : NULL ;
}

/*------------------------------------------------------------------------------
 * Find as-list by name (if any)  -- create (if name not NULL).
 *
 * Returns:  address of as-list -- may be new, empty as-list
 *           but NULL if name NULL.
 */
extern as_list
as_list_find(const char* name)
{
  as_list flist ;
  bool added ;

  if (name == NULL)
    return NULL;

  flist = vhash_lookup(as_lists->table, name, &added) ;

  return flist ;
} ;

/*------------------------------------------------------------------------------
 * Get a reference to the as-list of the given name.
 *
 * In any case, this returns the address of the as-list, "set" or not,
 * with the reference count incremented.
 *
 * Returns:  address of as-list (NULL if name NULL)
 */
extern as_list
as_list_get_ref(const char* name)
{
  return as_list_set_ref(as_list_find(name)) ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given as-list (if any).
 *
 * If as-list is no longer in use and is not set, will vanish.
 *
 * Returns:  as-list as given
 */
extern as_list
as_list_set_ref(as_list flist)
{
  if (flist != NULL)
    return vhash_inc_ref(flist) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given as-list (if any).
 *
 * If as-list is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  NULL
 */
extern as_list
as_list_clear_ref(as_list flist)
{
  if (flist != NULL)
    vhash_dec_ref(flist, as_lists->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return name of as-list -- will be NULL if as-list is NULL
 */
extern const char*
as_list_get_name(as_list flist)
{
  return (flist != NULL) ? flist->name : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return whether as_list is "set" -- that is, some value has been set.
 *
 * Will not be "set" if is NULL.
 */
extern bool
as_list_is_set(as_list flist)
{
  qassert(vhash_is_set(flist) == !as_list_is_empty(flist)) ;

  return vhash_is_set(flist) ;
} ;

/*------------------------------------------------------------------------------
 * Return whether as_list is "active".
 *
 * Will not be "active" if is NULL.
 *
 * Will be "active" iff there is at least one entry in the prefix-list.
 */
extern bool
as_list_is_active(as_list flist)
{
  return (flist != NULL) ? ddl_head(flist->base) != NULL : false ;
} ;

/*------------------------------------------------------------------------------
 * Delete as_list.
 *
 * If the as-list has any remaining entries discard them.  Clear the "set"
 * state.
 *
 * Invoke the delete_hook() if any.
 *
 * If there are no references, delete the as-list.  Otherwise, leave it to
 * be deleted when the reference count falls to zero, or leave it to have a
 * value redefined at some future date.
 */
static void
as_list_delete (as_list flist)
{
  vhash_inc_ref(flist) ;        /* want to hold onto the flist pro tem. */

  as_list_flush(flist) ;        /* hammer the value and clear "set"     */

  /* as-list no longer has a value
   *
   * If we need to tell the world, we pass the (now empty) as-list to the
   * call-back.
   */
  if (as_lists->delete_hook != NULL)
    as_lists->delete_hook();

  /* Now, if there are no references to the as-list, it is time for it
   * to go.
   */
   vhash_dec_ref(flist, as_lists->table) ;      /* now may disappear    */
} ;

/*------------------------------------------------------------------------------
 * Flush all contents of as_list, leaving it completely empty.
 *
 * Retains all red-tape.  Releases the as-list entries.
 *
 * NB: does not touch the reference count BUT clears the "set" state WITHOUT
 *     freeing the as-list.
 */
static void
as_list_flush(as_list flist)
{
  while (1)
    {
      as_list_entry ae ;

      ae = ddl_pop(&ae, flist->base, list) ;

      if (ae == NULL)
        break ;

      as_list_entry_free(ae) ;
    } ;

  /* Clear the "set" state -- but do NOT delete, even if reference count == 0
   */
  vhash_clear_set(flist) ;
} ;

/*==============================================================================
 * Operations on as-list entries
 */

/*------------------------------------------------------------------------------
 * Make new as-list entry
 */
static as_list_entry
as_list_entry_new(regex_t* reg, const char *reg_str, as_filter_type_t type)
{
  as_list_entry ae ;

  ae = XCALLOC (MTYPE_AS_FILTER, sizeof (as_list_entry_t));

  /* Zeroizing the new as-list entry has set:
   *
   *   * list                  -- NULLs        -- not on list, yet
   *
   *   * type                  -- X            -- set below
   *   * reg                   -- X            -- set below
   *   * reg_str               -- X            -- set below
   */
  ae->type    = type;
  ae->reg     = reg;
  ae->reg_str = XSTRDUP (MTYPE_AS_FILTER_STR, reg_str);

  return ae ;
} ;

/*------------------------------------------------------------------------------
 * Free allocated AS filter.
 */
static void
as_list_entry_free(as_list_entry ae)
{
  if (ae->reg != NULL)
    bgp_regex_free (ae->reg) ;

  if (ae->reg_str != NULL)
    XFREE (MTYPE_AS_FILTER_STR, ae->reg_str);

  XFREE (MTYPE_AS_FILTER, ae);
}

/*------------------------------------------------------------------------------
 * Lookup as-list entry by the reg_str.
 *
 * Note that does not consider the type of the entry.
 */
static as_list_entry
as_list_entry_lookup(as_list flist, const char* reg_str)
{
  as_list_entry p ;

  for (p = ddl_head(flist->base) ; p != NULL ; p = ddl_next(p, list))
    {
      if (strcmp (p->reg_str, reg_str) == 0)
        return p ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Delete given as-list entry from the as-list, and free it.
 *
 * NB: caller may wish to delete the as-list if it is empty after this delete.
 */
static void
as_list_entry_delete (as_list flist, as_list_entry ae)
{
  ddl_del(flist->base, ae, list) ;

  as_list_entry_free (ae);
} ;

/*------------------------------------------------------------------------------
 * Add given new entry to the given as-list.
 *
 * If an entry already exists with the same 'reg_str':
 *
 *   * if the 'type' is the same, leave the existing entry and discard the new
 *     one.
 *
 *     Note that in this case the existing entry stays where it was in the
 *     order of entries.
 *
 *   * if the 'type's are different, delete the existing entry, and then
 *     append the new one.
 *
 * NB: if the as-list was empty, caller may wish to now "set" it.
 */
static void
as_list_entry_add (as_list flist, as_list_entry ae)
{
  as_list_entry ae_was ;

  ae_was = as_list_entry_lookup(flist, ae->reg_str) ;

  if (ae_was != NULL)
    {
      if (ae_was->type == ae->type)
        {
          /* Have identical entry already -- discard new one.
           */
          as_list_entry_free(ae) ;
          return ;
        }
      else
        {
          /* New entry has different type, so discard old one.
           */
          as_list_entry_delete(flist, ae_was) ;
        } ;
    } ;

  ddl_append(flist->base, ae, list) ;
} ;

/*==============================================================================
 * AS-List Use.
 */

/*------------------------------------------------------------------------------
 * Apply AS path filter to AS.
 */
extern as_filter_type_t
as_list_apply (as_list flist, void* object)
{
  as_list_entry ae ;
  as_path asp ;

  asp = object;

  if (flist == NULL)
    return AS_FILTER_DENY;

  for (ae = ddl_head(flist->base) ; ae != NULL ; ae = ddl_next(ae, list))
    {
      if (bgp_regexec_asp (ae->reg, asp) != REG_NOMATCH)
        return ae->type;
    }
  return AS_FILTER_DENY;
}

/*==============================================================================
 * CLI
 */

DEFUN (ip_as_path, ip_as_path_cmd,
       "ip as-path access-list WORD (deny|permit) .LINE",
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A regular-expression to match the BGP AS paths\n")
{
  as_filter_type_t type ;
  as_list_entry    ae ;
  as_list          flist ;
  regex_t*         regex ;
  char*            regstr ;

  /* Check the filter type.
   */
  switch (*(const char*)argv[1])
    {
      case 'p':
        type = AS_FILTER_PERMIT;
        break ;

      case 'd':
        type = AS_FILTER_DENY;
        break ;

      default:
        return CMD_WARNING ;    /* impossible   */
    } ;

  /* Check AS path regex, and construct a new as-list entry if OK.
   */
  regstr = argv_concat(argv, argc, 2) ;         /* creates an MTYPE_TMP */

  regex = bgp_regcomp (regstr);
  if (regex == NULL)
    {
      XFREE (MTYPE_TMP, regstr);
      vty_out (vty, "can't compile regexp %s: %s\n", argv[0], regstr) ;
      return CMD_WARNING;
    } ;

  ae = as_list_entry_new(regex, regstr, type);

  XFREE (MTYPE_TMP, regstr);

  /* Get the as-list -- creating an empty one, if required.
   *
   * Since we are about to add an entry, if this is a new as-list, it must
   * now be "set" and the 'add_hook' kicked.
   *
   * (The as-list is "set" after the 'add_hook' is kicked, because do not
   *  want to have "set" when the list of entries is empty.)
   */
  flist = as_list_find(argv[0]) ;

  if (!as_list_is_set(flist))
    {
      if (as_lists->add_hook != NULL)
         as_lists->add_hook() ;

      vhash_set(flist) ;
    } ;

  /* Add new entry to the flist.
   *
   * If an entry with the same regex already exists, then if the type is the
   * same, then the existing entry is left where it is, otherwise the existing
   * entry is removed and the new one appended.
   */;
   as_list_entry_add (flist, ae);

  return CMD_SUCCESS;
}

DEFUN (no_ip_as_path,
       no_ip_as_path_cmd,
       "no ip as-path access-list WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A regular-expression to match the BGP AS paths\n")
{
  as_filter_type_t type ;
  as_list_entry    ae ;
  as_list          flist ;
  char*   regstr ;

  /* Check the filter type.
   */
  switch (*(const char*)argv[1])
    {
      case 'p':
        type = AS_FILTER_PERMIT;
        break ;

      case 'd':
        type = AS_FILTER_DENY;
        break ;

      default:
        return CMD_WARNING ;    /* impossible   */
    } ;

  /* Lookup AS list from AS path list.
   */
  flist = as_list_lookup (argv[0]);
  if (flist == NULL)
    {
      vty_out (vty, "ip as-path access-list %s not found\n", argv[0]) ;
      return CMD_WARNING;
    }

  /* Try to find the as-list entry -- with given regstr and type.
   *
   * If could not find, say so.
   */
  regstr = argv_concat(argv, argc, 2);

  ae = as_list_entry_lookup (flist, regstr);

  if ((ae == NULL) || (ae->type != type))
    {
      vty_out (vty, "ip as-path access-list %s %s '%s' not found\n", argv[0],
                                           filter_type_str (ae->type), regstr) ;

      XFREE (MTYPE_TMP, regstr) ;
      return CMD_WARNING;
    } ;

  XFREE (MTYPE_TMP, regstr) ;           /* discard      */

  /* Have the entry to be deleted.
   *
   * Do that and then if the as-list is empty, delete the while thing.
   * Deleting the whole thing will trigger the 'delete_hook'.
   */
  as_list_entry_delete (flist, ae) ;

  if (as_list_is_empty(flist))
    as_list_delete(flist) ;

  return CMD_SUCCESS;
}

DEFUN (no_ip_as_path_all,
       no_ip_as_path_all_cmd,
       "no ip as-path access-list WORD",
       NO_STR
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n")
{
  as_list flist ;

  flist = as_list_lookup (argv[0]);
  if (flist == NULL)
    {
      vty_out (vty, "ip as-path access-list %s not found\n", argv[0]);
      return CMD_WARNING;
    }

  as_list_delete (flist) ;              /* runs 'delete_hook'   */

  return CMD_SUCCESS;
}

/*==============================================================================
 * Mechanics and CLI for showing as-lists
 */
static int as_list_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb) ;

/*------------------------------------------------------------------------------
 * Show the given as-list -- if not NULL and "set"
 */
static cmd_ret_t
as_list_show (struct vty *vty, as_list flist)
{
  if ((flist != NULL) && vhash_is_set(flist))
    {
      as_list_entry ae ;

      vty_out (vty, "AS path access list %s\n", flist->name) ;

      for (ae = ddl_head(flist->base) ; ae != NULL ; ae = ddl_next(ae, list))
        vty_out (vty, "    %s %s\n", filter_type_str (ae->type), ae->reg_str) ;
    } ;

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Show all the as-list that exist -- ignore those which are not "set".
 */
static cmd_ret_t
as_list_show_all (struct vty *vty)
{
  as_list   flist ;
  vector extract ;
  vector_index_t  i ;

  extract = vhash_table_extract(as_lists->table, NULL, NULL, false,
                                                         as_list_sort_cmp) ;
  for (VECTOR_ITEMS(extract, flist, i))
    as_list_show (vty, flist) ;

  vector_free(extract) ;

  return CMD_SUCCESS;
} ;

DEFUN (show_ip_as_path_access_list,
       show_ip_as_path_access_list_cmd,
       "show ip as-path-access-list WORD",
       SHOW_STR
       IP_STR
       "List AS path access lists\n"
       "AS path access list name\n")
{
  return as_list_show (vty, as_list_lookup (argv[0]));
}

DEFUN (show_ip_as_path_access_list_all,
       show_ip_as_path_access_list_all_cmd,
       "show ip as-path-access-list",
       SHOW_STR
       IP_STR
       "List AS path access lists\n")
{
  return as_list_show_all (vty);
}

/*------------------------------------------------------------------------------
 * Comparison function for sorting an extract from the as-lists
 */
static int
as_list_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb)
{
  as_list_c a = *pa ;
  as_list_c b = *pb ;

  return strcmp_mixed(a->name, b->name) ;
} ;

/*==============================================================================
 * Configuration output
 */

static int
config_write_as_list (struct vty *vty)
{
  as_list   flist ;
  vector extract ;
  vector_index_t  i ;
  int write ;

  extract = vhash_table_extract(as_lists->table, NULL, NULL, false,
                                                         as_list_sort_cmp) ;
  write = 0 ;
  for (VECTOR_ITEMS(extract, flist, i))
    {
      if (as_list_is_set(flist))
        {
          as_list_entry ae ;

          for (ae = ddl_head(flist->base) ; ae != NULL ;
                                            ae = ddl_next(ae, list))
            vty_out (vty, "ip as-path access-list %s %s %s\n",
                         flist->name, filter_type_str(ae->type), ae->reg_str) ;
          ++write ;
        } ;
    } ;

  vector_free(extract) ;

  return write;
} ;

/*==============================================================================
 * Table of commands to be installed for bgp_filter
 */
CMD_INSTALL_TABLE(static, bgp_filter_cmd_table, BGPD) =
{
  { CONFIG_NODE,    &ip_as_path_cmd                                    },
  { CONFIG_NODE,    &no_ip_as_path_cmd                                 },
  { CONFIG_NODE,    &no_ip_as_path_all_cmd                             },
  { VIEW_NODE,      &show_ip_as_path_access_list_cmd                   },
  { VIEW_NODE,      &show_ip_as_path_access_list_all_cmd               },
  { ENABLE_NODE,    &show_ip_as_path_access_list_cmd                   },
  { ENABLE_NODE,    &show_ip_as_path_access_list_all_cmd               },

  CMD_INSTALL_END
} ;

/*------------------------------------------------------------------------------
 * Register bgp_filter commands.
 */
void
bgp_filter_cmd_init (void)
{
  cmd_install_node_config_write (AS_LIST_NODE, config_write_as_list);

  cmd_install_table(bgp_filter_cmd_table) ;
}

