/* Route map function.
   Copyright (C) 1998, 1999 Kunihiro Ishiguro

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

#include "linklist.h"
#include "memory.h"
#include "vector.h"
#include "prefix.h"
#include "routemap.h"
#include "command.h"
#include "vty.h"
#include "log.h"
#include "miyagi.h"

/*------------------------------------------------------------------------------
 * Route map rule. This rule has both `match' rule and `set' rule.
 */
struct route_map_rule
{
  struct dl_list_pair(route_map_rule) list ;

  route_map_rule_cmd_c cmd ;    /* "type"                       */

  char* rule_str ;              /* if required                  */

  void* value ;                 /* "compiled", as required      */
};

/*------------------------------------------------------------------------------
 * Master list of route map.
 *
 * There is one, static map... for one global route_map name-space.
 *
 * Note that the vhash_table is embedded in the master structure, and never
 * freed -- so do not need to worry about all that.
 */
typedef struct route_map_master  route_map_master_t ;
typedef struct route_map_master* route_map_master ;

struct route_map_master
{
  vhash_table_t  table[1] ;

  void (*add_hook)(const char *);
  void (*delete_hook)(const char *);
  void (*event_hook)(route_map_event_t, const char *);
};

static route_map_master_t route_maps[1] ;

/*------------------------------------------------------------------------------
 * Return string form of route_map_type_t
 */
static const char *
route_map_type_str (route_map_type_t type)
{
  switch (type)
    {
    case RMAP_PERMIT:
      return "permit";
      break;

    case RMAP_DENY:
      return "deny";
      break;

    default:
      return "??BUG UNKNOWN??";
      break;
    }
} ;

/*==============================================================================
 * Creating/Installing route-map 'match' and route-map 'set' statements.
 *
 * The "built out" 'match' and 'set' clauses are installed in these vectors.
 */
static vector route_match_vec  = NULL ;
static vector route_set_vec    = NULL ;

/*------------------------------------------------------------------------------
 * Install rule command to the match list.
 *
 * Note that the route_map_rule_cmd_c is const.  It cannot go into the vector
 * as such, but it is cast back to const when read back.
 */
extern void
route_map_install_match (route_map_rule_cmd_c cmd)
{
  vector_set (route_match_vec, miyagi(cmd));
}

/*------------------------------------------------------------------------------
 * Install rule command to the set list.
 *
 * Note that the route_map_rule_cmd_c is const.  It cannot go into the vector
 * as such, but it is cast back to const when read back.
 */
extern void
route_map_install_set (route_map_rule_cmd_c cmd)
{
  vector_set (route_set_vec, miyagi(cmd));
}

/*------------------------------------------------------------------------------
 * Lookup rule command from match list.
 */
static route_map_rule_cmd_c
route_map_lookup_match (const char *name)
{
  unsigned int i;
  route_map_rule_cmd_c rule;

  for (i = 0; i < vector_active (route_match_vec); i++)
    if ((rule = vector_get_item(route_match_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
        return rule;

  return NULL;
}

/*------------------------------------------------------------------------------
 * Lookup rule command from set list.
 */
static route_map_rule_cmd_c
route_map_lookup_set (const char *name)
{
  unsigned int i;
  struct route_map_rule_cmd *rule;

  for (i = 0; i < vector_active (route_set_vec); i++)
    if ((rule = vector_slot (route_set_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
        return rule;
  return NULL;
}

/*==============================================================================
 * Operations on route-map master and the vhash stuff
 */
static vhash_equal_func  route_map_vhash_equal ;
static vhash_new_func    route_map_vhash_new ;
static vhash_free_func   route_map_vhash_free ;
static vhash_orphan_func route_map_vhash_orphan ;

static const vhash_params_t route_map_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = route_map_vhash_equal,
  .new    = route_map_vhash_new,
  .free   = route_map_vhash_free,
  .orphan = route_map_vhash_orphan,
} ;

static void route_map_flush(route_map rmap) ;

/*------------------------------------------------------------------------------
 * Early morning initialisation of route-map master
 */
extern void
route_map_init (void)
{
  memset(route_maps, 0, sizeof(route_maps)) ;

  vhash_table_init(route_maps->table, NULL, 50, 200, &route_map_vhash_params) ;
} ;

/*------------------------------------------------------------------------------
 * Final termination of route-map master
 */
extern void
route_map_finish (void)
{
  /* Empty out the embedded route-map table.
   */
  vhash_table_reset(route_maps->table, keep_it) ;

  /* Discard the "match" and "set" vectors -- full of const items.
   */
  route_match_vec = vector_free (route_match_vec);
  route_set_vec   = vector_free (route_set_vec);
}

/*------------------------------------------------------------------------------
 * Set the route maps 'add_hook'
 */
extern void
route_map_add_hook (void (*func) (const char *))
{
  route_maps->add_hook = func;
}

/*------------------------------------------------------------------------------
 * Set the route maps 'delete_hook'
 */
extern void
route_map_delete_hook (void (*func) (const char *))
{
  route_maps->delete_hook = func;
}

/*------------------------------------------------------------------------------
 * Set the route maps 'event_hook'
 */
extern void
route_map_event_hook (void (*func) (route_map_event_t, const char *))
{
  route_maps->event_hook = func;
}

/*==============================================================================
 * Basic constructors and destructors for route_map.
 */

static void route_map_rule_delete (struct route_map_rule_list *,
                                                       struct route_map_rule *);

static void route_map_entry_delete (route_map_entry re);

/*------------------------------------------------------------------------------
 * Construct a new route-map -- vhash_new_func
 */
static vhash_item
route_map_vhash_new(vhash_table table, vhash_data_c data)
{
  route_map   new ;
  const char* name = data ;

  new = XCALLOC (MTYPE_ROUTE_MAP, sizeof(route_map_t)) ;

  /* Zeroizing has set:
   *
   *   * vhash                -- all zero   -- not that this matters
   *
   *   * name                 -- X          -- set below
   *
   *   * base                 -- NULLs      -- empty list
   */
  new->name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Comparison -- vhash_cmp_func
 */
static int
route_map_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  route_map_c rmap = item ;
  const char* name  = data ;

  return strcmp(rmap->name, name) ;
} ;

/*------------------------------------------------------------------------------
 * Free route-map -- vhash_free_func
 *
 * Makes sure that the route-map is empty, first.
 */
static vhash_item
route_map_vhash_free(vhash_item item, vhash_table table)
{
  route_map rmap = item ;

  route_map_flush(rmap) ;               /* make sure    */

  XFREE (MTYPE_ROUTE_MAP_NAME, rmap->name) ;
  XFREE (MTYPE_ROUTE_MAP, rmap) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Orphan route-map -- vhash_orphan_func
 *
 * Makes sure that the route-map is empty and unset.
 */
static vhash_item
route_map_vhash_orphan(vhash_item item, vhash_table table)
{
  route_map rmap = item ;

  route_map_flush(rmap) ;

  return vhash_unset(rmap, table) ;
} ;

/*------------------------------------------------------------------------------
 * Returns true <=> route-map is empty
 *
 * A NULL route-map is an empty route-map !
 */
static bool
route_map_is_empty(route_map rmap)
{
  if (rmap != NULL)
    qassert( ((rmap->base.head == NULL) && (rmap->base.tail == NULL)) ||
             ((rmap->base.head != NULL) && (rmap->base.tail != NULL)) ) ;

  return (rmap == NULL) || (ddl_head(rmap->base) == NULL) ;
} ;

/*==============================================================================
 * Operations on prefix_lists
 */
static void route_map_entry_free (route_map_entry re) ;

/*------------------------------------------------------------------------------
 * Lookup route-map of the given name (if any).
 *
 * Does not create.
 *
 * Returns:  NULL <=> not found or is not set
 *           otherwise is address of route_map
 *
 * NB: returns NULL if the route-map exists but is empty (<=> not "set").
 */
extern route_map
route_map_lookup (const char *name)
{
  route_map rmap ;

  if (name == NULL)
    return NULL ;

  rmap = vhash_lookup(route_maps->table, name, NULL /* don't add */) ;

  if (rmap == NULL)
    return NULL ;

  qassert(vhash_is_set(rmap) == !route_map_is_empty(rmap)) ;

  return vhash_is_set(rmap) ? rmap : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Find route-map by name (if any)  -- create (if name not NULL).
 *
 * Returns:  address of route-map -- may be new, empty route-map
 *           but NULL if name NULL.
 */
static route_map
route_map_find(const char *name)
{
  route_map rmap ;
  bool added ;

  if (name == NULL)
    return NULL;

  rmap = vhash_lookup(route_maps->table, name, &added) ;

  return rmap ;
} ;

/*------------------------------------------------------------------------------
 * Get a reference to the route-map of the given name.
 *
 * In any case, this returns the address of the route-map, "set" or not,
 * with the reference count incremented.
 *
 * Returns:  address of route-map (NULL if name NULL)
 */
extern route_map
route_map_get_ref(const char *name)
{
  return route_map_set_ref(route_map_find(name)) ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given route-map (if any).
 *
 * If route-map is no longer in use and is not set, will vanish.
 *
 * Returns:  route-map as given
 */
extern route_map
route_map_set_ref(route_map rmap)
{
  if (rmap != NULL)
    return vhash_inc_ref(rmap) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Finished with a reference to the given route-map (if any).
 *
 * If route-map is no longer in use and is not set, will vanish (and ditto
 * the related vhash_table).
 *
 * Returns:  NULL
 */
extern route_map
route_map_clear_ref(route_map rmap)
{
  if (rmap != NULL)
    vhash_dec_ref(rmap, route_maps->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return name of rmap -- will be NULL if rmap is NULL
 */
extern const char*
route_map_get_name(route_map rmap)
{
  return (rmap != NULL) ? rmap->name : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return whether route_map is "set" -- that is, some value has been set.
 *
 * Will not be "set" if is NULL.
 */
extern bool
route_map_is_set(route_map rmap)
{
  qassert(vhash_is_set(rmap) == !route_map_is_empty(rmap)) ;

  return vhash_is_set(rmap) ;
} ;

/*------------------------------------------------------------------------------
 * Return whether route_map is "active".
 *
 * Will not be "active" if is NULL.
 *
 * Will be "active" iff there is at least one entry in the prefix-list.
 */
extern bool
route_map_is_active(route_map rmap)
{
  return (rmap != NULL) ? ddl_head(rmap->base) != NULL : false ;
} ;

/*------------------------------------------------------------------------------
 * Delete route_map.
 *
 * If the route-map has any remaining entries discard them.  Clear the "set"
 * state.
 *
 * Invoke the delete_hook() if any.
 *
 * If there are no references, delete the route-map.  Otherwise, leave it to
 * be deleted when the reference count falls to zero, or leave it to have a
 * value redefined at some future date.
 */
static void
route_map_delete (route_map rmap)
{
  vhash_inc_ref(rmap) ;         /* want to hold onto the rmap pro tem. */

  route_map_flush(rmap) ;       /* hammer the value and clear "set"     */

  /* route-map no longer has a value
   *
   * If we need to tell the world, we pass the (now empty) rmap to the
   * call-back.
   */
  if (route_maps->delete_hook != NULL)
    route_maps->delete_hook(rmap->name);

  /* Now, if there are no references to the route-map, it is time for it
   * to go.
   */
   vhash_dec_ref(rmap, route_maps->table) ;     /* now may disappear    */
} ;

/*------------------------------------------------------------------------------
 * Flush all contents of route_map, leaving it completely empty.
 *
 * Retains all red-tape.  Releases the route-map entries.
 *
 * NB: does not touch the reference count BUT clears the "set" state WITHOUT
 *     freeing the route-map.
 */
static void
route_map_flush(route_map rmap)
{
  while (1)
    {
      route_map_entry re ;

      re = ddl_pop(&re, rmap->base, list) ;

      if (re == NULL)
        break ;

      route_map_entry_free(re) ;
    } ;

  /* Clear the "set" state -- but do NOT delete, even if reference count == 0
   */
  vhash_clear_set(rmap) ;
} ;

/*==============================================================================
 * Operations on prefix-list entries
 */

/*------------------------------------------------------------------------------
 * Create a new route-map entry and initialise
 */
static route_map_entry
route_map_entry_new (route_map rmap, route_map_type_t type, route_map_seq_t seq)
{
  route_map_entry re ;

  re = XCALLOC (MTYPE_ROUTE_MAP_ENTRY, sizeof (route_map_entry_t));

  /* Zeroizing sets:
   *
   *   * rmap                    -- X        -- set below
   *
   *   * description             -- NULL     -- none, yet
   *
   *   * list                    -- NULLs    -- not on any list, yet
   *
   *   * seq                     -- X        -- set below
   *   * type                    -- X        -- set below
   *   * exitpolicy              -- X        -- set below
   *
   *   * goto_seq                -- 0        -- no goto
   *   * call_name               -- NULL     -- no rmap to call
   *
   *   * match_list              -- NULLs    -- empty list
   *   * set_list                -- NULLs    -- empty list
   */
  re->rmap       = rmap ;
  re->type       = type ;
  re->seq        = seq ;
  re->exitpolicy = RMAP_EXIT ;  /* Default to Cisco-style */

  return re;
}

/*------------------------------------------------------------------------------
 * Free route map entry
 */
static void
route_map_entry_free (route_map_entry re)
{
  route_map_rule rule;

  while ((rule = ddl_head(re->match_list)) != NULL)
    route_map_rule_delete (&re->match_list, rule);

  while ((rule = ddl_head(re->set_list)) != NULL)
    route_map_rule_delete (&re->set_list, rule);

  if (re->call_name != NULL)
    XFREE (MTYPE_ROUTE_MAP_NAME, re->call_name);

  XFREE (MTYPE_ROUTE_MAP_ENTRY, re);
} ;

/*------------------------------------------------------------------------------
 * Delete route map entry
 *
 * Remove entry from the route-map, free it and then invoke the 'event_hook'
 * (if any).
 *
 * NB: if the route-map is now empty, the caller may wish to delete it, which
 *     will generate a 'delete_hook'.
 */
static void
route_map_entry_delete (route_map_entry re)
{
  const char* name ;

  name = re->rmap->name ;

  ddl_del(re->rmap->base, re, list) ;

  route_map_entry_free (re) ;

  if (route_maps->event_hook != NULL)
    route_maps->event_hook(RMAP_EVENT_INDEX_DELETED, name);
} ;

/*------------------------------------------------------------------------------
 * Lookup entry in route map.
 *
 * NB: expects the route-map entries to be in sequence number order.
 *
 *     A given sequence number should appear at most once, but does not depend
 *     on that -- if the type matches, will find the later of any repeated
 *     sequence number.
 */
static route_map_entry
route_map_entry_lookup (route_map rmap, route_map_type_t type,
                                                            route_map_seq_t seq)
{
  route_map_entry re;

  /* Works backwards along the list, to favour insertion in order.
   */
  for (re = ddl_tail(rmap->base) ; re != NULL ; re = ddl_prev(re, list))
    {
      if (seq > re->seq)
        break ;

      if (seq < re->seq)
        continue ;

      if ((type == RMAP_ANY) || (type == re->type))
        return re ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get route map entry.
 *
 * Find existing route-map entry, or create a new one.  If creates a new one,
 * generates an 'event_hook' event.
 *
 * Note that if an entry with the given 'seq' exists, but is of a different
 * 'type', then that entry is replaced (it is deleted and a new, empty entry
 * is inserted -- creating two 'event_hook' events).
 */
static route_map_entry
route_map_entry_get (route_map rmap, route_map_type_t type, route_map_seq_t seq)
{
  route_map_entry re;

  re = route_map_entry_lookup (rmap, RMAP_ANY, seq);

  if ((re != NULL) && (re->type != type))
    {
      /* Entry with the required 'seq' exists, but it is not of the required
       * 'type' -- delete it, generating an 'event_hook' event.
       */
      route_map_entry_delete (re);
      re = NULL;
    } ;

  if (re == NULL)
    {
      /* Add new entry to route map.
       */
      route_map_entry p ;

      /* Allocate and initialise route-map entry
       */
      re = route_map_entry_new(rmap, type, seq);

      /* Insert in required position in the route-map
       *
       * Works backwards along the list, to favour insertion in order.
       */
      for (p = ddl_tail(rmap->base) ; p != NULL ; p = ddl_prev(p, list))
        if (seq > p->seq)
          break;

      if (p != NULL)
        ddl_in_after(p, rmap->base, re, list) ;
      else
        ddl_push(rmap->base, re, list) ;

      /* Execute event hook.
       */
      if (route_maps->event_hook != NULL)
        route_maps->event_hook(RMAP_EVENT_INDEX_ADDED, rmap->name);
    } ;

  return re;
} ;

/*==============================================================================
 * Filling in a route-map entry
 */

/*------------------------------------------------------------------------------
 * Add new route map rule
 *
 * Create new rule, fill in and then append to the given list.
 *
 * Returns:  the new rule object
 *
 * NB: caller must ensure that list is ready for the new rule.
 */
static route_map_rule
route_map_rule_add(route_map_rule_list base, route_map_rule_cmd_c cmd,
                                              const char* rule_str, void* value)
{
  route_map_rule rule ;

  rule = XCALLOC (MTYPE_ROUTE_MAP_RULE, sizeof(route_map_rule_t));

  /* Zeroizing has set:
   *
   *   * list           -- NULLs      -- not on list (yet)
   *
   *   * cmd            -- X          -- set below
   *   * rule_str       -- NULL       -- set below if required
   *   * value          -- X          -- set below
   */
  rule->cmd   = cmd ;
  rule->value = value ;

  if (rule_str != NULL)
    rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, rule_str);

  ddl_append(*base, rule, list) ;

  return rule ;
} ;

/*------------------------------------------------------------------------------
 * Delete match or set rule from rule list.
 */
static void
route_map_rule_delete (route_map_rule_list base, route_map_rule rule)
{
  if (rule->cmd->func_free != NULL)
    rule->cmd->func_free(rule->value);

  if (rule->rule_str != NULL)
    XFREE (MTYPE_ROUTE_MAP_RULE_STR, rule->rule_str);

  ddl_del(*base, rule, list) ;

  XFREE (MTYPE_ROUTE_MAP_RULE, rule);
}

/*------------------------------------------------------------------------------
 * Is given 'arg' same as the 'rule_str' in the given rule ?
 *
 * NB: a NULL 'arg' will match any 'rule_str'
 *
 *     a NULL 'rule_str' is treated as "" (an empty string)
 */
static bool
rule_same(route_map_rule rule, const char* arg)
{
  const char* str ;

  if (arg == NULL)
    return true ;

  str = rule->rule_str ;
  if (str == NULL)
    str = "" ;

  return strcmp(str, arg) == 0;
}

/*------------------------------------------------------------------------------
 * Add match statement to route map.
 */
extern rmap_rule_ret_t
route_map_add_match (route_map_entry re, const char *match_name,
                                         const char *match_arg)
{
  route_map_rule rule;
  route_map_rule next;
  route_map_rule_cmd_c cmd;
  void *compile;
  bool replaced ;

  /* First lookup rule for add match statement.
   */
  cmd = route_map_lookup_match (match_name);
  if (cmd == NULL)
    return RMAP_RULE_MISSING;

  /* Next call compile function for this match statement.
   */
  if (cmd->func_compile != NULL)
    {
      compile= cmd->func_compile(match_arg);

      if (compile == NULL)
        return RMAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* Remove any (and all) existing instances of the same type of rule.
   */
  replaced = false ;
  for (rule = ddl_head(re->match_list) ; rule ; rule = next)
    {
      next = ddl_next(rule, list) ;
      if (rule->cmd == cmd)
        {
          route_map_rule_delete (&re->match_list, rule);
          replaced = true ;
        } ;
    } ;

  /* Add new route map match rule.
   */
  route_map_rule_add (&re->match_list, cmd, match_arg, compile) ;

  /* Execute event hook.
   */
  if (route_maps->event_hook != NULL)
    route_maps->event_hook(replaced ? RMAP_EVENT_MATCH_REPLACED
                                    : RMAP_EVENT_MATCH_ADDED,
                                            re->rmap->name);
  return RMAP_RULE_OK ;
}

/*------------------------------------------------------------------------------
 * Delete specified route match rule.
 */
extern rmap_rule_ret_t
route_map_delete_match (route_map_entry re, const char *match_name,
                                            const char *match_arg)
{
  route_map_rule       rule;
  route_map_rule_cmd_c cmd;

  cmd = route_map_lookup_match (match_name);
  if (cmd == NULL)
    return RMAP_RULE_MISSING ;

  for (rule = ddl_head(re->match_list) ; rule != NULL ;
                                         rule = ddl_next(rule, list))
    if ((rule->cmd == cmd) && rule_same(rule, match_arg))
      {
        route_map_rule_delete (&re->match_list, rule);

        if (route_maps->event_hook != NULL)
          route_maps->event_hook(RMAP_EVENT_MATCH_DELETED, re->rmap->name);

        return RMAP_RULE_OK;
      } ;

  /* Can't find matched rule.
   */
  return RMAP_RULE_MISSING ;
}

/*------------------------------------------------------------------------------
 * Add route-map set statement to the route map.
 */
extern rmap_rule_ret_t
route_map_add_set (route_map_entry re, const char *set_name,
                                       const char *set_arg)
{
  route_map_rule       rule, next ;
  route_map_rule_cmd_c cmd;
  void *compile;
  bool replaced ;

  cmd = route_map_lookup_set (set_name);
  if (cmd == NULL)
    return RMAP_RULE_MISSING;

  /* Next call compile function for this set statement.
   */
  if (cmd->func_compile != NULL)
    {
      compile= cmd->func_compile(set_arg);
      if (compile == NULL)
        return RMAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* Remove any (and all) existing instances of the same type of rule.
   */
  replaced = false ;
  for (rule = ddl_head(re->set_list) ; rule != NULL ; rule = next)
    {
      next = ddl_next(rule, list) ;
      if (rule->cmd == cmd)
        {
          route_map_rule_delete (&re->set_list, rule);
          replaced = true ;
        }
    } ;

  /* Add new route map set rule.
   */
  route_map_rule_add (&re->set_list, cmd, set_arg, compile) ;

  /* Execute event hook.
   */
  if (route_maps->event_hook != NULL)
    route_maps->event_hook(replaced ? RMAP_EVENT_SET_REPLACED
                                    : RMAP_EVENT_SET_ADDED,
                                       re->rmap->name);
  return RMAP_RULE_OK ;
}

/*------------------------------------------------------------------------------
 * Delete route map set rule.
 */
extern rmap_rule_ret_t
route_map_delete_set (route_map_entry re, const char *set_name,
                                          const char *set_arg)
{
  route_map_rule       rule;
  route_map_rule_cmd_c cmd;

  cmd = route_map_lookup_set (set_name);
  if (cmd == NULL)
    return RMAP_RULE_MISSING ;

  for (rule = ddl_head(re->set_list) ; rule != NULL ;
                                       rule = ddl_next(rule, list))
    if ((rule->cmd == cmd) && rule_same(rule, set_arg))
      {
        route_map_rule_delete (&re->set_list, rule);

        if (route_maps->event_hook != NULL)
          route_maps->event_hook(RMAP_EVENT_SET_DELETED, re->rmap->name);

        return RMAP_RULE_OK ;
      }

  /* Can't find matched rule.
   */
  return RMAP_RULE_MISSING ;
}

/*==============================================================================
 * Mechanics for showing access-list configuration.
 */
static int route_map_sort_cmp(const vhash_item_c* pa,
                              const vhash_item_c* pb) ;
static void route_map_show (struct vty *vty, route_map rmap) ;
static cmd_ret_t vty_route_map_not_found(struct vty *vty, const char *name) ;

/*------------------------------------------------------------------------------
 * Show route-map with the given name, or all route-maps if name == NULL.
 */
static cmd_ret_t
vty_show_route_map (struct vty *vty, const char *name)
{
  route_map   rmap ;

  if (name != NULL)
    {
      rmap = route_map_lookup(name) ;

      if (rmap != NULL)
        route_map_show (vty, rmap) ;
      else
        vty_route_map_not_found(vty, name) ;
    }
  else
    {
      /* Extract a vector of all route_maps, in name order.
       */
      vector extract ;
      vector_index_t  i ;

      extract = vhash_table_extract(route_maps->table, NULL, NULL, false,
                                                         route_map_sort_cmp) ;

      for (VECTOR_ITEMS(extract, rmap, i))
        {
          if (route_map_is_set(rmap))
            route_map_show (vty, rmap) ;
        } ;

      vector_free(extract) ;
    } ;

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * show the given route-map
 */
static void
route_map_show (struct vty *vty, route_map rmap)
{
  route_map_entry entry;
  struct route_map_rule *rule;

  /* Print the name of the protocol
   */
  if (zlog_default)
    vty_out (vty, "%s:%s", zlog_get_proto_name(NULL),
             VTY_NEWLINE);

  for (entry = ddl_head(rmap->base); entry; entry = ddl_next(entry, list))
    {
      vty_out (vty, "route-map %s, %s, sequence %lu%s",
               rmap->name, route_map_type_str (entry->type),
               (unsigned long)entry->seq, VTY_NEWLINE);
      confirm(sizeof(entry->seq) <= sizeof(unsigned long)) ;

      /* Description */
      if (entry->description != NULL)
        vty_out (vty, "  Description:%s    %s%s", VTY_NEWLINE,
                 entry->description, VTY_NEWLINE);

      /* Match clauses */
      vty_out (vty, "  Match clauses:%s", VTY_NEWLINE);
      for (rule = ddl_head(entry->match_list) ; rule != NULL ;
                                                rule = ddl_next(rule, list))
        vty_out (vty, "    %s %s%s",
                 rule->cmd->str, rule->rule_str, VTY_NEWLINE);

      vty_out (vty, "  Set clauses:%s", VTY_NEWLINE);
      for (rule = ddl_head(entry->set_list) ; rule != NULL ;
                                              rule = ddl_next(rule, list))
        vty_out (vty, "    %s %s%s",
                 rule->cmd->str, rule->rule_str, VTY_NEWLINE);

      /* Call clause */
      vty_out (vty, "  Call clause:%s", VTY_NEWLINE);
      if (entry->call_name != NULL)
        vty_out (vty, "    Call %s%s", entry->call_name, VTY_NEWLINE);

      /* Exit Policy */
      vty_out (vty, "  Action:%s", VTY_NEWLINE);
      switch (entry->exitpolicy)
      {
        case RMAP_GOTO:
          vty_out (vty, "    Goto %lu%s", (unsigned long)entry->goto_seq,
                                                                   VTY_NEWLINE);
          confirm(sizeof(entry->goto_seq) <= sizeof(unsigned long)) ;
          break ;

        case RMAP_NEXT:
          vty_out (vty, "    Continue to next entry%s", VTY_NEWLINE);
          break ;

        case RMAP_EXIT:
          vty_out (vty, "    Exit routemap%s", VTY_NEWLINE);
          break ;

        default:
          zabort("invalid route-map 'exitpolicy'") ;
      } ;
    }
}

/*------------------------------------------------------------------------------
 * Comparison function for sorting an extract from the access-lists
 */
static int
route_map_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb)
{
  route_map_c a = *pa ;
  route_map_c b = *pb ;

  return strcmp_mixed(a->name, b->name) ;
} ;

/*------------------------------------------------------------------------------
 * Generate not found error message and return CMD_WARNING
 */
static cmd_ret_t
vty_route_map_not_found(struct vty *vty, const char *name)
{
  vty_out (vty, "%% route-map %s not found\n", name);
  return CMD_WARNING;
} ;

/*==============================================================================
 * Route-Map Action
 *
 * The matrix for a route-map looks like this:
 *
 *             Match   |   No Match
 *                     |
 *   permit    action  |     next
 *                     |
 *   ------------------+---------------
 *                     |
 *   deny      deny    |     next
 *                     |
 *
 *  action)   - apply 'set' statements, accept route
 *
 *            - if 'call' statement is present call the specified route-map.
 *
 *              If the result of the called route-map is 'deny', then the result
 *              of the calling route-map is 'deny', as below.
 *
 *              If the result of the called route-map is not 'deny', then goes
 *              on to NEXT/GOTO/etc as follows.
 *
 *            - if NEXT is specified, goto NEXT statement
 *
 *              if there is no NEXT statement, we are finished.
 *
 *            - if GOTO is specified, step *forwards* to the first clause where
 *              seq >= goto_seq -- which will always step forwards to at least
 *              the next clause -- cannot go backwards !
 *
 *              if there is no such statement, we are finished.
 *
 *            - if nothing is specified, do as Cisco and finish
 *
 *            NB: 'finish' means the route is permitted by the route-map -- in
 *                its possibly new form.
 *
 *  deny)     - route is denied by route-map.
 *
 *              NB: the effect of any 'set' statements which have already been
 *                  executed remains -- deny cannot undo those.
 *
 *  next)     - proceed to the next entry
 *
 *              If there is no next entry, the route is denied (as above).
 *
 * If the route-map is empty or missing, all routes are denied (as above).
 * (There is an implicit route-map zzz deny at the end of every route-map.)
 */

/*------------------------------------------------------------------------------
 * Apply route map to the object.
 *
 * Returns:  RMAP_DENY_MATCH  -- matched a route-map 'deny' entry
 *                            -- did not match any entry in the route-map
 *                            -- the route-map is empty or not defined
 *
 *           RMAP_MATCH       -- matched at least one route-map entry
 *
 * NB:
 */
extern route_map_result_t
route_map_apply (route_map rmap, prefix_c pfx,
                                       route_map_object_t x_type, void *object)
{
  static int recursion = 0;
  route_map_entry re;
  route_map_object_t type ;
  bool do_set ;

  if (x_type & RMAP_NO_SET)
    {
      type   = x_type ^ RMAP_NO_SET ;
      do_set = false ;
    }
  else
    {
      type   = x_type ;
      do_set = true ;
    } ;

  if (rmap == NULL)
    return RMAP_DENY_MATCH;

  for (re = ddl_head(rmap->base) ; re != NULL ; re = ddl_next(re, list))
    {
      route_map_result_t  ret ;
      struct route_map_rule *match ;
      struct route_map_rule *set ;

      /* For match to succeed:
       *
       *   1) nothing to match to at all -- so no match statements => match
       *
       *   2) all match statements must match
       *
       * Expect match function to return: RMAP_NOT_MATCH  -- did not match
       *                              or: RMAP_MATCH      -- did match
       *
       * It is not clear why a match function should return anything else, but
       * anything else -> RMAP_DENY_MATCH.
       */
      ret = RMAP_MATCH ;
      for (match = ddl_head(re->match_list); match != NULL ;
                                                match = ddl_next(match, list))
        {
          ret = (*match->cmd->func_apply) (match->value, pfx, type, object) ;
          if (ret != RMAP_MATCH)
            break ;
          } ;

      if (ret == RMAP_NOT_MATCH)
        continue ;                      /* no match, so go on to next re  */

      if (ret != RMAP_MATCH)
        return RMAP_DENY_MATCH ;        /* unexpected -> RMAP_DENY_MATCH     */

      /* We have a RMAP_MATCH -- if type is RMAP_DENY, return RMAP_DENY_MATCH.
       *
       * The type may be RMAP_PERMIT or RMAP_DENY -- an RMAP_DENY re
       * terminates the route-rmap early.
       */
      if (re->type != RMAP_PERMIT)
        {
          qassert(re->type == RMAP_DENY) ;
          return RMAP_DENY_MATCH ;
        } ;

      /* We have a match (RMAP_MATCH) and we have 'set' operations, do those.
       */
      if (do_set)
        for (set = ddl_head(re->set_list) ; set != NULL ;
                                               set = ddl_next(set, list))
          {
            /* We expect a 'set' operation to return RMAP_OKAY or RMAP_ERROR.
             *
             * It is assumed that RMAP_ERROR is returned only if something has
             * gone badly wrong, and is treated as RMAP_DENY_MATCH.  But note
             * that it is too late to undo any set operations.
             *
             * It is not clear why a match function should return anything else,
             * but anything else -> RMAP_DENY_MATCH.
             */
            ret = (*set->cmd->func_apply) (set->value, pfx, type, object);

            if (ret != RMAP_OKAY)
              return RMAP_DENY_MATCH ;
          } ;

      /* Call another route-rmap if available
       *
       * Note that a missing or empty table is implicitly RMAP_DENY_MATCH in
       * in the usual way.
       */
      if (re->call_name != NULL)
        {
          recursion++;

          if (recursion <= RMAP_RECURSION_LIMIT)
            ret = route_map_apply (route_map_lookup(re->call_name),
                                                          pfx, type, object) ;
          else
            {
              zlog (NULL, LOG_WARNING,
                    "route-map recursion limit (%d) exceeded, discarding route",
                    RMAP_RECURSION_LIMIT);

              ret = RMAP_DENY_MATCH ;
            } ;

          recursion--;

          if (ret == RMAP_DENY_MATCH)
            return RMAP_DENY_MATCH ;
        } ;

      switch (re->exitpolicy)
        {
          case RMAP_EXIT:
            return RMAP_MATCH ;

          case RMAP_NEXT:
            break ;

          case RMAP_GOTO:
            {
              /* Find the next clause to jump to
               */
              route_map_seq_t goto_seq = re->goto_seq ;

              while (1)
                {
                  route_map_entry next_entry ;

                  next_entry = ddl_next(re, list) ;

                  if (next_entry == NULL)
                    break ;

                  if (next_entry->seq >= goto_seq)
                    break ;

                  re = next_entry ;
                } ;
              break ;
            } ;
        } ;
    } ;

  /* Run off the end of the route-rmap, into the implied 'deny' re.
   */
  return RMAP_DENY_MATCH;
} ;

/*==============================================================================
 * CLI
 */
DEFUN_ATTR (route_map_start,
           route_map_cmd,
           "route-map WORD (deny|permit) <1-4294967295>",
           "Create route-map or enter route-map command mode\n"
           "Route map tag\n"
           "Route map denies set operations\n"
           "Route map permits set operations\n"
           "Sequence to insert to/delete from existing route-map entry\n",
           CMD_ATTR_NODE + RMAP_NODE)
{
  route_map_type_t type;
  uint      seq;
  route_map rmap;
  char* endptr ;

  /* Permit/Deny -- already got through the parser, so assume is OK.
   */
  if (*((const char*)argv[1]) == 'p')
    type = RMAP_PERMIT;
  else
    type = RMAP_DENY;

  /* Sequence number -- already got through the parser, so assume is OK.
   */
  seq = strtoul (argv[2], &endptr, 0);
  confirm(sizeof(route_map_seq_t) <= sizeof(unsigned long)) ;

  /* Get route-map -- creates a new one if required.
   *
   * Since we are about to add an entry, if this is a new route-map, it must
   * now be "set" and the 'add_hook' kicked.
   *
   * (The route-map is "set" after the 'add_hook' is kicked, because do not
   *  want to have "set" when the list of entries is empty.)
   */
  rmap = route_map_find (argv[0]);

  if (!route_map_is_set(rmap))
    {
      if (route_maps->add_hook != NULL)
          route_maps->add_hook(rmap->name) ;

      vhash_set(rmap) ;
    } ;

  /* Get route-map -- creates a new one if required -- then add route-map
   * entry, if one does not already exist.
   *
   * Note that if an entry with the given 'seq' exists, but is of a different
   * 'type', then that entry is replaced (it is deleted and a new, empty entry
   * is inserted -- creating two 'event_hook' events).
   */
  vty->index = route_map_entry_get (rmap, type, seq) ;
  vty->node  = RMAP_NODE ;
  return CMD_SUCCESS;
}

DEFUN (no_route_map_all,
       no_route_map_all_cmd,
       "no route-map WORD",
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n")
{
  route_map rmap;

  rmap = route_map_lookup (argv[0]);
  if (rmap == NULL)
    return vty_route_map_not_found(vty, argv[0]) ;

  route_map_delete (rmap);

  return CMD_SUCCESS;
}

DEFUN (no_route_map,
       no_route_map_cmd,
       "no route-map WORD (deny|permit) <1-4294967295>",
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map denies set operations\n"
       "Route map permits set operations\n"
       "Sequence to insert to/delete from existing route-map entry\n")
{
  enum route_map_type permit;
  ulong           seq;
  route_map       rmap;
  route_map_entry re;
  char* endptr ;

  /* Permit/Deny -- already got through the parser, so assume is OK.
   */
  if (*((const char*)argv[1]) == 'p')
    permit = RMAP_PERMIT;
  else
    permit = RMAP_DENY;

  /* Sequence number -- already got through the parser, so assume is OK.
   */
  seq = strtoul (argv[2], &endptr, 0);
  confirm(sizeof(route_map_seq_t) <= sizeof(unsigned long)) ;

  /* Existence check.
   */
  rmap = route_map_lookup (argv[0]);
  if (rmap == NULL)
    return vty_route_map_not_found(vty, argv[0]) ;

  /* Lookup route map entry.
   */
  re = route_map_entry_lookup (rmap, permit, seq);
  if (re == NULL)
    {
      vty_out (vty, "%% route-map entry %s %s not found\n", argv[0], argv[2]) ;
      return CMD_WARNING;
    }

  /* Delete entry from route rmap.
   */
  route_map_entry_delete (re);

  /* If this route rule is the last one, delete route rmap itself.
   *
   * This will invoke the 'delete_hook' (if any).
   */
  if (route_map_is_empty (rmap))
    route_map_delete (rmap);

  return CMD_SUCCESS;
}

DEFUN (rmap_onmatch_next,
       rmap_onmatch_next_cmd,
       "on-match next",
       "Exit policy on matches\n"
       "Next clause\n")
{
  route_map_entry entry;

  entry = vty->index;

  if (entry)
    entry->exitpolicy = RMAP_NEXT;

  return CMD_SUCCESS;
}

DEFUN (no_rmap_onmatch_next,
       no_rmap_onmatch_next_cmd,
       "no on-match next",
       NO_STR
       "Exit policy on matches\n"
       "Next clause\n")
{
  route_map_entry entry;

  entry = vty->index;

  if (entry)
    entry->exitpolicy = RMAP_EXIT;

  return CMD_SUCCESS;
}

DEFUN (rmap_onmatch_goto,
       rmap_onmatch_goto_cmd,
       "on-match goto <1-4294967295>",
       "Exit policy on matches\n"
       "Goto Clause number\n"
       "Number\n")
{
  route_map_entry entry = vty->index;
  route_map_seq_t d = 0;

  if (entry)
    {
      if (argc == 1 && argv[0])
        /* TODO: why did the on-match goto range include 65536 ?        */
        VTY_GET_INTEGER_RANGE("route-map entry", d, argv[0], 1, 4294967295);
      else
        d = entry->seq + 1;

      if (d <= entry->seq)
        {
          /* Can't allow you to do that, Dave */
          vty_out (vty, "can't jump backwards in route-maps%s",
                   VTY_NEWLINE);
          return CMD_WARNING;
        }
      else
        {
          entry->exitpolicy = RMAP_GOTO;
          entry->goto_seq = d;
        }
    }
  return CMD_SUCCESS;
}

DEFUN (no_rmap_onmatch_goto,
       no_rmap_onmatch_goto_cmd,
       "no on-match goto",
       NO_STR
       "Exit policy on matches\n"
       "Goto Clause number\n")
{
  route_map_entry entry;

  entry = vty->index;

  if (entry)
    entry->exitpolicy = RMAP_EXIT;

  return CMD_SUCCESS;
}

/* Cisco/GNU Zebra compatible ALIASes for on-match next */
ALIAS (rmap_onmatch_goto,
       rmap_continue_cmd,
       "continue",
       "Continue on a different entry within the route-map\n")

ALIAS (no_rmap_onmatch_goto,
       no_rmap_continue_cmd,
       "no continue",
       NO_STR
       "Continue on a different entry within the route-map\n")

#if 0           // TODO should these be used somewhere ???
/* GNU Zebra compatible */
ALIAS (rmap_onmatch_goto,
       rmap_continue_seq_cmd,
       "continue <1-4294967295>",
       "Continue on a different entry within the route-map\n"
       "Route-map entry sequence number\n")

ALIAS (no_rmap_onmatch_goto,
       no_rmap_continue_seq,
       "no continue <1-4294967295>",
       NO_STR
       "Continue on a different entry within the route-map\n"
       "Route-map entry sequence number\n")
#endif

DEFUN (rmap_show_name,
       rmap_show_name_cmd,
       "show route-map [WORD]",
       SHOW_STR
       "route-map information\n"
       "route-map name\n")
{
    const char *name = NULL;
    if (argc)
      name = argv[0];
    return vty_show_route_map (vty, name);
}

ALIAS (rmap_onmatch_goto,
      rmap_continue_index_cmd,
      "continue <1-4294967295>",
      "Exit policy on matches\n"
      "Goto Clause number\n")

DEFUN (rmap_call,
       rmap_call_cmd,
       "call WORD",
       "Jump to another Route-Map after match+set\n"
       "Target route-map name\n")
{
  route_map_entry entry;

  entry = vty->index;
  if (entry)
    {
      if (entry->call_name != NULL)
          XFREE (MTYPE_ROUTE_MAP_NAME, entry->call_name);
      entry->call_name = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[0]);
    }
  return CMD_SUCCESS;
}

DEFUN (no_rmap_call,
       no_rmap_call_cmd,
       "no call",
       NO_STR
       "Jump to another Route-Map after match+set\n")
{
  route_map_entry entry;

  entry = vty->index;

  if (entry->call_name != NULL)
    {
      XFREE (MTYPE_ROUTE_MAP_NAME, entry->call_name);
      entry->call_name = NULL;
    }

  return CMD_SUCCESS;
}

DEFUN (rmap_description,
       rmap_description_cmd,
       "description .LINE",
       "Route-map comment\n"
       "Comment describing this route-map rule\n")
{
  route_map_entry entry;

  entry = vty->index;
  if (entry)
    {
      if (entry->description)
        XFREE (MTYPE_TMP, entry->description);
      entry->description = argv_concat (argv, argc, 0);
    }
  return CMD_SUCCESS;
}

DEFUN (no_rmap_description,
       no_rmap_description_cmd,
       "no description",
       NO_STR
       "Route-map comment\n")
{
  route_map_entry entry;

  entry = vty->index;
  if (entry)
    {
      if (entry->description)
        XFREE (MTYPE_TMP, entry->description);
      entry->description = NULL;
    }
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Configuration write function.
 */
static int
route_map_config_write (struct vty *vty)
{
  route_map      rmap;
  vector         extract ;
  vector_index_t i ;

  /* Extract a vector of all access_lists, in name order.
   */
  extract = vhash_table_extract(route_maps->table, NULL, NULL, false,
                                                           route_map_sort_cmp) ;

  for (VECTOR_ITEMS(extract, rmap, i))
    {
      route_map_entry re;
      route_map_rule  rule;

      for (re = ddl_head(rmap->base) ; re != NULL ;
                                          re = ddl_next(re, list))
        {
          vty_out_vtysh_config_group(vty, "route-map %s %s %u", rmap->name,
                                 route_map_type_str (re->type), re->seq) ;

          vty_out (vty, "route-map %s %s %u\n", rmap->name,
                                 route_map_type_str (re->type), re->seq) ;
          confirm(sizeof(re->seq) <= sizeof(uint)) ;

          if (re->description)
            vty_out (vty, " description %s\n", re->description);

          for (rule = ddl_head(re->match_list) ; rule != NULL ;
                                                  rule = ddl_next(rule, list))
            vty_out (vty, " match %s %s\n", rule->cmd->str,
                                          rule->rule_str ? rule->rule_str : "");

          for (rule = ddl_head(re->set_list) ; rule != NULL ;
                                                  rule = ddl_next(rule, list))
            vty_out (vty, " set %s %s\n", rule->cmd->str,
                                          rule->rule_str ? rule->rule_str : "");

          if (re->call_name != NULL)
            vty_out (vty, " call %s\n", re->call_name);

          if (re->exitpolicy == RMAP_GOTO)
            vty_out (vty, " on-match goto %lu\n", (ulong)re->goto_seq);
          confirm(sizeof(re->goto_seq) <= sizeof(ulong)) ;

          if (re->exitpolicy == RMAP_NEXT)
            vty_out (vty," on-match next\n");

          if (!vty_out_vtysh_config_group_end(vty))
            vty_out (vty, "!\n");
        } ;
    } ;

  vector_free(extract) ;

  return 0 ;
} ;

CMD_INSTALL_TABLE(static, routemap_cmd_table,
                            RIPD | RIPNGD | OSPFD | OSPF6D | BGPD | ZEBRA) =
{
  { CONFIG_NODE,     &route_map_cmd                                     },
  { CONFIG_NODE,     &no_route_map_cmd                                  },
  { CONFIG_NODE,     &no_route_map_all_cmd                              },

  /* Install the on-match stuff                         */
  { RMAP_NODE,       &route_map_cmd                                     },
  { RMAP_NODE,       &rmap_onmatch_next_cmd                             },
  { RMAP_NODE,       &no_rmap_onmatch_next_cmd                          },
  { RMAP_NODE,       &rmap_onmatch_goto_cmd                             },
  { RMAP_NODE,       &no_rmap_onmatch_goto_cmd                          },

  /* Install the continue stuff (ALIAS of on-match).    */
  { RMAP_NODE,       &rmap_continue_cmd                                 },
  { RMAP_NODE,       &no_rmap_continue_cmd                              },
  { RMAP_NODE,       &rmap_continue_index_cmd                           },

  /* Install the call stuff.                            */
  { RMAP_NODE,       &rmap_call_cmd                                     },
  { RMAP_NODE,       &no_rmap_call_cmd                                  },

  /* Install description commands.                      */
  { RMAP_NODE,       &rmap_description_cmd                              },
  { RMAP_NODE,       &no_rmap_description_cmd                           },

  /* Install show command */
  { ENABLE_NODE,     &rmap_show_name_cmd                                },

  CMD_INSTALL_END
} ;

/*------------------------------------------------------------------------------
 * Installation of routemap commands, and initialization of match/set options.
 *
 * MUST do this *before* installing matc/set clauses.
 */
extern void
route_map_cmd_init (void)
{
  /* Install route map top node & basic commands
   */
  cmd_install_node_config_write (RMAP_NODE, route_map_config_write);
  cmd_install_table(routemap_cmd_table) ;

  /* Make vector for match and set
   */
  route_match_vec = vector_init (1);
  route_set_vec   = vector_init (1);
} ;
