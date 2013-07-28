/* BGP community-list and extcommunity-list.
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
#include "prefix.h"
#include "memory.h"
#include "vector.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"

/*==============================================================================
 * Community-list handler.
 *
 * Contains a set of community and extcommunity filters.
 *
 * NB: have separate name-spaces for community-list and extcommunity-list.
 *
 * Currently, no references are kept for community lists... all use (which is
 * in route-maps, only) looks up the community list by name, every time.
*/
struct community_list_handler
{
  vhash_table cl[CLIST_TYPE_COUNT] ;
} ;

/*------------------------------------------------------------------------------
 * Lookup master structure for community-list or extcommunity-list.
 */
static vhash_table
community_list_master_lookup (community_list_handler ch, clist_type_t what)
{
  if ((ch != NULL) && (what < CLIST_TYPE_COUNT) && (what >= 0))
    return ch->cl[what] ;
  else
    return NULL ;
}

/*==============================================================================
 * Prototypes as required.
 */
static void community_list_flush_entries(community_list clist) ;

/*==============================================================================
 * Functions for community-list and extcommunity-list lists.
 */

/*------------------------------------------------------------------------------
 * The community-list and extcommunity-list hash tables.
 */
static vhash_equal_func  community_list_vhash_equal ;
static vhash_new_func    community_list_vhash_new ;
static vhash_free_func   community_list_vhash_free ;
static vhash_orphan_func community_list_vhash_orphan ;

static const vhash_params_t bgp_clist_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = community_list_vhash_equal,
  .new    = community_list_vhash_new,
  .free   = community_list_vhash_free,
  .orphan = community_list_vhash_orphan,
} ;

/*------------------------------------------------------------------------------
 * Create and initialize a community-list handler.
 *
 * Returns:  new community-list handler
 *
 * NB: it is the caller's responsibility to community_list_terminate() at a
 *     suitable moment.
 */
struct community_list_handler*
community_list_init (void)
{
  community_list_handler ch;
  uint clt ;

  ch = XCALLOC (MTYPE_COMMUNITY_LIST_HANDLER,
                sizeof (struct community_list_handler));

  for (clt = 0 ; clt < CLIST_TYPE_COUNT ; ++ clt)
    ch->cl[clt] = vhash_table_new(NULL,   50 /* chain bases */,
                                          200 /* % density   */,
                                                      &bgp_clist_vhash_params) ;

  return ch;
} ;

/*------------------------------------------------------------------------------
 * Terminate community-list handler -- for shut-down.
 *
 * Currently there are no references -- so freeing the symbol tables and all
 * symbol bodies should do the trick.
 */
extern void
community_list_terminate (community_list_handler ch)
{
  uint clt ;

  for (clt = 0 ; clt < CLIST_TYPE_COUNT ; ++clt)
    ch->cl[clt] = vhash_table_reset(ch->cl[clt], free_it) ;

  XFREE (MTYPE_COMMUNITY_LIST_HANDLER, ch);
}

/*------------------------------------------------------------------------------
 * Allocate a new community-list.
 */
static vhash_item
community_list_vhash_new(vhash_table table, vhash_data_c data)
{
  community_list clist ;
  const char*    name = data ;

  clist = XCALLOC (MTYPE_COMMUNITY_LIST, sizeof(community_list_t)) ;

  /* Zeroising the new community_list has set:
   *
   *   vhash     -- all zero  -- not that this matters
   *   table     -- X         -- set below
   *
   *   head      -- NULL      -- empty list
   *   tail      -- NULL      -- empty list
   *
   *   name      -- NULL      -- set below
   */
  clist->table = vhash_table_inc_ref(table) ;

  clist->name = XSTRDUP(MTYPE_COMMUNITY_LIST_NAME, name) ;

  return clist ;
} ;

/*------------------------------------------------------------------------------
 * Compare name with community list name -- vhash_equal_func
 */
static int
community_list_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  community_list_c clist = item ;
  const char*      name  = data ;

  return strcmp(clist->name, name) ;
} ;

/*------------------------------------------------------------------------------
 * Free community list -- symbol_table func.free_body function
 *
 * Make sure is completely empty, first.
 */
static vhash_item
community_list_vhash_free(vhash_item item, vhash_table table)
{
  community_list clist = item ;

  community_list_flush_entries(clist) ;

  XFREE(MTYPE_COMMUNITY_LIST_NAME, clist->name) ;
  XFREE(MTYPE_COMMUNITY_LIST, clist) ;

  vhash_table_dec_ref(table) ;          /* table may vanish     */

  return NULL ;
}

/*------------------------------------------------------------------------------
 * Orphan the given community list -- symbol_table func.free_body function
 *
 * Make sure is empty and unset.
 */
static vhash_item
community_list_vhash_orphan(vhash_item item, vhash_table table)
{
  community_list clist = item ;

  community_list_flush_entries(clist) ;

  return vhash_unset(item, table) ;
}

/*------------------------------------------------------------------------------
 * Lookup -- do not create.
 */
extern community_list
community_list_lookup (community_list_handler ch, clist_type_t what,
                                                               const char *name)
{
  vhash_table table;

  if (!name)
    return NULL;

  table = community_list_master_lookup (ch, what);
  if (!table)
    return NULL;

  confirm(offsetof(community_list_t, vhash) == 0) ;
                                /* community_list_t == vhash_item_t     */

  return vhash_lookup(table, name, NULL /* don't add */) ;
}

/*------------------------------------------------------------------------------
 * Lookup and create if not found.
 *
 * If is "set", then we are about to set some part of the community list value,
 * so want to "symbol_set" the symbol.
 */
static community_list
community_list_get (community_list_handler ch, clist_type_t what,
                                                    const char* name, bool set)
{
  community_list clist;
  vhash_table    table;
  bool           added ;

  if (name == NULL)
    return NULL;

  table = community_list_master_lookup (ch, what);
  if (table == NULL)
    return NULL;

  clist = vhash_lookup(table, name, &added /* add if required */) ;

  if (set)
    vhash_set(clist) ;           /* the clist has some value     */

  return clist;
}

/*------------------------------------------------------------------------------
 * Get a reference to the community list of the given type and name.
 *
 * If a community-list has been defined, its symbol value will be "set".  If
 * a community-list has not (yet) been defined, then its symbol may be, and
 * if or when the community-list is defined, then all references to it will
 * see that.
 *
 * In any case, this returns the address of the symbol for the community list,
 * with the reference count incremented.
 *
 * Returns:  address of symbol, whose body is the community-list (which may be
 *           empty/unset).
 */
extern community_list
community_list_get_ref(community_list_handler ch, clist_type_t what,
                                                               const char *name)
{
  community_list list ;

  list = community_list_get(ch, what, name, false /* no value being set */) ;

  return vhash_inc_ref(list) ;  /* return ref_counted reference */
} ;

/*------------------------------------------------------------------------------
 * Finished with the given symbol reference.
 */
extern community_list
community_list_clear_ref(community_list clist)
{
  if (clist != NULL)
    vhash_dec_ref(clist, clist->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Flush contents of community list and unset the symbol.
 *
 * If there are no references, will free the symbol and the community list.
 */
static void
community_list_delete(community_list clist)
{
  community_list_flush_entries(clist) ;
  vhash_unset(clist, clist->table) ;
} ;

/*==============================================================================
 * Basic functions for creating/destroying community-list and extcommunity-list
 * entries.
 */

/*------------------------------------------------------------------------------
 * Allocate a new community list entry.
 */
static community_entry
community_entry_new (void)
{
  return XCALLOC (MTYPE_COMMUNITY_LIST_ENTRY, sizeof (community_entry_t));
}

/*------------------------------------------------------------------------------
 * Free community list entry.
 */
static void
community_entry_free (community_entry ce)
{
  switch (ce->style)
    {
    case COMMUNITY_LIST_STANDARD:
      if (ce->u.comm != NULL)
        attr_community_free (ce->u.comm);
      break;

    case ECOMMUNITY_LIST_STANDARD:
      if (ce->u.ecomm != NULL)
        attr_ecommunity_free (ce->u.ecomm);
      break;

    case COMMUNITY_LIST_EXPANDED:
    case ECOMMUNITY_LIST_EXPANDED:
      if (ce->u.reg != NULL)
        bgp_regex_free (ce->u.reg);

    default:
      break;
    } ;

  if (ce->raw != NULL)
    XFREE (MTYPE_COMMUNITY_LIST_RAW, ce->raw) ;

  XFREE(MTYPE_COMMUNITY_LIST_ENTRY, ce) ;
} ;

/*------------------------------------------------------------------------------
 * Flush away entire contents (all entries) of given community list.
 *
 * Leaves list completely empty, apart from symbol and name.
 */
static void
community_list_flush_entries(community_list clist)
{
  community_entry  ce ;

  if (clist == NULL)
    return ;

  /* Free body of clist
   */
  while ((ce = ddl_pop(&ce, clist->entries, list)) != NULL)
    community_entry_free (ce);

  qassert(ddl_head(clist->entries) == NULL) ;
  qassert(ddl_tail(clist->entries) == NULL) ;
}

/*------------------------------------------------------------------------------
 * Is given clist empty ?
 */
static bool
community_list_is_empty (community_list clist)
{
  return ddl_head(clist->entries) == NULL ;
}

/*------------------------------------------------------------------------------
 * Add community-list entry to the list -- always adds at the tail.
 */
static void
community_list_entry_add (community_list clist, community_entry ce)
{
  ddl_append(clist->entries, ce, list) ;
}

/*------------------------------------------------------------------------------
 * Delete community-list entry from the list.
 *
 * If the community-list becomes empty, delete the list and its symbol.
 */
static void
community_list_entry_delete (community_list clist, community_entry ce,
                                                      clist_entry_style_t style)
{
  ddl_del(clist->entries, ce, list) ;

  community_entry_free (ce);

  if (community_list_is_empty (clist))
    community_list_delete (clist);
} ;

/*------------------------------------------------------------------------------
 * Lookup community-list entry from the list.
 *
 * For COMMUNITY_LIST_STANDARD:  arg == address of an attr_community
 *                                      NULL for empty, "any" or "internet".
 *
 *     COMMUNITY_LIST_EXPANDED:  arg == address of string (raw) form of
 *                                      regex == "" for "any".
 */
static community_entry
community_list_entry_lookup (community_list clist, clist_entry_style_t style,
                                   clist_action_type_t action, const void *arg)
{
  community_entry ce;

  for (ce = ddl_head(clist->entries); ce; ce = ddl_next(ce, list))
    {
      if (ce->style != style)
        continue ;

      if (ce->action != action)
        continue ;

      switch (style)
        {
          case COMMUNITY_LIST_STANDARD:
            /* Note that attr_community_equal() will:
             *
             *   - treat ce-> u.comm NULL as empty, which will only be
             *     equal to an empty (NULL) arg.
             *
             *   - treat arg NULL as empty, which will only be
             *     equal to an empty (NULL) ce-> u.comm.
             */
            if (attr_community_equal(ce->u.comm, arg))
              return ce;
            break;

          case ECOMMUNITY_LIST_STANDARD:
            /* Note that attr_ecommunity_equal() will:
             *
             *   - treat ce-> u.ecomm NULL as empty, which will only be
             *     equal to an empty (NULL) arg.
             *
             *   - treat arg NULL as empty, which will only be
             *     equal to an empty (NULL) ce-> u.ecomm.
             */
            if (attr_ecommunity_equal(ce->u.ecomm, arg))
              return ce;
            break;

          case COMMUNITY_LIST_EXPANDED:
          case ECOMMUNITY_LIST_EXPANDED:
            /* Note that for expanded entries, neither ce->raw nor arg will
             * be NULL.
             */
            qassert((ce->raw != NULL) && (arg != NULL)) ;

            if (strcmp (ce->raw, arg) == 0)
              return ce;
            break;

          default:
            break;
        } ;
    } ;

  return NULL;
} ;

/*------------------------------------------------------------------------------
 * Compare given possible new entry with all existing entries.
 *
 * This is used to avoid creating duplicate entries in a community-list.
 *
 * Returns:  true <=> the given possible new entry would be a duplicate
 */
static bool
community_list_dup_check (community_list clist, community_entry new_ce)
{
  community_entry  ce;

  for (ce = ddl_head(clist->entries) ; ce ; ce = ddl_next(ce, list))
    {
      if (ce->style != new_ce->style)
        continue;

      if (ce->action != new_ce->action)
        continue;

      if ((ce->u.any == NULL) || (new_ce->u.any == NULL))
        {
          if (ce->u.any == new_ce->u.any)
            return true ;       /* "any" == "any"               */

          continue ;            /* "any" != anything else       */
        } ;

      switch (ce->style)
        {
          case COMMUNITY_LIST_STANDARD:
            if (attr_community_equal(ce->u.comm, new_ce->u.comm))
              return true ;
            break;

          case ECOMMUNITY_LIST_STANDARD:
            if (attr_ecommunity_equal(ce->u.ecomm, new_ce->u.ecomm))
              return true ;
            break;

          case COMMUNITY_LIST_EXPANDED:
          case ECOMMUNITY_LIST_EXPANDED:
            if (strcmp (ce->raw, new_ce->raw) == 0)
              return true ;
            break;

          default:
            break;
        } ;
    } ;

  return false ;
} ;

/*==============================================================================
 * Functions for setting and clearing community-list and ecommunity list
 * entries -- from CLI/configuration.
 */

/*------------------------------------------------------------------------------
 * Set community-list.
 */
extern int
community_list_set (community_list_handler ch, const char *name,
        const char *str, clist_action_type_t action, clist_entry_style_t style)
{
  community_entry ce ;
  community_list  clist;
  attr_community  comm ;
  regex_t*        regex ;
  attr_community_type_t act ;

  /* Get community list.
   */
  clist = community_list_get (ch, COMMUNITY_LIST, name, true /* set */);

  /* When community-list already has entry, new entry should have same
   * style.  If you want to have mixed style community-list, you can
   * comment out this check.
   */
  if (!community_list_is_empty (clist))
    {
      clist_entry_style_t  list_style ;

      list_style = ddl_head(clist->entries)->style ;

      if (style != list_style)
        return (list_style == COMMUNITY_LIST_STANDARD
                                      ? COMMUNITY_LIST_ERR_STANDARD_CONFLICT
                                      : COMMUNITY_LIST_ERR_EXPANDED_CONFLICT);
    } ;

  /* Start by trying to construct a community object.  For expanded
   * entry this spots the empty, 'any' and 'internet' cases.
   *
   * Treats NULL or empty (other than whitespace) string as match "any"
   */
  comm  = attr_community_from_str(str, &act) ;
  regex = NULL ;

  switch (style)
    {
      case COMMUNITY_LIST_STANDARD:
        /* For standard community-list we must have received a valid list.
         *
         * If is empty/internet/any -- comm will be NULL, which is the signal
         * that we are matching anything and everything.
         *
         * Any other extra stuff (eg 'none' or 'additive') we reject.
         */
        switch (act)
          {
            case act_simple:
              qassert(comm->list.len != 0) ;
              break ;

            case act_empty:
            case act_internet:
            case act_any:
              qassert(comm == NULL) ;
              break ;

            case act_additive:
            default:
              comm = attr_community_free(comm) ;
              fall_through ;

            case act_none:
            case act_invalid:
              qassert(comm == NULL) ;
              return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
          } ;
        break ;

      case COMMUNITY_LIST_EXPANDED:
        /* For expanded community-list we treat as a regex, except that if is
         * empty/internet/any we set up a NULL regex, to signal that we are
         * matching anything and everything.  Also set the "raw" string to
         * the full "value" for this pseudo-regex
         *
         * We have parsed the string as a standard community-list in order to
         * pick out the empty/internet/any cases.  We are not otherwise
         * interested in the result.
         */
        comm = attr_community_free(comm) ;

        switch (act)
          {
            case act_empty:
              str = "" ;
              break ;                 /* leave the regex NULL */

            case act_internet:
              str = "internet" ;
              break ;                 /* leave the regex NULL */

            case act_any:
              str = "any" ;
              break ;                 /* leave the regex NULL */

            default:
              regex = bgp_regcomp (str) ;

              if (regex == NULL)
                return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
              break ;
          } ;

        qassert(str != NULL) ;  /* NULL str will be returned act_empty
                                 * by attr_community_from_str()         */
        break ;

      default:
        /* Anything else is invalid
         */
        attr_community_free(comm) ;
        return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
    } ;

  /* OK so far: create new entry
   */
  ce = community_entry_new () ;
  ce->action = action ;
  ce->style  = style ;
  ce->act    = act ;

  if (style == COMMUNITY_LIST_STANDARD)
    {
      ce->u.comm = comm ;    /* NULL <=> empty, "any" or "internet"  */
      ce->raw    = NULL ;
    }
  else
    {
      ce->u.reg  = regex ;   /* NULL <=> empty, "any" or "internet"  */
      ce->raw    = XSTRDUP (MTYPE_COMMUNITY_LIST_RAW, str) ;
    } ;

  /* Do not put duplicated community entry.
   */
  if (community_list_dup_check (clist, ce))
    {
      community_entry_free (ce);
      return COMMUNITY_LIST_ERR_ENTRY_EXISTS ;
    } ;

  community_list_entry_add (clist, ce);
  return 0;
}

/*------------------------------------------------------------------------------
 * Unset community-list entry.
 *
 * If result is an empty community-list, unset it.
 */
extern int
community_list_unset (community_list_handler ch, const char *name,
                                    const char *str, clist_action_type_t action,
                                                     clist_entry_style_t style)
{
  community_list  clist;
  community_entry ce ;
  attr_community  comm ;
  const void*     arg ;
  attr_community_type_t act ;

  /* Lookup community list.
   */
  clist = community_list_lookup (ch, COMMUNITY_LIST, name);
  if (clist == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  /* Prepare to lookup entry
   *
   * Treats NULL or empty (other than whitespace) string as match "any"
   */
  comm = attr_community_from_str(str, &act) ;

  switch (style)
    {
      case COMMUNITY_LIST_STANDARD:
        /* For standard community-list we must have received a valid list.
         *
         * If is empty/internet/any -- comm will be NULL, which is the signal
         * that we are matching anything and everything.
         *
         * Any other extra stuff (eg 'none' or 'additive') we reject.
         */
        switch (act)
          {
            case act_simple:
              qassert(comm->list.len != 0) ;
              break ;

            case act_empty:
            case act_internet:
            case act_any:
              qassert(comm == NULL) ;
              break ;

              if (comm == NULL)
                return COMMUNITY_LIST_ERR_MALFORMED_VAL ;

            case act_additive:
            default:
              comm = attr_community_free(comm) ;
              fall_through ;

            case act_none:
            case act_invalid:
              qassert(comm == NULL) ;
              return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
          } ;

        arg = comm ;
        break ;

      case COMMUNITY_LIST_EXPANDED:
        /* For expanded community-list we treat as a regex, except that if is
         * empty/internet/any then that is the regex "value", which matches
         * anything.
         *
         * We have parsed the string as a standard community-list in order to
         * pick out the empty/internet/any cases.  We are not otherwise
         * interested in the result.
         */
        comm = attr_community_free(comm) ;

        switch (act)
          {
            case act_empty:
              str = "" ;
              break ;

            case act_internet:
              str = "internet" ;
              break ;

            case act_any:
              str = "any" ;
              break ;

            default:
              break ;
          } ;

        arg = str ;

        qassert(arg != NULL) ;  /* NULL str will be returned act_empty
                                 * by attr_community_from_str()         */
        break ;

      default:
        /* Anything else is invalid
         */
        attr_community_free(comm) ;
        return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
    } ;

  /* For COMMUNITY_LIST_STANDARD:  arg == address of an attr_community
   *                                      NULL for empty, "any" or "internet".
   *
   *     COMMUNITY_LIST_EXPANDED:  arg == address of string (raw) form of
   *                                      regex == "" for "any".
   */
  ce = community_list_entry_lookup (clist, style, action, arg) ;

  if (comm != NULL)
    comm = attr_community_free(comm) ;

  if (ce == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  community_list_entry_delete (clist, ce, style);

  return 0;
} ;

/*------------------------------------------------------------------------------
 * Unset community-list -- discard all entries and delete.
 */
extern int
community_list_unset_all(community_list_handler ch, const char *name)
{
  community_list  list;

  list = community_list_lookup (ch, COMMUNITY_LIST, name);
  if (list == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  community_list_delete (list);
  return 0;
} ;

/*------------------------------------------------------------------------------
 * Set extcommunity-list entry
 *
 * A NULL or empty string => wild-card match.
 */
extern int
extcommunity_list_set (community_list_handler ch, const char *name,
                                    const char *str, clist_action_type_t action,
                                                     clist_entry_style_t style)
{
  community_entry  ce ;
  community_list   clist;
  attr_ecommunity  ecomm ;
  regex_t*         regex ;
  attr_community_type_t act ;

  /* Get community list
   */
  clist = community_list_get (ch, ECOMMUNITY_LIST, name, true /* set */) ;

  /* When community-list already has entry, new entry should have same style.
   *
   * If you want to have mixed style extcommunity-list, you can comment out
   * this check.
   */
  if (!community_list_is_empty (clist))
    {
      clist_entry_style_t  list_style ;

      list_style = ddl_head(clist->entries)->style ;

      if (style != list_style)
        return (list_style == ECOMMUNITY_LIST_STANDARD
                                      ? COMMUNITY_LIST_ERR_STANDARD_CONFLICT
                                      : COMMUNITY_LIST_ERR_EXPANDED_CONFLICT);
    } ;

  /* Strip leading spaces and convert NULL string to empty string.
   */
  if (str == NULL)
    str = "" ;
  else
    {
      while ((*str <= ' ') && (*str != '\0'))
        ++str ;
    } ;

  /* Set either ecomm or regex, depending on the style.
   *
   * Except that if this is a wild-card match, set both to NULL.
   */
  if (*str == '\0')
    {
      ecomm = NULL ;                    /* signal wild-card     */
      regex = NULL ;                    /* ditto                */
      act   = act_empty ;               /* only one form        */
    }
  else
    {
      act = act_simple ;                  /* not wild-card        */

      switch (style)
        {
          case COMMUNITY_LIST_STANDARD:
            /* For standard extcommunity-list we want valid ecommunities.
             *
             */
            ecomm = attr_ecommunity_from_str(str, true /* with prefix */, 0) ;
            regex = NULL ;

            if (ecomm == NULL)
              return COMMUNITY_LIST_ERR_MALFORMED_VAL ;

            break ;

          case COMMUNITY_LIST_EXPANDED:
            /* For expanded community-list we treat string as a regex.
             */
            ecomm = NULL ;
            regex = bgp_regcomp (str) ;

            if (regex == NULL)
              return COMMUNITY_LIST_ERR_MALFORMED_VAL ;

            break ;

          default:
            /* Anything else in invalid
             */
            return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
        } ;
    } ;

  /* OK so far: create new entry
   */
  ce = community_entry_new () ;
  ce->action = action ;
  ce->style  = style ;
  ce->act    = act ;

  if (style == COMMUNITY_LIST_STANDARD)
    {
      ce->u.ecomm = ecomm ;
      ce->raw     = NULL ;
    }
  else
    {
      ce->u.reg = regex;
      ce->raw   = XSTRDUP (MTYPE_COMMUNITY_LIST_RAW, str) ;
    } ;

  /* Do not put duplicated community entry.
   */
  if (community_list_dup_check (clist, ce))
    {
      community_entry_free (ce);
      return COMMUNITY_LIST_ERR_ENTRY_EXISTS ;
    } ;

  community_list_entry_add (clist, ce);
  return 0;
} ;

/*------------------------------------------------------------------------------
 * Unset extcommunity-list entry.
 *
 * If result is an empty extcommunity-list, unset it.
 */
extern int
extcommunity_list_unset (community_list_handler ch, const char *name,
                                    const char *str, clist_action_type_t action,
                                                     clist_entry_style_t style)
{
  community_entry  ce ;
  community_list   clist;
  attr_ecommunity  ecomm;
  const void*      arg ;

  clist = community_list_lookup (ch, ECOMMUNITY_LIST, name);
  if (clist == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  /* Strip leading spaces and convert NULL string to empty string.
   */
  if (str == NULL)
    str = "" ;
  else
    {
      while ((*str <= ' ') && (*str != '\0'))
        ++str ;
    } ;

  /* Construct argument to lookup.
   */
  if (*str == '\0')
    {
      ecomm = NULL ;                    /* no ecommunities      */
      arg   = NULL ;                    /* lookup wild-card     */
    }
  else
    {
      switch (style)
        {
          case COMMUNITY_LIST_STANDARD:
            /* For standard extcommunity-list we want valid ecommunities.
             */
            ecomm = attr_ecommunity_from_str(str, true /* with prefix */, 0) ;

            if (ecomm == NULL)
              return COMMUNITY_LIST_ERR_MALFORMED_VAL ;

            arg = ecomm ;
            break ;

          case COMMUNITY_LIST_EXPANDED:
            /* For expanded community-list we treat string as a regex.
             */
            ecomm = NULL ;              /* no ecommunities      */
            arg   =  str ;

            break ;

          default:
            /* Anything else in invalid
             */
            return COMMUNITY_LIST_ERR_MALFORMED_VAL ;
        } ;
    } ;

  /* Lookup and delete if find
   */
  ce = community_list_entry_lookup (clist, style, action, arg) ;

  if (ecomm != NULL)
    ecomm = attr_ecommunity_free(ecomm) ;

  if (ce == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  community_list_entry_delete (clist, ce, style);

  return 0;
} ;

/*------------------------------------------------------------------------------
 * Unset extcommunity-list -- discard all entries and delete.
 */
extern int
extcommunity_list_unset_all(community_list_handler ch, const char *name)
{
  community_list  clist;

  clist = community_list_lookup (ch, COMMUNITY_LIST, name);
  if (clist == NULL)
    return COMMUNITY_LIST_ERR_CANT_FIND_LIST;

  community_list_delete (clist);
  return 0;
} ;

/*==============================================================================
 * Functions to run match operations
 */
inline static bool
community_regexp_match (attr_community comm, regex_t* reg)
{
  return regexec (reg, attr_community_str (comm), 0, NULL, 0) == 0 ;
}

inline static bool
ecommunity_regexp_match (attr_ecommunity ecomm, regex_t* reg)
{
  return regexec (reg, attr_ecommunity_str (ecomm), 0, NULL, 0) == 0 ;
}

/*------------------------------------------------------------------------------
 * Delete community attribute using regular expression match.
 *
 * Return modified attr_community.
 */
static attr_community
community_regexp_delete (attr_community comm, regex_t* reg)
{
  uint  iv, ic ;
  vector text_v ;

  if (comm == NULL)
    return NULL;

  text_v = attr_community_text_vector(comm) ;
  ic = 0 ;
  for (iv = 0 ; iv < vector_length(text_v) ; iv++)
    {
      const char* text ;

      text = vector_get_item(text_v, iv) ;

      if (regexec(reg, text, 0, NULL, 0) == 0)
        comm = attr_community_drop_value(comm, ic) ;
      else
        ++ic ;
    } ;

  return comm;
} ;

/*------------------------------------------------------------------------------
 * Does the given community attribute match the given community-list ?
 *
 * Returns:  true <=> have a match and was 'permit'
 *           false => no match -- including an empty or list
 *                    or have a match and was 'deny'
 */
extern bool
community_list_match (attr_community comm, community_list clist)
{
  community_entry ce;

  for (ce = ddl_head(clist->entries) ; ce; ce = ddl_next(ce, list))
    {
      switch (ce->style)
        {
          case COMMUNITY_LIST_STANDARD:
            if (attr_community_match (comm, ce->u.comm))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          case COMMUNITY_LIST_EXPANDED:
            if ((ce->u.reg == NULL)
                                || community_regexp_match (comm, ce->u.reg))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          default:
            return false ;
        } ;
    } ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Does the given ecommunity attribute match the given ecommunity-list ?
 *
 * Returns:  true <=> have a match and was 'permit'
 *           false => no match -- including an empty or list
 *                    or have a match and was 'deny'
 */
extern bool
ecommunity_list_match (attr_ecommunity ecomm, community_list clist)
{
  community_entry ce;

  for (ce = ddl_head(clist->entries) ; ce; ce = ddl_next(ce, list))
    {
      switch (ce->style)
        {
          case ECOMMUNITY_LIST_STANDARD:
            if (attr_ecommunity_match (ecomm, ce->u.ecomm))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          case ECOMMUNITY_LIST_EXPANDED:
            if ((ce->u.reg == NULL)
                               || ecommunity_regexp_match (ecomm, ce->u.reg))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          default:
            return false ;
        } ;
    } ;

  return false ;
}

/*------------------------------------------------------------------------------
 * Perform exact matching.
 *
 * In case of expanded community-list, do same thing as community_list_match().
 *
 * Returns:  true <=> have a match and was 'permit'
 *           false => no match -- including an empty or list
 *                    or have a match and was 'deny'
 *
 * The only difference between this and ecommunity_list_match() is that when
 * matching a COMMUNITY_LIST_STANDARD entry, if is not a "wild-card", the two
 * communities must be exactly equal.
 */
extern bool
community_list_exact_match (attr_community comm, community_list clist)
{
  community_entry ce;

  for (ce = ddl_head(clist->entries) ; ce; ce = ddl_next(ce, list))
    {
      if (ce->u.any == NULL)
        return ce->action == COMMUNITY_PERMIT ;

      switch (ce->style)
        {
          case COMMUNITY_LIST_STANDARD:
            if (attr_community_equal (comm, ce->u.comm))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          case COMMUNITY_LIST_EXPANDED:
            if (community_regexp_match (comm, ce->u.reg))
              return ce->action == COMMUNITY_PERMIT ;
            break ;

          default:
            return false ;
        } ;
    } ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Delete all permitted communities in the list from comm.
 *
 * Stop if meets a 'deny' which matches.
 *
 * Note that where a community-list entry matches a number of communities,
 * will only delete those if all are present.  So:
 *
 *   ip community-list 500 permit 100:10 100:20
 *
 * will delete both 100:10 and 100:20, iff both are present.
 */
extern attr_community
community_list_match_delete (attr_community comm, community_list clist)
{
  community_entry  ce ;

  for (ce = ddl_head(clist->entries); ce; ce = ddl_next(ce, list))
    {
      if (comm->list.len == 0)
        break ;

      if (ce->u.any == NULL)
        {
          /* Got a "wild-card" match:
           *
           *   if 'permit', empty out the communities and return the result
           *
           *   if 'deny', stop now and return what we have.
           */
          if (ce->action == COMMUNITY_PERMIT)
            comm = attr_community_clear(comm) ;

          return comm ;
        } ;

      switch (ce->style)
        {
          case COMMUNITY_LIST_STANDARD:
            if (attr_community_match (comm, ce->u.comm))
              {
                if (ce->action == COMMUNITY_PERMIT)
                  comm = attr_community_del_list(comm, ce->u.comm) ;
                else
                  return comm ;         /* stop on 'deny'       */
              } ;

            break ;

          case COMMUNITY_LIST_EXPANDED:
            if (community_regexp_match (comm, ce->u.reg))
              {
                if (ce->action == COMMUNITY_PERMIT)
                  comm = community_regexp_delete(comm, ce->u.reg) ;
                else
                  return comm ;         /* stop on 'deny'       */
              } ;
            break ;

          default:
            return comm ;               /* stop on invalid      */
       } ;
    } ;

  return comm;
} ;

/*==============================================================================
 * Printing and configuration support.
 */

static int
community_list_sort_cmp(const vhash_item_c* pa, const vhash_item_c* pb)
{
  community_list_c a = *pa ;
  community_list_c b = *pb ;

  return strcmp_mixed(a->name, b->name ) ;
} ;

/*------------------------------------------------------------------------------
 * Make a sorted extract of the given type of community-list.
 *
 * Returns:  brand new vector containing the extract
 *           NULL if the table is
 */
extern vector
community_list_extract(community_list_handler ch, clist_type_t what,
                      vhash_select_test* selector, const void* p_val, bool most)
{
  vhash_table table ;

  table = community_list_master_lookup (ch, what);

  return vhash_table_extract(table, selector, p_val, most,
                                                      community_list_sort_cmp) ;
} ;

