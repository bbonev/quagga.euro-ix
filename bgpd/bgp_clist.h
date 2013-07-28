/* BGP Community list.
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

#ifndef _QUAGGA_BGP_CLIST_H
#define _QUAGGA_BGP_CLIST_H

#include "vhash.h"
#include "list_util.h"
#include "bgp_community.h"
#include "bgp_ecommunity.h"
#include "bgp_regex.h"

/* Master Community-list.
 */
enum clist_type
{
  COMMUNITY_LIST,
  ECOMMUNITY_LIST,

  CLIST_TYPE_COUNT      /* for array by clist_type      */
} ;
typedef enum clist_type clist_type_t ;

/* Community-list deny and permit.
 */
enum clist_action_type
{
  COMMUNITY_DENY,
  COMMUNITY_PERMIT,

} ;
typedef enum clist_action_type clist_action_type_t ;

/* Community-list entry styles
 */
enum clist_entry_style
{
  COMMUNITY_LIST_STANDARD,      /* Standard community-list entry        */
  COMMUNITY_LIST_EXPANDED,      /* Expanded community-list entry        */
  ECOMMUNITY_LIST_STANDARD,     /* Standard extcommunity-list entry     */
  ECOMMUNITY_LIST_EXPANDED,     /* Expanded extcommunity-list entry     */
} ;
typedef enum clist_entry_style clist_entry_style_t ;

/*------------------------------------------------------------------------------
 * Community-list.
 */
typedef struct community_entry  community_entry_t ;
typedef struct community_entry* community_entry ;

typedef struct community_list  community_list_t ;
typedef struct community_list* community_list ;

typedef const struct community_list* community_list_c ;

struct community_list
{
  /* Lives in a vhash by name, and we have a pointer to the vhash_table.
   */
  vhash_node_t  vhash ;
  vhash_table   table ;         /* has a reference to the table */

  /* Community-list entry in this community-list.
   */
  struct dl_base_pair(community_entry) entries ;

  /* Name of community-list
   */
  char*  name ;                 /* MTYPE_COMMUNITY_LIST_NAME    */
};

CONFIRM(offsetof(community_list_t, vhash) == 0) ;       /* see vhash.h  */

/* Each entry in community-list.
 */
struct community_entry
{
  struct dl_list_pair(community_entry) list ;

  clist_action_type_t    action ;
  clist_entry_style_t    style;
  attr_community_type_t  act ;

  union
  {
    attr_community   comm ;
    attr_ecommunity  ecomm ;
    regex_t*         reg ;
    void*            any ;      /* NULL <=> "any" or "internet"         */
  } u ;

  char*     raw ;               /* NULL if standard style               */
};

/*------------------------------------------------------------------------------
 * Community-list handler.
 *
 * community_list_init() returns this structure as handler -- contains a
 * distinct set of community-list and extcommunity-list filters.
 *
 * Should it be required, this allows for multiple community-list name-spaces.
 */
typedef struct community_list_handler*  community_list_handler ;

extern community_list_handler bgp_clist ;

/*------------------------------------------------------------------------------
 * Error code of community-list.
 */
enum clist_err_type
{
  COMMUNITY_LIST_ERR_CANT_FIND_LIST     = -1,
  COMMUNITY_LIST_ERR_MALFORMED_VAL      = -2,
  COMMUNITY_LIST_ERR_STANDARD_CONFLICT  = -3,
  COMMUNITY_LIST_ERR_EXPANDED_CONFLICT  = -4,
  COMMUNITY_LIST_ERR_ENTRY_EXISTS       = -5,
} ;
typedef enum clist_err_type clist_err_type_t ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern community_list_handler community_list_init (void);
extern void community_list_terminate (community_list_handler);

extern community_list community_list_lookup (community_list_handler ch,
                                              clist_type_t what, const char *) ;
extern community_list community_list_get_ref(community_list_handler ch,
                                          clist_type_t what, const char *name) ;
extern community_list community_list_clear_ref(community_list list) ;

extern int community_list_set (community_list_handler ch, const char *name,
                                    const char *str, clist_action_type_t action,
                                                     clist_entry_style_t style);
extern int community_list_unset (community_list_handler ch,
                                     const char *name, const char *str,
                                                    clist_action_type_t action,
                                                    clist_entry_style_t style);
extern int community_list_unset_all(community_list_handler ch,
                                                             const char *name);
extern int extcommunity_list_set (community_list_handler ch, const char *name,
                                    const char *str, clist_action_type_t action,
                                                     clist_entry_style_t style);
extern int extcommunity_list_unset (community_list_handler ch,
                                     const char *name, const char *str,
                                                     clist_action_type_t action,
                                                     clist_entry_style_t style);
extern int extcommunity_list_unset_all(community_list_handler ch,
                                                             const char *name);

extern bool community_list_match (attr_community comm, community_list list);
extern bool ecommunity_list_match (attr_ecommunity ecomm, community_list list);
extern bool community_list_exact_match (attr_community comm,
                                                          community_list list);
extern attr_community community_list_match_delete (attr_community comm,
                                                           community_list list);
extern vector community_list_extract(community_list_handler ch,
                                     clist_type_t what,
                     vhash_select_test* selector, const void* p_val, bool most) ;

#endif /* _QUAGGA_BGP_CLIST_H */
