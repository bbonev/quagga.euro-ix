/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_ROUTEMAP_H
#define _ZEBRA_ROUTEMAP_H

#include "misc.h"
#include "prefix.h"
#include "list_util.h"

/* Route map's type.
 */
enum route_map_type
{
  RMAP_ANY,                     /* Used only as a look-up value         */

  RMAP_PERMIT,
  RMAP_DENY,
};

typedef enum route_map_type route_map_type_t ;

typedef enum
{
  RMAP_MATCH,                   /* ...                                  */
  RMAP_DENY_MATCH,               /*                                      */

  RMAP_NOT_MATCH,
  RMAP_ERROR,
  RMAP_OKAY
} route_map_result_t;

typedef enum
{
  RMAP_RIP,
  RMAP_RIPNG,
  RMAP_OSPF,
  RMAP_OSPF6,
  RMAP_BGP,
  RMAP_ZEBRA,

  RMAP_NO_SET  = BIT(7),
} route_map_object_t;

typedef enum
{
  RMAP_EXIT,
  RMAP_GOTO,
  RMAP_NEXT
} route_map_end_t;

typedef enum
{
  RMAP_EVENT_SET_ADDED,
  RMAP_EVENT_SET_DELETED,
  RMAP_EVENT_SET_REPLACED,
  RMAP_EVENT_MATCH_ADDED,
  RMAP_EVENT_MATCH_DELETED,
  RMAP_EVENT_MATCH_REPLACED,
  RMAP_EVENT_INDEX_ADDED,
  RMAP_EVENT_INDEX_DELETED
} route_map_event_t;

/* Depth limit in RMAP recursion using RMAP_CALL. */
#define RMAP_RECURSION_LIMIT      10

/* Route map rule structure for matching and setting.
 */
typedef struct route_map_rule_cmd  route_map_rule_cmd_t ;
typedef struct route_map_rule_cmd* route_map_rule_cmd ;
typedef const struct route_map_rule_cmd* route_map_rule_cmd_c ;

struct route_map_rule_cmd
{
  /* Route map rule name (e.g. as-path, metric)
   */
  const char *str;

  /* Function for value set or match.
   */
  route_map_result_t (*func_apply)(void *, prefix_c,
                                                  route_map_object_t, void *);

  /* Compile argument and return result as void *
   */
  void *(*func_compile)(const char *);

  /* Free allocated value by func_compile (). */
  void (*func_free)(void *);
};

/* Route map apply error -- or not
 */
enum rmap_rule_ret
{
  RMAP_RULE_OK      = 0,

  /* Route map rule is missing. */
  RMAP_RULE_MISSING,

  /* Route map rule can't compile */
  RMAP_COMPILE_ERROR
};

typedef enum rmap_rule_ret rmap_rule_ret_t ;

/*------------------------------------------------------------------------------
 * Route map rules.
 */
typedef struct route_map_rule  route_map_rule_t ;
typedef struct route_map_rule* route_map_rule ;

struct route_map_rule_list dl_base_pair(route_map_rule) ;

typedef struct route_map_rule_list  route_map_rule_list_t ;
typedef struct route_map_rule_list* route_map_rule_list ;

/* Route map entry and route map structures.
 */
typedef struct route_map  route_map_t ;
typedef struct route_map* route_map ;
typedef const struct route_map* route_map_c ;

typedef struct route_map_entry  route_map_entry_t ;
typedef struct route_map_entry* route_map_entry ;

typedef struct route_map_entry_list route_map_entry_list_t ;
struct route_map_entry_list dl_base_pair(route_map_entry) ;

typedef uint32_t route_map_seq_t ;

struct route_map_entry
{
  route_map  rmap;

  char* description;

  struct dl_list_pair(route_map_entry) list ;

  /* Preference of this route map rule.
   */
  route_map_seq_t       seq;

  /* Route map type permit or deny.
   */
  route_map_type_t      type;

  /* Do we follow old rules, or hop forward?
   */
  route_map_end_t       exitpolicy;

  /* If we're using "GOTO", to where do we go?
   */
  route_map_seq_t       goto_seq;

  /* If we're using "CALL", to which route-map do we go?
   */
  char *call_name;

  /* The lists of match and set rules
   */
  route_map_rule_list_t match_list ;
  route_map_rule_list_t set_list ;
};

/*------------------------------------------------------------------------------
 * A route-map -- ...
 */
struct route_map
{
  vhash_node_t  vhash ;

  char*         name ;

  struct dl_base_pair(route_map_entry) base ;
};

CONFIRM(offsetof(route_map_t, vhash) == 0) ;  /* see vhash.h  */

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void route_map_cmd_init (void);
extern void route_map_init (void);
extern void route_map_finish (void);

extern void route_map_add_hook (void (*func) (const char *));
extern void route_map_delete_hook (void (*func) (const char *));
extern void route_map_event_hook (void (*func) (route_map_event_t, const char *));

extern rmap_rule_ret_t route_map_add_match (route_map_entry re,
                                                 const char *match_name,
                                                 const char *match_arg);
extern rmap_rule_ret_t route_map_delete_match (route_map_entry re,
                                                 const char *match_name,
                                                 const char *match_arg);
extern rmap_rule_ret_t route_map_add_set (route_map_entry re,
                                                 const char *set_name,
                                                 const char *set_arg);
extern rmap_rule_ret_t route_map_delete_set (route_map_entry re,
                                                 const char *set_name,
                                                 const char *set_arg);

extern void route_map_install_match (route_map_rule_cmd_c cmd);
extern void route_map_install_set (route_map_rule_cmd_c cmd);

extern route_map route_map_lookup (const char *name);

extern route_map route_map_get_ref(const char *name) ;
extern route_map route_map_set_ref(route_map rmap) ;
extern route_map route_map_clear_ref(route_map rmap) ;
extern const char* route_map_get_name(route_map rmap) ;
extern bool route_map_is_set(route_map rmap) ;
extern bool route_map_is_active(route_map rmap) ;

extern route_map_result_t route_map_apply (route_map map, prefix_c pfx,
                                       route_map_object_t x_type, void* object);

#endif /* _ZEBRA_ROUTEMAP_H */
