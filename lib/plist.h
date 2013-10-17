/*
 * Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _QUAGGA_PLIST_H
#define _QUAGGA_PLIST_H

#include "qafi_safi.h"
#include "prefix.h"
#include "sockunion.h"
#include "vty.h"

enum
{
  qAFI_ORF_PREFIX = qAFI_last + 1
} ;

enum prefix_list_type
{
  PREFIX_DENY,
  PREFIX_PERMIT,
};
typedef enum prefix_list_type prefix_list_type_t ;

typedef struct prefix_list  prefix_list_t ;
typedef struct prefix_list* prefix_list ;

typedef struct orf_prefix_value  orf_prefix_value_t ;
typedef struct orf_prefix_value* orf_prefix_value ;

struct orf_prefix_value
{
  uint32_t     seq ;
  prefix_list_type_t type ;
  prefix_len_t ge ;
  prefix_len_t le ;
  prefix_t     pfx ;
};

/* Name of a BGP ORF prefix list -- IP-99999
 */
enum
  {
    bgp_orf_name_len  = (((SU_ADDRSTRLEN + 1 + 5 + 1) + 7) / 8) * 8
  } ;
typedef char bgp_orf_name[bgp_orf_name_len] ;

/*==============================================================================
 * Prototypes.
 */
extern void prefix_list_cmd_init (void);
extern void prefix_list_init (void);
extern void prefix_list_reset (free_keep_b free);
extern void prefix_list_add_hook (void (*func) (prefix_list));
extern void prefix_list_delete_hook (void (*func) (prefix_list));

extern prefix_list prefix_list_lookup (qAFI_t, const char *);
extern prefix_list prefix_list_find (qAFI_t, const char *);
extern prefix_list_type_t prefix_list_apply (prefix_list, const void *);

extern prefix_list prefix_list_get_ref(qAFI_t q_afi, const char *name) ;
extern prefix_list prefix_list_set_ref(prefix_list plist) ;
extern prefix_list prefix_list_clear_ref(prefix_list plist) ;

extern bool prefix_list_is_active(prefix_list plist) ;
extern bool prefix_list_is_set(prefix_list plist) ;
extern const char* prefix_list_get_name(prefix_list plist) ;

extern void prefix_bgp_orf_name_set(bgp_orf_name, sockunion_c, uint16_t qafx) ;
extern bool prefix_bgp_orf_get(orf_prefix_value orfpv, prefix_list plist,
                                                              vector_index_t i);
extern cmd_ret_t prefix_bgp_orf_set (bgp_orf_name, qAFI_t, orf_prefix_value,
                                                                     bool set) ;
extern void prefix_bgp_orf_remove_all (bgp_orf_name);
extern prefix_list prefix_bgp_orf_delete(prefix_list plist) ;

extern int prefix_bgp_show_prefix_list (struct vty *, char *);

#endif /* _QUAGGA_PLIST_H */
