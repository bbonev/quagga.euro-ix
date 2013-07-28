/*
 * Route filtering function.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_FILTER_H
#define _ZEBRA_FILTER_H

#include "zebra.h"
#include "if.h"
#include "vty_vtysh_content.h"

/* Filter type is made by `permit', `deny' and `dynamic'.
 */
enum filter_type
{
  FILTER_DENY,
  FILTER_PERMIT,
  FILTER_DYNAMIC
};

typedef struct access_list  access_list_t ;
typedef struct access_list* access_list ;

/* Prototypes for access-list.
 */
extern void access_list_cmd_init (void);
extern void access_list_init (void);
extern void access_list_reset (free_keep_b free);

extern void access_list_add_hook (void (*func)(access_list));
extern void access_list_delete_hook (void (*func)(access_list));

extern access_list access_list_lookup(qAFI_t afi, const char *);
extern access_list access_list_find(qAFI_t afi, const char *);

extern access_list access_list_get_ref(qAFI_t q_afi, const char *name) ;
extern access_list access_list_set_ref(access_list alist) ;
extern access_list access_list_clear_ref(access_list alist) ;
extern const char* access_list_get_name(access_list alist) ;
extern bool access_list_is_set(access_list alist) ;
extern bool access_list_is_active(access_list alist) ;

extern enum filter_type access_list_apply (access_list alist,
                                                           const void* object) ;

extern cmd_ret_t access_list_parse_section(vtysh_content_parse cp,
                                                            cmd_parsed parsed) ;

#endif /* _ZEBRA_FILTER_H */
