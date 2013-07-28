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

#ifndef _QUAGGA_BGP_FILTER_H
#define _QUAGGA_BGP_FILTER_H

enum as_filter_type
{
  AS_FILTER_DENY,
  AS_FILTER_PERMIT
};

typedef enum as_filter_type as_filter_type_t ;

typedef struct as_list  as_list_t ;
typedef struct as_list* as_list ;

extern void bgp_filter_cmd_init (void);
extern void bgp_filter_init (void);
extern void bgp_filter_reset (void);

extern void as_list_add_hook (void (*func) (void));
extern void as_list_delete_hook (void (*func) (void));

extern as_list as_list_lookup (const char* name);
extern as_list as_list_find(const char* name) ;
extern as_list as_list_get_ref(const char* name) ;
extern as_list as_list_set_ref(as_list flist) ;
extern as_list as_list_clear_ref(as_list flist) ;
extern const char* as_list_get_name(as_list flist) ;
extern bool as_list_is_set(as_list flist) ;
extern bool as_list_is_active(as_list flist) ;

extern as_filter_type_t as_list_apply (as_list, void *);



#endif /* _QUAGGA_BGP_FILTER_H */
