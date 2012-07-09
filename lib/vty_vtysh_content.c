/* VTY SHELL -- VTY Shell Content
 * Virtual terminal [aka TeletYpe] interface routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * Revisions: Copyright (C) 2010 Chris Hall (GMCH), Highwayman
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
#include "misc.h"

#include "vty_vtysh_content.h"

#include "filter.h"

/*==============================================================================
 * For the vtysh integrated configuration, some types of content are parsed
 * to extract the implicit group/section structure of the command lines.
 */

/*==============================================================================
 * Content type names and parser functions.
 */
static const char* const section_name_table[] =
{
    [vct_end]           = "end",

    [vct_basic]         = "basic",

    [vct_access_list]   = "access-list",
    [vct_prefix_list_s] = "prefix-list_s",
    [vct_prefix_list_u] = "prefix-list_u",
    [vct_route_maps]    = "route-map",
    [vct_keychain]      = "keychain",
} ;

CONFIRM((sizeof(section_name_table) / sizeof(const char*)) <= vct_unknown) ;

static const struct vtysh_content_table
{
  vtysh_content_func*   func ;
  bool                  sort ;

} section_parser_table[] =
{
    [vct_none]          = { .func = NULL,
                            .sort = false
                          },
    [vct_basic]         = { .func = NULL,
                            .sort = false
                          },
    [vct_access_list]   = { .func = &access_list_parse_section,
                            .sort = false
                          },
#if 0
    [vct_prefix_list_s] = &prefix_list_s_parse_section,
    [vct_prefix_list_u] = &prefix_list_u_parse_section,
    [vct_route_map]     = &route_map_parse_section,
    [vct_keychain]      = &key_chain_parse_section,
#endif
} ;

CONFIRM((sizeof(section_parser_table) / sizeof(struct vtysh_content_table))
                                                                <= vct_unknown) ;

/*------------------------------------------------------------------------------
 * Map content type to name
 */
extern const char*
vtysh_content_type_name(vtysh_content_t sect)
{
  const char* name ;

  if ((sect < vct_unknown) && (sect >= 0))
    name = section_name_table[sect] ;
  else
    name = NULL ;

  return (name != NULL) ? name : "*unknown*" ;
} ;

/*------------------------------------------------------------------------------
 * Map content type name to type -- returns vct_unknown if not recognised
 */
extern vtysh_content_t
vtysh_content_type(const char* name)
{
  vtysh_content_t sect ;

  for (sect = 0 ; sect < vct_unknown ; ++sect)
    {
      if (section_name_table[sect] != NULL)
        if (strcmp(section_name_table[sect], name) == 0)
          break ;
    } ;

  return sect ;
} ;

/*------------------------------------------------------------------------------
 * Map content type to parser function -- returns NULL if no parser function.
 *
 * Note that no parser function exists for vct_basic.
 */
extern vtysh_content_func*
vtysh_content_parser(vtysh_content_t sect)
{
  if ((sect < vct_unknown) && (sect >= 0))
    return section_parser_table[sect].func ;
  else
    return  NULL ;
} ;

/*------------------------------------------------------------------------------
 * Map content type to sorted flag -- returns false if not.
 *
 * Note that sorted is false for for vct_basic.
 */
extern bool
vtysh_content_sorted(vtysh_content_t sect)
{
  if ((sect < vct_unknown) && (sect >= 0))
    return section_parser_table[sect].sort ;
  else
    return false ;
} ;

