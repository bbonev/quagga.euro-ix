/* VTY SHELL -- VTY Shell Content -- header
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

#ifndef _ZEBRA_VTY_SHELL_CONTENT_H
#define _ZEBRA_VTY_SHELL_CONTENT_H

#include "misc.h"

#include "vty_common.h"
#include "command_parse.h"
#include "qstring.h"

/*==============================================================================
 * Handling of the content of groups/sections of commands for the vtysh
 * integrated configuration.
 *
 * To support the clean integration of common groups/sections of configuration
 * lines, this provides a mechanism to "parse" command lines in a group/section,
 * to identify implicit subgroups/subsections, and possibly specify a key for
 * lines/groups in groups/sections which are to be sorted.
 *
 * The content types are vct_xxxx values -- see command_common.h
 */
enum vtysh_content_parse_result
{
  vcp_line      = BIT(0),       /* An actual line item...               */
  vcp_meta_line = BIT(1),       /* ...or a meta line item...
                                 * ...or neither, but not both.         */

  vcp_group     = BIT(2),       /* A group change...                    */
  vcp_section   = BIT(3),       /* ...or a section change...
                                 * ...or neither, but not both.         */
} ;

typedef enum vtysh_content_parse_result vsp_result_t ;

typedef struct vtysh_content_parse* vtysh_content_parse ;
typedef struct vtysh_content_parse  vtysh_content_parse_t ;

/* If there is a content parser for a given content type, then each line is
 * passed (tokenised) to the content parser, along with a
 * vtysh_content_parse structure.
 */
struct vtysh_content_parse
{
  /* The current group/section depth is passed in.  The parser must not change
   * this !
   */
  uint            depth ;

  /* The result of the parse is encoded here.
   *
   * An incoming line may generate:
   *
   *          0               -- nothing at all, ignore the line
   *
   *   vcp_line               -- a line item in the current group/section
   *   vcp_line | vcp_group   -- a line item in the given group
   *   vcp_line | vcp_section -- a line item in the given section
   *
   *     in these cases the group/section selection is implicit.
   *
   *   vcp_meta_line | vcp_group   -- a line which selects a new group
   *   vcp_meta_line | vcp_section -- a line which selects a new section
   *
   *     in these cases the group/section selection is explicit, and there
   *     is no line item.
   */
  vsp_result_t    result ;

  /* If the current group/section is "sorted", if vcp_line then the line_key
   * is set to the required key.
   */
  qstring         line_key ;

  /* If the current group/section is "sorted", if vcp_group then the group_key
   * is set to the required key.
   */
  qstring         group_key ;

  /* If vcp_group or vcp_section, then the following describe the group/section
   * to be selected.
   */
  uint            new_depth ;
  qstring         new_name ;
  vtysh_content_t new_type ;

  /* If the content parser hits an error, a simple message is planted here.
   */
  const char*     error_msg ;
} ;

/*------------------------------------------------------------------------------
 * The content parser function is:
 */
typedef cmd_ret_t vtysh_content_func(vtysh_content_parse content,
                                                            cmd_parsed parsed) ;

/*==============================================================================
 * Functions
 */
extern const char* vtysh_content_type_name(vtysh_content_t sect) ;
extern vtysh_content_t vtysh_content_type(const char* name) ;
extern vtysh_content_func* vtysh_content_parser(vtysh_content_t sect) ;
extern bool vtysh_content_sorted(vtysh_content_t sect) ;

#endif /* _ZEBRA_VTY_SHELL_CONTENT_H */
