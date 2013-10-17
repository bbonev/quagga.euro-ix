/* BGP VTY interface for Community and Ext-Community.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * Recast: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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
#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_clist_vty.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
//#include "bgpd/bgp_ecommunity.h"

#include "memory.h"
#include "command.h"
#include "vty.h"
#include "log.h"
#include "memory.h"
#include "hash.h"
#include "prefix.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *
community_action_str (clist_action_type_t action)
{
  switch (action)
    {
    case COMMUNITY_DENY:
      return "deny";
    case COMMUNITY_PERMIT:
      return "permit";
    default:
      return "unknown";
    }
}

/* Display error string.  */
static void
community_list_perror (struct vty *vty, int ret)
{
  switch (ret)
    {
    case COMMUNITY_LIST_ERR_CANT_FIND_LIST:
      vty_out (vty, "%% Can't find community-list\n");
      break;
    case COMMUNITY_LIST_ERR_MALFORMED_VAL:
      vty_out (vty, "%% Malformed community-list value\n");
      break;
    case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
      vty_out (vty, "%% Community name conflict, "
                                  "previously defined as standard community\n");
      break;
    case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
      vty_out (vty, "%% Community name conflict, "
                                  "previously defined as expanded community\n");
      break;
    case COMMUNITY_LIST_ERR_ENTRY_EXISTS:
      vty_out (vty, "%% Community-list entry already exists\n");
      break;
    default:
      break ;
    }
}

/*------------------------------------------------------------------------------
 * VTY interface for community_set() function.
 */
static int
community_list_set_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;
  clist_action_type_t action ;
  char *str;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    }

  /* Check the list type.
   */
  switch (argv[1][0])
    {
      case 'p':
        action = COMMUNITY_PERMIT ;
        break ;

      case 'd':
        action = COMMUNITY_DENY;
        break ;

      default:
        vty_out (vty, "%% Matching condition must be permit or deny\n") ;
        return CMD_WARNING;
    } ;

  /* When community_list_set() return negative value, it means malformed
   * community string or a clash of style.
   */
  str = argv_concat (argv, argc, 2);

  ret = community_list_set (bgp_clist, argv[0], str, action, style);

  XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      /* Display error string.  */
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Community-list entry delete.
 */
static int
community_list_unset_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    } ;

  if (argc < 2)
    {
      ret = community_list_unset_all (bgp_clist, argv[0]);
    }
  else
    {
      clist_action_type_t action ;
      char* str ;

      switch (argv[1][0])
        {
          case 'p':
            action = COMMUNITY_PERMIT ;
            break ;

          case 'd':
            action = COMMUNITY_DENY;
            break ;

          default:
            vty_out (vty, "%% Matching condition must be permit or deny\n") ;
            return CMD_WARNING;
        } ;

      /* Concat community string argument and unset the relevant entry.
       */
      str = argv_concat (argv, argc, 2) ;

      ret = community_list_unset (bgp_clist, argv[0], str, action, style);

      XFREE (MTYPE_TMP, str);
    } ;

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"
#define COMMUNITY_VAL_STR  "Community number in aa:nn format or internet|local-AS|no-advertise|no-export\n"

DEFUN (ip_community_list_standard,
       ip_community_list_standard_cmd,
       "ip community-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

ALIAS (ip_community_list_standard,
       ip_community_list_standard2_cmd,
       "ip community-list <1-99> (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_expanded,
       ip_community_list_expanded_cmd,
       "ip community-list <100-500> (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (ip_community_list_name_standard,
       ip_community_list_name_standard_cmd,
       "ip community-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

ALIAS (ip_community_list_name_standard,
       ip_community_list_name_standard2_cmd,
       "ip community-list standard WORD (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_name_expanded,
       ip_community_list_name_expanded_cmd,
       "ip community-list expanded WORD (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_standard_all,
       no_ip_community_list_standard_all_cmd,
       "no ip community-list <1-99>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_expanded_all,
       no_ip_community_list_expanded_all_cmd,
       "no ip community-list <100-500>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_name_standard_all,
       no_ip_community_list_name_standard_all_cmd,
       "no ip community-list standard WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_name_expanded_all,
       no_ip_community_list_name_expanded_all_cmd,
       "no ip community-list expanded WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_standard,
       no_ip_community_list_standard_cmd,
       "no ip community-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_expanded,
       no_ip_community_list_expanded_cmd,
       "no ip community-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_name_standard,
       no_ip_community_list_name_standard_cmd,
       "no ip community-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify a standard community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_name_expanded,
       no_ip_community_list_name_expanded_cmd,
       "no ip community-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify an expanded community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

static qstring
community_list_entry_value(qstring qs, community_entry entry)
{
  qstring     qsx ;
  const char* what ;

  qsx = NULL ;

  if (entry->u.any == NULL)
    {
      switch (entry->act)
        {
          case act_internet:
            what = "internet" ;
            break ;

          case act_any:
            what = "any" ;
            break ;

          default:
            what = "" ;
            break ;
        } ;
    }
  else
    {
      switch (entry->style)
        {
          case COMMUNITY_LIST_STANDARD:
            what = attr_community_str(entry->u.comm) ;
            break ;

          case ECOMMUNITY_LIST_STANDARD:
            qsx = attr_ecommunity_str_form(qsx, entry->u.ecomm,
                                        ECOMMUNITY_FORMAT_COMMUNITY_LIST) ;
            what = qs_string(qsx) ;
            break ;

          case COMMUNITY_LIST_EXPANDED:
          case ECOMMUNITY_LIST_EXPANDED:
            what = entry->raw ;
            break ;

          default:
            what = "???" ;
            break ;
        } ;
    } ;

  qs = qs_set_str(qs, community_action_str (entry->action)) ;

  if (*what != '\0')
    {
      qs_append_ch(qs, ' ') ;
      qs_append_str(qs, what) ;
    } ;

  qs_free(qsx) ;

  return qs ;
} ;

static void
community_list_show (struct vty *vty, community_list list, const char* tag)
{
  community_entry entry;
  qstring     qs ;

  qs = NULL ;

  for (entry = ddl_head(list->entries); entry; entry = ddl_next(entry, list))
    {
      if (entry == ddl_head(list->entries))
        {
          if (all_digit (list->name))
            vty_out (vty, "Community %s list %s%s",
                     entry->style == COMMUNITY_LIST_STANDARD ? "(standard)"
                                                             : "(expanded)",
                     list->name, VTY_NEWLINE);
          else
            vty_out (vty, "Named Community %s list %s%s",
                     entry->style == COMMUNITY_LIST_STANDARD ?
                     "standard" : "expanded",
                     list->name, VTY_NEWLINE);
        }

      qs = community_list_entry_value(qs, entry) ;
      vty_out (vty, "    %s\n", qs_string(qs));
    } ;

  qs_free(qs) ;
} ;

DEFUN (show_ip_community_list,
       show_ip_community_list_cmd,
       "show ip community-list",
       SHOW_STR
       IP_STR
       "List community-list\n")
{
  vector extract ;
  vector_index_t i ;
  struct community_list *list;

  extract = community_list_extract(bgp_clist, COMMUNITY_LIST,
                                                           NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    community_list_show (vty, list, "Community");

  vector_free(extract) ;        /* discard temporary vector */

  return CMD_SUCCESS;
}

DEFUN (show_ip_community_list_arg,
       show_ip_community_list_arg_cmd,
       "show ip community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, COMMUNITY_LIST, argv[0]);
  if (! list)
    {
      vty_out (vty, "%% Can't find community-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  community_list_show (vty, list, "Community");

  return CMD_SUCCESS;
}

static int
extcommunity_list_set_vty (struct vty *vty, int argc, argv_t argv,
                           int style, int reject_all_digit_name)
{
  int ret;
  int direct;
  char *str;

  /* Check the list type.
   */
  if (strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      vty_out (vty, "%% Matching condition must be permit or deny%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* All digit name check.
   */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  str = argv_concat (argv, argc, 2);

  ret = extcommunity_list_set (bgp_clist, argv[0], str, direct, style);

  XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * extcommunity-list entry delete.
 */
static int
extcommunity_list_unset_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    } ;

  /* Now unset everything or just the given entry.
   */
  if (argc < 2)
    {
      ret = extcommunity_list_unset_all (bgp_clist, argv[0]);
    }
  else
    {
      clist_action_type_t action ;
      char* str ;

      switch (argv[1][0])
        {
          case 'p':
            action = COMMUNITY_PERMIT ;
            break ;

          case 'd':
            action = COMMUNITY_DENY;
            break ;

          default:
            vty_out (vty, "%% Matching condition must be permit or deny\n") ;
            return CMD_WARNING;
        } ;

      str = argv_concat (argv, argc, 2) ;

      ret = extcommunity_list_unset (bgp_clist, argv[0], str, action, style);

      XFREE (MTYPE_TMP, str) ;
    } ;

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in "\
                 "'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

DEFUN (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard_cmd,
       "ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

ALIAS (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard2_cmd,
       "ip extcommunity-list <1-99> (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_expanded,
       ip_extcommunity_list_expanded_cmd,
       "ip extcommunity-list <100-500> (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard_cmd,
       "ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

ALIAS (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard2_cmd,
       "ip extcommunity-list standard WORD (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_name_expanded,
       ip_extcommunity_list_name_expanded_cmd,
       "ip extcommunity-list expanded WORD (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (no_ip_extcommunity_list_standard_all,
       no_ip_extcommunity_list_standard_all_cmd,
       "no ip extcommunity-list <1-99>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

DEFUN (no_ip_extcommunity_list_expanded_all,
       no_ip_extcommunity_list_expanded_all_cmd,
       "no ip extcommunity-list <100-500>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (no_ip_extcommunity_list_name_standard_all,
       no_ip_extcommunity_list_name_standard_all_cmd,
       "no ip extcommunity-list standard WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

DEFUN (no_ip_extcommunity_list_name_expanded_all,
       no_ip_extcommunity_list_name_expanded_all_cmd,
       "no ip extcommunity-list expanded WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (no_ip_extcommunity_list_standard,
       no_ip_extcommunity_list_standard_cmd,
       "no ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

DEFUN (no_ip_extcommunity_list_expanded,
       no_ip_extcommunity_list_expanded_cmd,
       "no ip extcommunity-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (no_ip_extcommunity_list_name_standard,
       no_ip_extcommunity_list_name_standard_cmd,
       "no ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

DEFUN (no_ip_extcommunity_list_name_expanded,
       no_ip_extcommunity_list_name_expanded_cmd,
       "no ip extcommunity-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (show_ip_extcommunity_list,
       show_ip_extcommunity_list_cmd,
       "show ip extcommunity-list",
       SHOW_STR
       IP_STR
       "List extended-community list\n")
{
  vector extract ;
  vector_index_t i ;
  struct community_list *list;

  extract = community_list_extract(bgp_clist, ECOMMUNITY_LIST,
                                                            NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    community_list_show (vty, list, "Extended-Community");

  vector_free(extract) ;        /* discard temporary vector */

  return CMD_SUCCESS;
}

DEFUN (show_ip_extcommunity_list_arg,
       show_ip_extcommunity_list_arg_cmd,
       "show ip extcommunity-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, ECOMMUNITY_LIST, argv[0]);
  if (! list)
    {
      vty_out (vty, "%% Can't find extcommunity-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  community_list_show (vty, list, "Extended-Community");

  return CMD_SUCCESS;
}

/* Put entire community-list or extcommunity-list.      */
static int
community_list_config_write_list(struct vty* vty, clist_type_t what)
{
  vector extract ;
  vector_index_t i ;
  community_list list;
  qstring  qs ;

  int write = 0;
  qs = NULL ;

  extract = community_list_extract(bgp_clist, what, NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    {
      community_entry entry;

      for (entry = ddl_head(list->entries); entry;
                                            entry = ddl_next(entry, list))
        {
          const char* list_type  = "" ;
          const char* list_style = "" ;

          switch (entry->style)
            {
              case COMMUNITY_LIST_STANDARD:
                list_type  = "community-list" ;
                list_style = "standard " ;
                break ;
              case COMMUNITY_LIST_EXPANDED:
                list_type  = "community-list" ;
                list_style = "expanded " ;
                break ;
              case ECOMMUNITY_LIST_STANDARD:
                list_type  = "extcommunity-list" ;
                list_style = "standard " ;
                break ;
              case ECOMMUNITY_LIST_EXPANDED:
                list_type  = "extcommunity-list" ;
                list_style = "expanded " ;
                break ;
              default:
                break ;
            } ;

          if (all_digit(list->name))
            list_style = "" ;   /* squash style for all digit names     */

          qs = community_list_entry_value(qs, entry) ;

          vty_out (vty, "ip %s %s%s %s\n",
                             list_type, list_style, list->name, qs_string(qs));
          write++;
        }
   }

  vector_free(extract) ;        /* discard temporary vector */
  qs_free(qs) ;

  return write;
}

/* Display community-list and extcommunity-list configuration.  */
static int
community_list_config_write (struct vty *vty)
{
  int write = 0;

  write += community_list_config_write_list(vty, COMMUNITY_LIST) ;
  write += community_list_config_write_list(vty, ECOMMUNITY_LIST);

  return write;
}

CMD_INSTALL_TABLE(static, bgp_community_cmd_table, BGPD) =
{
  /* Community-list.  */
  { CONFIG_NODE,     &ip_community_list_standard_cmd                    },
  { CONFIG_NODE,     &ip_community_list_standard2_cmd                   },
  { CONFIG_NODE,     &ip_community_list_expanded_cmd                    },
  { CONFIG_NODE,     &ip_community_list_name_standard_cmd               },
  { CONFIG_NODE,     &ip_community_list_name_standard2_cmd              },
  { CONFIG_NODE,     &ip_community_list_name_expanded_cmd               },
  { CONFIG_NODE,     &no_ip_community_list_standard_all_cmd             },
  { CONFIG_NODE,     &no_ip_community_list_expanded_all_cmd             },
  { CONFIG_NODE,     &no_ip_community_list_name_standard_all_cmd        },
  { CONFIG_NODE,     &no_ip_community_list_name_expanded_all_cmd        },
  { CONFIG_NODE,     &no_ip_community_list_standard_cmd                 },
  { CONFIG_NODE,     &no_ip_community_list_expanded_cmd                 },
  { CONFIG_NODE,     &no_ip_community_list_name_standard_cmd            },
  { CONFIG_NODE,     &no_ip_community_list_name_expanded_cmd            },
  { VIEW_NODE,       &show_ip_community_list_cmd                        },
  { VIEW_NODE,       &show_ip_community_list_arg_cmd                    },
  { ENABLE_NODE,     &show_ip_community_list_cmd                        },
  { ENABLE_NODE,     &show_ip_community_list_arg_cmd                    },

  /* Extcommunity-list.  */
  { CONFIG_NODE,     &ip_extcommunity_list_standard_cmd                 },
  { CONFIG_NODE,     &ip_extcommunity_list_standard2_cmd                },
  { CONFIG_NODE,     &ip_extcommunity_list_expanded_cmd                 },
  { CONFIG_NODE,     &ip_extcommunity_list_name_standard_cmd            },
  { CONFIG_NODE,     &ip_extcommunity_list_name_standard2_cmd           },
  { CONFIG_NODE,     &ip_extcommunity_list_name_expanded_cmd            },
  { CONFIG_NODE,     &no_ip_extcommunity_list_standard_all_cmd          },
  { CONFIG_NODE,     &no_ip_extcommunity_list_expanded_all_cmd          },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_standard_all_cmd     },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_expanded_all_cmd     },
  { CONFIG_NODE,     &no_ip_extcommunity_list_standard_cmd              },
  { CONFIG_NODE,     &no_ip_extcommunity_list_expanded_cmd              },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_standard_cmd         },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_expanded_cmd         },
  { VIEW_NODE,       &show_ip_extcommunity_list_cmd                     },
  { VIEW_NODE,       &show_ip_extcommunity_list_arg_cmd                 },
  { ENABLE_NODE,     &show_ip_extcommunity_list_cmd                     },
  { ENABLE_NODE,     &show_ip_extcommunity_list_arg_cmd                 },

  CMD_INSTALL_END
} ;

extern void
community_list_cmd_init(void)
{
  cmd_install_node_config_write(COMMUNITY_LIST_NODE,
                                                   community_list_config_write);
  cmd_install_table(bgp_community_cmd_table) ;
} ;
