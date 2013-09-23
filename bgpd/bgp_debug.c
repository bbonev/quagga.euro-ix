/* BGP-4, BGP-4+ packet debug routine
   Copyright (C) 1996, 97, 99 Kunihiro Ishiguro

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
#include <stdbool.h>

#include "lib/version.h"
#include "prefix.h"
#include "linklist.h"
#include "stream.h"
#include "command.h"
#include "str.h"
#include "log.h"
#include "sockunion.h"
#include "memory.h"
#include "qfstring.h"

#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_names.h"

unsigned long conf_bgp_debug_as4;
unsigned long conf_bgp_debug_fsm;
unsigned long conf_bgp_debug_io;
unsigned long conf_bgp_debug_events;
unsigned long conf_bgp_debug_packet;
unsigned long conf_bgp_debug_filter;
unsigned long conf_bgp_debug_keepalive;
unsigned long conf_bgp_debug_update;
unsigned long conf_bgp_debug_normal;
unsigned long conf_bgp_debug_zebra;

unsigned long term_bgp_debug_as4;
unsigned long term_bgp_debug_fsm;
unsigned long term_bgp_debug_io;
unsigned long term_bgp_debug_events;
unsigned long term_bgp_debug_packet;
unsigned long term_bgp_debug_filter;
unsigned long term_bgp_debug_keepalive;
unsigned long term_bgp_debug_update;
unsigned long term_bgp_debug_normal;
unsigned long term_bgp_debug_zebra;

/*------------------------------------------------------------------------------
 * Dump attribute to given buffer in human readable form.
 *
 * Note that it does not matter whether the given attributes are interned or
 * not !  They are not changed by this function.
 */
extern int
bgp_dump_attr (struct peer *peer, const struct attr *attr, char *buf,
                                                                    size_t size)
{
  if (! attr)
    return 0;

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP)))
    snprintf (buf, size, "nexthop %s", safe_inet_ntoa (attr->nexthop));

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", origin %s",
                          map_direct(bgp_origin_short_map, attr->origin).str) ;

#ifdef HAVE_IPV6
  if (attr->extra)
    {
      char addrbuf[BUFSIZ];

      /* Add MP case. */
      if (attr->extra->mp_nexthop_len == 16
          || attr->extra->mp_nexthop_len == 32)
        snprintf (buf + strlen (buf), size - strlen (buf), ", mp_nexthop %s",
                  inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                             addrbuf, BUFSIZ));

      if (attr->extra->mp_nexthop_len == 32)
        snprintf (buf + strlen (buf), size - strlen (buf), "(%s)",
                  inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                             addrbuf, BUFSIZ));
    }
#endif /* HAVE_IPV6 */

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", localpref %d",
              attr->local_pref);

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", metric %d",
              attr->med);

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", community %s",
              community_str (attr->community));

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", atomic-aggregate");

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", aggregated by %u %s",
              attr->extra->aggregator_as,
              safe_inet_ntoa (attr->extra->aggregator_addr));

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", originator %s",
              safe_inet_ntoa (attr->extra->originator_id));

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_CLUSTER_LIST)))
    {
      int i;

      snprintf (buf + strlen (buf), size - strlen (buf), ", clusterlist");
      for (i = 0; i < attr->extra->cluster->length / 4; i++)
        snprintf (buf + strlen (buf), size - strlen (buf), " %s",
                  safe_inet_ntoa (attr->extra->cluster->list[i]));
    }

  if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)))
    snprintf (buf + strlen (buf), size - strlen (buf), ", path %s",
              aspath_print (attr->aspath));

  if (strlen (buf) > 1)
    return 1;
  else
    return 0;
}

/*------------------------------------------------------------------------------
 * Log given notification, if required.
 */
void
bgp_notify_print(struct peer *peer, bgp_notify notification)
{
  map_direct_p subcode_map ;
  const char* hex_form ;
  bool  log_neighbor_changes ;
  uint  length ;
  char* alloc ;

  /* See if we need to do any of this
   */
  if      (bgp_flag_check (peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
    log_neighbor_changes = true ;
  else if (BGP_DEBUG (normal, NORMAL))
    log_neighbor_changes = false ;
  else
    return ;                    /* quit if nothing to do        */

  /* Select map for subcode
   */
  switch (notification->code)
    {
    case BGP_NOTIFY_HEADER_ERR:
      subcode_map = bgp_notify_head_msg_map ;
      break;

    case BGP_NOTIFY_OPEN_ERR:
      subcode_map = bgp_notify_open_msg_map ;
      break;

    case BGP_NOTIFY_UPDATE_ERR:
      subcode_map = bgp_notify_update_msg_map ;
      break;

    case BGP_NOTIFY_HOLD_ERR:
    case BGP_NOTIFY_FSM_ERR:
      subcode_map = bgp_notify_unspecific_msg_map ;
      break;

    case BGP_NOTIFY_CEASE:
      subcode_map = bgp_notify_cease_msg_map ;
      break;

    case BGP_NOTIFY_CAPABILITY_ERR:
      subcode_map = bgp_notify_capability_msg_map ;
      break;

    default:
      subcode_map = bgp_notify_unknown_msg_map ;
      break ;
    }

  /* Construct hex_form of data, if required.
   */
  length = bgp_notify_get_length(notification) ;
  if (length != 0)
    {
      const char* form ;
      uint8_t* p = bgp_notify_get_data(notification) ;
      uint8_t* e = p + length ;
      char* q ;

      hex_form = alloc = q = XMALLOC(MTYPE_TMP, (length * 3) + 1) ;

      form = "%02x" ;
      while (p < e)
        {
          int n = snprintf (q, 4, form, *p++) ;
          q += n ;
          form = " %02x" ;
        } ;
    }
  else
    {
      hex_form = "" ;
      alloc = NULL ;
    } ;

  /* Output the required logging
   */
  if (log_neighbor_changes)
    zlog_info("%%NOTIFICATION: %s neighbor %s %s%s (%d/%d) %d bytes %s",
              notification->received ? "received from" : "sent to", peer->host,
              map_direct(bgp_notify_msg_map, notification->code).str,
              map_direct(subcode_map, notification->subcode).str,
              notification->code, notification->subcode, length, hex_form) ;
  else
    plog_debug(peer->log, "%s %s NOTIFICATION %s%s (%d/%d) %d bytes %s",
               peer->host, notification->received ? "received" : "sending",
               map_direct(bgp_notify_msg_map, notification->code).str,
               map_direct(subcode_map, notification->subcode).str,
               notification->code, notification->subcode, length, hex_form) ;

  /* Release the space allocated to the hex form of the data, if any
   */
  if (alloc != NULL)
    XFREE(MTYPE_TMP, alloc) ;
} ;

/*==============================================================================
 * Debug option setting commands
 */

/* Debug option setting interface.
 */
unsigned long bgp_debug_option = 0;

int
debug (unsigned int option)
{
  return bgp_debug_option & option;
}

DEFUN (debug_bgp_as4,
       debug_bgp_as4_cmd,
       "debug bgp as4",
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (as4, AS4);
  else
    {
      TERM_DEBUG_ON (as4, AS4);
      vty_out (vty, "BGP as4 debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_as4,
       no_debug_bgp_as4_cmd,
       "no debug bgp as4",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (as4, AS4);
  else
    {
      TERM_DEBUG_OFF (as4, AS4);
      vty_out (vty, "BGP as4 debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_as4,
       undebug_bgp_as4_cmd,
       "undebug bgp as4",
       UNDEBUG_STR
       BGP_STR
       "BGP AS4 actions\n")

DEFUN (debug_bgp_as4_segment,
       debug_bgp_as4_segment_cmd,
       "debug bgp as4 segment",
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n"
       "BGP AS4 aspath segment handling\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (as4, AS4_SEGMENT);
  else
    {
      TERM_DEBUG_ON (as4, AS4_SEGMENT);
      vty_out (vty, "BGP as4 segment debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_as4_segment,
       no_debug_bgp_as4_segment_cmd,
       "no debug bgp as4 segment",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP AS4 actions\n"
       "BGP AS4 aspath segment handling\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (as4, AS4_SEGMENT);
  else
    {
      TERM_DEBUG_OFF (as4, AS4_SEGMENT);
      vty_out (vty, "BGP as4 segment debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_as4_segment,
       undebug_bgp_as4_segment_cmd,
       "undebug bgp as4 segment",
       UNDEBUG_STR
       BGP_STR
       "BGP AS4 actions\n"
       "BGP AS4 aspath segment handling\n")

DEFUN (debug_bgp_fsm,
       debug_bgp_fsm_cmd,
       "debug bgp fsm",
       DEBUG_STR
       BGP_STR
       "BGP Finite State Machine\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (fsm, FSM);
  else
    {
      TERM_DEBUG_ON (fsm, FSM);
      vty_out (vty, "BGP fsm debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_fsm,
       no_debug_bgp_fsm_cmd,
       "no debug bgp fsm",
       NO_STR
       DEBUG_STR
       BGP_STR
       "Finite State Machine\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (fsm, FSM);
  else
    {
      TERM_DEBUG_OFF (fsm, FSM);
      vty_out (vty, "BGP fsm debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_fsm,
       undebug_bgp_fsm_cmd,
       "undebug bgp fsm",
       UNDEBUG_STR
       BGP_STR
       "Finite State Machine\n")

DEFUN (debug_bgp_io,
       debug_bgp_io_cmd,
       "debug bgp io",
       DEBUG_STR
       BGP_STR
       "BGP io activity\n")
{
  if (vty->node == CONFIG_NODE)
    {
      DEBUG_ON (io, IO_IN);
      DEBUG_ON (io, IO_OUT);
    }
  else
    {
      TERM_DEBUG_ON (io, IO_IN);
      TERM_DEBUG_ON (io, IO_OUT);
      vty_out (vty, "BGP io debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (debug_bgp_io_direct,
       debug_bgp_io_direct_cmd,
       "debug bgp io (in|out)",
       DEBUG_STR
       BGP_STR
       "BGP io\n"
       "Inbound io\n"
       "Outbound io\n")
{
  if (vty->node == CONFIG_NODE)
    {
      if (strncmp ("i", argv[0], 1) == 0)
        {
          DEBUG_OFF (io, IO_OUT);
          DEBUG_ON (io, IO_IN);
        }
      else
        {
          DEBUG_OFF (io, IO_IN);
          DEBUG_ON (io, IO_OUT);
        }
    }
  else
    {
      if (strncmp ("i", argv[0], 1) == 0)
        {
          TERM_DEBUG_OFF (io, IO_OUT);
          TERM_DEBUG_ON (io, IO_IN);
          vty_out (vty, "BGP io debugging is on (inbound)%s", VTY_NEWLINE);
        }
      else
        {
          TERM_DEBUG_OFF (update, IO_IN);
          TERM_DEBUG_ON (update, IO_OUT);
          vty_out (vty, "BGP io debugging is on (outbound)%s", VTY_NEWLINE);
        }
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_io,
       no_debug_bgp_io_cmd,
       "no debug bgp io",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP io\n")
{
  if (vty->node == CONFIG_NODE)
    {
      DEBUG_OFF (io, IO_IN);
      DEBUG_OFF (io, IO_OUT);
    }
  else
    {
      TERM_DEBUG_OFF (io, IO_IN);
      TERM_DEBUG_OFF (io, IO_OUT);
      vty_out (vty, "BGP io debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_io,
       undebug_bgp_io_cmd,
       "undebug bgp io",
       UNDEBUG_STR
       BGP_STR
       "BGP io\n")

DEFUN (debug_bgp_events,
       debug_bgp_events_cmd,
       "debug bgp events",
       DEBUG_STR
       BGP_STR
       "BGP events\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (events, EVENTS);
  else
    {
      TERM_DEBUG_ON (events, EVENTS);
      vty_out (vty, "BGP events debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_events,
       no_debug_bgp_events_cmd,
       "no debug bgp events",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP events\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (events, EVENTS);
  else
    {
      TERM_DEBUG_OFF (events, EVENTS);
      vty_out (vty, "BGP events debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_events,
       undebug_bgp_events_cmd,
       "undebug bgp events",
       UNDEBUG_STR
       BGP_STR
       "BGP events\n")

DEFUN (debug_bgp_filter,
       debug_bgp_filter_cmd,
       "debug bgp filters",
       DEBUG_STR
       BGP_STR
       "BGP filters\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (filter, FILTER);
  else
    {
      TERM_DEBUG_ON (filter, FILTER);
      vty_out (vty, "BGP filters debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_filter,
       no_debug_bgp_filter_cmd,
       "no debug bgp filters",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP filters\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (filter, FILTER);
  else
    {
      TERM_DEBUG_OFF (filter, FILTER);
      vty_out (vty, "BGP filters debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_filter,
       undebug_bgp_filter_cmd,
       "undebug bgp filters",
       UNDEBUG_STR
       BGP_STR
       "BGP filters\n")

DEFUN (debug_bgp_keepalive,
       debug_bgp_keepalive_cmd,
       "debug bgp keepalives",
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (keepalive, KEEPALIVE);
  else
    {
      TERM_DEBUG_ON (keepalive, KEEPALIVE);
      vty_out (vty, "BGP keepalives debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_keepalive,
       no_debug_bgp_keepalive_cmd,
       "no debug bgp keepalives",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (keepalive, KEEPALIVE);
  else
    {
      TERM_DEBUG_OFF (keepalive, KEEPALIVE);
      vty_out (vty, "BGP keepalives debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_keepalive,
       undebug_bgp_keepalive_cmd,
       "undebug bgp keepalives",
       UNDEBUG_STR
       BGP_STR
       "BGP keepalives\n")

DEFUN (debug_bgp_update,
       debug_bgp_update_cmd,
       "debug bgp updates",
       DEBUG_STR
       BGP_STR
       "BGP updates\n")
{
  if (vty->node == CONFIG_NODE)
    {
      DEBUG_ON (update, UPDATE_IN);
      DEBUG_ON (update, UPDATE_OUT);
    }
  else
    {
      TERM_DEBUG_ON (update, UPDATE_IN);
      TERM_DEBUG_ON (update, UPDATE_OUT);
      vty_out (vty, "BGP updates debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (debug_bgp_update_direct,
       debug_bgp_update_direct_cmd,
       "debug bgp updates (in|out)",
       DEBUG_STR
       BGP_STR
       "BGP updates\n"
       "Inbound updates\n"
       "Outbound updates\n")
{
  if (vty->node == CONFIG_NODE)
    {
      if (strncmp ("i", argv[0], 1) == 0)
        {
          DEBUG_OFF (update, UPDATE_OUT);
          DEBUG_ON (update, UPDATE_IN);
        }
      else
        {
          DEBUG_OFF (update, UPDATE_IN);
          DEBUG_ON (update, UPDATE_OUT);
        }
    }
  else
    {
      if (strncmp ("i", argv[0], 1) == 0)
        {
          TERM_DEBUG_OFF (update, UPDATE_OUT);
          TERM_DEBUG_ON (update, UPDATE_IN);
          vty_out (vty, "BGP updates debugging is on (inbound)%s", VTY_NEWLINE);
        }
      else
        {
          TERM_DEBUG_OFF (update, UPDATE_IN);
          TERM_DEBUG_ON (update, UPDATE_OUT);
          vty_out (vty, "BGP updates debugging is on (outbound)%s", VTY_NEWLINE);
        }
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_update,
       no_debug_bgp_update_cmd,
       "no debug bgp updates",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n")
{
  if (vty->node == CONFIG_NODE)
    {
      DEBUG_OFF (update, UPDATE_IN);
      DEBUG_OFF (update, UPDATE_OUT);
    }
  else
    {
      TERM_DEBUG_OFF (update, UPDATE_IN);
      TERM_DEBUG_OFF (update, UPDATE_OUT);
      vty_out (vty, "BGP updates debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_update,
       undebug_bgp_update_cmd,
       "undebug bgp updates",
       UNDEBUG_STR
       BGP_STR
       "BGP updates\n")

DEFUN (debug_bgp_normal,
       debug_bgp_normal_cmd,
       "debug bgp",
       DEBUG_STR
       BGP_STR)
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (normal, NORMAL);
  else
    {
      TERM_DEBUG_ON (normal, NORMAL);
      vty_out (vty, "BGP debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_normal,
       no_debug_bgp_normal_cmd,
       "no debug bgp",
       NO_STR
       DEBUG_STR
       BGP_STR)
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (normal, NORMAL);
  else
    {
      TERM_DEBUG_OFF (normal, NORMAL);
      vty_out (vty, "BGP debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_normal,
       undebug_bgp_normal_cmd,
       "undebug bgp",
       UNDEBUG_STR
       BGP_STR)

DEFUN (debug_bgp_zebra,
       debug_bgp_zebra_cmd,
       "debug bgp zebra",
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (zebra, ZEBRA);
  else
    {
      TERM_DEBUG_ON (zebra, ZEBRA);
      vty_out (vty, "BGP zebra debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_zebra,
       no_debug_bgp_zebra_cmd,
       "no debug bgp zebra",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP Zebra messages\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (zebra, ZEBRA);
  else
    {
      TERM_DEBUG_OFF (zebra, ZEBRA);
      vty_out (vty, "BGP zebra debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_zebra,
       undebug_bgp_zebra_cmd,
       "undebug bgp zebra",
       UNDEBUG_STR
       BGP_STR
       "BGP Zebra messages\n")

DEFUN (no_debug_bgp_all,
       no_debug_bgp_all_cmd,
       "no debug all bgp",
       NO_STR
       DEBUG_STR
       "Enable all debugging\n"
       BGP_STR)
{
  TERM_DEBUG_OFF (normal, NORMAL);
  TERM_DEBUG_OFF (events, EVENTS);
  TERM_DEBUG_OFF (keepalive, KEEPALIVE);
  TERM_DEBUG_OFF (update, UPDATE_IN);
  TERM_DEBUG_OFF (update, UPDATE_OUT);
  TERM_DEBUG_OFF (as4, AS4);
  TERM_DEBUG_OFF (as4, AS4_SEGMENT);
  TERM_DEBUG_OFF (io, IO_IN);
  TERM_DEBUG_OFF (io, IO_OUT);
  TERM_DEBUG_OFF (fsm, FSM);
  TERM_DEBUG_OFF (filter, FILTER);
  TERM_DEBUG_OFF (zebra, ZEBRA);
  vty_out (vty, "All possible debugging has been turned off%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_all,
       undebug_bgp_all_cmd,
       "undebug all bgp",
       UNDEBUG_STR
       "Enable all debugging\n"
       BGP_STR)

DEFUN (show_debugging_bgp,
       show_debugging_bgp_cmd,
       "show debugging bgp",
       SHOW_STR
       DEBUG_STR
       BGP_STR)
{
  vty_out (vty, "BGP debugging status:%s", VTY_NEWLINE);

  if (BGP_DEBUG (normal, NORMAL))
    vty_out (vty, "  BGP debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (events, EVENTS))
    vty_out (vty, "  BGP events debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (keepalive, KEEPALIVE))
    vty_out (vty, "  BGP keepalives debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (update, UPDATE_IN) && BGP_DEBUG (update, UPDATE_OUT))
    vty_out (vty, "  BGP updates debugging is on%s", VTY_NEWLINE);
  else if (BGP_DEBUG (update, UPDATE_IN))
    vty_out (vty, "  BGP updates debugging is on (inbound)%s", VTY_NEWLINE);
  else if (BGP_DEBUG (update, UPDATE_OUT))
    vty_out (vty, "  BGP updates debugging is on (outbound)%s", VTY_NEWLINE);
  if (BGP_DEBUG (fsm, FSM))
    vty_out (vty, "  BGP fsm debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (io, IO_IN) && BGP_DEBUG (io, IO_OUT))
    vty_out (vty, "  BGP io debugging is on%s", VTY_NEWLINE);
  else if (BGP_DEBUG (io, IO_IN))
    vty_out (vty, "  BGP io debugging is on (inbound)%s", VTY_NEWLINE);
  else if (BGP_DEBUG (io, IO_OUT))
    vty_out (vty, "  BGP io debugging is on (outbound)%s", VTY_NEWLINE);
  if (BGP_DEBUG (filter, FILTER))
    vty_out (vty, "  BGP filter debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (zebra, ZEBRA))
    vty_out (vty, "  BGP zebra debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (as4, AS4))
    vty_out (vty, "  BGP as4 debugging is on%s", VTY_NEWLINE);
  if (BGP_DEBUG (as4, AS4_SEGMENT))
    vty_out (vty, "  BGP as4 aspath segment debugging is on%s", VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

static int
bgp_config_write_debug (struct vty *vty)
{
  int write = 0;

  if (CONF_BGP_DEBUG (normal, NORMAL))
    {
      vty_out (vty, "debug bgp%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (as4, AS4))
    {
      vty_out (vty, "debug bgp as4%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (as4, AS4_SEGMENT))
    {
      vty_out (vty, "debug bgp as4 segment%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (events, EVENTS))
    {
      vty_out (vty, "debug bgp events%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (keepalive, KEEPALIVE))
    {
      vty_out (vty, "debug bgp keepalives%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (update, UPDATE_IN) && CONF_BGP_DEBUG (update, UPDATE_OUT))
    {
      vty_out (vty, "debug bgp updates%s", VTY_NEWLINE);
      write++;
    }
  else if (CONF_BGP_DEBUG (update, UPDATE_IN))
    {
      vty_out (vty, "debug bgp updates in%s", VTY_NEWLINE);
      write++;
    }
  else if (CONF_BGP_DEBUG (update, UPDATE_OUT))
    {
      vty_out (vty, "debug bgp updates out%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (fsm, FSM))
    {
      vty_out (vty, "debug bgp fsm%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (io, IO_IN) && CONF_BGP_DEBUG (io, IO_OUT))
    {
      vty_out (vty, "debug bgp io%s", VTY_NEWLINE);
      write++;
    }
  else if (CONF_BGP_DEBUG (io, IO_IN))
    {
      vty_out (vty, "debug bgp io in%s", VTY_NEWLINE);
      write++;
    }
  else if (CONF_BGP_DEBUG (io, IO_OUT))
    {
      vty_out (vty, "debug bgp io out%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (filter, FILTER))
    {
      vty_out (vty, "debug bgp filters%s", VTY_NEWLINE);
      write++;
    }

  if (CONF_BGP_DEBUG (zebra, ZEBRA))
    {
      vty_out (vty, "debug bgp zebra%s", VTY_NEWLINE);
      write++;
    }

  return write;
}

/*------------------------------------------------------------------------------
 * Table of commands to be installed for bgp_debug
 */
CMD_INSTALL_TABLE(static, bgp_debug_cmd_table, BGPD) =
{
  { ENABLE_NODE,     &show_debugging_bgp_cmd                            },
  { ENABLE_NODE,     &debug_bgp_as4_cmd                                 },
  { CONFIG_NODE,     &debug_bgp_as4_cmd                                 },
  { ENABLE_NODE,     &debug_bgp_as4_segment_cmd                         },
  { CONFIG_NODE,     &debug_bgp_as4_segment_cmd                         },
  { ENABLE_NODE,     &debug_bgp_fsm_cmd                                 },
  { CONFIG_NODE,     &debug_bgp_fsm_cmd                                 },
  { ENABLE_NODE,     &debug_bgp_io_cmd                                  },
  { CONFIG_NODE,     &debug_bgp_io_cmd                                  },
  { ENABLE_NODE,     &debug_bgp_io_direct_cmd                           },
  { CONFIG_NODE,     &debug_bgp_io_direct_cmd                           },
  { ENABLE_NODE,     &debug_bgp_events_cmd                              },
  { CONFIG_NODE,     &debug_bgp_events_cmd                              },
  { ENABLE_NODE,     &debug_bgp_filter_cmd                              },
  { CONFIG_NODE,     &debug_bgp_filter_cmd                              },
  { ENABLE_NODE,     &debug_bgp_keepalive_cmd                           },
  { CONFIG_NODE,     &debug_bgp_keepalive_cmd                           },
  { ENABLE_NODE,     &debug_bgp_update_cmd                              },
  { CONFIG_NODE,     &debug_bgp_update_cmd                              },
  { ENABLE_NODE,     &debug_bgp_update_direct_cmd                       },
  { CONFIG_NODE,     &debug_bgp_update_direct_cmd                       },
  { ENABLE_NODE,     &debug_bgp_normal_cmd                              },
  { CONFIG_NODE,     &debug_bgp_normal_cmd                              },
  { ENABLE_NODE,     &debug_bgp_zebra_cmd                               },
  { CONFIG_NODE,     &debug_bgp_zebra_cmd                               },
  { ENABLE_NODE,     &no_debug_bgp_as4_cmd                              },
  { ENABLE_NODE,     &undebug_bgp_as4_cmd                               },
  { CONFIG_NODE,     &no_debug_bgp_as4_cmd                              },
  { ENABLE_NODE,     &no_debug_bgp_as4_segment_cmd                      },
  { ENABLE_NODE,     &undebug_bgp_as4_segment_cmd                       },
  { CONFIG_NODE,     &no_debug_bgp_as4_segment_cmd                      },
  { ENABLE_NODE,     &no_debug_bgp_fsm_cmd                              },
  { ENABLE_NODE,     &undebug_bgp_fsm_cmd                               },
  { CONFIG_NODE,     &no_debug_bgp_fsm_cmd                              },
  { ENABLE_NODE,     &no_debug_bgp_io_cmd                               },
  { ENABLE_NODE,     &undebug_bgp_io_cmd                                },
  { CONFIG_NODE,     &no_debug_bgp_io_cmd                               },
  { ENABLE_NODE,     &no_debug_bgp_events_cmd                           },
  { ENABLE_NODE,     &undebug_bgp_events_cmd                            },
  { CONFIG_NODE,     &no_debug_bgp_events_cmd                           },
  { ENABLE_NODE,     &no_debug_bgp_filter_cmd                           },
  { ENABLE_NODE,     &undebug_bgp_filter_cmd                            },
  { CONFIG_NODE,     &no_debug_bgp_filter_cmd                           },
  { ENABLE_NODE,     &no_debug_bgp_keepalive_cmd                        },
  { ENABLE_NODE,     &undebug_bgp_keepalive_cmd                         },
  { CONFIG_NODE,     &no_debug_bgp_keepalive_cmd                        },
  { ENABLE_NODE,     &no_debug_bgp_update_cmd                           },
  { ENABLE_NODE,     &undebug_bgp_update_cmd                            },
  { CONFIG_NODE,     &no_debug_bgp_update_cmd                           },
  { ENABLE_NODE,     &no_debug_bgp_normal_cmd                           },
  { ENABLE_NODE,     &undebug_bgp_normal_cmd                            },
  { CONFIG_NODE,     &no_debug_bgp_normal_cmd                           },
  { ENABLE_NODE,     &no_debug_bgp_zebra_cmd                            },
  { ENABLE_NODE,     &undebug_bgp_zebra_cmd                             },
  { CONFIG_NODE,     &no_debug_bgp_zebra_cmd                            },
  { ENABLE_NODE,     &no_debug_bgp_all_cmd                              },
  { ENABLE_NODE,     &undebug_bgp_all_cmd                               },

  CMD_INSTALL_END
} ;

extern void
bgp_debug_cmd_init (void)
{
  cmd_install_node_config_write (DEBUG_NODE, bgp_config_write_debug);
  cmd_install_table(bgp_debug_cmd_table) ;
} ;

extern void
bgp_debug_init (void)
{
} ;
