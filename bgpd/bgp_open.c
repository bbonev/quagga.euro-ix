/* BGP open message handling
   Copyright (C) 1998, 1999 Kunihiro Ishiguro

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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_vty.h"

#include "linklist.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "log.h"
#include "command.h"
#include "memory.h"

/*  */

void
bgp_capability_vty_out (struct vty *vty, struct peer *peer)
{
  char *pnt;
  char *end;
  struct capability_mp_data mpc;
  struct capability_header *hdr;

  if ((peer == NULL) || (peer->session == NULL)
                     || (peer->session->notification == NULL))
    return;

  pnt = (char*)peer->session->notification->data;
  end = pnt + peer->session->notification->length;

  while (pnt < end)
    {
      if (pnt + sizeof (struct capability_mp_data) + 2 > end)
        return;

      hdr = (struct capability_header *)pnt;
      if (pnt + hdr->length + 2 > end)
        return;

      memcpy (&mpc, pnt + 2, sizeof(struct capability_mp_data));

      if (hdr->code == BGP_CAN_MP_EXT)
        {
          vty_out (vty, "  Capability error for: Multi protocol ");

          switch (ntohs (mpc.afi))
            {
            case iAFI_IP:
              vty_out (vty, "AFI IPv4, ");
              break;
            case iAFI_IP6:
              vty_out (vty, "AFI IPv6, ");
              break;
            default:
              vty_out (vty, "AFI Unknown %d, ", ntohs (mpc.afi));
              break;
            }
          switch (mpc.safi)
            {
            case iSAFI_Unicast:
              vty_out (vty, "SAFI Unicast");
              break;
            case iSAFI_Multicast:
              vty_out (vty, "SAFI Multicast");
              break;
            case iSAFI_MPLS_VPN:
              vty_out (vty, "SAFI MPLS-labeled VPN");
              break;
            default:
              vty_out (vty, "SAFI Unknown %d ", mpc.safi);
              break;
            }
          vty_out (vty, "%s", VTY_NEWLINE);
        }
      else if (hdr->code >= 128)
        vty_out (vty, "  Capability error: vendor specific capability code %d",
                                                                   hdr->code);
      else
        vty_out (vty, "  Capability error: unknown capability code %d",
                                                                   hdr->code);
      pnt += hdr->length + 2;
    }
}

const struct message orf_type_str[] =
{
  { ORF_TYPE_PREFIX,            "Prefixlist"            },
  { ORF_TYPE_PREFIX_OLD,        "Prefixlist (old)"      },
};
const int orf_type_str_max
        = sizeof(orf_type_str)/sizeof(orf_type_str[0]);

const struct message orf_mode_str[] =
{
  { ORF_MODE_RECEIVE,   "Receive"       },
  { ORF_MODE_SEND,      "Send"          },
  { ORF_MODE_BOTH,      "Both"          },
};
const int orf_mode_str_max
         = sizeof(orf_mode_str)/sizeof(orf_mode_str[0]);

const struct message capcode_str[] =
{
  { BGP_CAN_MP_EXT    ,                 "MultiProtocol Extensions"      },
  { BGP_CAN_R_REFRESH,                  "Route Refresh"                 },
  { BGP_CAN_ORF,                        "Cooperative Route Filtering"   },
  { BGP_CAN_G_RESTART,                  "Graceful Restart"              },
  { BGP_CAN_AS4,                        "4-octet AS number"             },
  { BGP_CAN_DYNAMIC_CAP_dep,            "Dynamic"                       },
  { BGP_CAN_R_REFRESH_pre,              "Route Refresh (Old)"           },
  { BGP_CAN_ORF_pre,                    "ORF (Old)"                     },
};
const int capcode_str_max = sizeof(capcode_str)/sizeof(capcode_str[0]);

/* Minimum sizes for length field of each cap (so not inc. the header)
 */
const size_t cap_minsizes[] =
{
  [BGP_CAN_MP_EXT]              = sizeof (struct capability_mp_data),
  [BGP_CAN_R_REFRESH]           = BGP_CAP_RRF_L,
  [BGP_CAN_ORF]                 = sizeof (struct capability_orf_entry),
  [BGP_CAN_G_RESTART]           = sizeof (struct capability_gr),
  [BGP_CAN_AS4]                 = BGP_CAP_AS4_L,
  [BGP_CAN_DYNAMIC_CAP_dep]     = BGP_CAP_DYN_L,
  [BGP_CAN_R_REFRESH_pre]       = BGP_CAP_RRF_L,
  [BGP_CAN_ORF_pre]             = sizeof (struct capability_orf_entry),
};

