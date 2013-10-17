/* BGP VTY interface.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

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

#include "misc.h"

#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "plist.h"
#include "log.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_run_vty.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_names.h"

/*==============================================================================
 * Here we have vty/cli stuff which affects the run-time state.
 */

/*==============================================================================
 */

/*------------------------------------------------------------------------------
 * "bgp log-neighbor-changes" configuration.
 */
DEFUN (bgp_log_neighbor_changes,
       bgp_log_neighbor_changes_cmd,
       "bgp log-neighbor-changes",
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  return bgp_config_flag_change(vty, BGP_FLAG_LOG_NEIGHBOR_CHANGES,
                                                               true /* set */) ;
}

DEFUN (no_bgp_log_neighbor_changes,
       no_bgp_log_neighbor_changes_cmd,
       "no bgp log-neighbor-changes",
       NO_STR
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  return bgp_config_flag_change(vty, BGP_FLAG_LOG_NEIGHBOR_CHANGES,
                                                            false /* clear */) ;
}


/*==============================================================================
 * Peer/Peer-Group shutdown
 *
 * For peer:
 *
 *   * can shutdown a peer which is a member of a group, separately from all
 *     other members of the group.
 *
 *   * shutdown will disable any running session, and leave peer disabled.
 *
 *   * startup (no shutdown) reverses any shutdown.
 *
 *
 * For group:
 *
 */

/* neighbor shutdown. */
DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       NEIGHBOR_CMD2 "shutdown",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_modify_vty (vty, argv[0], cgs_SHUTDOWN, true /* set */);
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       NO_NEIGHBOR_CMD2 "shutdown",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_modify_vty (vty, argv[0], cgs_SHUTDOWN, false /* unset */);
}

ALIAS (no_neighbor_shutdown,
       neighbor_startup_cmd,
       NEIGHBOR_CMD2 "startup",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively start this neighbor (reverse shut down)\n") ;

/*==============================================================================
 *
 */
typedef enum clear_sort clear_sort_t ;
enum clear_sort
{
  clear_all,
  clear_peer,
  clear_group,
  clear_external,
  clear_as
} ;

static cmd_ret_t
bgp_clear_vty_error (vty vty, bgp_prun prun, qafx_t qafx, bgp_ret_t error)
{
  switch (error)
    {
      case BGP_ERR_AF_NOT_CONFIGURED:
        vty_out (vty,
           "%%BGP: neighbor %s is not enabled for %s\n",
                                               prun->name, get_qafx_name(qafx));
        break;

      case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
        vty_out (vty, "%%BGP: Inbound soft reconfig for %s not possible as it\n"
                      "      has neither refresh capability, nor inbound soft"
                                                    " reconfig\n", prun->name);
        break;

      default:
        vty_out (vty, "%%BGP: unknown issue clear for %s\n", prun->name);
        break;
    } ;

  return CMD_WARNING ;
} ;

/*------------------------------------------------------------------------------
 * `clear ip bgp' functions.
 *
 *   * sort   -- clear_all        -- clear all peers
 *            -- clear_peer       -- clear the peer given by 'arg'
 *            -- clear_group      -- clear the group given by 'arg'
 *            -- clear_external   -- clear all external peers
 *            -- clear_as         -- clear all peers with AS given by 'arg'
 *
 *   * type   -- BGP_CLEAR_HARD   -- hard reset of peer(s) -- ignores qafx
 *
 *            -- BGP_CLEAR_SOFT_OUT            ) attempt soft reset of the
 *            -- BGP_CLEAR_SOFT_IN             ) given qafx
 *            -- BGP_CLEAR_SOFT_BOTH           )
 *            -- BGP_CLEAR_SOFT_IN_ORF_PREFIX  )
 *            -- BGP_CLEAR_SOFT_RSCLIENT       )
 */
static int
bgp_clear (vty vty, bgp_run brun, qafx_t qafx,
           clear_sort_t sort, bgp_clear_type_t stype, const char *arg)
{
  cmd_ret_t cret ;
  bgp_prun  prun ;
  int ret;
  union sockunion su;
  as_t as ;
  bool found ;

  cret = CMD_SUCCESS ;

  switch (sort)
    {
      case clear_all:
        for (prun = ddl_head(brun->pruns) ; prun != NULL ;
                                            prun = ddl_next(prun, prun_list))
          {
            if (stype == BGP_CLEAR_HARD)
              peer_clear (prun);
            else
              {
                ret = peer_clear_soft (prun, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, prun, qafx, ret);
              } ;
          } ;
        break ;

      case clear_peer:
        ret = str2sockunion (arg, &su);
        if (ret < 0)
          {
            vty_out (vty, "Malformed address: %s\n", arg);
            return CMD_WARNING;
          }

        prun = bgp_peer_lookup_su (brun, &su);
        if (! prun)
          {
            vty_out (vty, "%%BGP: Unknown neighbor - \"%s\"\n", arg);
            return CMD_WARNING;
          }

        if (stype == BGP_CLEAR_HARD)
          peer_clear (prun);
        else
          {
            ret = peer_clear_soft (prun, qafx, stype);

            if (ret < 0)
              cret =  bgp_clear_vty_error (vty, prun, qafx, ret);
          } ;
        break ;

      case clear_group:
        group = peer_group_lookup (brun, arg);
        if (! group)
          {
            vty_out (vty, "%%BGP: No such peer-group %s\n", arg);
            return CMD_WARNING;
          }

        for (prun = ddl_head(prun->group->members) ;
             prun != NULL ;
             prun = ddl_next(prun->c, member.list))
          {
            if    (stype == BGP_CLEAR_HARD)
              peer_clear (prun);
            else
              {
                bgp_prib  prib ;

                prib = prun->prib[qafx] ;

                if ((prib != NULL) && prib->af_group_member)
                  {
                    ret = peer_clear_soft (prun, qafx, stype);

                    if (ret < 0)
                      cret =  bgp_clear_vty_error (vty, prun, qafx, ret);
                  } ;
              } ;
          } ;
        break ;


      case clear_external:
        for (prun = ddl_head(brun->pruns) ; prun != NULL ;
                                            prun = ddl_next(prun, prun_list))
          {
            if (prun->sort == BGP_PEER_IBGP)
              continue;

            if (stype == BGP_CLEAR_HARD)
              peer_clear (prun);
            else
              {
                ret = peer_clear_soft (prun, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, prun, qafx, ret);
              } ;
          } ;
        break ;

      case clear_as:
        VTY_GET_INTEGER_RANGE ("AS", as, arg, 1, BGP_AS4_MAX);

        found = false ;

        for (prun = ddl_head(brun->pruns) ; prun != NULL ;
                                            prun = ddl_next(prun, prun_list))
          {
            if (prun->args_r.remote_as != as)
              continue;

            found = true;

            if (stype == BGP_CLEAR_HARD)
              peer_clear (prun);
            else
              {
                ret = peer_clear_soft (prun, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, prun, qafx, ret);
              } ;
          } ;

        if (! found)
          {
            vty_out (vty, "%%BGP: No peer is configured with AS %s\n", arg);
            cret = CMD_WARNING ;
          } ;

        break ;

      default:
        vty_out(vty, "%% unknown clear_xx in %s() -- BUG\n", __func__) ;
        return CMD_ERROR ;
    }

  return cret;
} ;

/*------------------------------------------------------------------------------
 * Perform a bgp clear operation
 *
 *   * name  -- NULL => default bgp instance
 *              otherwise, name of BGP instance
 *
 *   * qafx   )
 *   * sort   ) see bgp_clear()
 *   * type   )
 *   * arg    )
 */
static int
bgp_clear_vty (vty vty, chs_c name, qafx_t qafx,
                           clear_sort_t sort, bgp_clear_type_t stype, chs_c arg)
{
  bgp_run brun;

  brun = bgp_run_lookup_vty(vty, name) ;

  if (brun != NULL)
    return bgp_clear (vty, brun, qafx, sort, stype, arg);
  else
    return CMD_WARNING ;
}

/*------------------------------------------------------------------------------
 * Select unicast or multicast qafx, according to "m" (or "u")
 */
static qafx_t
bgp_clear_qafx_how_cast(const char* opt, qafx_t unicast, qafx_t multicast)
{
  if (*opt == 'm')
    return multicast ;
  else
    return unicast ;
} ;

DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear ip bgp *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_undef, clear_all, BGP_CLEAR_HARD,
                                                                         NULL);
}

ALIAS (clear_ip_bgp_all,
       clear_bgp_all_cmd,
       "clear bgp *",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_ipv6_all_cmd,
       "clear bgp ipv6 *",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_ip_bgp_instance_all_cmd,
       "clear ip bgp view WORD *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_instance_all_cmd,
       "clear bgp view WORD *",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n")

DEFUN (clear_ip_bgp_peer,
       clear_ip_bgp_peer_cmd,
       "clear ip bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_peer, BGP_CLEAR_HARD,
                                                                       argv[0]);
}

ALIAS (clear_ip_bgp_peer,
       clear_bgp_peer_cmd,
       "clear bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_ipv6_peer_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n")

DEFUN (clear_ip_bgp_peer_group,
       clear_ip_bgp_peer_group_cmd,
       "clear ip bgp peer-group WORD",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_group, BGP_CLEAR_HARD,
                                                                       argv[0]);
}

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_peer_group_cmd,
       "clear bgp peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_ipv6_peer_group_cmd,
       "clear bgp ipv6 peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

DEFUN (clear_ip_bgp_external,
       clear_ip_bgp_external_cmd,
       "clear ip bgp external",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_external,
                                                    BGP_CLEAR_HARD, NULL);
}

ALIAS (clear_ip_bgp_external,
       clear_bgp_external_cmd,
       "clear bgp external",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_ipv6_external_cmd,
       "clear bgp ipv6 external",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n")

DEFUN (clear_ip_bgp_as,
       clear_ip_bgp_as_cmd,
       "clear ip bgp " CMD_AS_RANGE,
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_as,
                                                  BGP_CLEAR_HARD, argv[0]);
}

ALIAS (clear_ip_bgp_as,
       clear_bgp_as_cmd,
       "clear bgp " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_ipv6_as_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n")

/* Outbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_soft_out_cmd,
       "clear ip bgp * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_out_cmd,
       "clear ip bgp * out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_instance_all_soft_out_cmd,
       "clear ip bgp view WORD * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_soft_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all, BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_out,
       clear_ip_bgp_instance_all_ipv4_soft_out_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                                     BGP_CLEAR_SOFT_OUT, NULL) ;
}

DEFUN (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_soft_out_cmd,
       "clear ip bgp * vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_out_cmd,
       "clear ip bgp * vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_all_soft_out,
       clear_bgp_all_soft_out_cmd,
       "clear bgp * soft out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_all_soft_out_cmd,
       "clear bgp view WORD * soft out",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_all_out_cmd,
       "clear bgp * out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_soft_out_cmd,
       "clear bgp ipv6 * soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_out_cmd,
       "clear bgp ipv6 * out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_soft_out_cmd,
       "clear ip bgp A.B.C.D soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_out_cmd,
       "clear ip bgp A.B.C.D out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_soft_out_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_out_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_soft_out_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_out_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_peer_soft_out,
       clear_bgp_peer_soft_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_soft_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_peer_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_soft_out_cmd,
       "clear ip bgp peer-group WORD soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_out_cmd,
       "clear ip bgp peer-group WORD out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_soft_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_soft_out_cmd,
       "clear bgp peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_soft_out_cmd,
       "clear bgp ipv6 peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_out_cmd,
       "clear bgp peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_out_cmd,
       "clear bgp ipv6 peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_soft_out_cmd,
       "clear ip bgp external soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_out_cmd,
       "clear ip bgp external out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_soft_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_external_soft_out,
       clear_bgp_external_soft_out_cmd,
       "clear bgp external soft out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_soft_out_cmd,
       "clear bgp ipv6 external soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_external_out_cmd,
       "clear bgp external out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_out_cmd,
       "clear bgp ipv6 external WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as, BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_as_soft_out,
       clear_bgp_as_soft_out_cmd,
       "clear bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                 BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_soft_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_as_out_cmd,
       "clear bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

/* Inbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_soft_in_cmd,
       "clear ip bgp * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_instance_all_soft_in_cmd,
       "clear ip bgp view WORD * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_in_cmd,
       "clear ip bgp * in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_all_in_prefix_filter,
       clear_ip_bgp_all_in_prefix_filter_cmd,
       "clear ip bgp * in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_ip_bgp_all_in_prefix_filter,
       clear_ip_bgp_instance_all_in_prefix_filter_cmd,
       "clear ip bgp view WORD * in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")


DEFUN (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_soft_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_in,
       clear_ip_bgp_instance_all_ipv4_soft_in_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

DEFUN (clear_ip_bgp_all_ipv4_in_prefix_filter,
       clear_ip_bgp_all_ipv4_in_prefix_filter_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_in_prefix_filter,
       clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_soft_in_cmd,
       "clear ip bgp * vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_in_cmd,
       "clear ip bgp * vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_all_soft_in,
       clear_bgp_all_soft_in_cmd,
       "clear bgp * soft in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_all_soft_in_cmd,
       "clear bgp view WORD * soft in",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_soft_in_cmd,
       "clear bgp ipv6 * soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_all_in_cmd,
       "clear bgp * in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_in_cmd,
       "clear bgp ipv6 * in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_all_in_prefix_filter,
       clear_bgp_all_in_prefix_filter_cmd,
       "clear bgp * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_all_in_prefix_filter,
       clear_bgp_ipv6_all_in_prefix_filter_cmd,
       "clear bgp ipv6 * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_soft_in_cmd,
       "clear ip bgp A.B.C.D soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_in_cmd,
       "clear ip bgp A.B.C.D in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_in_prefix_filter,
       clear_ip_bgp_peer_in_prefix_filter_cmd,
       "clear ip bgp A.B.C.D in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_soft_in_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_in_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_soft_in_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_in_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_soft_in,
       clear_bgp_peer_soft_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_soft_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_peer_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_in_prefix_filter,
       clear_bgp_peer_in_prefix_filter_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_in_prefix_filter,
       clear_bgp_ipv6_peer_in_prefix_filter_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")

DEFUN (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_soft_in_cmd,
       "clear ip bgp peer-group WORD soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                   BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_in_cmd,
       "clear ip bgp peer-group WORD in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_group_in_prefix_filter,
       clear_ip_bgp_peer_group_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_soft_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_group_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_soft_in_cmd,
       "clear bgp peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_soft_in_cmd,
       "clear bgp ipv6 peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_in_cmd,
       "clear bgp peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_in_cmd,
       "clear bgp ipv6 peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_peer_group_in_prefix_filter_cmd,
       "clear bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_ipv6_peer_group_in_prefix_filter_cmd,
       "clear bgp ipv6 peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_soft_in_cmd,
       "clear ip bgp external soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_in_cmd,
       "clear ip bgp external in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_external_in_prefix_filter,
       clear_ip_bgp_external_in_prefix_filter_cmd,
       "clear ip bgp external in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_soft_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_external_ipv4_in_prefix_filter,
       clear_ip_bgp_external_ipv4_in_prefix_filter_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_bgp_external_soft_in,
       clear_bgp_external_soft_in_cmd,
       "clear bgp external soft in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_soft_in_cmd,
       "clear bgp ipv6 external soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_external_in_cmd,
       "clear bgp external in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_in_cmd,
       "clear bgp ipv6 external WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_external_in_prefix_filter,
       clear_bgp_external_in_prefix_filter_cmd,
       "clear bgp external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_external_in_prefix_filter,
       clear_bgp_ipv6_external_in_prefix_filter_cmd,
       "clear bgp ipv6 external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_as_in_prefix_filter,
       clear_ip_bgp_as_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as, BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_as_ipv4_in_prefix_filter,
       clear_ip_bgp_as_ipv4_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_as_soft_in,
       clear_bgp_as_soft_in_cmd,
       "clear bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_soft_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_as_in_cmd,
       "clear bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_as_in_prefix_filter,
       clear_bgp_as_in_prefix_filter_cmd,
       "clear bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_as_in_prefix_filter,
       clear_bgp_ipv6_as_in_prefix_filter_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

/* Both soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft,
       clear_ip_bgp_all_soft_cmd,
       "clear ip bgp * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_ip_bgp_all_soft,
       clear_ip_bgp_instance_all_soft_cmd,
       "clear ip bgp view WORD * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n")


DEFUN (clear_ip_bgp_all_ipv4_soft,
       clear_ip_bgp_all_ipv4_soft_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_soft,
       clear_ip_bgp_instance_all_ipv4_soft_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                                    BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft,
       clear_ip_bgp_all_vpnv4_soft_cmd,
       "clear ip bgp * vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_all_soft,
       clear_bgp_all_soft_cmd,
       "clear bgp * soft",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_all_soft,
       clear_bgp_instance_all_soft_cmd,
       "clear bgp view WORD * soft",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n")

ALIAS (clear_bgp_all_soft,
       clear_bgp_ipv6_all_soft_cmd,
       "clear bgp ipv6 * soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_peer_soft,
       clear_ip_bgp_peer_soft_cmd,
       "clear ip bgp A.B.C.D soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_ipv4_soft,
       clear_ip_bgp_peer_ipv4_soft_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft,
       clear_ip_bgp_peer_vpnv4_soft_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_peer_soft,
       clear_bgp_peer_soft_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_soft,
       clear_bgp_ipv6_peer_soft_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_peer_group_soft,
       clear_ip_bgp_peer_group_soft_cmd,
       "clear ip bgp peer-group WORD soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group_ipv4_soft,
       clear_ip_bgp_peer_group_ipv4_soft_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_peer_group_soft,
       clear_bgp_peer_group_soft_cmd,
       "clear bgp peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft,
       clear_bgp_ipv6_peer_group_soft_cmd,
       "clear bgp ipv6 peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_external_soft,
       clear_ip_bgp_external_soft_cmd,
       "clear ip bgp external soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_external_ipv4_soft,
       clear_ip_bgp_external_ipv4_soft_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_bgp_external_soft,
       clear_bgp_external_soft_cmd,
       "clear bgp external soft",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_bgp_external_soft,
       clear_bgp_ipv6_external_soft_cmd,
       "clear bgp ipv6 external soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_as_soft,
       clear_ip_bgp_as_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                 BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_as_ipv4_soft,
       clear_ip_bgp_as_ipv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;

  return bgp_clear_vty (vty, NULL, qafx, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft,
       clear_ip_bgp_as_vpnv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_as_soft,
       clear_bgp_as_soft_cmd,
       "clear bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_as_soft,
       clear_bgp_ipv6_as_soft_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n")

/* RS-client soft reconfiguration. */
#ifdef HAVE_IPV6
DEFUN (clear_bgp_all_rsclient,
       clear_bgp_all_rsclient_cmd,
       "clear bgp * rsclient",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_RSCLIENT, NULL);
}

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_ipv6_all_rsclient_cmd,
       "clear bgp ipv6 * rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_instance_all_rsclient_cmd,
       "clear bgp view WORD * rsclient",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_ipv6_instance_all_rsclient_cmd,
       "clear bgp ipv6 view WORD * rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
#endif /* HAVE_IPV6 */

DEFUN (clear_ip_bgp_all_rsclient,
       clear_ip_bgp_all_rsclient_cmd,
       "clear ip bgp * rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_RSCLIENT, NULL);
}

ALIAS (clear_ip_bgp_all_rsclient,
       clear_ip_bgp_instance_all_rsclient_cmd,
       "clear ip bgp view WORD * rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

#ifdef HAVE_IPV6
DEFUN (clear_bgp_peer_rsclient,
       clear_bgp_peer_rsclient_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name   = (argc == 2) ? argv[0] : NULL ;
  const char* client = (argc == 2) ? argv[1] : argv[0] ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_peer,
                                               BGP_CLEAR_SOFT_RSCLIENT, client);
}

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_ipv6_peer_rsclient_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_instance_peer_rsclient_cmd,
       "clear bgp view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_ipv6_instance_peer_rsclient_cmd,
       "clear bgp ipv6 view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
#endif /* HAVE_IPV6 */

DEFUN (clear_ip_bgp_peer_rsclient,
       clear_ip_bgp_peer_rsclient_cmd,
       "clear ip bgp (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name   = (argc == 2) ? argv[0] : NULL ;
  const char* client = (argc == 2) ? argv[1] : argv[0] ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_peer,
                                              BGP_CLEAR_SOFT_RSCLIENT, client);
}

ALIAS (clear_ip_bgp_peer_rsclient,
       clear_ip_bgp_instance_peer_rsclient_cmd,
       "clear ip bgp view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

/*------------------------------------------------------------------------------
 * Table of commands to be installed for bgp_vty
 */
CMD_INSTALL_TABLE(static, bgp_vty_cmd_table, BGPD) =
{
  { BGP_NODE,        &bgp_log_neighbor_changes_cmd                      },
  { BGP_NODE,        &no_bgp_log_neighbor_changes_cmd                   },

  /* "neighbor shutdown" commands. */
  { BGP_NODE,        &neighbor_shutdown_cmd                             },
  { BGP_NODE,        &no_neighbor_shutdown_cmd                          },
  { BGP_NODE,        &neighbor_startup_cmd                              },

  { ENABLE_NODE,     &clear_ip_bgp_all_cmd                              },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_as_cmd                               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_cmd                             },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_external_cmd                         },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_cmd                                 },
  { ENABLE_NODE,     &clear_bgp_instance_all_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_cmd                            },
  { ENABLE_NODE,     &clear_bgp_peer_cmd                                },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_cmd                           },
  { ENABLE_NODE,     &clear_bgp_peer_group_cmd                          },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_cmd                     },
  { ENABLE_NODE,     &clear_bgp_external_cmd                            },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_cmd                       },
  { ENABLE_NODE,     &clear_bgp_as_cmd                                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_cmd                             },
#endif /* HAVE_IPV6 */

  { ENABLE_NODE,     &clear_ip_bgp_all_soft_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_in_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_all_in_cmd                           },
  { ENABLE_NODE,     &clear_ip_bgp_all_in_prefix_filter_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_in_prefix_filter_cmd    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_in_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_in_prefix_filter_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_in_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_in_prefix_filter_cmd      },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_external_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_external_in_prefix_filter_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_in_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_as_in_cmd                            },
  { ENABLE_NODE,     &clear_ip_bgp_as_in_prefix_filter_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_in_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_in_prefix_filter_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_in_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd       },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_in_cmd          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_in_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_in_prefix_filter_cmd   },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_in_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_in_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_in_prefix_filter_cmd         },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_in_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_in_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_in_cmd                      },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_in_cmd                },
  { ENABLE_NODE,     &clear_bgp_all_in_cmd                              },
  { ENABLE_NODE,     &clear_bgp_all_in_prefix_filter_cmd                },
  { ENABLE_NODE,     &clear_bgp_peer_soft_in_cmd                        },
  { ENABLE_NODE,     &clear_bgp_peer_in_cmd                             },
  { ENABLE_NODE,     &clear_bgp_peer_in_prefix_filter_cmd               },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_in_cmd                  },
  { ENABLE_NODE,     &clear_bgp_peer_group_in_cmd                       },
  { ENABLE_NODE,     &clear_bgp_peer_group_in_prefix_filter_cmd         },
  { ENABLE_NODE,     &clear_bgp_external_soft_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_external_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_external_in_prefix_filter_cmd           },
  { ENABLE_NODE,     &clear_bgp_as_soft_in_cmd                          },
  { ENABLE_NODE,     &clear_bgp_as_in_cmd                               },
  { ENABLE_NODE,     &clear_bgp_as_in_prefix_filter_cmd                 },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_in_prefix_filter_cmd           },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_in_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_in_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_in_prefix_filter_cmd          },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_in_cmd             },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_in_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_in_prefix_filter_cmd    },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_in_cmd               },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_in_prefix_filter_cmd      },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_in_cmd                     },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_in_cmd                          },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_in_prefix_filter_cmd            },
#endif /* HAVE_IPV6 */

  { ENABLE_NODE,     &clear_ip_bgp_all_soft_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_out_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_all_out_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_out_cmd                         },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_out_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_external_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_out_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_as_out_cmd                           },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_out_cmd       },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_out_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_out_cmd         },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_out_cmd           },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_out_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_out_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_out_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_out_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_out_cmd                     },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_out_cmd               },
  { ENABLE_NODE,     &clear_bgp_all_out_cmd                             },
  { ENABLE_NODE,     &clear_bgp_peer_soft_out_cmd                       },
  { ENABLE_NODE,     &clear_bgp_peer_out_cmd                            },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_out_cmd                 },
  { ENABLE_NODE,     &clear_bgp_peer_group_out_cmd                      },
  { ENABLE_NODE,     &clear_bgp_external_soft_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_external_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_as_soft_out_cmd                         },
  { ENABLE_NODE,     &clear_bgp_as_out_cmd                              },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_out_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_out_cmd                       },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_out_cmd            },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_out_cmd                 },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_out_cmd              },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_out_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_out_cmd                         },
#endif /* HAVE_IPV6 */

  { ENABLE_NODE,     &clear_ip_bgp_all_soft_cmd                         },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_cmd                        },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_cmd           },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_cmd                    },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_cmd                            },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_cmd                   },
  { ENABLE_NODE,     &clear_bgp_peer_soft_cmd                           },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_cmd                     },
  { ENABLE_NODE,     &clear_bgp_external_soft_cmd                       },
  { ENABLE_NODE,     &clear_bgp_as_soft_cmd                             },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_cmd                       },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_cmd                      },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_cmd                },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_cmd                        },
#endif /* HAVE_IPV6 */

  { ENABLE_NODE,     &clear_ip_bgp_all_rsclient_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_rsclient_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_peer_rsclient_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_instance_peer_rsclient_cmd           },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_rsclient_cmd                        },
  { ENABLE_NODE,     &clear_bgp_instance_all_rsclient_cmd               },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_rsclient_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_instance_all_rsclient_cmd          },
  { ENABLE_NODE,     &clear_bgp_peer_rsclient_cmd                       },
  { ENABLE_NODE,     &clear_bgp_instance_peer_rsclient_cmd              },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_rsclient_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_instance_peer_rsclient_cmd         },
#endif /* HAVE_IPV6 */

  CMD_INSTALL_END
} ;

extern void
bgp_vty_cmd_init (void)
{
  cmd_install_table(bgp_vty_cmd_table) ;
}

void
bgp_vty_init (void)
{
}

