/* Quagga AFI/SAFI
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002 Kunihiro Ishiguro
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#include "qafi_safi.h"
#include "name_map.h"

/*==============================================================================
 * Conversion tables for: qAFI        => sa_family_t
 *                   and: sa_family_t => qAFI
 */
const sa_family_t qAFI_to_family_map[qAFI_count] =
  {
    [qAFI_ipv4]    = AF_INET,
#ifdef HAVE_IPV6
    [qAFI_ipv6]    = AF_INET6,
#endif
    [qAFI_undef]   = AF_UNSPEC,
  } ;
CONFIRM(AF_UNSPEC == 0) ;       /* not known -> AF_UNSPEC       */

const qAFI_t  qAFI_from_family_map[sa_family_count] =
  {
    [AF_INET]     = qAFI_ipv4,
#ifdef HAVE_IPV6
    [AF_INET6]    = qAFI_ipv6,
#endif
    [AF_UNSPEC]   = qAFI_undef
  } ;
CONFIRM(qAFI_undef == 0) ;      /* not known -> qAFI_undef      */

/*==============================================================================
 * Mapping values to name strings
 */

static const char* afi_name_lc_map_body[] =
{
  [AFI_IP]                    = "afi_ipv4",
  [AFI_IP6]                   = "afi_ipv6",
};

static const map_direct_t afi_name_lc_map =
             map_direct_s(afi_name_lc_map_body, "afi(%u)") ;

static const char* afi_name_uc_map_body[] =
{
  [AFI_IP]                    = "AFI_IPv4",
  [AFI_IP6]                   = "AFI_IPv6",
};

static const map_direct_t afi_name_uc_map =
             map_direct_s(afi_name_uc_map_body, "AFI(%u)") ;


/*------------------------------------------------------------------------------
 * Map Internet AFI to afi_xxx, eg: afi_ipv4 -- lower case
 */
extern name_str_t
afitoa_lc(afi_t afi)
{
  return map_direct(afi_name_lc_map, afi) ;
} ;

/*------------------------------------------------------------------------------
 * Map Internet AFI to AFI_xxx, eg: AFI_IPv4 -- upper case
 */
extern name_str_t
afitoa_uc(afi_t afi)
{
  return map_direct(afi_name_uc_map, afi) ;
} ;

