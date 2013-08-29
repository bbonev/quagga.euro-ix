/*
 * Prefix related functions.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#include <zebra.h>

#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"
#include "tstring.h"
#include "string.h"
#include "miyagi.h"
#include "ring_buffer.h"

/* Some advantages with __GNUC__ !
 *
 * Can set __GNUC_LOCAL to 0 for testing
 */
#ifdef __GNUC__
#define __GNUC__LOCAL 1
#else
#define __GNUC__LOCAL 0
#endif

/*==============================================================================
 * "Macros" for banging 32 and 64 bits of masks
 */
                        /* 0123456701234567 */
#define U32_1s (uint32_t)0xFFFFFFFF
#define U64_1s (uint64_t)0xFFFFFFFFFFFFFFFF

inline static uint32_t n32_mask(uint len)              Always_Inline ;
inline static uint32_t n32_wild(uint len)              Always_Inline ;
inline static u_char n32_mask_check (uint32_t mask_n)  Always_Inline ;

inline static uint64_t n64_mask(uint len)              Always_Inline ;
inline static uint64_t n64_wild(uint len)              Always_Inline ;
inline static u_char n64_mask_check (uint64_t mask_n)  Always_Inline ;

inline static uint8_t local_clz_n32(uint32_t n32)      Always_Inline ;
inline static uint8_t local_clz_u32(uint32_t u32)      Always_Inline ;
static uint8_t local_clz_u32_long(uint32_t u32) ;

inline static uint8_t local_clz_n64(uint64_t n64)      Always_Inline ;

/*------------------------------------------------------------------------------
 * Return 32 bit mask
 */
inline static uint32_t
n32_mask(uint len)
{
  return (len < 32) ? ~htonl((U32_1s >> len))
                    :         U32_1s ;
} ;

/*------------------------------------------------------------------------------
 * Return 32 bit wild bits -- ie: inverse of n32_mask.
 */
inline static uint32_t
n32_wild(uint len)
{
  return (len < 32) ? htonl((U32_1s >> len))
                    :             0 ;
} ;

/*------------------------------------------------------------------------------
 * Check whether given uint32_t is valid as a netmask.
 *
 * Netmask is valid if there are no '1' bits after the LS '0' (if any)
 *
 * Argument should be network byte order.
 */
inline static u_char
n32_mask_check (uint32_t mask_n)
{
  uint32_t mask_h ;

  mask_h = ntohl(mask_n) ;

  return (mask_h | (mask_h - 1)) == U32_1s ;

  /* So: where ip_h has at some unknown MS bits, and then '1' followed by
   *     '0's we have:
   *
   *        'X..X10..0' - 1 -> 'X..X01..1'
   *
   *     so to be a valid mask: 'X..X10..0' | 'X..X01..1' == '1..1' !
   *
   *     ip_h is unsigned, so if ip_h == 0
   *
   *        '0..0' - 1 -> '1..1' and '0..0' | '1..1' == '1..1'
   *
   *     so that's fine too.
   */
} ;

/*------------------------------------------------------------------------------
 * Return 64 bit mask
 */
inline static uint64_t
n64_mask(uint len)
{
  return (len < 64) ? ~htonq((U64_1s >> len))
                    :         U64_1s ;
} ;

/*------------------------------------------------------------------------------
 * Return 64 bit wild bits -- ie: inverse of n64_mask.
 */
inline static uint64_t
n64_wild(uint len)
{
  return (len < 64) ?  htonq((U64_1s >> len))
                    :              0 ;
} ;

/*------------------------------------------------------------------------------
 * Check whether given uint32_t is valid as a netmask.
 *
 * Netmask is valid if there are no '1' bits after the LS '0' (if any)
 *
 * Argument should be network byte order.
 */
inline static u_char
n64_mask_check (uint64_t mask_n)
{
  uint64_t mask_h ;

  mask_h = ntohq(mask_n) ;

  return (mask_h | (mask_h - 1)) == U64_1s ;
} ;

/*------------------------------------------------------------------------------
 * Wrapper for __builtin_clz() for 32-bit Network Order value
 *
 * NB: *undefined* result for n32 == 0
 */
inline static uint8_t
local_clz_n32(uint32_t n32)
{
  return local_clz_u32(ntohl(n32)) ;
} ;

/*------------------------------------------------------------------------------
 * Wrapper for __builtin_clz() for 32-bit Host Order value
 *
 * NB: *undefined* result for u32 == 0
 */
inline static uint8_t
local_clz_u32(uint32_t u32)
{
  /* Expect the compiler to reap the unused code here.
   *
   * Done this way to ensure that the obscure code is kept up to date !
   */
  if (__GNUC__LOCAL)
    {
      confirm(UINT_MAX == U32_1s) ;

#if __GNUC__LOCAL
      return __builtin_clz(u32) ;
#else
      assert(false) ;                   /* CANNOT reach here !! */
#endif
    }
  else
    {
      /* NB: we try to use ffs() if we can.  We want to count the leading
       *     zeros, so we can only do this if have '0's followed by '1's,
       *     which is the case for valid prefix masks, and is the case we
       *     want to handle most quickly.
       *
       *     If we give ffs() zero we get 0, which is completely wrong, so
       *     need to look out for u32 = 0xFFFFFFFF.  Since we have to do that,
       *     we deal with all the cases where the result is zero, and for
       *     good measure we deal with the one case where we would present
       *     ffs() with a value > 0x7FFFFFFF -- because ffs() technically
       *     takes an int !
       */
      if (u32 >= 0x7FFFFFFF)
        return (u32 > 0x7FFFFFFF) ? 0 : 1 ;

      if ((u32 & (u32 + 1)) == 0)
        return 33 - ffs(u32 + 1) ;

      return local_clz_u32_long(u32) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Long alternative to __builtin_clz() for 32-bit (Host Order) value
 *
 * For use where u32 is *not* '1's followed by '0's, only -- so cannot use
 * ffs() because
 *
 * NB: *undefined* result for u32 == 0
 */
static uint8_t
local_clz_u32_long(uint32_t u32)
{
  uint8_t n ;

  if (u32 > 0x0000FFFF)
    {
      if (u32 > 0x00FFFFFF)
        {
          if (u32 > 0x0FFFFFFF)
            {
              n   = (28    - 28) ;
              u32 = (u32 >> (28 - 1)) ;
            }
          else
            {
              n   = (28    - 24) ;
              u32 = (u32 >> (24 - 1)) ;
            } ;
        }
      else
        {
          if (u32 > 0x000FFFFF)
            {
              n   = (28    - 20) ;
              u32 = (u32 >> (20 - 1)) ;
            }
          else
            {
              n   = (28    - 16) ;
              u32 = (u32 >> (16 - 1)) ;
            } ;
        }
    }
  else
    {
      if (u32 > 0x000000FF)
        {
          if (u32 > 0x00000FFF)
            {
              n   = (28    - 12) ;
              u32 = (u32 >> (12 - 1)) ;
            }
          else
            {
              n   = (28    -  8) ;
              u32 = (u32 >> ( 8 - 1)) ;
            } ;
        }
      else
        {
          if (u32 > 0x0000000F)
            {
              n   = (28    -  4) ;
              u32 = (u32 >> ( 4 - 1)) ;
            }
          else
            {
              n   = (28    -  0) ;
              u32 = (u32 << 1) ;
            } ;
        }
    } ;

  return n + ((0x000055AC >> (u32 & 0x1E)) & 0x3) ;
} ;

/*------------------------------------------------------------------------------
 * Wrapper for __builtin_clz() for 64-bit Network Order value
 *
 * NB: *undefined* result for n64 == 0
 */
inline static uint8_t
local_clz_n64(uint64_t n64)
{
  uint64_t u64 ;

  u64 = ntohq(n64) ;

  /* Expect the compiler to reap the unused code here.
   *
   * Done this way to ensure that the obscure code is kept up to date !
   */
  if (__GNUC__LOCAL)
    {
      confirm(ULONG_MAX == U64_1s) ;

#if __GNUC__LOCAL
      return __builtin_clzl(u64) ;
#else
      assert(false) ;                   /* CANNOT reach here !! */
#endif
    }
  else
    {
      /* Break this down so that can operate of 32 bit parts.
       */
      if (u64 > U32_1s)
        return local_clz_u32(u64 >> 32) ;
      else
        return 32 + local_clz_u32(u64) ;
    } ;
} ;

/*==============================================================================
 */

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)

unsigned int
prefix_bit (const u_char *prefix, const u_char prefixlen)
{
  uint offset = prefixlen / PNBBY;
  uint shift  = (PNBBY - 1) - (prefixlen % PNBBY);

  return (prefix[offset] >> shift) & 1;
}

#ifdef HAVE_IPV6

unsigned int
prefix6_bit (const struct in6_addr *prefix, const u_char prefixlen)
{
  return prefix_bit((const u_char *) &prefix->s6_addr, prefixlen);
}

#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * If pfx_n includes prefix pfx then return true.
 *
 * NB: takes no notice of the prefixes' families.
 *
 *     Inter alia, does not check that the prefixlen is valid.  (If it is not
 *     valid, may read beyond the end of either prefix.)
 *
 * NB: the arguments are nominally prefix_t, but both may be one of the
 *     variations on the prefix theme.
 *
 *     The result if arguments are different variants is *undefined*.  (But
 *     may include reading beyond the end of prefix pfx.)
 */
extern bool
prefix_match (prefix_c pfx_n, prefix_c pfx)
{
  uint i, m ;

  if (pfx_n->prefixlen > pfx->prefixlen)
    return false ;

  i = pfx_n->prefixlen / 32 ;
  m = pfx_n->prefixlen % 32 ;

  if (m != 0)
    if (ntohl(pfx_n->u.n32[i] ^ pfx->u.n32[i]) > (0xFFFFFFFF >> m))
      return false ;

  while (i-- != 0)
    if (pfx_n->u.n32[i] != pfx->u.n32[i])
      return false ;

  return true ;         /* match        */
}

/*------------------------------------------------------------------------------
 * Copy prefix from src to dst.
 *
 * NB: the src and dst are nominally prefix_t, but only the parts known to be
 *     present for the given AF_XXX are touched.
 *
 *     So both the src and the dst may be one of the variations on the prefix
 *     theme.
 *
 *     BUT: if the dst is, indeed, a generic prefix_t, any parts of the body
 *          which are unused for the AF_XXX are untouched.
 *
 * NB: the prefix_ls_t and the prefix_rd_t both use AF_UNSPEC.  Happily, the
 *     "body" part of their prefix structures are the same size.
 *
 * NB: assumes that any and all bits beyond 'prefixlen' are zero.
 */
extern void
prefix_copy (prefix dst, prefix_c src)
{
  /* Copy the common "header"
   */
  *(prefix_h)dst = *(prefix_hc)src ;

  /* Copy the body according to the AF_XXX
   */
  switch (dst->family)
    {
      case AF_INET:
        dst->u.prefix4 = ((prefix_ipv4_c)src)->prefix ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
        dst->u.prefix6 = ((prefix_ipv6_c)src)->prefix ;
        break ;
#endif /* HAVE_IPV6 */

      case AF_UNSPEC:
        memcpy(dst->u.val, ((prefix_hc)src)->body, sizeof(dst->u.val)) ;

        /* For a prefix_ls_t the 'id' and the 'adv_router' are the same as
         * the generic prefix_t 'val'.
         */
        confirm(offsetof(prefix_ls_t, id) == offsetof(prefix_t, u.val)) ;
        confirm((offsetof(prefix_ls_t, end) - offsetof(prefix_ls_t, id))
                                                == sizeof(((prefix)0)->u.val)) ;
#if 0
        /* For a prefix_rd_t the 'val' is the same as the generic prefix_t 'val'
         */
        confirm(offsetof(prefix_rd_t, val)  == offsetof(prefix_t, u.val)) ;
        confirm(sizeof(((prefix_rd)0)->val) == sizeof(((prefix)0)->u.val)) ;
#endif
        break ;

      default:
        zlog (NULL, LOG_ERR, "prefix_copy(): Unknown address family %d",
                                                                   src->family);
        assert (0);
    } ;
}

/*------------------------------------------------------------------------------
 * Return true if the address/netmask contained in the prefix structure
 * is the same, and else return false.
 *
 * For this routine, 'same' requires that not only the prefix length and the
 * network part be the same, but also the host part.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are not the same.
 *
 * Note that this routine has the same return value sense as '==' (which is
 * different from prefix_cmp).
 *
 * If the Families are the same, they must be either AF_INET or AF_INET6 --
 * otherwise returns false.
 *
 * If the Prefix Lengths are different, will return false.  Takes no notice of
 * what the Prefix Length is, however.  The check for "same" checks the
 * address part specified by the Family.
 *
 * NB: the two prefixes are nominally prefix_t, but may be any of the variations
 *     on the prefix theme (though only prefix_ipv4_t and prefix_ipv6_t make
 *     much sense).
 *
 * NB: does *not* compare the rd_id fields.
 *
 * NB: assumes that any and all bits beyond 'prefixlen' are zero.
 */
extern bool
prefix_same (prefix_c pfx1, prefix_c pfx2)
{
  if ((pfx1->prefixlen == pfx2->prefixlen) && (pfx1->family == pfx2->family))
    {
      switch (pfx1->family)
      {
        case AF_INET:
          return pfx1->u.ipv4 == pfx2->u.ipv4 ;
#ifdef HAVE_IPV6
        case AF_INET6:
          return IPV6_ADDR_SAME (&pfx1->u.ipv6, &pfx2->u.ipv6) ;
#endif /* HAVE_IPV6 */

        default:
          break ;
      } ;
    }

  return false ;
}

/*------------------------------------------------------------------------------
 * This is just like prefix_same() -- except that returns 0 for equal and not
 * 0 otherwise.
 *
 * NB: the two prefixes are nominally prefix_t, but may be any of the variations
 *     on the prefix theme (though only prefix_ipv4_t and prefix_ipv6_t make
 *     much sense).
 *
 * NB: does *not* compare the rd_id fields.
 *
 * NB: assumes that any and all bits beyond 'prefixlen' are zero.
 */
extern int
prefix_equal (prefix_c pfx1, prefix_c pfx2)
{
  if ((pfx1->prefixlen == pfx2->prefixlen) && (pfx1->family == pfx2->family))
    {
      switch (pfx1->family)
      {
        case AF_INET:
          return (pfx1->u.ipv4 == pfx2->u.ipv4) ? 0 : 1 ;
#ifdef HAVE_IPV6
        case AF_INET6:
          return IPV6_ADDR_CMP (&pfx1->u.ipv6, &pfx2->u.ipv6) ;
#endif /* HAVE_IPV6 */

        default:
          break ;
      } ;
    }

  return -1 ;
}

/*------------------------------------------------------------------------------
 * Return 0 if the network prefixes represented by the struct prefix
 * arguments are the same prefix, and 1 otherwise.  Network prefixes
 * are considered the same if the prefix lengths are equal and the
 * network parts are the same.  Host bits (which are considered masked
 * by the prefix length) are not significant.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are considered equivalent by this routine.  Note that
 * this routine has the same return sense as strcmp (which is different
 * from prefix_same).
 *
 * Does not care what the Family is and does not check that Prefix Length is
 * feasible (either for the Family or for the size of the struct prefix !)
 *
 * Whatever the prefix length is, requires the body of the prefix to be some
 * multiple of uint32_t (in future uint64_t and uint128_t !)
 *
 * NB: the two prefixes are nominally prefix_t, but may be any of the variations
 *     on the prefix theme (though only prefix_ipv4_t and prefix_ipv6_t make
 *     much sense).
 *
 * NB: does *not* compare the rd_id fields.
 *
 * NB: assumes that any and all bits beyond 'prefixlen' are zero.
 */
extern int
prefix_cmp (prefix_c pfx1, prefix_c pfx2)
{
  uint i, m ;

  if ((pfx1->family != pfx2->family) || (pfx1->prefixlen != pfx2->prefixlen))
    return 1;

  i = pfx1->prefixlen / 32 ;
  m = pfx1->prefixlen % 32 ;

  if (m != 0)
    if (ntohl(pfx1->u.n32[i] ^ pfx2->u.n32[i]) > (U32_1s >> m))
      return 1;

  while (i--)
    if (pfx1->u.n32[i] != pfx2->u.n32[i])
      return 1;

  return 0;             /* equal        */
}

/*------------------------------------------------------------------------------
 * Return -1, 0 or +1 for sorting prefixes
 *
 * For two prefixes a & b:
 *
 *   * if a.family != b.family   -- return -1 for a.family < b.family
 *                                  return +1 for a.family > b.family
 *
 *   * if a.value  != b.value for the smaller of the two prefix lengths
 *
 *                               -- return -1 for a.value  < b.value
 *                                  return +1 for a.value  > b.value
 *
 *   * if a.length != b.length   -- return -1 for a.length < b.length
 *                                  return +1 for a.length > b.length
 *
 *   * return 0
 *
 * NB: does *not* compare the rd_id fields.
 *
 * NB: assumes that any and all bits beyond 'prefixlen' are zero.
 */
extern int
prefix_sort_cmp (prefix_c pfx1, prefix_c pfx2)
{
  uint  i, pl1, pl2 ;
  int   pl ;

  if (pfx1->family != pfx2->family)
    return (pfx1->family < pfx2->family) ? -1 : +1 ;

  pl1 = pfx1->prefixlen ;
  pl2 = pfx2->prefixlen ;

  i  = 0 ;
  pl = (pl1 <= pl2) ? pl1 : pl2 ;

  while (pl > 0)
    {
      uint32_t w1, w2 ;

      w1 = pfx1->u.n32[i] ;
      w2 = pfx2->u.n32[i] ;

      if (w1 != w2)
        return (ntohl(w1) < ntohl(w2)) ? -1 : +1 ;

      i  += 1 ;
      pl -= 32 ;
    } ;

  if (pl1 != pl2)
    return (pl1 < pl2) ? -1 : +1 ;

  return 0 ;            /* equal        */
}

/*------------------------------------------------------------------------------
 * Count the number of common bits in 2 prefixes. The prefix length is
 * ignored for this function; the whole prefix is compared. If the prefix
 * address families don't match, return -1; otherwise the return value is
 * in range 0 ... maximum prefix length for the address family.
 */
extern int
prefix_common_bits (prefix_c pfx1, prefix_c pfx2)
{
  uint32_t dn32 ;
#ifdef HAVE_IPV6
  uint64_t dn64 ;
#endif

  if (pfx1->family != pfx2->family)
    return -1;

  switch (pfx1->family)
    {
      case AF_INET:

        dn32 = pfx1->u.n32[0] ^ pfx2->u.n32[0] ;

        return (dn32 != 0) ? local_clz_n32(dn32) : 32 ;

#ifdef HAVE_IPV6
      case AF_INET6:
        dn64 = pfx1->u.n64[0] ^ pfx2->u.n64[0] ;

        if (dn64 != 0)
          return local_clz_n64(dn64) ;

        dn64 = pfx1->u.n64[1] ^ pfx2->u.n64[1] ;

        return (dn64 != 0) ? 64 + local_clz_n64(dn64) : 128 ;
#endif

      default:
        return -1 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return prefix family type string.
 */
const char *
prefix_family_str (prefix_c pfx)
{
  switch (pfx->family)
    {
      case AF_INET:
        return "inet";

#ifdef HAVE_IPV6
      case AF_INET6:
        return "inet6";
#endif /* HAVE_IPV6 */

      case AF_UNSPEC:
        return "unspec";

      default:
        return "unknown" ;
    } ;
}

/*==============================================================================
 * IPv4 Stuff
 */

/*------------------------------------------------------------------------------
 * Allocate new prefix_ipv4 structure.
 *
 * NB: does not, in fact, allocate a prefix_ipv4_t... allocates a prefix_t !!
 */
struct prefix_ipv4 *
prefix_ipv4_new ()
{
  struct prefix_ipv4 *pfx;

  /* Call prefix_new to allocate a full-size struct prefix to avoid problems
   * where the struct prefix_ipv4 is cast to struct prefix and unallocated
   * bytes were being referenced (e.g. in structure assignments).
   */
  pfx = (struct prefix_ipv4 *)prefix_new();
  pfx->family = AF_INET;
  return pfx;
}

/*------------------------------------------------------------------------------
 * Free prefix_ipv4 structure.
 *
 * NB: does not, in fact, free a prefix_ipv4_t... frees a prefix_t !!
 */
extern void
prefix_ipv4_free (struct prefix_ipv4 *pfx)
{
  prefix_free((struct prefix *)pfx);
}

/*------------------------------------------------------------------------------
 * When string format is valid return 1 otherwise return 0.
 *
 * inet_aton() returns 1 <=> valid, 0 <=> invalid.
 * inet_pton() returns 1 <=> valid, 0 <=> invalid, -1 <=> error
 *                                where error => unknown address family argument
 *
 * Callers of this function vary in how they test the return:
 *
 *   1) some treat non-0 as OK and 0 as invalid -- consistent with inet_aton().
 *
 *   2) some treat > 0 as OK and <= 0 as invalid -- consistent with inet_pton().
 *
 * Since this function returns 1 <=> valid and 0 <=> invalid, both the above
 * work.
 *
 * NB: if is not a valid IPv4 address or prefix, returns AF_UNSPEC.
 *
 * NB: sets rd_id == prefix_rd_id_null.
 *
 * NB: does NOT check that the address part is all zeros beyond the given
 *     prefix length.
 */
extern int
str2prefix_ipv4 (const char *str, prefix_ipv4 pfx)
{
  const char* pnt ;
  uint     plen ;
  strtox_t tox ;

  memset(pfx, 0, sizeof(prefix_ht)) ;

  confirm((AF_UNSPEC == 0) && (prefix_rd_id_null == 0)) ;

  if (!str2ipv4 (&pfx->prefix.s_addr, str, &pnt))
    return 0 ;                  /* Invalid leading IPv4 part    */

  switch (*pnt)
    {
      case '\0':                /* => simple address            */
        plen = IPV4_MAX_BITLEN ;
        break ;

      case '/':                 /* => prefix                    */
        plen = strtoul_xr(pnt + 1, &tox, &pnt, 0, IPV4_MAX_BITLEN) ;

        if ((tox != strtox_ok) || (*pnt != '\0'))
          return 0 ;

        break ;

      default:
        return 0 ;
    } ;

  pfx->family    = AF_INET;
  pfx->prefixlen = plen;

  return 1 ;
}

/*------------------------------------------------------------------------------
 * Convert leading part of the given string to an IPv4 address.
 *
 * Assumes that all leading decimal digits and '.' are the address.
 *
 * Returns:  true <=> was a valid IPv4 address -- per inet_pton()
 *
 * Sets:     *end to point at the character which terminated the IPv4 address
 */
extern bool
str2ipv4 (in_addr_t* ipv4, const char *str, const char** end)
{
  tstring_t(temp, 24) ;
  const char* cp ;
  uint len ;
  int  ret ;

  len = strspn(str, "0123456789.") ;
  cp  = &str[len] ;

  *end = cp ;

  if (*cp != '\0')
    cp = tstring_set_n(temp, str, len) ;

  ret = inet_pton (AF_INET, cp, ipv4);

  tstring_free(temp) ;

  return (ret > 0) ;
} ;

/*------------------------------------------------------------------------------
 * Convert masklen into IP address's netmask (network byte order).
 */
extern void
masklen2ip (const uint masklen, struct in_addr *netmask)
{
  netmask->s_addr = n32_mask(masklen) ;

  confirm(IPV4_MAX_BITLEN == 32) ;
} ;

/*------------------------------------------------------------------------------
 * Convert IPv4 netmask to prefix length.
 *
 * If the netmask is invalid, all '1's after the first '0' are ignored.
 *
 * Argument netmask should be network byte order.
 */
extern byte
ip_mask2len(in_addr_t netmask)
{
  return (netmask != U32_1s) ? local_clz_n32(~netmask) : 32 ;
} ;

/*------------------------------------------------------------------------------
 * Convert masklen into IP address's netmask (network byte order).
 */
extern in_addr_t
ip_len2mask (byte len)
{
  confirm(IPV4_MAX_BITLEN == 32) ;

  return n32_mask(len) ;
} ;

/*------------------------------------------------------------------------------
 * Check whether given IPv4 netmask is valid.
 *
 * Netmask is valid if there are no '1' bits after the LS '0' (if any)
 *
 * Argument netmask should be network byte order.
 */
extern bool
ip_mask_check (in_addr_t netmask)
{
  return n32_mask_check(netmask) ;
} ;

/*------------------------------------------------------------------------------
 * Apply mask to IPv4 prefix (network byte order).
 */
extern void
apply_mask_ipv4 (prefix_ipv4 pfx)
{
  pfx->prefix.s_addr &= n32_mask(pfx->prefixlen) ;
}

/*------------------------------------------------------------------------------
 * Check for all zeros beyond the prefix length
 *
 * Return:  true <=> is all zeros beyond the prefix length
 */
extern bool
prefix_check_ipv4 (prefix_ipv4 pfx)
{
  return !(pfx->prefix.s_addr & n32_wild(pfx->prefixlen)) ;
}

/*------------------------------------------------------------------------------
 * If prefix is 0.0.0.0/0 then return 1 else return 0. */
extern bool
prefix_ipv4_any (prefix_ipv4_c pfx)
{
  return (pfx->prefix.s_addr == 0 && pfx->prefixlen == 0);
}

/*==============================================================================
 * IPv6 Stuff
 */
#ifdef HAVE_IPV6

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *
prefix_ipv6_new (void)
{
  struct prefix_ipv6 *pfx;

  /* Allocate a full-size struct prefix to avoid problems with structure
     size mismatches. */
  pfx = (struct prefix_ipv6 *)prefix_new();
  pfx->family = AF_INET6;
  return pfx;
}

/* Free prefix for IPv6. */
void
prefix_ipv6_free (struct prefix_ipv6 *pfx)
{
  prefix_free((struct prefix *)pfx);
}

/*------------------------------------------------------------------------------
 * If given string is valid IPv6 address or prefix return 1 else return 0
 *
 * inet_aton() returns 1 <=> valid, 0 <=> invalid.
 * inet_pton() returns 1 <=> valid, 0 <=> invalid, -1 <=> error
 *                                where error => unknown address family argument
 *
 * Any error returned by inet_pton() is reported as an invalid address or
 * prefix.  So best not to call this if IPv6 is not supported.
 *
 * Callers of this function vary in how they test the return:
 *
 *   1) some treat non-0 as OK and 0 as invalid -- consistent with inet_aton().
 *
 *   2) some treat > 0 as OK and <= 0 as invalid -- consistent with inet_pton().
 *
 * Since this function returns 1 <=> valid and 0 <=> invalid, both the above
 * work.
 */
int
str2prefix_ipv6 (const char *str, prefix_ipv6 pfx)
{
  const char* pnt ;
  uint     plen ;
  strtox_t tox ;

  memset(pfx, 0, sizeof(prefix_ht)) ;

  confirm((AF_UNSPEC == 0) && (prefix_rd_id_null == 0)) ;

  if (!str2ipv6 (&pfx->prefix, str, &pnt))
    return 0 ;                  /* Invalid leading IPv6 part    */

  switch (*pnt)
    {
      case '\0':                /* => simple address            */
        plen = IPV6_MAX_BITLEN ;
        break ;

      case '/':                 /* => prefix                    */
        plen = strtoul_xr(pnt + 1, &tox, &pnt, 0, IPV6_MAX_BITLEN) ;

        if ((tox != strtox_ok) || (*pnt != '\0'))
          return 0 ;

        break ;

      default:
        return 0 ;
    } ;

  pfx->family    = AF_INET6;
  pfx->prefixlen = plen;

  return 1 ;
} ;

/*------------------------------------------------------------------------------
 * Convert leading part of the given string to an IPv6 address.
 *
 * Assumes that all leading hexadecimal digits, ':' and '.' are the address.
 *
 * Returns:  true <=> was a valid IPv6 address -- per inet_pton()
 *
 * Sets:     *end to point at the character which terminated the IPv4 address
 */
extern bool
str2ipv6 (in6_addr_s* ipv6, const char *str, const char** end)
{
  tstring_t(temp, 64) ;
  const char* cp ;
  uint len ;
  int  ret ;

  len = strspn(str, "0123456789ABCDEFabcdef:.") ;
  cp  = &str[len] ;

  *end = cp ;

  if (*cp != '\0')
    cp = tstring_set_n(temp, str, len) ;

  ret = inet_pton (AF_INET6, cp, &ipv6);

  tstring_free(temp) ;

  return (ret > 0) ;
} ;

/* Convert IPv6 netmask to prefix length.
 *
 * If the netmask is invalid, all '1's after the first '0' are ignored.
 *
 * Argument netmask should be network byte order.
 */
u_char
ip6_masklen (const struct in6_addr* p_s6_addr)
{
  in6_addr_t netmask ;

  netmask.addr = *p_s6_addr ;

  if (netmask.n64[0] != U64_1s)
    return local_clz_n64(~netmask.n64[0]) ;

  if (netmask.n64[1] != U64_1s)
    return local_clz_n64(~netmask.n64[1]) + 64 ;

  return 128 ;
}

/* Check whether given IPv6 netmask is valid.
 *
 * Netmask is valid if there are no '1' bits after the LS '0' (if any)
 *
 * Argument netmask should be network byte order.
 */
bool
ip6_mask_check (const struct in6_addr* p_s6_addr)
{
  union in6_addr_u netmask ;

  netmask.addr = *p_s6_addr ;

  if (netmask.n64[1] == 0)
    return n64_mask_check(netmask.n64[0]) ;

  if (netmask.n64[0] == U64_1s)
    return n64_mask_check(netmask.n64[1]) ;

  return false ;
} ;

void
masklen2ip6 (uint masklen, struct in6_addr *netmask)
{
  uint64_t m0, m1 ;

  if      (masklen < 64)
    {
      m0 = n64_mask(masklen) ;
      m1 = 0 ;
    }
  else
    {
      m0 = U64_1s;
      m1 = n64_mask(masklen - 64) ;
    } ;

  memcpy((char*)netmask + 0, &m0, 8) ;
  memcpy((char*)netmask + 8, &m1, 8) ;
}

void
apply_mask_ipv6 (struct prefix_ipv6 *pfx)
{
  uint plen ;

  confirm(sizeof(in6_addr_t) == sizeof(pfx->prefix)) ;

  plen = pfx->prefixlen ;
  if (plen < 64)
    {
      ((in6_addr_t)pfx->prefix).n64[0] &= n64_mask(plen) ;
      ((in6_addr_t)pfx->prefix).n64[1] = 0 ;
    }
  else
    {
      ((in6_addr_t)pfx->prefix).n64[1] &= n64_mask(plen - 64) ;
    } ;
}

extern bool
prefix_check_ipv6 (prefix_ipv6 pfx)
{
  uint plen ;

  confirm(sizeof(in6_addr_t) == sizeof(pfx->prefix)) ;

  plen = pfx->prefixlen ;
  if (plen < 64)
    {
      if (((in6_addr_t)pfx->prefix).n64[1] != 0)
        return false ;

      return ( ((in6_addr_t)pfx->prefix).n64[0] & n64_wild(plen) ) == 0 ;
    }
  else
    {
      return ( ((in6_addr_t)pfx->prefix).n64[1] & n64_wild(plen - 64) ) == 0 ;
    } ;
} ;

void
str2in6_addr (const char *str, struct in6_addr *addr)
{
  int i;
  unsigned int x;

  /* %x must point to unsinged int */
  for (i = 0; i < 16; i++)
    {
      sscanf (str + (i * 2), "%02x", &x);
      addr->s6_addr[i] = x & 0xff;
    }
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * General prefix and sockunion stuff
 */

/*------------------------------------------------------------------------------
 * Clamp the given prefix prefixlen to the maximum allowed for the family, and
 * then apply the prefixlen mask.
 *
 * This ensures that the prefix is valid.
 */
extern void
apply_mask (prefix pfx)
{
  switch (pfx->family)
    {
      case AF_INET:
        if (pfx->prefixlen > IPV4_MAX_BITLEN)
          pfx->prefixlen = IPV4_MAX_BITLEN ;
        apply_mask_ipv4 ((prefix_ipv4)pfx);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        if (pfx->prefixlen > IPV6_MAX_BITLEN)
          pfx->prefixlen = IPV6_MAX_BITLEN ;
        apply_mask_ipv6 ((prefix_ipv6)pfx);
        break;
#endif /* HAVE_IPV6 */
      default:
        break;
    }
  return;
}

/*------------------------------------------------------------------------------
 * Construct prefix from sockunion -- allocate prefix if required.
 *
 * NB: if constructs a prefix, constructs a generic prefix_t.
 *
 *     If is given a prefix -- must be prefix_t, or otherwise suitable for the
 *     sockunion family.
 *
 * NB: sets the rd_id == prefix_rd_id_null
 */
extern prefix
prefix_from_sockunion (prefix pfx, sockunion_c su)
{
  switch (su->sa.sa_family)
    {
      case AF_INET:
        if (pfx == NULL)
          pfx = prefix_new() ;          /* zeroises entire structure    */
        else
          memset(pfx, 0, sizeof(prefix_ht)) ;

        confirm(prefix_rd_id_null == 0) ;

        pfx->family    = AF_INET;
        pfx->prefixlen = IPV4_MAX_BITLEN;
        pfx->u.prefix4 = su->sin.sin_addr;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
        if (pfx == NULL)
          pfx = prefix_new() ;          /* zeroises entire structure    */
        else
          memset(pfx, 0, sizeof(prefix_ht)) ;

        confirm(prefix_rd_id_null == 0) ;

        pfx->family    = AF_INET6;
        pfx->prefixlen = IPV6_MAX_BITLEN;
        pfx->u.prefix6 = su->sin6.sin6_addr;
        break ;
#endif /* HAVE_IPV6 */

      default:
        pfx = NULL ;
    } ;

  return pfx ;
} ;

/*------------------------------------------------------------------------------
 * Return byte length of address for family of the given prefix.
 *
 * Returns 0 if family is not recognised.
 */
extern uint
prefix_byte_len (prefix_c pfx)
{
  switch (pfx->family)
    {
      case AF_INET:
        return IPV4_MAX_BYTELEN;

#ifdef HAVE_IPV6
      case AF_INET6:
        return IPV6_MAX_BYTELEN;
#endif /* HAVE_IPV6 */

      default:
        return 0 ;
    } ;
}

/*------------------------------------------------------------------------------
 * Return bit length of address for family of the given prefix.
 *
 * Returns 0 if family is not recognised.
 */
extern uint
prefix_bit_len (prefix_c pfx)
{
  switch (pfx->family)
    {
      case AF_INET:
        return IPV4_MAX_BITLEN;

#ifdef HAVE_IPV6
      case AF_INET6:
        return IPV6_MAX_BITLEN;
#endif /* HAVE_IPV6 */

      default:
        return 0 ;
    } ;
}

/*------------------------------------------------------------------------------
 * Generic function for conversion string to struct prefix, checking that the
 *                                address part and prefix length are consistent.
 *
 * Accepts addresses without '/' and prefixes with.
 *
 * Will return "invalid" if there is a prefix length and one or more bits are
 * set in the address part beyond the prefix length -- ie. the address part is
 * not consistent with the prefix length.
 *
 * Returns true  <=> valid IPv4 or (if HAVE_IPV6) IPv6 address or prefix.
 *         false <=> not a valid address or prefix
 *
 * NB: if the address is badly formed or the prefix length is invalid,
 *     returns AF_UNSPEC.
 *
 *     if the address part is not consistent with the prefix length, returns
 *     the prefix as read.
 *
 * NB: sets rd_id == prefix_rd_id_null.
 *
 * NB: the address part is all zeros beyond the given prefix length (if any).
 */
extern bool
str2prefix_check(prefix pfx, const char *str)
{
  memset(pfx, 0, sizeof(prefix_t)) ;

  /* First we try to convert string to struct prefix_ipv4.
   */
  if (str2prefix_ipv4(str, (prefix_ipv4)pfx) > 0)
    return prefix_check_ipv4((prefix_ipv4)pfx) ;

#ifdef HAVE_IPV6
  /* Not IPv43, so try to convert string to struct prefix_ipv6.
  */
  if (str2prefix_ipv6(str, (prefix_ipv6)pfx) > 0)
    return prefix_check_ipv6((prefix_ipv6)pfx) ;

#endif /* HAVE_IPV6 */

  /* Failed...
   */
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Generic function for conversion string to struct prefix.
 *
 * Accepts addresses without '/' and prefixes with.
 *
 * Returns 1 <=> valid IPv4 or (if HAVE_IPV6) IPv6 address or prefix.
 *         0 <=> not a valid address or prefix
 *
 * NB: if is not a valid address or prefix, returns AF_UNSPEC.
 *
 * NB: sets rd_id == prefix_rd_id_null.
 *
 * NB: does NOT check that the address part is all zeros beyond the given
 *     prefix length -- so can read "address + network mask" in '/' notation.
 */
extern int
str2prefix (const char *str, prefix pfx)
{
  int ret;

  memset(pfx, 0, sizeof(prefix_t)) ;

  /* First we try to convert string to struct prefix_ipv4.
   */
  ret = str2prefix_ipv4 (str, (prefix_ipv4)pfx);

#ifdef HAVE_IPV6
  /* If not IPv4, try to convert to struct prefix_ipv6.
   */
  if (ret == 0)
    ret = str2prefix_ipv6 (str, (prefix_ipv6)pfx);
#endif /* HAVE_IPV6 */

  return ret;
}

/*------------------------------------------------------------------------------
 * Convert given prefix to string in the given buffer.
 */
extern int
prefix2str (prefix_c pfx, char *str, int size)
{
  char buf[BUFSIZ];

  inet_ntop (pfx->family, &pfx->u.prefix, buf, BUFSIZ);
  snprintf (str, size, "%s/%d", buf, pfx->prefixlen);
  return 0;
}

/*------------------------------------------------------------------------------
 * Return str_pfxtoa_t structure containing string representation of given
 * prefix.
 */
extern str_pfxtoa_t
spfxtoa(prefix_c pfx)
{
  str_pfxtoa_t QFB_QFS(pfa, qfs) ;

  switch (pfx->family)
    {
      case AF_INET:
        confirm(sizeof(pfa.str) > (INET_ADDRSTRLEN + 3)) ;

        qfs_put_ip_prefix(qfs, &pfx->u.prefix, pfx->prefixlen, pf_ipv4, 0) ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
        confirm(sizeof(pfa.str) > (INET6_ADDRSTRLEN + 4)) ;

        qfs_put_ip_prefix(qfs, &pfx->u.prefix, pfx->prefixlen, pf_ipv6, 0) ;
        break ;
#endif

      default:
        qfs_printf(qfs, "?unknown address family=%u?", pfx->family) ;
        break ;
    } ;

  qfs_term(qfs) ;
  return pfa;
} ;

/*------------------------------------------------------------------------------
 * Create new prefix_t object -- ie, generic prefix
 *
 * Zeroises the entire structure for tininess, which sets:
 *
 *   * AF_UNSPEC
 *
 *   * prefix_rd_id_null
 */
extern prefix
prefix_new ()
{
  confirm((AF_UNSPEC == 0) && (prefix_rd_id_null == 0)) ;

  return XCALLOC (MTYPE_PREFIX, sizeof(prefix_t));
}

/*------------------------------------------------------------------------------
 * Free prefix structure.
 *
 * NB: must be generic prefix_t object.
 */
extern void
prefix_free (struct prefix *pfx)
{
  XFREE (MTYPE_PREFIX, pfx);
}

/*------------------------------------------------------------------------------
 * Utility function.  Check the string only contains digit
 *
 * character.
 * FIXME str.[c|h] would be better place for this function. */
extern int
all_digit (const char *str)
{
  for (; *str != '\0'; str++)
    if (!isdigit ((int) *str))
      return 0;
  return 1;
}

/*------------------------------------------------------------------------------
 * Utility function to convert ipv4 prefixes to Classful prefixes
 */
extern void
apply_classful_mask_ipv4 (prefix_ipv4 pfx)
{
  uint32_t destination;

  destination = ntohl (pfx->prefix.s_addr);

  if (pfx->prefixlen == IPV4_MAX_PREFIXLEN)
    {
      /* do nothing for host routes     */
    }
  else if (IN_CLASSC (destination))
    {
      pfx->prefixlen = 24;
      apply_mask_ipv4(pfx);
    }
  else if (IN_CLASSB(destination))
    {
      pfx->prefixlen = 16;
      apply_mask_ipv4(pfx);
    }
  else
    {
      pfx->prefixlen = 8;
      apply_mask_ipv4(pfx);
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return IPv4 address after application of the mask specified by masklen.
 */
extern in_addr_t
ipv4_network_addr (in_addr_t hostaddr, int masklen)
{
  return hostaddr & ip_len2mask (masklen) ;
}

/*------------------------------------------------------------------------------
 * Return IPv4 address after oring in the wild-card specified by masklen
 */
extern in_addr_t
ipv4_broadcast_addr (in_addr_t hostaddr, int masklen)
{
  struct in_addr mask;

  masklen2ip (masklen, &mask);
  return (masklen != IPV4_MAX_PREFIXLEN-1) ?
         /* normal case */
         (hostaddr | ~mask.s_addr) :
         /* special case for /31 */
         (hostaddr ^ ~mask.s_addr);
}

/*------------------------------------------------------------------------------
 * Utility function to convert ipv4 netmask to prefixes -- all in string form
 *
 *  ex.) "1.1.0.0" "255.255.0.0" => "1.1.0.0/16"
 *  ex.) "1.0.0.0" NULL => "1.0.0.0/8"
 */
extern int
netmask_str2prefix_str (const char *net_str, const char *mask_str,
                        char *prefix_str)
{
  struct in_addr network;
  struct in_addr mask;
  u_char prefixlen;
  u_int32_t destination;
  int ret;

  ret = inet_aton (net_str, &network);
  if (! ret)
    return 0;

  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (! ret)
        return 0;

      prefixlen = ip_masklen (mask);
    }
  else
    {
      destination = ntohl (network.s_addr);

      if (network.s_addr == 0)
        prefixlen = 0;
      else if (IN_CLASSC (destination))
        prefixlen = 24;
      else if (IN_CLASSB (destination))
        prefixlen = 16;
      else if (IN_CLASSA (destination))
        prefixlen = 8;
      else
        return 0;
    }

  sprintf (prefix_str, "%s/%d", net_str, prefixlen);

  return 1;
}

/*------------------------------------------------------------------------------
 * Utility function for making IPv6 address string.
 *
 * NB: returns address of static buffer -- not pThread- or async-signal-safe
 */
#ifdef HAVE_IPV6
extern const char *
inet6_ntoa (struct in6_addr addr)
{
  static char buf[INET6_ADDRSTRLEN];

  inet_ntop (AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
  return buf;
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Raw prefix handling
 */
static const byte prefix_last_byte_mask[8] = { 0xFF, 0x80, 0xC0, 0xE0,
                                               0xF0, 0xF8, 0xFC, 0xFE } ;
inline static void prefix_body_set(prefix pfx, const byte* pb, uint plen,
                                                           sa_family_t family) ;
inline static ulen prefix_body_copy(byte* dst, const byte* src, uint plen) ;

/*------------------------------------------------------------------------------
 * Make raw form of prefix_len + prefix, and return total length.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the prefix beyond the (clamped) prefix length (bits).
 *
 * Returns:  byte length of the prefix -- prefix length + prefix body
 */
extern ulen
prefix_to_raw(prefix_raw raw, prefix_c pfx)
{
  ulen  plen ;

  plen = pfx->prefixlen ;

  switch (pfx->family)
    {
      case AF_INET:
        if (plen > IPV4_MAX_PREFIXLEN)
          plen = IPV4_MAX_PREFIXLEN ;
        break ;

#if HAVE_IPV6
      case AF_INET6:
        if (plen > IPV6_MAX_PREFIXLEN)
          plen = IPV6_MAX_PREFIXLEN ;
        break ;
#endif

      default:
        plen = 0 ;
    } ;

  return prefix_body_copy(raw->prefix, pfx->u.b, plen) ;
} ;

/*------------------------------------------------------------------------------
 * Make raw form of prefix_len + prefix, and return total length.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the prefix beyond the (clamped) prefix length (bits).
 *
 * Returns:  byte length of the prefix -- prefix length + prefix body
 */
extern ulen
prefix_blow(blower br, prefix_c pfx)
{
  ulen  plen ;

  plen = pfx->prefixlen ;

  switch (pfx->family)
    {
      case AF_INET:
        if (plen > IPV4_MAX_PREFIXLEN)
          plen = IPV4_MAX_PREFIXLEN ;
        break ;

#if HAVE_IPV6
      case AF_INET6:
        if (plen > IPV6_MAX_PREFIXLEN)
          plen = IPV6_MAX_PREFIXLEN ;
        break ;
#endif

      default:
        plen = 0 ;
    } ;

  return prefix_body_copy(blow_ptr(br), pfx->u.b, plen) ;
} ;

/*------------------------------------------------------------------------------
 * Set prefix from raw value and given family.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the prefix beyond the (clamped) prefix length (bits and bytes).
 *
 * NB:
 */
extern void
prefix_from_raw(prefix pfx, sa_family_t family, prefix_raw raw)
{
  memset(pfx, 0, sizeof(prefix_t)) ;
  confirm(prefix_rd_id_null == 0) ;

  pfx->family = family ;

  prefix_body_set(pfx, raw->prefix, raw->prefix_len, family) ;
} ;

/*------------------------------------------------------------------------------
 * Set prefix length and body for the current family.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the prefix beyond the (clamped) prefix length (bits and bytes).
 *
 * NB: requires and does not change pfx->family
 *
 *     does not affect the pfx->pr_id
 */
extern void
prefix_body_from_bytes(prefix pfx, const byte* pb, uint plen)
{
  memset(pfx->u.b, 0, sizeof(((prefix)0)->u)) ;

  prefix_body_set(pfx, pb, plen, pfx->family) ;
} ;

/*------------------------------------------------------------------------------
 * Set prefix length and body from nlri.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the prefix beyond the (clamped) prefix length (bits and bytes).
 *
 * NB: requires and does not change pfx->family
 *
 *     does not affect the pfx->pr_id
 */
extern void
prefix_body_from_nlri(prefix pfx, const byte* pb, uint plen)
{
  pfx->prefixlen = plen ;
  prefix_body_copy(pfx->u.b, pb, plen) ;
} ;

/*------------------------------------------------------------------------------
 * Set prefix length and body for the given family.
 *
 * Silently enforces maximum prefix length for known families.  Forces zero
 * prefix length for unknown families.
 *
 * Zeroises the last prefix byte beyond the (clamped) prefix length (bits only).
 *
 * NB: does NOT zeroise *bytes* beyond the last prefix byte.
 *
 * NB: does not affect pfx->family
 *     does not affect the pfx->pr_id
 */
inline static void
prefix_body_set(prefix pfx, const byte* pb, uint plen, sa_family_t family)
{
  switch (family)
    {
      case AF_INET:
        if (plen > IPV4_MAX_PREFIXLEN)
          plen = IPV4_MAX_PREFIXLEN ;
        break ;

#if HAVE_IPV6
      case AF_INET6:
        if (plen > IPV6_MAX_PREFIXLEN)
          plen = IPV6_MAX_PREFIXLEN ;
        break ;
#endif

      default:
        plen = 0 ;
    } ;

  pfx->prefixlen = plen ;
  prefix_body_copy(pfx->u.b, pb, plen) ;
} ;

/*------------------------------------------------------------------------------
 * Copy body of prefix -- zeroising bits in the last byte as required.
 *
 * Returns:  byte length of the result -- *including* the prefix length byte.
 */
inline static ulen
prefix_body_copy(byte* dst, const byte* src, uint plen)
{
  ulen len ;

  if (plen == 0)
    return 1 ;

  len = (plen - 1) / 8 ;
  if (len != 0)
    memcpy(dst, src, len) ;

  dst[len] = src[len] & prefix_last_byte_mask[plen & 0x7] ;

  return len + 2 ;
} ;

/*------------------------------------------------------------------------------
 * Set prefix to default route for given family -- ie. 0.0.0.0/0 or ::/0
 *
 * Sets pfx->pr_id to prefix_rd_id_null
 *
 * Will set an unknown family -- setting prefix length and body all zero.
 */
extern void
prefix_default(prefix pfx, sa_family_t family)
{
  memset(pfx, 0, sizeof(prefix_t)) ;
  confirm(prefix_rd_id_null == 0) ;

  pfx->family = family ;
} ;

/*==============================================================================
 * Converting various forms of address pair to/from prefix
 */

/*------------------------------------------------------------------------------
 * Fill address range from the given prefix.
 *
 * Note that this assumes that the prefix is valid (that the prefixlen is
 * valid for its family, and that the prefix is all zero from the prefixlen
 * bit onwards).  The result is undefined if this is not the case.  Also,
 * only sets the parts of the union that are used.  (This is intended for
 * where minimum overhead is required.)
 *
 * See prefix_to_pair_range_tidy() for a more careful approach.
 *
 * Zeroizes the ip_union_pair if the prefix family is not known
 *
 * NB: components of the address range are in HOST ORDER, so that address
 *     ranges can be compared most readily.
 *
 *     IPv6 addresses are held as pairs of uint64_t, where the [0] value is
 *     the MS of the pair.  (So on a Big-Endian machine the entire address is
 *     in network order, but on a Little-Endian machine each half is in
 *     host order, but the two halves are in network order !
 */
extern void
prefix_to_pair_range(ip_union_pair pair, prefix_c pfx)
{
  in_addr_t  ipv4 ;
#if HAVE_IPV6
  uint64_t ipv6_0, ipv6_1 ;
#endif

  switch (pfx->family)
    {
      case AF_INET:
        ipv4 = ntohl(pfx->u.ipv4) ;
        pair->ipv4[0] = ipv4 ;

        if (pfx->prefixlen < 32)
          ipv4 |= (U32_1s >> pfx->prefixlen) ;

        pair->ipv4[1] = ipv4 ;
        break ;

#if HAVE_IPV6
      case AF_INET6:
        ipv6_0 = ntohq(pfx->u.ipv6.n64[0]) ;

        if      (pfx->prefixlen <  64)
          {
            ipv6_1 = 0 ;

            pair->ipv6[1].n64[0] = ipv6_0 | (U64_1s >> pfx->prefixlen) ;
            pair->ipv6[1].n64[1] = U64_1s ;
          }
        else
          {
            ipv6_1 = ntohq(pfx->u.ipv6.n64[1]) ;

            pair->ipv6[1].n64[0] = ipv6_0 ;

            if (pfx->prefixlen < 128)
              pair->ipv6[1].n64[1] = ipv6_1 | (U64_1s >> (pfx->prefixlen - 64));
            else
              pair->ipv6[1].n64[1] = ipv6_1 ;
          } ;

        pair->ipv6[0].n64[0] = ipv6_0 ;
        pair->ipv6[0].n64[1] = ipv6_1 ;
        break ;
#endif

      default:
        memset(pair, 0, sizeof(ip_union_pair_t)) ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Fill address range from the given prefix, and do it tidily.
 *
 * Zeroizes the ip_union_pair before starting (and if prefix family not known).
 *
 * If the prefix has '1' bits beyond the prefixlen, zeroizes those.  (If the
 * prefixlen is invalid for the family, treats as maximum possible.)
 *
 * NB: see prefix_to_pair_range() for note on HOST ORDER.
 */
extern void
prefix_to_pair_range_tidy(ip_union_pair pair, prefix_c pfx)
{
  in_addr_t  ipv4, ipv4_wild ;
#if HAVE_IPV6
  uint64_t ipv6, ipv6_wild ;
#endif

  memset(pair, 0, sizeof(ip_union_pair_t)) ;

  switch (pfx->family)
    {
      case AF_INET:
        ipv4 = ntohl(pfx->u.ipv4) ;

        if (pfx->prefixlen < 32)
          ipv4_wild = U32_1s >> pfx->prefixlen ;
        else
          ipv4_wild = 0 ;

        confirm(IPV4_MAX_PREFIXLEN == 32) ;

        pair->ipv4[0] = ipv4 & ~ipv4_wild ;
        pair->ipv4[1] = ipv4 |  ipv4_wild ;

        break ;

#if HAVE_IPV6
      case AF_INET6:
        ipv6 = ntohq(pfx->u.ipv6.n64[0]) ;

        if      (pfx->prefixlen <  64)
          {
            ipv6_wild = U64_1s >> pfx->prefixlen ;

            pair->ipv6[0].n64[0] = ipv6 & ~ipv6_wild ;
            pair->ipv6[0].n64[1] = 0 ;

            pair->ipv6[1].n64[0] = ipv6 |  ipv6_wild ;
            pair->ipv6[1].n64[1] = U64_1s ;
          }
        else
          {
            pair->ipv6[0].n64[0] = ipv6 ;
            pair->ipv6[1].n64[0] = ipv6 ;

            ipv6 = ntohq(pfx->u.ipv6.n64[1]) ;

            if (pfx->prefixlen < 128)
              ipv6_wild = U64_1s >> (pfx->prefixlen - 64) ;
            else
              ipv6_wild = 0 ;

            confirm(IPV6_MAX_PREFIXLEN == 128) ;

            pair->ipv6[0].n64[1] = ipv6 & ~ipv6_wild ;
            pair->ipv6[1].n64[1] = ipv6 |  ipv6_wild ;
          } ;
        break ;
#endif

      default:
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Fill address and mask from the given prefix.
 *
 * NB: the address range are in the conventional Network Order.
 *
 * NB: no check is made to ensure that the address is valid for the prefix
 *     length.
 */
extern void
prefix_to_pair_mask(ip_union_pair pair, prefix pfx)
{

} ;

/*------------------------------------------------------------------------------
 *
 */
extern void
prefix_to_pair_wild(ip_union_pair pair, prefix pfx)
{

} ;

/*------------------------------------------------------------------------------
 * Fill prefix from the given address range, of the given sa_family.
 *
 * NB: components of the address range are in HOST ORDER, so that address
 *     ranges can be compared most readily.
 *
 *     IPv6 addresses are held as pairs of uint64_t, where the [0] value is
 *     the MS of the pair.  (So on a Big-Endian machine the entire address is
 *     in network order, but on a Little-Endian machine each half is in
 *     host order, but the two halves are in network order !
 *
 * NB: the prefix length is the number of leading zeros on the result of
 *     xoring the two ends of the range.
 *
 *     There is no check made on the validity of the start and end of the
 *     range.
 *
 * AF_UNSPEC ignores the given 'pair' and returns zeroized prefix.
 */
extern void
prefix_from_pair_range(prefix pfx, ip_union_pair pair, sa_family_t family)
{
  in_addr_t  ipv4 ;
#if HAVE_IPV6
  uint64_t ipv6_0, ipv6_1 ;
#endif

  memset(pfx, 0, sizeof(prefix_t)) ;

  pfx->family = family ;
  switch (family)
    {
      case AF_INET:
        ipv4 = pair->ipv4[0] ;
        pfx->u.ipv4 = htonl(ipv4) ;

        ipv4 ^= pair->ipv4[1] ;

        if (ipv4 != 0)
          pfx->prefixlen = local_clz_u32(ipv4) ;
        else
          pfx->prefixlen = 32 ;

        break ;

#if HAVE_IPV6
      case AF_INET6:
        ipv6_0 = pair->ipv6[0].n64[0] ;
        ipv6_1 = pair->ipv6[0].n64[1] ;

        pfx->u.ipv6.n64[0]  = htonq(ipv6_0) ;
        pfx->u.ipv6.n64[1]  = htonq(ipv6_1) ;

        ipv6_0 ^= pair->ipv6[1].n64[0] ;

        if (ipv6_0 != 0)
          pfx->prefixlen = local_clz_n64(ipv6_0) ;
        else
          {
            ipv6_1 ^= pair->ipv6[1].n64[1] ;

            if (ipv6_1 != 0)
              pfx->prefixlen = local_clz_n64(ipv6_1) + 64 ;
            else
              pfx->prefixlen = 128 ;
          } ;
        break ;
#endif
      case AF_UNSPEC:
        break ;

      default:
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 *
 */
extern void
prefix_from_pair_mask(prefix pfx, ip_union_pair pair, sa_family_t family)
{
  ;
} ;

/*------------------------------------------------------------------------------
 *
 */
extern void
prefix_from_pair_wild(prefix pfx, ip_union_pair pair, sa_family_t family)
{
  ;
} ;

