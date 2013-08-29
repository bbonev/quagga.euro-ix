/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_PREFIX_H
#define _ZEBRA_PREFIX_H

#include "misc.h"
#include "sockunion.h"          /* defines: typedef ... prefix_c        */
#include "qafi_safi.h"
#include "qfstring.h"
#include "ring_buffer.h"

/*------------------------------------------------------------------------------
 * A struct prefix contains an address family, a prefix length, and an
 * address.  This can represent either a 'network prefix' as defined
 * by CIDR, where the 'host bits' of the prefix are 0
 * (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 * (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 * interface.
 *
 * For MPLS VPN in BGP, a prefix has a "Route Distinguisher" on the front.
 * Assuming that is rendered (by some means, not known here) to a 32-bit
 * ID, we tuck that into the "prefix" structure in what is otherwise unused
 * space.  So, can handle MPLS VPN prefixes the same as ordinary ones.
 */
typedef uint32_t prefix_rd_id_t ;
enum { prefix_rd_id_null  = 0 } ;

/* Prefix Header.
 *
 * There are a number of variants on the common prefix structure -- mainly
 * so that there is an IPv4 variant which is 12 bytes, where the full
 * structure is 24 -- for IPv6.
 *
 * All variants have the same "header" part -- which is defined here so that
 * can (a) cast pointers and copy the header and (b) confirm that the header
 * is the same in all variants
 */
typedef byte prefix_len_t ;

typedef struct prefix_h  prefix_ht ;
typedef struct prefix_h* prefix_h ;
typedef const struct prefix_h* prefix_hc ;

struct prefix_h
{
  sa_family_t   family;
  prefix_len_t  prefixlen;

  prefix_rd_id_t rd_id ;

  byte          body[] ;
} ;

CONFIRM((offsetof(prefix_ht, body) % 8) == 0) ;
CONFIRM(offsetof(prefix_ht, body) == sizeof(prefix_ht)) ;

/* Generic prefix structure -- with/without Route Distinguisher.
 *
 * NB: prefix.h #includes sockunion.h, and sockunion.h needs prefix_c,
 *     so that is defined there !
 */
typedef struct prefix  prefix_t ;
typedef struct prefix* prefix ;

struct prefix
{
  sa_family_t   family;
  prefix_len_t  prefixlen;

  prefix_rd_id_t rd_id ;

  union
    {
      byte      prefix ;        /* anonymous    */

      in_addr_s  prefix4 ;      /* prefix_ipv4  */
      in_addr_t  ipv4 ;

#ifdef HAVE_IPV6
      in6_addr_s prefix6 ;      /* prefix_ipv6  */
      in6_addr_t ipv6 ;

      uint64_t  n64[2] ;
      uint32_t  n32[4] ;
      uint8_t   b[16] ;

#else
      uint32_t  n32[1] ;
      uint8_t   b[4] ;
#endif /* HAVE_IPV6 */

      struct
        {
          in_addr_s id;
          in_addr_s adv_router;
        } lp ;                  /* prefix_ls_t  */

      byte      val[8] ;        /* prefix_rd_t  */
  } u ;
};

CONFIRM(sizeof(((prefix)0)->u.n32) >= sizeof(((prefix)0)->u.ipv4)) ;
CONFIRM(sizeof(((prefix)0)->u.b)   >= sizeof(((prefix)0)->u.ipv4)) ;

#if HAVE_IPV6
CONFIRM(sizeof(((prefix)0)->u.n64) == sizeof(((prefix)0)->u.ipv6)) ;
CONFIRM(sizeof(((prefix)0)->u.n32) == sizeof(((prefix)0)->u.ipv6)) ;
CONFIRM(sizeof(((prefix)0)->u.b)   == sizeof(((prefix)0)->u.ipv6)) ;
#endif

CONFIRM(offsetof(prefix_t,  family)
     == offsetof(prefix_ht, family)) ;
CONFIRM(offsetof(prefix_t,  prefixlen)
     == offsetof(prefix_ht, prefixlen)) ;
CONFIRM(offsetof(prefix_t,  rd_id)
     == offsetof(prefix_ht, rd_id)) ;
CONFIRM(offsetof(prefix_t,  u)
     == offsetof(prefix_ht, body)) ;

/* So we know that the AF_INET, IPv4 prefix address maps to *network order*
 * uint32_t.
 *
 * And that the AF_INET6, IPv6 prefix address maps to Big Endian array of four
 * *network order* uint32_t (or two *network order uint64_t !)
 */
CONFIRM(sizeof(in_addr_s) == sizeof(((prefix)0)->u.n32[0])) ;

#ifdef HAVE_IPV6
CONFIRM(sizeof(in6_addr_s) == sizeof(((prefix)0)->u.b)) ;
CONFIRM(sizeof(in6_addr_s) == sizeof(((prefix)0)->u.n32)) ;
CONFIRM(sizeof(in6_addr_s) == sizeof(((prefix)0)->u.n64)) ;
#endif

/* Prefix as carried in protocols
 */
typedef struct prefix_raw  prefix_raw_t ;
typedef struct prefix_raw* prefix_raw ;
typedef const struct prefix_raw* prefix_raw_c ;

struct prefix_raw
{
  prefix_len_t prefix_len ;
  byte prefix[256 / 8] ;
} ;

CONFIRM(offsetof(prefix_raw_t, prefix_len) == 0) ;
CONFIRM(offsetof(prefix_raw_t, prefix)     == 1) ;

/* IPv4 prefix structure.
 */
typedef struct prefix_ipv4  prefix_ipv4_t ;
typedef struct prefix_ipv4* prefix_ipv4 ;
typedef const struct prefix_ipv4* prefix_ipv4_c ;

struct prefix_ipv4
{
  sa_family_t    family ;
  prefix_len_t   prefixlen ;
  prefix_rd_id_t rd_id ;
  in_addr_s      prefix ;
};
CONFIRM(offsetof(prefix_ipv4_t, family)
     == offsetof(prefix_ht,    family)) ;
CONFIRM(offsetof(prefix_ipv4_t, prefixlen)
     == offsetof(prefix_ht,    prefixlen)) ;
CONFIRM(offsetof(prefix_ipv4_t, rd_id)
     == offsetof(prefix_ht,    rd_id)) ;
CONFIRM(offsetof(prefix_ipv4_t, prefix)
     == offsetof(prefix_t,      u.prefix4)) ;
CONFIRM(sizeof(prefix_ipv4_t) <= sizeof(prefix_t)) ;

/* IPv6 prefix structure.
 */
#ifdef HAVE_IPV6
typedef struct prefix_ipv6  prefix_ipv6_t ;
typedef struct prefix_ipv6* prefix_ipv6 ;
typedef const struct prefix_ipv6* prefix_ipv6_c ;

struct prefix_ipv6
{
  sa_family_t    family;
  prefix_len_t   prefixlen;
  prefix_rd_id_t rd_id ;
  in6_addr_s     prefix ;
};
CONFIRM(offsetof(prefix_ipv6_t, family)
     == offsetof(prefix_ht,     family)) ;
CONFIRM(offsetof(prefix_ipv6_t, prefixlen)
     == offsetof(prefix_ht,     prefixlen)) ;
CONFIRM(offsetof(prefix_ipv6_t, rd_id)
     == offsetof(prefix_ht,     rd_id)) ;
CONFIRM(offsetof(prefix_ipv6_t,   prefix)
     == offsetof(prefix_t,      u.prefix6)) ;
CONFIRM(sizeof(prefix_ipv6_t) <= sizeof (prefix_t)) ;
#endif /* HAVE_IPV6 */

/* Link State prefix structure
 */
typedef struct prefix_ls  prefix_ls_t ;
typedef struct prefix_ls* prefix_ls ;
typedef const struct prefix_ls* prefix_ls_c ;

struct prefix_ls
{
  sa_family_t    family;
  prefix_len_t   prefixlen;
  prefix_rd_id_t unused ;
  in_addr_s      id ;
  in_addr_s      adv_router;
  byte end[] ;
};
CONFIRM(offsetof(prefix_ls_t, family)
     == offsetof(prefix_ht,   family)) ;
CONFIRM(offsetof(prefix_ls_t, prefixlen)
     == offsetof(prefix_ht,   prefixlen)) ;
CONFIRM(offsetof(prefix_ls_t,      id)
     == offsetof(prefix_t,    u.lp.id)) ;
CONFIRM(offsetof(prefix_ls_t,      adv_router)
     == offsetof(prefix_t,    u.lp.adv_router)) ;
CONFIRM(sizeof(prefix_ls_t)   <= sizeof(prefix_t)) ;

#if 0
/* (Pseudo) Prefix for routing distinguisher -- uses AF_UNSPEC.
 *
 * The rd_id will/must be prefix_rd_id_null (0) -- these things do not nest.
 */
typedef struct prefix_rd  prefix_rd_t ;
typedef struct prefix_rd* prefix_rd ;
typedef const struct prefix_rd* prefix_rd_c ;

struct prefix_rd
{
  sa_family_t   family;
  prefix_len_t  prefixlen;
  prefix_rd_id_t unused ;
  byte          val[8] ;
  byte          end[] ;
};
CONFIRM(offsetof(prefix_rd_t, family)
     == offsetof(prefix_ht,   family)) ;
CONFIRM(offsetof(prefix_rd_t, prefixlen)
     == offsetof(prefix_ht,   prefixlen)) ;
CONFIRM(offsetof(prefix_rd_t, unused)
     == offsetof(prefix_ht,   rd_id)) ;
CONFIRM(offsetof(prefix_rd_t,   val)
     == offsetof(prefix_t,    u.val)) ;
CONFIRM(sizeof(prefix_rd_t)   <= sizeof(prefix_t)) ;

#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 51
#endif /* INET6_BUFSIZ */

/* Max bit/byte length of IPv4 address.
 */
enum
{
  IPV4_MAX_BYTELEN    =  4,
  IPV4_MAX_BITLEN     = 32,
  IPV4_MAX_PREFIXLEN  = 32,
} ;

/* Comparing and copying IPv4 addresses
 *
 * These use memcmp() and memcpy() with fixed (at compile time) length, which
 * we hope the compiler will transform into suitable 32-bit operations.
 *
 * NB: result of the compare assumes Network Order address (as usual)
 */
#define IPV4_ADDR_CMP(D,S)   memcmp ((D), (S), IPV4_MAX_BYTELEN)
#define IPV4_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV4_MAX_BYTELEN) == 0)
#define IPV4_ADDR_COPY(D,S)  memcpy ((D), (S), IPV4_MAX_BYTELEN)

/* Checking certain network types -- but for Host Order addresses
 *
 * The use of Host Order addresses follows IN_CLASSA() et al.
 */
#define IPV4_NET0(a)      ((((uint32_t)(a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a)    ((((uint32_t)(a)) & 0xff000000) == 0x7f000000)
#define IPV4_LINKLOCAL(a) ((((uint32_t)(a)) & 0xffff0000) == 0xa9fe0000)
#define IPV4_CLASS_DE(a)  ((((uint32_t)(a)) & 0xe0000000) == 0xe0000000)

#if   BYTE_ORDER == BIG_ENDIAN
#define IPV4_N_NET0(a)      IPV4_NET0(a)
#define IPV4_N_NET127(a)    IPV4_NET127(a)
#define IPV4_N_LINKLOCAL(a) IPV4_LINKLOCAL(a)
#define IPV4_N_CLASS_DE(a)  IPV4_CLASS_DE(a)
#else
#define IPV4_N_NET0(a)      ((((uint32_t)(a)) & 0x000000ff) == 0x00000000)
#define IPV4_N_NET127(a)    ((((uint32_t)(a)) & 0x000000ff) == 0x0000007f)
#define IPV4_N_LINKLOCAL(a) ((((uint32_t)(a)) & 0x0000ffff) == 0x0000fea9)
#define IPV4_N_CLASS_DE(a)  ((((uint32_t)(a)) & 0xe00000e0) == 0x000000e0)
#endif

/* Max bit/byte length of IPv6 address.
 */
enum
{
  IPV6_MAX_BYTELEN    =  16,
  IPV6_MAX_BITLEN     = 128,
  IPV6_MAX_PREFIXLEN  = 128,
} ;

/* Comparing and copying IPv6 addresses
 *
 * These use memcmp() and memcpy() with fixed (at compile time) length, which
 * we hope the compiler will transform into suitable 64/128-bit operations.
 *
 * NB: result of the compare assumes Network Order address (as usual)
 */
#define IPV6_ADDR_CMP(D,S)  memcmp (D, S, IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)  (IPV6_ADDR_CMP(D,S) == 0)
#define IPV6_ADDR_COPY(D,S)  memcpy (D, S, IPV6_MAX_BYTELEN)

/* Count prefix size from mask length
 */
#define PSIZE(a) (((a) + 7) / (8))

/* Prefix's family member.
 */
#define PREFIX_FAMILY(pfx)  ((pfx)->family)

/* Fixed length string structure for prefix in string form.
 */
QFB_T(60) str_pfxtoa_t ;


/*==============================================================================
 * Prototypes.
 */
/* Check bit of the prefix. */
extern unsigned int prefix_bit (const u_char *prefix, const u_char prefixlen);
#ifdef HAVE_IPV6
extern unsigned int prefix6_bit (const struct in6_addr *prefix,
                                                        const u_char prefixlen);
#endif
extern prefix prefix_new (void);
extern void prefix_free (prefix pfx);
extern const char *prefix_family_str (prefix_c pfx);
extern uint prefix_byte_len (prefix_c pfx);
extern uint prefix_bit_len (prefix_c pfx);

extern ulen prefix_to_raw(prefix_raw eaw, prefix_c pfx) ;
extern ulen prefix_blow(blower br, prefix_c pfx) ;
extern void prefix_from_raw(prefix pfx, sa_family_t family, prefix_raw raw) ;
extern void prefix_body_from_bytes(prefix pfx, const byte* pb, uint plen) ;
extern void prefix_body_from_nlri(prefix pfx, const byte* pb, uint plen) ;
extern void prefix_default(prefix pfx, sa_family_t family) ;

extern bool str2prefix_check(prefix pfx, const char *str) ;
extern int str2prefix (const char* str, prefix pfx);
extern int prefix2str (const struct prefix *, char *, int);
extern str_pfxtoa_t spfxtoa(prefix_c pfx) ;

extern bool prefix_match (prefix_c pfx1, prefix_c pfx2);
extern bool prefix_same (prefix_c pfx1, prefix_c pfx2);
extern int prefix_equal (prefix_c pfx1, prefix_c pfx2) ;
extern int prefix_cmp (prefix_c pfx1, prefix_c pfx2);
extern int prefix_sort_cmp (prefix_c pfx1, prefix_c pfx2);
extern int prefix_common_bits (prefix_c pfx1, prefix_c pfx2);
extern void prefix_copy (prefix dst, prefix_c src);
extern void apply_mask (prefix pfx);

extern prefix prefix_from_sockunion (prefix pfx, sockunion_c src);

extern prefix_ipv4 prefix_ipv4_new (void);
extern void prefix_ipv4_free (prefix_ipv4 pfx);
extern int str2prefix_ipv4 (const char* str, prefix_ipv4 pfx);
extern bool str2ipv4 (in_addr_t* ipv4, const char* str, const char** end) ;
extern void apply_mask_ipv4 (prefix_ipv4 pfx);
extern bool prefix_check_ipv4 (prefix_ipv4 pfx) ;

#define PREFIX_COPY_IPV4(DST, SRC)      \
        *((struct prefix_ipv4 *)(DST)) = *((const struct prefix_ipv4 *)(SRC));

Inline void
prefix_copy_ipv4(struct prefix* dst, struct prefix* src)
{
  *dst = *src ;
} ;

extern bool prefix_ipv4_any (const struct prefix_ipv4 *);
extern void apply_classful_mask_ipv4 (struct prefix_ipv4 *);

extern byte ip_mask2len (in_addr_t netmask);
extern in_addr_t ip_len2mask (byte len);
extern bool ip_mask_check (in_addr_t netmask) ;

#define ip_masklen(netmask) ip_mask2len((netmask).s_addr)
extern void masklen2ip (const uint, struct in_addr *);
/* returns the network portion of the host address */
extern in_addr_t ipv4_network_addr (in_addr_t hostaddr, int masklen);
/* given the address of a host on a network and the network mask length,
 * calculate the broadcast address for that network;
 * special treatment for /31: returns the address of the other host
 * on the network by flipping the host bit */
extern in_addr_t ipv4_broadcast_addr (in_addr_t hostaddr, int masklen);

extern int netmask_str2prefix_str (const char *, const char *, char *);

#ifdef HAVE_IPV6
extern prefix_ipv6 prefix_ipv6_new (void);
extern void prefix_ipv6_free (prefix_ipv6 pfx);
extern int str2prefix_ipv6 (const char* str, prefix_ipv6 pfx);
extern bool str2ipv6 (in6_addr_s* ipv6, const char* str, const char** end) ;
extern void apply_mask_ipv6 (prefix_ipv6 pfx);
extern bool prefix_check_ipv6 (prefix_ipv6 pfx) ;

#define PREFIX_COPY_IPV6(DST, SRC)      \
        *((struct prefix_ipv6 *)(DST)) = *((const struct prefix_ipv6 *)(SRC));

Inline void
prefix_copy_ipv6(struct prefix* dst, struct prefix* src)
{
  *dst = *src ;
} ;

extern u_char ip6_masklen (const struct in6_addr* p_s6_addr);
extern bool ip6_mask_check (const struct in6_addr* p_s6_addr) ;
extern void masklen2ip6 (uint, struct in6_addr *);

extern void str2in6_addr (const char *, struct in6_addr *);
extern const char *inet6_ntoa (struct in6_addr);

#endif /* HAVE_IPV6 */

extern void prefix_to_pair_range(ip_union_pair pair, prefix_c pfx) ;
extern void prefix_to_pair_range_tidy(ip_union_pair pair, prefix_c pfx) ;
extern void prefix_to_pair_mask(ip_union_pair pair, prefix pfx) ;
extern void prefix_to_pair_wild(ip_union_pair pair, prefix pfx) ;
extern void prefix_from_pair_range(prefix pfx, ip_union_pair pair,
                                                           sa_family_t family) ;
extern void prefix_from_pair_mask(prefix pfx, ip_union_pair pair,
                                                           sa_family_t family) ;
extern void prefix_from_pair_wild(prefix pfx, ip_union_pair pair,
                                                           sa_family_t family) ;

extern int all_digit (const char *);

#endif /* _ZEBRA_PREFIX_H */
