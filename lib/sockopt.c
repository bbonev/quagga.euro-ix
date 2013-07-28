/* Setting and getting socket options -- utility functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include "log.h"
#include "sockopt.h"
#include "sockunion.h"
#include "pthread_safe.h"

/*------------------------------------------------------------------------------
 * getsockopt -- SO_ERROR
 *
 * NB: does not distinguish between errors raised by the getsockopt() and
 *     errors it returns...
 *
 *     getsockopt() can return:
 *
 *       EBADF       -- same-like a read() or write() -- not logged
 *
 *       EACCES      -- unlikely -- but would be logged
 *       EINVAL      -- unlikely -- but would be logged
 *       ENOTSOCK    -- unlikely -- but would be logged
 *
 *       EINVAL      -- "impossible" -- but would be logged
 *       ENOPROTOOPT -- "impossible" -- but would be logged
 *       ENOBUFS     -- "impossible" -- but would be logged
 *
 * Returns:  == 0   => OK (and errno == 0)
 *            < 0   => some error.  errno == error
 *
 * NB: if OK, returns 0 -- same like a read(..., 0).
 *
 * NB: according to "Unix Network Programming" (ISBN 0-13-141155-1) Solaris
 *     can return -1 from getsockopt(), setting errno to the pending so_error.
 *
 *     This sounds nuts, but apart from some extra logging, this code will
 *     cope.
 */
extern int
getsockopt_so_error (int sock_fd)
{
  int       err;
  socklen_t optlen ;
  int       ret ;

  optlen = sizeof(err) ;
  err = 0 ;
  ret    = getsockopt (sock_fd, SOL_SOCKET, SO_ERROR, &err, &optlen) ;
  if (ret >= 0)
    ret = 0 ;
  else
    {
      err = errno ;
      if (err != EBADF)
        zlog_err ("cannot get sockopt SO_ERROR on socket %d: %s",
                                                  sock_fd, errtoa(err, 0).str) ;
    } ;

  errno = err ;
  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set socket SO_REUSEADDR option
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_WARNING message if fails.
 */
extern int
setsockopt_reuseaddr (int sock_fd)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (ret < 0)
    {
      int err = errno ;
      zlog_warn ("cannot set sockopt SO_REUSEADDR on socket %d: %s", sock_fd,
                                                           errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret ;
}

/*------------------------------------------------------------------------------
 * Set socket SO_REUSEPORT option -- if it is locally supported.
 *
 * Returns: >= 0 => OK -- or not supported
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_WARNING message if fails.
 */
extern int
setsockopt_reuseport (int sock_fd)
{
  int ret;

#ifdef SO_REUSEPORT
  int on = 1;
  ret = setsockopt (sock_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#else
  ret = 0 ;
#endif

  if (ret < 0)
    {
      int err = errno ;
      zlog_warn ("cannot set sockopt SO_REUSEPORT on socket %d: %s", sock_fd,
                                                           errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set socket SO_BROADCAST option
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_WARNING message if fails.
 */
extern int
setsockopt_broadcast (int sock_fd)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
  if (ret < 0)
    {
      int err = errno ;
      zlog_warn ("cannot set sockopt SO_BROADCAST on socket %d: %s", sock_fd,
                                                          errtoa(err, 0).str) ;
      errno = err ;
    }
  return ret ;
}

/*------------------------------------------------------------------------------
 * Set TCP_CORK, if available.
 *
 * Returns: >= 0 => OK -- or not supported
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_WARNING message if fails.
 */
extern int
setsockopt_cork (int sock_fd, int onoff)
{
#ifdef TCP_CORK
  int ret;

  ret = setsockopt (sock_fd, IPPROTO_TCP, TCP_CORK, &onoff, sizeof(onoff));
  if (ret < 0)
    {
      int err = errno ;
      zlog_warn ("cannot set sockopt TCP_CORK to %d on socket %d: %s", onoff,
                                                 sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    }
  return ret ;
#else
  return 0;
#endif
}

/*------------------------------------------------------------------------------
 * Set IP_TTL/IPV6_UNICAST_HOPS for socket, if available
 *
 * The ttl given is the maximum number of hops to allow -- so will generally
 * be 1 or 255 or some small number.
 *
 * NB: This code treats any ttl outside the range 1..MAXTTL as MAXTTL.
 *
 * Returns: >= 0 => OK -- or not supported
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_WARNING message if fails.
 *
 * NB: for AF_INET6 where have: IN6_IS_ADDR_V4MAPPED, there is the question
 *     of whether to use IPPROTO_IP/IP_TTL or IPPROTO_IPV6/IPV6_UNICAST_HOPS.
 *
 *     Here we try first to use the socket family, and if that fails on
 *     AF_INET6, then if the protocol family is AF_INET, then tries that.
 */
extern int
setsockopt_ttl (int sock_fd, int ttl)
{
  const char* name ;
  int   af ;
  int   ret ;

  af = sockunion_getsockfamily(sock_fd) ;
  if (af < 0)
    return af ;

  if ((ttl < 1) || (ttl > MAXTTL))
    ttl = MAXTTL ;

  ret  = 0 ;
  name = NULL ;

  while (1)
    {
      switch (af)
        {
          case AF_INET:
#ifdef IP_TTL
            ret  = setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) ;
            name = "IP_TTL" ;
#endif /* IP_TTL */
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            ret  = setsockopt (sock_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                                                           &ttl, sizeof(ttl)) ;
            name = "IPV6_UNICAST_HOPS" ;

            if (ret < 0)
              {
                af = sockunion_getprotofamily(sock_fd) ;
                if (af == AF_INET)
                  continue ;
              } ;
            break ;
#endif

          default:              /* ignore unknown family        */
            break ;
        } ;

      break ;
    } ;

  if (ret < 0)
    {
      int err = errno ;
      zlog_warn("cannot set sockopt %s to %d on socket %d: %s", name, ttl,
                                                  sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set IP_MINTTL/IPV6_MINHOPCOUNT (GTSM), if available.
 *
 * The ttl given is the maximum number of hops to allow -- so will generally
 * be 1 -- which is the same as IP_TTL/IPV6_UNICAST_HOPS.
 *
 * To turn off GTSM, need to ask for ttl = 0 (or < 0 !).
 *
 * Any ttl greater than MAX_TTL is clapped to MAX_TTL.
 *
 * The underlying mechanics take "minttl" value, which is:
 *
 *   minttl = 0 => turn off GTSM
 *
 *   minttl = MAX_TTL - (ttl - 1)   -- ie MAX_TTL..1 for hop count 1..MAX_TTL.
 *
 * Returns: >= 0 => OK == the minttl actually set
 *           < 0 => failed or not supported -- see errno -- WARNINGS issued
 *                                             EOPNOTSUPP if not supported
 *
 * Logs a LOG_WARNING message if fails (including not supported).
 *
 * NB: for AF_INET6 where have: IN6_IS_ADDR_V4MAPPED, there is the question
 *     of whether to use IPPROTO_IP/IP_TTL or IPPROTO_IPV6/IPV6_UNICAST_HOPS.
 *
 *     Here we try first to use the socket family, and if that fails on
 *     AF_INET6, then if the protocol family is AF_INET, then tries that.
 */
extern int
setsockopt_minttl (int sock_fd, int ttl)
{
  const char* name ;
  int   af ;
  int   minttl ;
  int   ret, err ;

  af = sockunion_getsockfamily(sock_fd) ;
  if (af < 0)
    return af ;

  ret  = 0 ;
  name = NULL ;

  if (ttl < 1)
    minttl = 0 ;
  else
    {
      if (ttl > MAXTTL)
        minttl = 1 ;
      else
        minttl = MAXTTL - (ttl - 1) ;
    } ;

  /* We have a while(1) loop so that for an IPv6 family socket, can try first
   * with an IPPROTO_IPV6 operation, but if that fails, can try again with
   * IPPROTO_IP iff we have a mapped IPv4 address.
   *
   * The scope for confusion here just emphasises what a BAD IDEA mapped IPv4
   * addresses are :-(
   */
  while (1)
    {
      enum
        {
#ifdef  IP_MINTTL
          have_ip_minttl = true,
          ip_minttl      = IP_MINTTL
#else
          have_ip_minttl = false,
          ip_minttl      = 0
#endif
        } ;

#ifdef HAVE_IPV6

# ifndef IPV6_MINHOPCOUNT
  /* IPV6_MINHOPCOUNT ought to find its way into in.h at some point.
   *
   * For GNU_LINUX it is currently found in linux/in6.h.  Unfortunately, that
   * seems to redefine a number of things which are defined in in.h... so,
   * the #include to bring in IPV6_MINHOPCOUNT is buried more or less as
   * deep as we can get it.
   *
   * However, this trick does not always work... for example, if linux/in6.h
   * redefines "extern const struct in6_addr in6addr_any" !!  Do not know
   * any way to fix that, so -DNO_LINUX_IN6_H can be set to turn this off !
   */
#  if defined(GNU_LINUX) && !defined(NO_LINUX_IN6_H)
    #include <linux/in6.h>
#  endif
# endif

      enum
        {
# ifdef  IPV6_MINHOPCOUNT
          have_ipv6_minhopcount = true,
          ipv6_minhopcount      = IPV6_MINHOPCOUNT
# else
          have_ipv6_minhopcount = false,
          ipv6_minhopcount      = 0
# endif
        } ;
#endif /* HAVE_IPV6 */

      switch (af)
        {
          case AF_INET:
            name = "IP_MINTTL" ;
            if (have_ip_minttl)
              {
                ret = setsockopt(sock_fd, IPPROTO_IP, ip_minttl,
                                                      &minttl, sizeof(minttl)) ;
              }
            else
              {
                ret   = -1 ;
                errno = EOPNOTSUPP ;
              } ;

            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            name = "IPV6_MINHOPCOUNT" ;
            if (have_ipv6_minhopcount)
              {
                ret = setsockopt(sock_fd, IPPROTO_IPV6, ipv6_minhopcount,
                                                      &minttl, sizeof(minttl)) ;
              }
            else
              {
                ret   = -1 ;
                errno = EOPNOTSUPP ;
              } ;

            if (ret < 0)
              {
                af = sockunion_getprotofamily(sock_fd) ;
                if (af == AF_INET)
                  continue ;
              } ;

            break ;
#endif /* HAVE_IPV6 */

          default:      /* ignore unknown family        */
            break ;
        } ;

      break ;
    } ;

  if (ret >= 0)
    return minttl ;

  err = errno ;
  zlog_warn("cannot set sockopt %s to %d on socket %d: %s", name, minttl,
                                                  sock_fd, errtoa(err, 0).str) ;
  errno = err ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set TCP MD5 signature socket option, if available.
 *
 * A NULL password or an empty password both signify unsetting the MD5
 * signature.
 *
 * Returns: >= 0 => OK (or not supported, but password NULL or empty)
 *           < 0 => failed or not supported, see errno.
 *
 * NB: returns EOPNOTSUPP if TCP MD5 is not supported and password is not NULL
 *     and is not empty.
 *
 * Logs a LOG_ERR message if fails (and is supported).
 */
extern int
setsockopt_tcp_signature (int sock_fd, sockunion_c su, const char *password)
{
  int ret ;

  if ((password != NULL) && (*password == '\0'))
    password = NULL ;

  errno = 0 ;
  ret   = 0 ;           /* so far, so good              */

#if defined(HAVE_TCP_MD5_LINUX24) && defined(GNU_LINUX)
  /* Support for the old Linux 2.4 TCP-MD5 patch, taken from Hasso Tepper's
   * version of the Quagga patch (based on work by Rick Payne, and Bruce
   * Simpson)
   */
#define TCP_MD5_AUTH 13
#define TCP_MD5_AUTH_ADD 1
#define TCP_MD5_AUTH_DEL 2
  struct tcp_rfc2385_cmd {
    u_int8_t     command;    /* Command - Add/Delete */
    u_int32_t    address;    /* IPV4 address associated */
    u_int8_t     keylen;     /* MD5 Key len (do NOT assume 0 terminated ascii) */
    void         *key;       /* MD5 Key */
  } cmd;
  struct in_addr *addr = &su->sin.sin_addr;

  cmd.command = (password != NULL ? TCP_MD5_AUTH_ADD : TCP_MD5_AUTH_DEL);
  cmd.address = addr->s_addr;
  cmd.keylen  = (password != NULL ? strlen (password) : 0);
  cmd.key     = password;

  ret = setsockopt (sock_fd, IPPROTO_TCP, TCP_MD5_AUTH, &cmd, sizeof cmd) ;
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("sockopt_tcp_signature: setsockopt(%d): %s",
                                                  sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    }

#elif HAVE_DECL_TCP_MD5SIG

# ifdef GNU_LINUX
  struct tcp_md5sig md5sig ;
#  ifdef HAVE_IPV6
  int    saf ;
  union  sockunion sux[1] ;
#  endif

  /* Testing reveals that in order to set an MD5 password for an AF_INET6
   * socket, the address passed in must be AF_INET6, even if what we are
   * dealing with here is an IN6_IS_ADDR_V4MAPPED socket.
   */
#  ifdef HAVE_IPV6
  saf = sockunion_getsockfamily(sock_fd) ;
  if (saf < 0)
    return saf ;

  if ((saf == AF_INET6) && (sockunion_family(su) == AF_INET))
    {
      sockunion_copy (sux, su) ;
      sockunion_map_ipv4 (sux) ;
      su = sux ;                /* substitute v4 mapped address */
    } ;
#  endif

  /* Set address to AF_UNSPEC and key length and everything else to zero,
   * then copy in the address and the key.
   */
  memset (&md5sig, 0, sizeof (md5sig)) ;
  confirm(AF_UNSPEC == 0) ;

  memcpy (&md5sig.tcpm_addr, &su->sa, sockunion_get_len(su)) ;

  if (password != NULL)
    {
      size_t keylen = strlen(password) ;

      if (md5sig.tcpm_keylen <= TCP_MD5SIG_MAXKEYLEN)
        {
          md5sig.tcpm_keylen = keylen ;
          memcpy (md5sig.tcpm_key, password, keylen);
        }
      else
        {
          errno = EINVAL ;      /* manufactured error           */
          ret   = -1 ;
        } ;
    } ;

# else
  /*
   * XXX Need to do PF_KEY operation here to add/remove an SA entry,
   * and add/remove an SP entry for this peer's packet flows also.
   */
  int    md5sig = (password != NULL) ? 1 : 0;

# endif /* GNU_LINUX */

  if (ret >= 0)
    {
      ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_MD5SIG,
                                                   &md5sig, sizeof(md5sig)) ;
      if (ret < 0)
        /* ENOENT is harmless.  It is returned when we clear a password where
         * one was not previously set.
         */
        if ((errno == ENOENT) && (password == NULL))
          ret = 0 ;
    } ;

#else

  /* TCP MD5 is not supported
   */
  if (password != NULL)
    {
      errno = EOPNOTSUPP ;      /* manufactured error           */
      ret = -1 ;
    } ;

#endif /* !HAVE_TCP_MD5SIG */

  if (ret < 0)
    {
      int err = errno ;
      zlog_err("sockopt_tcp_signature: setsockopt(%d): %s",
                                                  sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set SO_RCVBUF option on socket, if not already bigger, and get result.
 *
 * Returns:  > 0 => OK -- the (new) current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_so_recvbuf_x(int sock_fd, int size)
{
  int ret;

  ret = getsockopt_so_recvbuf(sock_fd) ;

  if ((ret <= 0) || (ret >= size))
    return ret ;        /* failed, not supported, or already bigger     */

  return setsockopt_so_recvbuf(sock_fd, size) ;
} ;

/*------------------------------------------------------------------------------
 * Set SO_RCVBUF option on socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_so_recvbuf (int sock_fd, int size)
{
  int ret ;

  ret = setsockopt (sock_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) ;

  if      (ret >= 0)
    return getsockopt_so_recvbuf(sock_fd) ;
  else if (errno == ENOPROTOOPT)
    ret = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err ("cannot set sockopt SO_RCVBUF to %d on socket %d: %s",
                                            size, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret;
} ;

/*------------------------------------------------------------------------------
 * Get SO_SNDBUF option value from socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
getsockopt_so_recvbuf (int sock_fd)
{
  uint32_t  optval;
  socklen_t optlen ;
  int       ret ;

  optlen = sizeof (optval) ;
  optval = 0 ;
  ret    = getsockopt (sock_fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) ;
  if      (ret >= 0)
    errno = 0 ;
  else if (errno == ENOPROTOOPT)
    optval = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err ("cannot get sockopt SO_SNDBUF on socket %d: %s",
                                                  sock_fd, errtoa(err, 0).str) ;
      errno = err ;
      return ret;
    } ;

  return optval;
} ;

/*------------------------------------------------------------------------------
 * Set SO_SNDBUF option on socket, if not already bigger, and get result.
 *
 * Returns:  > 0 => OK -- the (new) current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_so_sendbuf_x(int sock_fd, int size)
{
  int ret;

  ret = getsockopt_so_sendbuf(sock_fd) ;

  if ((ret <= 0) || (ret >= size))
    return ret ;        /* failed, not supported, or already bigger     */

  return setsockopt_so_sendbuf(sock_fd, size) ;
} ;

/*------------------------------------------------------------------------------
 * Set SO_SNDBUF option on socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_so_sendbuf (int sock_fd, int size)
{
  int ret ;

  ret = setsockopt (sock_fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

  if      (ret >= 0)
    return getsockopt_so_sendbuf(sock_fd) ;
  else if (errno == ENOPROTOOPT)
    ret = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err("cannot set sockopt SO_SNDBUF to %d on socket %d: %s",
                                        size, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret;
}

/*------------------------------------------------------------------------------
 * Get SO_SNDBUF option value from socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
getsockopt_so_sendbuf (int sock_fd)
{
  uint32_t  optval;
  socklen_t optlen ;
  int       ret ;

  optlen = sizeof (optval) ;
  optval = 0 ;
  ret    = getsockopt (sock_fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) ;
  if      (ret >= 0)
    errno = 0 ;
  else if (errno == ENOPROTOOPT)
    optval = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err ("cannot get sockopt SO_SNDBUF on socket %d: %s",
                                              sock_fd, errtoa(err, 0).str) ;
      errno = err ;
      return ret ;
    } ;

  return optval;
} ;

/*------------------------------------------------------------------------------
 * Set SO_SNDLOWAT option on socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_so_sendlowat(int sock_fd, int size)
{
  int ret ;

  ret = setsockopt (sock_fd, SOL_SOCKET, SO_SNDLOWAT, &size, sizeof(size));

  if      (ret >= 0)
    return getsockopt_so_sendlowat(sock_fd) ;
  else if (errno == ENOPROTOOPT)
    ret = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err("cannot set sockopt SO_SNDLOWAT to %d on socket %d: %s",
                                        size, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;

  return ret;
} ;

/*------------------------------------------------------------------------------
 * Get SO_SNDLOWAT option value from socket.
 *
 * Returns:  > 0 => OK -- the current setting -- by getsockopt()
 *             0 => not supported (or the current setting) -- see errno
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
getsockopt_so_sendlowat(int sock_fd)
{
  uint32_t  optval;
  socklen_t optlen ;
  int       ret ;

  optlen = sizeof(optval) ;
  optval = 0 ;
  ret    = getsockopt (sock_fd, SOL_SOCKET, SO_SNDLOWAT, &optval, &optlen) ;
  if      (ret >= 0)
    errno = 0 ;
  else if (errno == ENOPROTOOPT)
    optval = 0 ;
  else
    {
      int err ;
      err = errno ;

      zlog_err ("cannot get sockopt SO_SNDLOWAT on socket %d: %s",
                                              sock_fd, errtoa(err, 0).str) ;
      errno = err ;
      return ret ;
    } ;

  return optval;
} ;

/*------------------------------------------------------------------------------
 * Set IP_TOS option for AF_INET socket.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed, see errno.
 *
 * Logs a LOG_ERR message if fails
 */
extern int
setsockopt_ipv4_tos(int sock_fd, int tos)
{
  int ret;

  ret = setsockopt (sock_fd, IPPROTO_IP, IP_TOS, &tos, sizeof (tos));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt IP_TOS option %#x on socket %d: %s",
                                             tos, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;
  return ret;
} ;

/*------------------------------------------------------------------------------
 * Process multicast socket options for IPv4 in an OS-dependent manner.
 * Supported options are IP_{ADD,DROP}_MEMBERSHIP.
 *
 * Many operating systems have a limit on the number of groups that
 * can be joined per socket (where each group and local address
 * counts).  This impacts OSPF, which joins groups on each interface
 * using a single socket.  The limit is typically 20, derived from the
 * original BSD multicast implementation.  Some systems have
 * mechanisms for increasing this limit.
 *
 * In many 4.4BSD-derived systems, multicast group operations are not
 * allowed on interfaces that are not UP.  Thus, a previous attempt to
 * leave the group may have failed, leaving it still joined, and we
 * drop/join quietly to recover.  This may not be necessary, but aims to
 * defend against unknown behavior in that we will still return an error
 * if the second join fails.  It is not clear how other systems
 * (e.g. Linux, Solaris) behave when leaving groups on down interfaces,
 * but this behavior should not be harmful if they behave the same way,
 * allow leaves, or implicitly leave all groups joined to down interfaces.
 */
extern int
setsockopt_ipv4_multicast(int sock,
                        int optname,
                        unsigned int mcast_addr,
                        unsigned int ifindex)
{
#ifdef HAVE_RFC3678
  struct group_req gr;
  struct sockaddr_in *si;
  int ret;
  memset (&gr, 0, sizeof(gr));
  si = (struct sockaddr_in *)&gr.gr_group;
  gr.gr_interface = ifindex;
  si->sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  si->sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
  si->sin_addr.s_addr = mcast_addr;
  ret = setsockopt(sock, IPPROTO_IP, (optname == IP_ADD_MEMBERSHIP) ?
    MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP, (void *)&gr, sizeof(gr));
  if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP) && (errno == EADDRINUSE))
    {
      setsockopt(sock, IPPROTO_IP, MCAST_LEAVE_GROUP, (void *)&gr, sizeof(gr));
      ret = setsockopt(sock, IPPROTO_IP, MCAST_JOIN_GROUP, (void *)&gr, sizeof(gr));
    }
  return ret;

#elif defined(HAVE_STRUCT_IP_MREQN_IMR_IFINDEX) && !defined(__FreeBSD__)
  struct ip_mreqn mreqn;
  int ret;

  assert(optname == IP_ADD_MEMBERSHIP || optname == IP_DROP_MEMBERSHIP);
  memset (&mreqn, 0, sizeof(mreqn));

  mreqn.imr_multiaddr.s_addr = mcast_addr;
  mreqn.imr_ifindex = ifindex;

  ret = setsockopt(sock, IPPROTO_IP, optname,
                   (void *)&mreqn, sizeof(mreqn));
  if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP) && (errno == EADDRINUSE))
    {
      /* see above: handle possible problem when interface comes back up */
      char buf[1][INET_ADDRSTRLEN];
      zlog_info("setsockopt_ipv4_multicast attempting to drop and "
                "re-add (fd %d, mcast %s, ifindex %u)",
                sock,
                inet_ntop(AF_INET, &mreqn.imr_multiaddr,
                          buf[0], sizeof(buf[0])), ifindex);
      setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                 (void *)&mreqn, sizeof(mreqn));
      ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (void *)&mreqn, sizeof(mreqn));
    }
  return ret;

  /* Example defines for another OS, boilerplate off other code in this
     function, AND handle optname as per other sections for consistency !! */
  /* #elif  defined(BOGON_NIX) && EXAMPLE_VERSION_CODE > -100000 */
  /* Add your favourite OS here! */

#elif defined(HAVE_BSD_STRUCT_IP_MREQ_HACK) /* #if OS_TYPE */
  /* standard BSD API */

  struct in_addr m;
  struct ip_mreq mreq;
  int ret;

  assert(optname == IP_ADD_MEMBERSHIP || optname == IP_DROP_MEMBERSHIP);

  m.s_addr = htonl(ifindex);

  memset (&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = mcast_addr;
  mreq.imr_interface = m;

  ret = setsockopt (sock, IPPROTO_IP, optname, (void *)&mreq, sizeof(mreq));
  if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP) && (errno == EADDRINUSE))
    {
      /* see above: handle possible problem when interface comes back up */
      char buf[1][INET_ADDRSTRLEN];
      zlog_info("setsockopt_ipv4_multicast attempting to drop and "
                "re-add (fd %d, mcast %s, ifindex %u)",
                sock,
                inet_ntop(AF_INET, &mreq.imr_multiaddr,
                          buf[0], sizeof(buf[0])), ifindex);
      setsockopt (sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                  (void *)&mreq, sizeof(mreq));
      ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        (void *)&mreq, sizeof(mreq));
    }
  return ret;

#else
  #error "Unsupported multicast API"
#endif /* #if OS_TYPE */

}

/*
 * Set IP_MULTICAST_IF socket option in an OS-dependent manner.
 */
extern int
setsockopt_ipv4_multicast_if(int sock,
                             unsigned int ifindex)
{

#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
  struct ip_mreqn mreqn;
  memset (&mreqn, 0, sizeof(mreqn));

  mreqn.imr_ifindex = ifindex;
  return setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&mreqn, sizeof(mreqn));

  /* Example defines for another OS, boilerplate off other code in this
     function */
  /* #elif  defined(BOGON_NIX) && EXAMPLE_VERSION_CODE > -100000 */
  /* Add your favourite OS here! */
#elif defined(HAVE_BSD_STRUCT_IP_MREQ_HACK)
  struct in_addr m;

  m.s_addr = htonl(ifindex);

  return setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&m, sizeof(m));
#else
  #error "Unsupported multicast API"
#endif
}

/*==============================================================================
 * Set pktinfo and get ifindex etc
 */

static int setsockopt_ipv4_pktinfo (int sock_fd, int val) ;
static int getsockopt_ipv4_ifindex (struct msghdr *msgh) ;

#ifdef HAVE_IPV6
static int getsockopt_ipv6_ifindex (struct msghdr *msgh) ;
#endif

static void * getsockopt_cmsg_data (struct msghdr *msgh, int level, int type) ;

/*------------------------------------------------------------------------------
 * Set IP_PKTINFO/IP_RECVIF or IPV6_RECVPKTINFO/IPV6_PKTINFO -- if available.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_pktinfo (int af, int sock_fd, int val)
{
  int ret = -1;

  switch (af)
    {
      case AF_INET:
        ret = setsockopt_ipv4_pktinfo (sock_fd, val);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        ret = setsockopt_ipv6_pktinfo (sock_fd, val);
        break;
#endif
      default:
        zlog_warn("setsockopt_ifindex: unknown address family %d", af) ;
        ret = -1 ;
        errno = EINVAL;
        break ;
    }
  return ret;
}

/*------------------------------------------------------------------------------
 * Set IP_PKTINFO or IP_RECVIF -- if available.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
static int
setsockopt_ipv4_pktinfo (int sock_fd, int val)
{
  int ret;

#if defined(IP_PKTINFO) || defined(IP_RECVIF)

  int opt ;
  const char* name ;

# if defined(IP_PKTINFO)
  opt  =  IP_PKTINFO ;
  name = "IP_PKTINFO" ;
# else
  opt  =  IP_RECVIF ;
  name = "IP_RECVIF" ;
# endif

  ret = setsockopt (sock_fd, IPPROTO_IP, opt, &val, sizeof (val)) ;
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt %s to %d on socket %d: %s", name,
                                              val, sock_fd, errtoa(err, 0).str);
      errno = err ;
    } ;
#else
#warning "Neither IP_PKTINFO nor IP_RECVIF is available."
#warning "Will not be able to receive link info."
#warning "Things might be seriously broken.."
  /* XXX Does this ever happen?  Should there be a zlog_warn message here? */
  ret   = -1;
  errno = EOPNOTSUPP ;      /* manufactured error           */
#endif
  return ret;
}

/*------------------------------------------------------------------------------
 * Set IPV6_RECVPKTINFO (RFC3542) or IPV6_RECVIF (RFC2292) -- if available.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
#ifdef HAVE_IPV6
extern int
setsockopt_ipv6_pktinfo (int sock_fd, int val)
{
  int ret;
  int opt ;
  const char* name ;

# ifdef IPV6_RECVPKTINFO
  opt  =  IPV6_RECVPKTINFO ;    /* RFC3542 == RFC2292-bis       */
  name = "IPV6_RECVPKTINFO" ;
# else
  opt  =  IPV6_PKTINFO ;        /* RFC2292                      */
  name = "IPV6_PKTINFO" ;
# endif

  ret = setsockopt(sock_fd, IPPROTO_IPV6, opt, &val, sizeof(val));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt %s to %d on socket %d: %s", name,
                                              val, sock_fd, errtoa(err, 0).str);
      errno = err ;
    } ;

  return ret;
}
#endif

/*------------------------------------------------------------------------------
 * Given a struct msghdr*, extract and return ifindex.
 *
 * Returns: > 0 => OK == ifindex
 *            0 => none found or error
 *
 * Note: this is badly named, since it is not really a getsockopt() operation,
 *       but extracting data from a sendmsg/recvmsg struct msghdr.
 *
 *       To have the ifindex returned, need to have setsockopt_pktinfo().
 */
extern int
getsockopt_ifindex (int af, struct msghdr *msgh)
{
  switch (af)
    {
      case AF_INET:
        return (getsockopt_ipv4_ifindex (msgh));

#ifdef HAVE_IPV6
      case AF_INET6:
        return (getsockopt_ipv6_ifindex (msgh));
#endif

      default:
        zlog_warn ("%s: unknown address family %d", __func__, af);
        return 0 ;
    }
}

/*------------------------------------------------------------------------------
 * AF_INET: extract ifindex from struct msghdr, if can
 *
 * Requires: msgh is not NULL and points to a valid struct msghdr, which
 * may or may not have control data about the incoming interface.
 *
 * Returns the interface index (small integer >= 1) if it can be
 * determined, or else 0.
 */
static int
getsockopt_ipv4_ifindex (struct msghdr *msgh)
{
  int ifindex ;

#if defined(IP_PKTINFO)
/* Linux pktinfo based ifindex retrieval */
  struct in_pktinfo *pktinfo;

  pktinfo = getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_PKTINFO);
  if (pktinfo != NULL)
    ifindex = pktinfo->ipi_ifindex ;
  else
    ifindex = 0 ;

#elif defined(IP_RECVIF)

  /* retrieval based on IP_RECVIF */

#ifndef SUNOS_5
  /* BSD systems use a sockaddr_dl as the control message payload. */
  struct sockaddr_dl *sdl;
#else
  /* SUNOS_5 uses an integer with the index. */
  int *ifindex_p;
#endif /* SUNOS_5 */

#ifndef SUNOS_5
  /* BSD */
  sdl =
    (struct sockaddr_dl *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF);
  if (sdl != NULL)
    ifindex = sdl->sdl_index;
  else
    ifindex = 0;
#else
  /*
   * Solaris.  On Solaris 8, IP_RECVIF is defined, but the call to
   * enable it fails with errno=99, and the struct msghdr has
   * controllen 0.
   */
  ifindex_p = (uint_t *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF);
  if (ifindex_p != NULL)
    ifindex = *ifindex_p;
  else
    ifindex = 0;
#endif /* SUNOS_5 */

#else
  /*
   * Neither IP_PKTINFO nor IP_RECVIF defined - warn at compile time.
   * XXX Decide if this is a core service, or if daemons have to cope.
   * Since Solaris 8 and OpenBSD seem not to provide it, it seems that
   * daemons have to cope.
   */
#warning "getsockopt_ipv4_ifindex: Neither IP_PKTINFO nor IP_RECVIF defined."
#warning "Some daemons may fail to operate correctly!"
  ifindex = 0;

#endif /* IP_PKTINFO */

  return ifindex;
}

#ifdef HAVE_IPV6

/*------------------------------------------------------------------------------
 * AF_INET6: extract ifindex from struct msghdr, if can
 *
 * Requires: msgh is not NULL and points to a valid struct msghdr, which
 * may or may not have control data about the incoming interface.
 *
 * Returns the interface index (small integer >= 1) if it can be
 * determined, or else 0.
 */
static int
getsockopt_ipv6_ifindex (struct msghdr *msgh)
{
  struct in6_pktinfo *pktinfo;

  pktinfo = getsockopt_cmsg_data (msgh, IPPROTO_IPV6, IPV6_PKTINFO);

  if (pktinfo != NULL)
    return pktinfo->ipi6_ifindex;
  else
    return 0 ;
}

#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * Scan msg_control portion of struct msghdr, looking for a cmsg with the given
 * level and type.
 *
 * Requires: msgh is not NULL and points to a valid struct msghdr, which
 * may or may not have control data about the incoming interface.
 *
 * Returns:  address of data part of cmsg
 *       or: NULL => not found
 */
static void *
getsockopt_cmsg_data (struct msghdr *msgh, int level, int type)
{
  struct cmsghdr *cmsg;

  for (cmsg = ZCMSG_FIRSTHDR(msgh);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(msgh, cmsg))
    if ((cmsg->cmsg_level == level) && (cmsg->cmsg_type == type))
      return (void*)CMSG_DATA(cmsg);

  return NULL;
} ;

/*------------------------------------------------------------------------------
 * swab iph between order system uses for IP_HDRINCL and host order
 *
 * This is done before handing struct ip to the system.
 *
 * There are four u_short fields in the IPv4 header:
 *
 *    u_short ip_len  -- convert to network order, except as noted below
 *    u_short ip_id   -- convert to network order
 *    u_short ip_off  -- convert to network order, except as noted below
 *    u_short ip_sum  -- which we don't touch -- set by kernel
 */
extern void
sockopt_iphdrincl_swab_htosys (struct ip *iph)
{
  /* BSD and derived take iph in network order, except for ip_len and ip_off.
   *
   * So if *not* BSD-like, then need to convert ip_len and ip_off to network
   * order.
   */
#ifndef HAVE_IP_HDRINCL_BSD_ORDER
  iph->ip_len = htons(iph->ip_len);
  iph->ip_off = htons(iph->ip_off);
#endif /* HAVE_IP_HDRINCL_BSD_ORDER */

  iph->ip_id = htons(iph->ip_id);
}

/*------------------------------------------------------------------------------
 * swab iph between order system uses for IP_HDRINCL and host order
 *
 * This is done after receiving struct ip from the system -- see notes above.
 */
extern void
sockopt_iphdrincl_swab_systoh (struct ip *iph)
{
#ifndef HAVE_IP_HDRINCL_BSD_ORDER
  iph->ip_len = ntohs(iph->ip_len);
  iph->ip_off = ntohs(iph->ip_off);
#endif /* HAVE_IP_HDRINCL_BSD_ORDER */

  iph->ip_id = ntohs(iph->ip_id);
}

/*==============================================================================
 * IPv6 Stuff
 */
#ifdef HAVE_IPV6

/*------------------------------------------------------------------------------
 * Set IPV6_V6ONLY.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_v6only(int sock_fd)
{
  int ret;
  int on = 1 ;

  ret = setsockopt (sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err ("cannot set sockopt IPV6_V6ONLY on socket %d: %s",
                                                 sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    }
  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Set IPV6_CHECKSUM
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_checksum (int sock_fd, int val)
{
  int ret;

#ifdef GNU_LINUX
  ret = setsockopt(sock_fd, IPPROTO_RAW,  IPV6_CHECKSUM, &val, sizeof(val));
#else
  ret = setsockopt(sock_fd, IPPROTO_IPV6, IPV6_CHECKSUM, &val, sizeof(val));
#endif /* GNU_LINUX */
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt IPV6_CHECKSUM to %d on socket %d: %s", val,
                                                  sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;
  return ret;
}

/*------------------------------------------------------------------------------
 * Set unicast hops val to the socket (cf IP_TTL).
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_unicast_hops (int sock_fd, int val)
{
  int ret;

  ret = setsockopt(sock_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt IPV6_UNICAST_HOPS to %d on socket %d: %s",
                                             val, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;
  return ret;
}

/*------------------------------------------------------------------------------
 * Set multicast hops val to the socket.
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_multicast_hops (int sock_fd, int val)
{
  int ret;

  ret = setsockopt(sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val,
                                                                   sizeof(val));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt IPV6_MULTICAST_HOPS to %d on socket %d: %s",
                                             val, sock_fd, errtoa(err, 0).str) ;
      errno = err ;
    } ;
  return ret;
}

/*------------------------------------------------------------------------------
 * Set IPV6_RECVHOPLIMIT option (or IPV6_HOPLIMIT)
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_hoplimit (int sock_fd, int val)
{
  int ret;
  int opt ;
  const char* name ;

# ifdef IPV6_RECVHOPLIMIT
  opt  =  IPV6_RECVHOPLIMIT ;   /* RFC3542 == RFC2292-bis       */
  name = "IPV6_RECVHOPLIMIT" ;
# else
  opt  =  IPV6_HOPLIMIT ;       /* RFC2292                      */
  name = "IPV6_HOPLIMIT" ;
# endif

  ret = setsockopt(sock_fd, IPPROTO_IPV6, opt, &val, sizeof(val));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt %s to %d on socket %d: %s", name,
                                              val, sock_fd, errtoa(err, 0).str);
      errno = err ;
    } ;

  return ret;
}

/*------------------------------------------------------------------------------
 * Set IPV6_MULTICAST_LOOP option
 *
 * Returns: >= 0 => OK
 *           < 0 => failed -- see errno
 *
 * Logs a LOG_ERR message if fails.
 */
extern int
setsockopt_ipv6_multicast_loop (int sock_fd, int val)
{
  int ret;

  ret = setsockopt (sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val,
                                                                  sizeof (val));
  if (ret < 0)
    {
      int err = errno ;
      zlog_err("cannot set sockopt IPV6_MULTICAST_LOOP to %d on socket %d: %s",
                                              val, sock_fd, errtoa(err, 0).str);
      errno = err ;
    } ;
  return ret;
}



extern int
setsockopt_ipv6_tclass(int sock_fd, int tclass)
{
  int ret = 0;

#ifdef IPV6_TCLASS /* RFC3542 */
  ret = setsockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
  if (ret < 0)
    {
      int err = errno ;
      zlog_warn ("Can't set IPV6_TCLASS option for fd %d to %#x: %s",
                                          sock_fd, tclass, errtoa(err, 0).str);
      errno = err ;
    } ;
#endif

  return ret;
}

#endif /* HAVE_IPV6 */


