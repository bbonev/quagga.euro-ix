/* BGP network related fucntions
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include <stdbool.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgpd.h"

#include "bgpd/bgp_fsm.h"

#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "qpselect.h"
#include "vector.h"

/*==============================================================================
 * This is the socket connect/listen/accept/close stuff for the BGP Engine.
 *
 * NB: this code is for use in the BGP Engine *only*, with the exception of
 *     bgp_listeners_init().
 */
static bool bgp_raise_privs(const char* func) ;
static bool bgp_lower_privs(const char* func, bool raised) ;

/*==============================================================================
 * Management of Listeners.
 *
 * When the BGP Engine is started it is passed the address and port to listen
 * to.  By default the address is NULL, which maps to INADDR_ANY and
 * (if supported) IN6ADDR_ANY_INIT.
 *
 * When the BGP Engine is stopped the listening ports are closed.
 *
 * NB: once the listeners are opened they are active in the BGP Engine Nexus,
 *     and will be fielding attempts to connect.
 *
 * The BGP listeners are kept here.  Keep lists of IPv4 and IPv6 listeners for
 * the convenience of setting MD5 passwords.
 */
typedef struct bgp_listener_list  bgp_listener_list_t ;
typedef struct bgp_listener_list* bgp_listener_list ;

typedef struct bgp_listener  bgp_listener_t ;
typedef struct bgp_listener* bgp_listener ;

struct bgp_listener_list
{
  struct dl_base_pair(bgp_listener)  base ;

  uint    use_count ;
  port_t  port ;
} ;

struct bgp_listener
{
  bgp_listener  next ;

  qfile_t       qf ;
  sockunion_t   su ;
} ;

/* Lists of lists of listeners
 */
static vector bgp_listener_lists           = NULL ;

static vector bgp_listener_address_list    = NULL ;
static char*  bgp_listener_address_strings = NULL ;
static char*  bgp_listener_addresses       = NULL ;

/* Local human-readable rendition of the 'any' address.
 */
static const char* bgp_any_address_str = "<any>" ;

/* Establish whether we have access to getaddrinfo() -- which we prefer
 */
#if defined(HAVE_IPV6) && !defined(NRL)
# define BGP_USE_ADDRINFO 1
#else
# define BGP_USE_ADDRINFO 0
#endif

/* Uses an array of bgp_listener_info structures to collect all the
 * possible listeners, before setting out to open etc.
 */
typedef struct bgp_listener_info  bgp_listener_info_t ;
typedef struct bgp_listener_info* bgp_listener_info ;

struct bgp_listener_info
{
  const char*  address_str ;
  const char*  port_str ;

  const char*  failed ;
  int          err ;
  int          ai_err ;

  sockunion_t  su ;

  port_t       port ;
  int          sock_type ;
  int          protocol ;

  int          sock_fd ;
} ;

/* Forward references
 */
static int bgp_socket_set_common_options(int sock_fd,
                        bgp_connection_options cops, uint rcvbuf, uint sndbuf) ;
static void bgp_accept_action(qfile qf, void* file_info) ;

static bgp_listener_list bgp_listeners_for_port(port_t port) ;

static void bgp_listeners_set_md5(bgp_listener_list listener_list,
                                  bgp_connection_options_c cops, on_off_b how) ;

static int bgp_md5_set_socket(int sock_fd, sockunion_c su,
                                                         const char* password) ;

static vector bgp_listeners_collect(const char* port_str) ;

static void bgp_listeners_collect_addrinfo(vector collection,
                                const char* address_str, const char* port_str) ;
static void bgp_listeners_collect_simple(vector collection,
                                const char* address_str, const char* port_str) ;



static bgp_listener_list bgp_listeners_find_list(port_t port, bool make) ;
static void bgp_listeners_del_list(bgp_listener_list listener_list) ;

static bgp_listener_info bgp_listener_info_new(vector collection,
                                const char* address_str, const char* port_str) ;
static bgp_listener_info bgp_listener_info_free(bgp_listener_info li) ;

/*------------------------------------------------------------------------------
 * Initialise Listeners.
 *
 * This is called *before* the BGP Engine is started up.
 *
 * Using given address(es) and port, get all possible addresses and set up a
 * listener on each one.
 *
 * Accepts: addresses = NULL => any local address
 *          addresses = comma separated list of addresses
 *                      -- discards leading and trailing isspace() and and
 *                         any isspace() around commas.
 *
 * If BGP_USE_ADDRINFO, the addresses need not be numeric.
 *
 * NB: "<any>" counts as "any local address" -- with some latitude on isspace()
 *     around the '<' and '>', and case-insensitive
 *
 * NB: an empty address counts as "any local address", so:
 *
 *      "80.177.246.130,80.177.246.131" -- will listen on those addresses.
 *
 *      "80.177.246.130,"               -- will list on that address and
 *                                         any other local address.
 *
 * NB: only listens on AF_INET and AF_INET6 (if HAVE_IPV6).
 *
 * Returns:  number of listeners set up
 */
extern uint
bgp_listeners_init(const char* addresses, const char* port_str)
{
  bool  done_null ;
  char* next, * end ;
  uint  len, i, count ;
  vector collection ;

  bgp_listener_lists        = vector_new(5) ;
  bgp_listener_address_list = vector_new(5) ;

  if (addresses == NULL)
    addresses = "" ;

  /* Extract the addresses and construct vector of same
   */
  bgp_listener_address_strings = XSTRDUP(MTYPE_BGP_LISTENER, addresses) ;

  done_null = false ;
  next      = bgp_listener_address_strings ;
  len       = 0 ;
  do
    {
      char* this ;

      this = next ;
      next = strchr(next, ',') ;

      if (next != NULL)
        *next++ = '\0' ;        /* replace ',' and step past            */

      strtrim_space(this) ;
      if (strcmp_lax(this, bgp_any_address_str) == 0)
        this = '\0' ;           /* treat <any> as ""                    */

      len += strlen(this) + 2 ; /* "<address>, " or "<address>\0"       */

      if (*this == '\0')
        {
          if (done_null)
            continue ;          /* don't do <any> more than once        */

          done_null = true ;
          this      = NULL ;

          len += strlen(bgp_any_address_str) ;
        } ;

      vector_push_item(bgp_listener_address_list, this) ;
    }
  while (next != NULL) ;

  /* Make a new string with all the addresses in it.
   */
  bgp_listener_addresses = XMALLOC(MTYPE_BGP_LISTENER, len) ;
  next = bgp_listener_addresses ;
  end  = next + len ;

  for (i = 0 ; i <= vector_length(bgp_listener_address_list) ; ++i)
    {
      const char* str ;

      str = vector_get_item(bgp_listener_address_list, i) ;
      if (str == NULL)
        str = bgp_any_address_str ;

      len = strlen(str) ;
      assert((next + len + 2) <= end) ;

      strcpy(next, str) ;
      next += len ;
      *next++ = ',' ;
      *next++ = ' ' ;
    } ;

  next[-2] = '\0' ;
  next[-1] = '\0' ;

  /* Collect all possible listeners, then report any issues.
   *
   * Does everything except actually listen().
   */
  collection = bgp_listeners_collect(port_str) ;

  count = 0 ;
  for (i = 0 ; i < vector_length(collection) ; ++i)
    {
      bgp_listener_info li ;

      li = vector_get_item(collection, i) ;
      vector_set_item(collection, i, NULL) ;

      if (li->sock_fd >= 0)
        ++count ;
      else
        {
          /* Failed to set up a potential listener... time to report this.
           */
          fprintf(stderr, "%% Failed to set up listener: %s;"
                                                 " for address %s and port %s",
                 li->failed != NULL ? li->failed : "*reason unknown*",
                                               li->address_str, li->port_str) ;

          if (sockunion_family(&li->su) != AF_UNSPEC)
            fprintf(stderr, " [%s]", sutoa(&li->su).str) ;

          if ((li->err != 0) || (li->ai_err != 0))
            fprintf(stderr, ".  Error: %s",
                       (li->ai_err != 0) ? eaitoa(li->ai_err, li->err, 0).str
                                         : errtoa(li->err, 0).str) ;

          fprintf(stderr, ".\n") ;
        } ;

      bgp_listener_info_free(li) ;          /* closes sock_fd       */
    } ;

  vector_free(collection) ;

  return count ;
} ;

/*------------------------------------------------------------------------------
 * Finish off all listeners -- when BGP Engine stops
 *
 * Empty the listener lists, close files, remove from the selection, discard
 * all known addresses, etc.
 */
extern void
bgp_listeners_finish(void)
{
  while (vector_length(bgp_listener_lists) > 0)
    bgp_listeners_del_list(vector_get_item(bgp_listener_lists, 0)) ;

  bgp_listener_lists        = vector_free(bgp_listener_lists) ;
  bgp_listener_address_list = vector_free(bgp_listener_address_list) ;

  XFREE(MTYPE_BGP_LISTENER, bgp_listener_address_strings) ;
  XFREE(MTYPE_BGP_LISTENER, bgp_listener_addresses) ;
} ;

/*------------------------------------------------------------------------------
 * Get listeners for the given port.
 *
 * If none exist, attempt to open all possible listeners for the port.
 *
 * Returns:  address of listeners base for the port -- if OK.
 *           NULL <=> unable to open up any listener at all
 */
static bgp_listener_list
bgp_listeners_for_port(port_t port)
{
  bgp_listener_list listener_list ;
  bgp_listener      first ;
  vector            collection ;
  uint   i ;
  char   port_str[16] ;

  listener_list = bgp_listeners_find_list(port, true /* make */) ;

  if (dsl_head(listener_list->base) != NULL)
    return listener_list ;              /* at least one listener exists */

  /* We have a new and empty set of listeners for the given port, proceed
   * to populate that.
   */
  snprintf (port_str, sizeof(port_str), "%u", port);

  collection = bgp_listeners_collect(port_str) ;

  for (i = 0 ; i < vector_length(collection) ; ++i)
    {
      bgp_listener_info li ;

      li = vector_get_item(collection, i) ;
      vector_set_item(collection, i, NULL) ;

      if (li->sock_fd >= 0)
        {
          /* Last lap... listen()
           */
          int ret ;

          ret = listen (li->sock_fd, 43);
          if (ret < 0)
            {
              zlog_err ("%s: listen: %s", __func__, errtoa(errno, 0).str) ;
            }
          else
            {
              /* Having successfully opened the listener, record it so that can
               * be found again, add it to the BGP Engine Nexus file selection
               * and enable it for reading.
               */
              bgp_listener listener ;

              listener = XCALLOC(MTYPE_BGP_LISTENER, sizeof(bgp_listener_t)) ;
              dsl_append(listener_list->base, listener, next) ;

              qfile_init_new(&listener->qf, NULL) ;
              qps_add_qfile(bgp_nexus->selection, &listener->qf, li->sock_fd,
                                                                     listener) ;
              qfile_enable_mode(&listener->qf, qps_read_mnum, bgp_accept_action) ;

              sockunion_copy(&listener->su, &li->su) ;

              /* Log set up of listener
               */
              if (BGP_DEBUG(io, IO_IN))
                zlog_debug ("Listening on %s port %u",
                                               sutoa(&listener->su).str, port) ;
            } ;
        } ;

      bgp_listener_info_free(li) ;
    } ;

  vector_free(collection) ;

  first = dsl_head(listener_list->base) ;
  if (first != NULL)
    return listener_list ;              /* at least one listener exists */

  /* Tried to open listeners for the known addresses and the given port, and
   * every one failed !
   */
  bgp_listeners_del_list(listener_list) ;

  zlog_warn("Failed to open any listeners on '%s' for port '%u'",
                                             bgp_listener_addresses, port) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set (or clear) MD5 password for given peer in the listener(s) for the peer's
 * address family.
 *
 * This allows system to accept MD5 "signed" incoming connections from the
 * given address.
 *
 * Empty password clears the password for the given peer.
 *
 * NB: peer address must be AF_INET or (if supported) AF_INET6
 *
 * NB: does nothing if there are no listeners in the address family -- wanting
 *     to set MD5 makes no difference to this !
 */
static void
bgp_listeners_set_md5(bgp_listener_list listener_list,
                                    bgp_connection_options_c cops, on_off_b how)
{
  bgp_listener listener ;
  const char* password ;

  if (how == on)
    password = cops->password ;         /* may be empty !       */
  else
    password = NULL ;

  listener = dsl_head(listener_list->base) ;

  while (listener != NULL)
    {
      if (sockunion_family(&listener->su) == sockunion_family(&cops->su_remote))
        bgp_md5_set_socket(qfile_fd_get(&listener->qf), &listener->su,
                                                                     password) ;
      listener = dsl_next(listener, next) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Collect all the possible listeners.
 *
 * Constructs a vector of bgp_listener_info structures, at least 1 for each
 * entry in the bgp_listener_address_list.
 */
static vector
bgp_listeners_collect(const char* port_str)
{
  vector collection ;
  uint i ;

  /* Collect all possible address/port from the bgp_listener_address_list and
   * the given port string.
   */
  collection = vector_new(vector_length(bgp_listener_address_list) * 2) ;

  for (i = 0 ; i < vector_length(bgp_listener_address_list) ; ++i)
    {
      const char* address_str ;

      address_str = vector_get_item(bgp_listener_address_list, i) ;

      if (BGP_USE_ADDRINFO)
        bgp_listeners_collect_addrinfo(collection, address_str, port_str) ;
      else
        bgp_listeners_collect_simple(collection, address_str, port_str) ;
    } ;

  /* Now, for all entries which have not already failed, construct socket,
   * set common options and bind address.
   */
  for (i = 0 ; i < vector_length(collection) ; ++i)
    {
      bgp_listener_info li ;
      uint slen ;
      int  ret ;
      bool raised ;

      li = vector_get_item(collection, i) ;

      if (li->failed != NULL)
        continue ;

      /* Construct socket and set the common and size options.
       */
      li->sock_fd = sockunion_socket(&li->su,
                                          li->sock_type, li->protocol) ;
      if (li->sock_fd < 0)
        {
          /* sockunion_socket() has already logged errors.
           */
          li->failed = "could not open socket" ;
          li->err    = errno ;

          continue ;
        }

      li->err = bgp_socket_set_common_options(li->sock_fd, NULL, 1, 1) ;
      if (li->err != 0)
        {
          /* bgp_socket_set_common_options() has already logged errors.
           */
          li->failed = "could not set common socket options" ;

          close(li->sock_fd) ;
          li->sock_fd = -1 ;
          continue ;
        } ;

#ifdef HAVE_IPV6
      /* Want only IPV6 on ipv6 socket (not mapped addresses)
       *
       * This distinguishes 0.0.0.0 from :: -- without this, bind() will
       * reject the attempt to bind to :: after binding to 0.0.0.0.
       *
       * Also, for all the apparent utility of IPv4-mapped addresses, the
       * semantics are simpler if IPv6 sockets speak IPv6 and IPv4 sockets
       * speak IPv4.
       */
      if (sockunion_family(&li->su) == AF_INET6)
        {
          if (setsockopt_ipv6_v6only(li->sock_fd) < 0)
            {
              /* setsockopt__ipv6_v6only() has logged the error already.
               */
              li->failed = "could not setsockopt_ipv6_v6only()" ;
              li->err    = errno ;

              close(li->sock_fd) ;
              li->sock_fd = -1 ;
              continue ;
            } ;
        } ;
#endif

      /* Bind to port and address (if any)
       */
      raised = bgp_raise_privs(__func__) ;

      slen = sockunion_set_port(&li->su, li->port) ;

      ret = bind(li->sock_fd, &li->su.sa, slen) ;
      if (ret < 0)
        {
          li->err    = errno ;
          li->failed = "could not bind socket" ;

          zlog_err ("%s: bind: %s",  __func__, errtoa(li->err, 0).str);

          close(li->sock_fd) ;
          li->sock_fd = -1 ;
        } ;

      bgp_lower_privs(__func__, raised) ;
    } ;

  return collection ;
} ;

/*------------------------------------------------------------------------------
 * Collect listeners using getaddrinfo() to find the addresses and port.
 *
 * Note that this will accept names as well as numeric addresses and names
 * as well as numeric port numbers.
 *
 * Adds at least one bgp_listener_info to the collection, even if that is
 * only to signal errors for the givem address/port.
 */
static void
bgp_listeners_collect_addrinfo(vector collection, const char* address_str,
                                                  const char* port_str)
{
#if BGP_USE_ADDRINFO

# ifndef HAVE_IPV6
#  error Using getaddrinfo() but HAVE_IPV6 is not defined ??
# endif

  struct addrinfo *ainfo;
  struct addrinfo *ainfo_save;
  int ret, count ;

  static const struct addrinfo req =
    {
      .ai_family   = AF_UNSPEC,
      .ai_flags    = AI_PASSIVE,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = IPPROTO_TCP,
    }  ;

  if ((address_str != NULL) && (*address_str == '\0'))
    address_str = NULL ;

  ret = getaddrinfo (address_str, port_str, &req, &ainfo_save);
  if (ret != 0)
    {
      bgp_listener_info li ;

      li = bgp_listener_info_new(collection, address_str, port_str) ;

      li->failed = "getaddrinfo() failed" ;
      li->err    = errno ;
      li->ai_err = ret ;

      zlog_err ("bgp listeners: getaddrinfo(%s, %s, ...): %s", address_str,
                         port_str, eaitoa(li->ai_err, li->err, 0).str) ;
      return  ;
    } ;

  /* Cycle through the possible address/port combinations.
   *
   * NB: we ignore any addresses other than AF_INET or AF_INET6... we don't
   *     expect any, but any we were to get we sincerely do not want !
   *
   * NB: we ignore any IPv4-Mapped addresses... again, we don't expect any.
   *
   *     So: for listening sockets, socket and address families are absolutely
   *         the same.
   */
  count = 0;
  for (ainfo = ainfo_save; ainfo; ainfo = ainfo->ai_next)
    {
      port_t  port ;
      bgp_listener_info li ;

      switch (ainfo->ai_family)
        {
          case AF_INET:
            port = ntohs(((struct sockaddr_in*)ainfo)->sin_port) ;
            break ;

#if HAVE_IPV6
          case AF_INET6:
            if ( IN6_IS_ADDR_V4MAPPED(
                             ((struct sockaddr_in6*)ainfo)->sin6_addr.s6_addr) )
              port = 0 ;
            else
              port = ntohs(((struct sockaddr_in6*)ainfo)->sin6_port) ;
            break ;
#endif
          default:
            port = 0 ;
            break ;
        } ;

      if (port == 0)            /* not an error at this stage   */
        continue ;

      li = bgp_listener_info_new(collection, address_str, port_str) ;

      li->port      = port ;
      li->sock_type = ainfo->ai_socktype ;
      li->protocol  = ainfo->ai_protocol ;

      sockunion_new_sockaddr(&li->su, ainfo->ai_addr) ;
    } ;

  freeaddrinfo (ainfo_save);

  /* If we failed to collect anything usable for the address, set up a failed
   * bgp_listener_info.
   */
  if (count == 0)
    {
      bgp_listener_info li ;

      li = bgp_listener_info_new(collection, address_str, port_str) ;

      li->failed = "getaddrinfo() returned no addresses" ;
    } ;

#else
  zabort("bgp_open_listeners_addrinfo not implemented") ;
#endif /* BGP_USE_ADDRINFO */
}
/*------------------------------------------------------------------------------
 * Collect listener the old fashioned way.
 *
 * NB: if address is "" collects <any> for IPv4 and IPv6 (if supported).
 *
 * NB: if address is not NULL, must be a numeric IP address (which may be IPv6
 *     if that is supported).
 *
 * Adds at least one bgp_listener_info to the collection, even if that is
 * only to signal errors for the givem address/port.
 */
static void
bgp_listeners_collect_simple(vector collection, const char* address_str,
                                                const char* port_str)
{
  static const sa_family_t families[] =
    {
      AF_INET,
#ifdef HAVE_IPV6
      AF_INET6,
#endif
      AF_UNSPEC
    } ;

  port_t port ;

  /* Map the port_str to port.
   */
  port = str2port(port_str, "tcp") ;

  if (port == 0)
    {
      bgp_listener_info li ;

      li = bgp_listener_info_new(collection, address_str, port_str) ;

      li->failed = "invalid port" ;

      zlog_warn("Invalid port '%s' when opening listener(s)", port_str) ;
      return  ;
    } ;

  /* If address is not null, must be a single, specific, numeric address
   *
   * Note that if we are (for some unknown reason) given an IPv4-Mapped address,
   * we map that to AF_INET and create an AF_INET socket.
   */
  if ((address_str != NULL) && (*address_str != '\0'))
    {
      bgp_listener_info li ;
      int ret ;

      li = bgp_listener_info_new(collection, address_str, port_str) ;

      ret = str2sockunion (address_str, &li->su) ;

      if (ret >= 0)
        {
          /* If, for some unearthly reason, we have an IPv4-Mapped address,
           * change to AF_INET -- so socket and address family will both be
           * that.
           */
          sockunion_unmap_ipv4 (&li->su) ;

          li->port      = port ;
          li->sock_type = SOCK_STREAM ;
          li->protocol  = IPPROTO_TCP ;
        }
      else
        {
          li->failed = "invalid address" ;

          zlog_warn("Could not parse ip address '%s' "
                                              "when opening listener(s): %s",
                                           address_str, errtoa(errno, 0).str) ;
        } ;
    }
  else
    {
      /* Null address, set up <any> for IPv4 and (if supported) IPv6 etc.
       */
      uint i ;

      for (i = 0 ; families[i] != AF_UNSPEC ; ++i)
        {
          bgp_listener_info li ;

          li = bgp_listener_info_new(collection, address_str, port_str) ;

          sockunion_init_new(&li->su, families[i]) ;

          li->port      = port ;
          li->sock_type = SOCK_STREAM ;
          li->protocol  = IPPROTO_TCP ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get pointer to list base for listeners in the given address family.
 */
static bgp_listener_list
bgp_listeners_find_list(port_t port, bool make)
{
  uint i ;
  bgp_listener_list listeners ;

  for (i = 0 ; i < vector_length(bgp_listener_lists) ; ++i)
    {
      listeners = vector_get_item(bgp_listener_lists, i) ;

      if (listeners->port == port)
        return listeners ;
    } ;

  if (!make)
    return NULL ;

  /* Create new, empty bas of listeners for the given port.
   *
   * Zeroizing the structure sets:
   *
   *   * base              -- NULLs   -- empty list
   *   * use_count         -- 0       -- nothing yet
   *   * port              -- X       -- set below
   */
  listeners = XCALLOC(MTYPE_BGP_LISTENER, sizeof(bgp_listener_list_t)) ;
  listeners->port = port ;

  vector_push_item(bgp_listener_lists, listeners) ;

  return NULL ;
}
/*------------------------------------------------------------------------------
 * Delete the given listener_list, and all associated listeners.
 */
static void
bgp_listeners_del_list(bgp_listener_list listener_list)
{
  bgp_listener listener ;
  uint i ;

  if (listener_list == NULL)
    return ;

  /* Stop any listeners.
   */
  while ((listener = dsl_pop(&listener, listener_list->base, next)) != NULL)
    {
      qps_remove_qfile(&listener->qf) ;

      close(qfile_fd_get(&listener->qf)) ;

      XFREE(MTYPE_BGP_LISTENER, listener) ;
    } ;

  /* Find and remove listener_list from main table, and free.
   */
  for (i = 0 ; i < vector_length(bgp_listener_lists) ; ++i)
    {
      if (listener_list == vector_get_item(bgp_listener_lists, i))
        {
          vector_delete_item(bgp_listener_lists, i) ;
          break ;
        }
    } ;

  XFREE(MTYPE_BGP_LISTENER, listener_list) ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, clean bgp_listener_info structure.
 *
 * NB: the given address and port_str are pointers to strings maintained
 *     elsewhere, and which are guaranteed (by the caller) to persist until
 *     the bgp_listener_info structure is dismantled.
 *
 * NB: the address_str is set to be the "human-readable" version of 'any'.
 */
static bgp_listener_info
bgp_listener_info_new(vector collection, const char* address_str,
                                         const char* port_str)
{
  bgp_listener_info li ;

  li = XCALLOC(MTYPE_TMP, sizeof(bgp_listener_info_t)) ;

  /* Zeroizing sets:
   *
   *   * address_str          -- X       -- set below
   *   * port_str             -- X       -- set below
   *
   *   * failed               -- NULL    )  no failure, yet
   *   * err                  -- 0       )
   *   * ai_err               -- 0       )
   *
   *   * su                   -- AF_UNSPEC
   *
   *   * port                 -- 0       -- undefined
   *   * sock_type            -- X       -- not set
   *   * protocol             -- X       -- not set
   *
   *   * sock_fd              -- X       -- set to -1 below
   */
  confirm(AF_UNSPEC   == 0) ;

  if ((address_str == NULL) || (*address_str == '\0'))
    li->address_str = bgp_any_address_str ;
  else
    li->address_str = address_str ;

  li->port_str = port_str ;
  li->sock_fd  = -1 ;

  return vector_push_item(collection, li) ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, clean bgp_listener_info structure.
 *
 * NB: the given address and port_str are pointers to strings maintained
 *     elsewhere, and which are guaranteed (by the caller) to persist until
 *     the bgp_listener_info structure is dismantled.
 *
 * NB: the address_str is set to be the "human-readable" version of 'any'.
 */
static bgp_listener_info
bgp_listener_info_free(bgp_listener_info li)
{
  if (li->sock_fd >= 0)
    close(li->sock_fd) ;

  XFREE(MTYPE_TMP, li) ;

  return NULL ;
} ;

/*==============================================================================
 * The accept() logic
 */
static int bgp_get_names(int sock_fd, bgp_connection_options cops) ;

/*------------------------------------------------------------------------------
 * Set listening on the given port -- incrementing the port's use count.
 *
 * This is to be called when an acceptor is first enabled.
 *
 * If a not-NULL and not-empty password is provided, then that is set for the
 * given su.  If there are no listeners for the relevant address family, or
 * otherwise fails to set the password, that will be logged but we continue,
 * anyway.
 *
 * NB: if there is no password will still set the password to empty, which
 *     forces the issue.  Does not log an "unsupported" error when setting
 *     an empty password.
 *
 * Returns:  true <=> there is at least one listener for the given port.
 *           false => failed to set up any listener for the given port.
 */
extern bool
bgp_listen_set(bgp_connection_options_c cops)
{
  bgp_listener_list listener_list ;

  listener_list = bgp_listeners_for_port(cops->port) ;

  if (listener_list == NULL)
    return false ;

  listener_list->use_count += 1 ;

  bgp_listeners_set_md5(listener_list, cops, on) ;
  return true ;
} ;

/*------------------------------------------------------------------------------
 * Set (new) password for all listeners associated with the address and
 *                                               port given by the given 'cops'.
 *
 * This has no effect if there are no listeners.
 *
 * NB: should probably avoid calling this if the password has not actually
 *     changed... but shouldn't make any difference.
 */
extern void
bgp_listen_set_password(bgp_connection_options_c cops)
{
  bgp_listener_list listener_list ;

  listener_list = bgp_listeners_find_list(cops->port, false /* no make */) ;

  if (listener_list != NULL)
    bgp_listeners_set_md5(listener_list, cops, on) ;
} ;

/*------------------------------------------------------------------------------
 * Unset all listeners associated with the address and port given by the
 *                                          given 'cops', clearing any password.
 *
 * This has no effect if there are no listeners.
 *
 * NB: in this case, if no password has been set, will not bother to clear
 *     it.  When the listening is set again for this address, will force the
 *     issue if even of the (then) password is empty.
 */
extern void
bgp_listen_unset(bgp_connection_options_c cops)
{
  bgp_listener_list listener_list ;

  listener_list = bgp_listeners_find_list(cops->port, false /* no make */) ;

  if (listener_list != NULL)
    {
      if (cops->password[0] != '\0')
        bgp_listeners_set_md5(listener_list, cops, off) ;

      if (listener_list->use_count > 1)
        listener_list->use_count -= 1 ;
      else
        bgp_listeners_del_list(listener_list) ;
    } ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * No longer prepared to accept() connection
 *
 * If the session has a password, then this is where it is withdrawn from the
 * listener(s) for the appropriate address family.
 *
 * NB: requires the session mutex LOCKED.
 *
 * TODO -- should do this when peer is stopped or about to be deleted !!
 */
extern void
bgp_not_prepared_to_accept(bgp_connection connection)
{
  int err Unused ;

  if (connection->session->password != NULL)
    {
      err = bgp_listeners_set_md5(connection->session->su_peer, NULL) ;

      qassert(err >= 0) ;       /* TODO ??? something more intelligent ??? */
    } ;

  return ;
} ;
#endif

/*------------------------------------------------------------------------------
 * Accept bgp connection -- this is the read action for qpselect.
 *
 * Accepts the connection, but if the source is not a configured peer, then
 * immediately and unceremoneously drop the connection.
 *
 * If connection passes those tests, sets up the new listener connection for
 * the session (including qpselect file), and kicks the FSM for that into life
 * by generating a bgp_fsm_TCP_connection_open event.  At this point the qfile
 * is not enabled in any mode and no timers are running.
 *
 * NB: uses bgp_session_lookup() to find the session, so will lock and unlock
 *     its mutex.
 *
 * NB: locks and unlocks the session mutex.
 *
 * NB: does not set up connection unless all parts of the accept process
 *     succeed.
 *
 * Events and Errors:
 *
 *   * if the accept() fails, log (err) the error and continue.
 *
 *     Error is no associated with any connection or session.
 *
 *   * if the connection is not acceptable, because:
 *
 *       (a) peer is not configured
 *       (b) session not currently accepting connections (for whatever reason)
 *
 *     log (debug) the event and continue.
 *
 *       -- could Cease/Connection Rejected in most cases
 *       -- could Cease/Connection Collision Resolution in those cases
 *
 *   * if the connection is acceptable, but fails in getting the remote/local
 *     addresses or in setting options
 *
 *     report error on primary connection and generate bgp_fsm_TCP_fatal_error
 *     event.
 *
 *   * if all goes well, generate bgp_fsm_TCP_connection_open either for the
 *     new (secondary) connection or for the primary.
 *
 * Sets connection->err to the error (if any).
 */
static void
bgp_accept_action(qfile qf, void* file_info)
{
  bgp_session   session ;
  bgp_acceptor  acceptor ;
  sockunion_t   sock_su[1] ;
  int  sock_fd, err ;

  /* Accept client connection.
   *
   * We arrange for an IPv4 listener *and* an IPv6 one (assuming have IPv6),
   * and we arrange for AF_INET6 listener to be IPV6_V6ONLY.  This means that
   * should NOT get an IPv4 mapped address.  However, should we get such an
   * address, the su_remote will be set to the actual IPv4 address.
   *
   * This means: the address family of su_remote is the address family of the
   * underlying connection, NOT NECESSARILY the socket -- should that matter.
   */
  sock_fd = sockunion_accept(qfile_fd_get(qf), sock_su) ;
  if (sock_fd < 0)
    {
      if (sock_fd == -1)
        zlog_err("[Error] BGP accept() failed (%s)", errtoa(errno, 0).str) ;

      return ;          /* have no connection to report this to         */
    } ;

  if (sockunion_is_mapped_ipv4(sock_su))
    {
      /* The listen() socket should have been set to IPV6_V6ONLY, so this
       * really should not happen.
       */
      zlog_err("[Error] BGP accept() returned IPv6 with "
                                 "IPv4-Mapped address %s", sutoa(sock_su).str) ;
      close(sock_fd) ;
      return ;          /* have no connection to report this to         */
    } ;

  if (BGP_DEBUG(fsm, FSM))
    zlog_debug("[FSM] BGP accept() from %s", sutoa(sock_su).str) ;

  /* See if the connecting party is configured -- reject with NOTIFICATION if
   * not.
   */
  session  = bgp_peer_index_seek_session(sock_su) ;
  acceptor = (session != NULL) ? session->acceptor : NULL ;

  if ( (acceptor == NULL) || (acceptor->state == bacs_unset) )
    {
      /* Reject: send NOTIFICATION: Cease/Connection Rejected -- per RFC 4486
       *
       * We have no knowledge whatsoever of the incoming "peer".
       *
       * NB: there is clearly an opportunity to DDOS a bgpd by sending it large
       *     numbers of bogus incoming connections.  These will be queued up by
       *     the system, and then rejected as soon as the accept() code is run.
       *     This occupies the (limited) space in the incoming queue, and takes
       *     up processing time here.
       *
       *     By the time bgpd sees the incoming connection, an attacker knows
       *     that there is something running on the port.  It is too late to
       *     disguise that fact.  Sending a NOTIFICATION confirms that there
       *     really is a BGP speaker at this end... which is extra information.
       *
       *     That extra information may be of use where the other end is
       *     legitimate.
       *
       *     To protect the bgpd from DDOS requires the system to screen out
       *     stuff before it reaches bgpd... not giving away (a small amount
       *     of) extra information is not going to help... and could hinder
       *     legitimate use.
       */
      bgp_notify notification ;

      if (BGP_DEBUG(fsm, FSM))
        zlog_debug("[FSM] BGP accept() rejected %s -- peer not configured",
                                                         sutoa(sock_su).str) ;

      notification = bgp_notify_new(BGP_NOMC_CEASE, BGP_NOMS_C_REJECTED) ;
      bgp_notify_put(sock_fd, notification) ;
      bgp_notify_free(notification) ;

      close(sock_fd) ;
      return ;          /* socket closed        */
    } ;

  /* We recognise the connecting party, so now proceed on the basis of the
   * state of the acceptor.
   */
  acceptor->cops = bgp_connection_options_copy(acceptor->cops,
                                                         session->cops_config) ;

  err = bgp_socket_set_common_options(sock_fd, acceptor->cops, 0, 0) ;

  if (err == 0)
    err = bgp_get_names(sock_fd, acceptor->cops) ;

  bgp_acceptor_accept(acceptor, sock_fd, (err == 0), sock_su) ;
} ;

/*==============================================================================
 * Open BGP Connection -- connect() to the other end
 */
static void bgp_connect_action(qfile qf, void* file_info) ;

static int bgp_bind_ifname(int sock_fd, bgp_connection_options cops) ;
static int bgp_bind_ifaddress(int sock_fd, bgp_connection_options cops) ;

/*------------------------------------------------------------------------------
 * Open BGP Connection -- connect() to the other end
 *
 * Creates a *non-blocking* socket.
 *
 * If fails immediately, generate suitable FSM event.
 *
 * Success (immediate or otherwise) and delayed failure are dealt with in the
 * qpselect action -- bgp_connect_action() -- below.
 */
extern void
bgp_connect(bgp_connection connection)
{
  bgp_connection_options cops ;
  qfile  qf ;
  int    sock_fd ;
  int    err ;

  cops = bgp_connection_prepare(connection) ;
  err = 0 ;

  /* Make socket for the connect connection.
   */
  sock_fd = sockunion_socket(&cops->su_remote, SOCK_STREAM, 0) ;
  if (sock_fd <= 0)
    err = errno ;

  if (BGP_DEBUG(fsm, FSM))
    {
      if (err == 0)
        plog_debug(connection->lox.log, "%s [FSM] connect start on socket %d",
                                                connection->lox.host, sock_fd) ;
      else
        plog_debug(connection->lox.log,
                    "%s [FSM] connect start failed to create socket (!)",
                                                         connection->lox.host) ;
    } ;

  /* Set the common options.
   */
  if (err == 0)
    err = bgp_socket_set_common_options(sock_fd, cops, 1, 1) ;

  /* Set the TCP MD5 "password", if required.
   */
  if (err== 0)
    if (cops->password[1] != '\0')
      err = bgp_md5_set_socket(sock_fd, &cops->su_remote, cops->password) ;

  /* Bind socket to given interface, if any and if possible.
   *
   * Sets cops->ifindex to the result -- 0 if no interface or unable to set.
   */
  if (err == 0)
    err = bgp_bind_ifname(sock_fd, cops) ;

  /* Bind socket to the given source (local) address, if any and if can.
   */
  if (err == 0)
    err = bgp_bind_ifaddress(sock_fd, cops) ;

  /* Connect to the remote peer.
   */
  if (err == 0)
    err = sockunion_connect(sock_fd, &cops->su_remote, cops->port,
                                                       cops->ifindex) ;
                          /* does not report EINPROGRESS as an error.   */

  /* If not OK now, signal the error and close the sock_fd (if any) and give
   * up.
   */
  if (err != 0)
    {
      bgp_fsm_connect_event(connection, sock_fd, err) ;

      if (sock_fd >= 0)
        close(sock_fd) ;

      return ;                          /* failed in connect()  */
    } ;

  /* Set connection waiting for connection to complete.
   *
   * NB: according to "Unix Network Programming" (ISBN 0-13-141155-1) there
   *     are a number of portability issues surrounding non-blocking
   *     connect.
   *
   *     POSIX seems to be clear:
   *
   *       * when the connection is successfully established, it will become
   *         writable -- see description of connect() and pselect().
   *
   *       * if an error occurs, it will be readable and writable and
   *         an exception will be deemed to be set -- see description of
   *         pselect().
   *
   *     The difficulty appears to be that some (pre-POSIX ?) systems may not
   *     go writable if there is an error.
   *
   *     So... we set both read-ready and write-ready.  When either goes off
   *     we use getsockopt_so_error() to pick up any error.
   *
   * Generally, expect it to be a while before the sock_fd becomes readable or
   * writable.  But for local connections this may happen immediately.  But,
   * in any case, this will be handled by the qpselect action.
   */
  qf = bgp_connection_connecting(connection, sock_fd) ;

  qfile_enable_mode(qf, qps_read_mnum,  bgp_connect_action) ;
  qfile_enable_mode(qf, qps_write_mnum, bgp_connect_action) ;

  return ;                      /* connect() succeeded  */
} ;

/*------------------------------------------------------------------------------
 * Complete non-blocking bgp connect() -- this is the read and write action for
 * qpselect.
 *
 * If the connection succeeds, expect the socket to become writable.  May also
 * become readable if data arrives immediately.
 *
 * If the connection fails, expect the socket to also become writable.  But may
 * only become readable... apparently.
 *
 * Either way, use getsockopt() to extract any error condition.
 *
 * If becomes both readable and writable at the same time, then the first to
 * arrive here will disable the file for both read and write, which will
 * discard the other pending event -- so will not attempt to do this more than
 * once.
 *
 * See bgp_fsm_connect_completed() for events etc to be raised.
 */
static void
bgp_connect_action(qfile qf, void* file_info)
{
  bgp_connection  connection ;
  int err, sock_fd ;

  connection = file_info ;
  qassert(connection->qf == qf) ;

  sock_fd = qfile_fd_get(qf) ;

  /* See if connection successful or not.
   *
   * If successful, set the connection->cops->su_local and ->su_remote
   */
  if (getsockopt_so_error(sock_fd) < 0)
    err = errno ;
  else
    err = bgp_get_names(sock_fd, connection->cops) ;

  /* In any case, disable both read and write for this file, and signal to
   * the FSM that something has happened.
   */
  qfile_disable_modes(qf, qps_write_mbit | qps_read_mbit) ;

  bgp_fsm_connect_event(connection, sock_fd, err) ;
} ;

#if 0
/*==============================================================================
 * Set the TTL for the given connection (if any), if there is an sock_fd.
 */
extern void
bgp_set_new_ttl(bgp_connection connection, int ttl, bool gtsm)
{
  int sock_fd ;

  if (connection == NULL)
    return ;

  sock_fd = qfile_fd_get(connection->qf) ;
  if (sock_fd < 0)
    return ;

  bgp_set_ttl(sock_fd, connection, cops) ; // TODO handle error(s)
} ;
#endif

/*------------------------------------------------------------------------------
 * BGP set minttl (GTSM) and/or ttl.
 *
 * If GTSM is not requested, sets the outbound ttl as given -- clamped to
 * 1..TTL_MAX.  (If GTSM was set, clears it.)
 *
 * If GTSM is requested, the ttl is the maximum number of hops away the peer
 * is -- clamped to 1..TTL_MAX.  Sets GTSM if that is supported -- issues
 * WARNINGS if not.  In any case, sets the outgoing ttl to TTL_MAX, so that
 * the neighbour can implement GTSM.
 *
 * Treats:  cops->ttl & cops->gtsm as *read-only*
 *
 *          sets cops->ttl_out and cops->ttl_min according to what is possible
 *          and acheived.
 *
 * So:
 *
 *   * cops->ttl and cops->gtsm are the *requested*, values
 *                                               -- not the actual values set
 *
 *   * cops->ttl_out is clamped to 1..TTL_MAX,
 *
 *     and forced to TTL_MAX if is cops->gtsm (or fails to clear GTSM which
 *     was previously set -- returns with an error).
 *
 *   * cops->ttl_min is zero if not cops->gtsm or cannot set GTSM.
 *
 *     cops->ttl_min is otherwise TTL_MAX..1 -- depending on cops->ttl.
 *
 * Returns:  0 : OK (so far so good)
 *        != 0 : error number (from errno or otherwise) -- WARNING(s) issued
 *
 * NB: returns OK, but has logged a WARNING, if GTSM is not supported (and
 *     is not currently set !).
 */
static int
bgp_set_ttl(int sock_fd, bgp_connection_options cops)
{
  uint ttl, ttl_gtsm, ttl_out, ttl_min ;
  bool was_gtsm ;
  int  err, ret ;

  if      (cops->ttl < 1)
    ttl = 1 ;                           /* clamp        */
  else if (cops->ttl > TTL_MAX)
    ttl = TTL_MAX ;                     /* clamp        */
  else
    ttl  = cops->ttl ;

  if (cops->gtsm)
    {
      /* If we wish to set gtsm, then we set ttl_gtsm to the request, and
       * ttl_send to TTL_MAX... in case the other end also uses gtsm !
       */
      ttl_gtsm = ttl ;
      ttl_out  = TTL_MAX ;
    }
  else
    {
      /* If we wish to set ttl without gtsm, then we set ttl_gtsm zero, and
       * ttl_send to the requested value.
       */
      ttl_gtsm = 0 ;            /* clear if was set     */
      ttl_out  = ttl ;
    } ;

  was_gtsm = (cops->ttl_min != 0) ;
  err      = 0 ;
  ttl_min  = 0 ;

  if (cops->gtsm || was_gtsm)
    {
      ret = setsockopt_minttl(sock_fd, ttl_gtsm) ;

      if (ret >= 0)
        ttl_min = ret ;                 /* set as required      */
      else
        {
          /* If we could not set (or clear) GTSM, we have failed.
           *
           * However, if GTSM is not supported AND we don't think it was set
           * before, we continue, without GTSM checking at this end.  If GTSM
           * was requested, we set the outgoing TTL to TTL_MAX, so that the
           * other end can do GTSM, if it wishes.
           *
           * If we return with an error, then we force ttl_out to TTL_MAX.
           */
          if ((errno != EOPNOTSUPP) || was_gtsm)
            {
              err = errno ;
              ttl_min = 0 ;             /* assume off           */
              ttl_out = TTL_MAX ;       /* force a default      */
            } ;
        } ;
    } ;

  cops->ttl_out  = ttl_out ;            /* what we ask for      */
  cops->ttl_min  = ttl_min ;            /* what we got          */

  ret = setsockopt_ttl(sock_fd, ttl_out) ;
  if ((ret < 0) && (err == 0))
    err = errno ;

  return err ;
} ;

/*==============================================================================
 * Get local and remote address and port for connection -- unmaps IPv4-Mapped.
 *
 * Returns:  0 => OK
 *        != 0 : error number (from errno or otherwise)
 */
static int
bgp_get_names(int sock_fd, bgp_connection_options cops)
{
  int ret, err ;

  err = 0 ;

  ret = sockunion_getsockname(sock_fd, &cops->su_local) ;
  if (ret < 0)
    err = errno ;

  ret = sockunion_getpeername(sock_fd, &cops->su_remote) ;
  if ((ret < 0) && (err == 0))
    err = errno ;

  return err ;
} ;

/*==============================================================================
 * Specific binding of outbound connections to interfaces...
 *
 */

/*------------------------------------------------------------------------------
 * BGP socket bind to interface name, if any and set the interface index.
 *
 * If there is a specific interface to bind an outbound connection to, that
 * is done here.
 *
 * Returns:  0 : OK (so far so good)
 *        != 0 : error number (from errno or otherwise)
 */
static int
bgp_bind_ifname(int sock_fd, bgp_connection_options cops)
{
  enum
    {
      can_so_bindtodevice =
#ifdef SO_BINDTODEVICE
                            true,
#else
                            false,
#endif
      so_bindtodevice     = SO_BINDTODEVICE + 0,
    } ;

  int  err ;

  cops->ifindex  = 0 ;              /* unknown      */
  err = 0 ;                         /* OK           */

  if (cops->ifname[0] != '\0')
    {
      cops->ifindex  = if_nametoindex(cops->ifname) ;

      if (cops->ifindex == 0)
        {
          zlog_warn("Cannot bind to unknown interface %s for %s",
                                    cops->ifname, sutoa(&cops->su_remote).str) ;
        }
      else if (can_so_bindtodevice)
        {
          int  ret ;
          bool raised ;
#ifdef SO_BINDTODEVICE
          struct ifreq ifreq ;
          char*  ifname      = (char *)&ifreq.ifr_name ;
          uint   ifname_size = sizeof (ifreq.ifr_name) ;
#else
          struct { bgp_ifname_t ifname ; } ifreq ;
          char*  ifname      = ifreq.ifname ;
          uint   ifname_size = sizeof (ifreq.ifname) ;
#endif
          memset(&ifreq, 0, sizeof(ifreq)) ;
          strncpy (ifname, cops->ifname, ifname_size) ;

          raised = bgp_raise_privs(__func__) ;

          ret = setsockopt (sock_fd, SOL_SOCKET, so_bindtodevice,
                                                       &ifreq, sizeof (ifreq)) ;
          if (ret >= 0)
            {
              err = 0 ;
            }
          else
            {
              err = errno ;
              zlog_warn("bind to interface %s failed for %s (%s)",
                                    cops->ifname, sutoa(&cops->su_remote).str,
                                                           errtoa(err, 0).str) ;
              cops->ifindex = 0 ;
            } ;

          bgp_lower_privs(__func__, raised) ;
        }
      else
        {
          zlog_warn("Cannot SO_BINDTODEVICE, so bind to %s for %s ignored",
                                    cops->ifname, sutoa(&cops->su_remote).str) ;
        } ;
    } ;

  return err ;
} ;

/*------------------------------------------------------------------------------
 * Update source selection -- if connection specifies an IP address.
 *
 * If required, tries to bind the given socket to the given address.  Does not
 * attempt to bind the port at this stage.
 *
 * Returns:  0 : OK (so far so good)
 *        != 0 : error number (from errno or otherwise)
 */
static int
bgp_bind_ifaddress(int sock_fd, bgp_connection_options cops)
{
  if (sockunion_family(&cops->su_local) != AF_UNSPEC)
    {
      sockunion_t su[1] ;
      int ret ;

      sockunion_new_sockaddr(su, &cops->su_local.sa) ;
      ret = sockunion_bind(sock_fd, su, 0 /* no port number */,
                                                        false /* not 'any' */) ;
      if (ret < 0)
        return errno ;
    } ;

  return 0 ;
} ;

/*==============================================================================
 * BGP Socket Option handling
 */

/*------------------------------------------------------------------------------
 * Common socket options for listen/connect/accept:
 *
 *   * non-blocking -- at all times
 *   * reuseaddr
 *   * reuseport
 *
 * and, for connect/accept (ie: cops != NULL):
 *
 *   * set security ttl (GTSM) and/or ttl -- if connection given.
 *   * set TOS or equivalent  if required
 *
 * NB: it is assumed that is setting these options as soon as the socket is
 *     created... so GTSM is definitely not set.
 *
 * Returns:  0 => OK
 *        != 0 == errno -- not that we really expect any errors here
 *                         WARNING or ERROR logged.
 */
static int
bgp_socket_set_common_options(int sock_fd, bgp_connection_options cops,
                                                       uint rcvbuf, uint sndbuf)
{
  int  err ;

  /* Set the assumed defaults for a new connection for TTL and MINTTL.
   */
  cops->ttl_out  = TTL_MAX ;
  cops->ttl_min  = 0 ;

  /* Make socket non-blocking and close-on-exec
   */
  if (set_nonblocking(sock_fd) < 0)
    return errno ;              /* WARNING logged               */

  if (set_close_on_exec(sock_fd) < 0)
    return errno ;              /* WARNING logged               */

  /* Reuse addr and port
   */
  if (setsockopt_reuseaddr(sock_fd) < 0)
    return errno ;              /* WARNING logged               */
  if (setsockopt_reuseport(sock_fd) < 0)
    return errno ;              /* WARNING logged               */

  /* Set sizes if required.
   *
   * NB: this is a bit of a disappointment -- under LINUX SO_SNDLOWAT is
   *     not implemented... and the value of the SO_RCVBUF and SO_SNDBUF
   *     is doubled...  so if we could set a SO_SNDLOWAT in terms of the
   *     SO_SNDBUF, it is bent out of shape !
   */
  if (rcvbuf != 0)
    {
      uint actual Unused ;

      rcvbuf = 64 * 1024 ;              // TODO --- configurable rcvbuf !!

      actual = setsockopt_so_recvbuf_x(sock_fd, rcvbuf) ;
    } ;

  if (sndbuf != 0)
    {
      uint actual ;
      uint lowat  Unused ;

      sndbuf = 64 * 1024 ;              // TODO --- configurable sndbuf !!

      actual = setsockopt_so_sendbuf_x(sock_fd, sndbuf) ;

      if (actual >= sndbuf)
        lowat  = setsockopt_so_sendlowat(sock_fd, actual / 4) ;
    } ;

  /* Done if listener.
   */
  if (cops == NULL)
    return 0 ;

  /* Adjust ttl and gtsm if required
   */
  err = bgp_set_ttl(sock_fd, cops) ;            /* WARNING logged       */

  /* Worry about TOS etc, if possible.
   */
#ifdef IPTOS_PREC_INTERNETCONTROL
  if (err == 0)
    {
      int  family ;

      family = sockunion_getsockfamily(sock_fd) ;

      if (family < 0)
        err = errno ;
      else
        {
          bool raised ;

          raised = bgp_raise_privs(__func__) ;

          switch (family)
            {
              case AF_INET:
                if (setsockopt_ipv4_tos (sock_fd,
                                               IPTOS_PREC_INTERNETCONTROL) < 0)
                  err = errno ;
                break ;

# ifdef HAVE_IPV6
              case AF_INET6:
                if (setsockopt_ipv6_tclass (sock_fd,
                                                IPTOS_PREC_INTERNETCONTROL) < 0)
                  err = errno ;
                break ;
# endif

              default:
                break ;
            } ;

          bgp_lower_privs(__func__, raised) ;
        } ;
    } ;
#endif

  return errno = err ;
} ;

/*------------------------------------------------------------------------------
 * Set (or clear) MD5 key for the socket, for the given IPv4 peer address.
 *
 * If the password is NULL or zero-length, the option will be disabled.
 *
 * Returns:  0 => OK (or not supported, but password NULL or empty).
 *    otherwise: errno   -- ERROR logged
 *
 * NB: if MD5 is not supported, returns EOPNOTSUPP error -- unless password
 *     NULL or empty.
 *
 * NB: has to change up privileges, which can fail (if things are badly set up)
 */
static int
bgp_md5_set_socket(int sock_fd, sockunion_c su, const char* password)
{
  int err, ret ;
  bool raised ;

  assert(sock_fd >= 0) ;

  raised = bgp_raise_privs(__func__) ;

  ret = setsockopt_tcp_signature(sock_fd, su, password) ;
  if (ret >= 0)
    err = 0 ;
  else
    err = errno ;               /* ERROR logged         */

  bgp_lower_privs(__func__, raised) ;

  return err ;
} ;

/*==============================================================================
 * Local support for raising/lowering privilege.
 *
 * Logs error if fails to do either.
 */

/*------------------------------------------------------------------------------
 * Raise privilege -- return true if succeeds.
 */
static bool
bgp_raise_privs(const char* func)
{
  int ret ;

  ret = bgpd_privs.change(ZPRIVS_RAISE) ;
  if (ret == 0)
    return true ;               /* done         */

  zlog_err("Failed to raise privs (in %s): %s", func, errtoa(errno, 0).str) ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Lower privilege -- return true if succeeds or was not raised.
 *
 * NB: even if bgp_raise_privs() failed, this will lower, so whatever happens,
 *     hopefully we are back in lowered state.
 *
 *     But if bgp_raise_privs() failed, any error from lowering is ignored.
 */
static bool
bgp_lower_privs(const char* func, bool raised)
{
  int ret ;

  ret = bgpd_privs.change(ZPRIVS_LOWER) ;

  if ((ret == 0) || !raised)
    return true ;               /* done         */

  zlog_err("%s: could not lower privs: %s", func, errtoa(errno, 0).str) ;

  return false ;
} ;
