/* Quagga Pthreads support -- thread safe versions of standard functions
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

/* We use thread specific storage to provide buffers for the _r versions
 * of standard functions, so that the callers don't need to provide
 * their own.  The contents of a buffer will remain intact until another
 * safe_ function is called on the same thread
 */

#include "misc.h"
#include "pthread_safe.h"
#include "qpthreads.h"
#include "memory.h"

#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

#include "qstring.h"
#include "qfstring.h"
#include "errno_names.h"

/*==============================================================================
 * Initialisation, close down and local variables.
 *
 * Note that the "thread_safe" mutex is recursive, so one thread safe function
 * can call another, if required.
 */
static qpt_own_data_t tsd ;
static const int buff_size = 1024;

static qpt_mutex thread_safe = NULL ;

static const char ellipsis[] = "..." ;

static void destructor(void* data);
static char * thread_buff(void);

#define THREAD_SAFE_LOCK()   qpt_mutex_lock(thread_safe)
#define THREAD_SAFE_UNLOCK() qpt_mutex_unlock(thread_safe)

/*------------------------------------------------------------------------------
 * Module initialization, before any threads have been created
 */
void
safe_init_r(void)
{
  qpt_own_data_create(tsd, destructor) ;

  thread_safe = qpt_mutex_new(qpt_mutex_recursive, "pthread safe") ;
} ;

/*------------------------------------------------------------------------------
 * Clean up
 */
void
safe_finish(void)
{
  qpt_own_data_delete(tsd) ;

  thread_safe = qpt_mutex_destroy(thread_safe) ;
} ;

/*------------------------------------------------------------------------------
 * called when thread terminates, clean up
 */
static void
destructor(void* data)
{
  XFREE(MTYPE_TSD, data);
}

/*==============================================================================
 * Alternative error number handling.
 *
 * The descriptive strings for error numbers are all very well, but for some
 * purposes knowing the name for the error is more useful -- the name, not the
 * number, as the number is system dependent.
 *
 * The following provides:
 *
 *   * errtoa()     -- which maps error number to: ENAME '<strerror>'
 *
 *   * errtoname()  -- which maps error number to: ENAME
 *
 *   * errtostr()   -- which maps error number to: <strerror>
 *
 * where:
 *
 *   * if name is not known gives: ERRNO=999
 *
 *   * if strerror rejects the number gives: *unknown error*
 *
 *   * err == 0 gives:  EOK          -- for the name
 *                      'no error'   -- for the <strerror>
 *
 * These functions take a 'len' argument, and truncates the result to the given
 * len (0 => no truncation) -- silently imposing the maximum length allowed by
 * the strerror_t.
 *
 * If has to truncate the <strerror>, places "..." at the end of the message
 * to show this has happened.
 */

static strerror_t errtox(int err, ulen len, uint want) ;
static const char* qstrerror_r(int err, char *buf, size_t n) ;
static const char* qstrerror(int err) ;

/*------------------------------------------------------------------------------
 * Construct string to describe the given error of the form:
 *
 *   ENAME '<strerror>'
 *
 * Thread safe extension to strerror.  Never returns NULL.
 */
extern strerror_t
errtoa(int err, ulen len)
{
  return errtox(err, len, 3) ;
} ;

/*------------------------------------------------------------------------------
 * Convert error number to its name
 *
 * Thread-safe.  Never returns NULL.
 */
extern strerror_t
errtoname(int err, ulen len)
{
  return errtox(err, len, 1) ;
} ;

/*------------------------------------------------------------------------------
 * Alternative thread-safe safe_strerror()
 *
 * Thread safe replacement for strerror.  Never returns NULL.
 */
extern strerror_t
errtostr(int err, ulen len)
{
  return errtox(err, len, 2) ;
} ;

/*-----------------------------------------------------------------------------
 * Common code for errto<x> above.
 *
 *   len  >  0 -- limit length (unless longer than maximum for strerror_t)
 *   len  <= 0 -- allow up to the maximum  for strerror_t
 *
 *   want == 1 -- return just name
 *   want == 2 -- return just the strerror()
 *   want == 3 -- return both, with the strerror() in single quotes.
 *
 * NB: this is not async-signal-safe !
 */
static strerror_t
errtox(int err, ulen len, uint want)
{
  strerror_t QFB_QFS(st, qfs) ;
  int   errno_saved ;
  const char* q ;
  ulen ql ;

  /* Prepare.                                                   */
  errno_saved = errno ;

  if ((len > 0) && (len < sizeof(st.str)))
    qfs_init(qfs, st.str, len + 1) ;    /* limit the size       */

  q  = "" ;
  ql = 0 ;

  /* If want the error name, do that now.                       */
  if (want & 1)
    {
      const char* name = errno_name_lookup(err) ;

      if (name != NULL)
        qfs_put_str(qfs, name) ;
      else
        qfs_printf(qfs, "ERRNO=%d", err) ;
    } ;

  /* name and string ?                                          */
  if (want == 3)
    {
      qfs_put_str(qfs, " ") ;
      q  = "'" ;
      ql = 2 ;
    } ;

  /* If want the error string, do that now                      */
  if (want & 2)
    {
      char  buf[400] ;      /* impossibly vast      */
      const char* errm ;

      if (err == 0)
        errm = "no error" ;
      else
        {
          if (qpthreads_enabled)
            errm = qstrerror_r(err, buf, sizeof(buf)) ;
          else
            errm = qstrerror(err) ;

          /* Deal with errors, however exotic.                          */
          if (errm == NULL)
            {
              int ret = errno ;
              qf_str_t qfs_b ;

              qfs_init(qfs_b, buf, sizeof(buf)) ;

              if      (ret == EINVAL)
                qfs_printf(qfs_b, "unknown error number %d", err) ;
              else if (ret == ERANGE)
                qfs_printf(qfs_b, "strerror%s(%d) returned impossibly large "
                                                 " error message (> %d bytes)",
                         qpthreads_enabled ? "_r" : "", err, (int)sizeof(buf)) ;
              else
                qfs_printf(qfs_b, "strerror%s(%d) returned error %d",
                                      qpthreads_enabled ? "_r" : "", err, ret) ;

              qfs_term(qfs_b) ;

              q    = "*" ;
              ql   = 2 ;        /* force "*" "quotes"   */
              errm = buf ;
            } ;
        } ;

      /* Add strerror to the result... with quotes as rquired           */
      if (ql != 0)
        qfs_put_str(qfs, q) ;

      qfs_put_str(qfs, errm) ;

      if (ql != 0)
        qfs_put_str(qfs, q) ;
    } ;

  /* '\0' terminate -- if has overflowed, replace last few characters
   * by "..." -- noting that sizeof("...") includes the '\0'.
   */
  if (qfs_term(qfs) != 0)
    qfs_term_string(qfs, ellipsis, sizeof(ellipsis)) ;

  /* Put back errno and we are done
   */
  errno = errno_saved ;
  return st ;
} ;

/*==============================================================================
 * getaddrinfo() and getnameinfo() "EAI_XXXX" error number handling.
 *
 * This is similar to the above for errno.
 *
 * The following provides:
 *
 *   * eaitoa()     -- which maps error number to: EAI_XXX '<gai_strerror>'
 *                                             or: as errtoa()
 *
 *   * eaitoname()  -- which maps error number to: EAI_XXX
 *                                             or: as errtoname()
 *
 *   * eaitostr()   -- which maps error number to: <gai_strerror>
 *                                             or: as errtostr()
 *
 * where:
 *
 *   * if given EAI_SYSTEM, and given a non-zero errno type error number,
 *     produce the errno string.
 *
 *   * if name is not known gives: EAI=999
 *
 *   * gai_strerror returns a string saying the error is not known if that is
 *     the case.
 *
 *   * eai == 0 gives:  EAI_OK       -- for the name
 *                      'no error'   -- for the <sgai_strerror>
 *
 * NB: EAI_SYSTEM is an invitation to look at errno to discover the true
 *     error.
 */

static strerror_t eaitox(int eai, int err, ulen len, uint want) ;

/*------------------------------------------------------------------------------
 * Construct string to describe the given EAI_XXX error of the form:
 *
 *      EAI_XXX '<gai_strerror>'
 *  or: ENAME '<strerror>'       -- if EAI_SYSTEM and err != 0
 *
 * Thread safe.  Never returns NULL.
 */
extern strerror_t
eaitoa(int eai, int err, ulen len)
{
  return eaitox(eai, err, len, 3) ;
} ;

/*------------------------------------------------------------------------------
 * Convert EAI_XXX error number to its name...
 *
 * ...or, if EAI_SYSTEM and err != 0, convert err to its name.
 *
 * Thread-safe.  Never returns NULL.
 */
extern strerror_t
eaitoname(int eai, int err, ulen len)
{
  return eaitox(eai, err, len, 1) ;
} ;

/*------------------------------------------------------------------------------
 * Alternative to gai_strerror()...
 *
 * ...or, if EAI_SYSTEM and err != 0, do strerror(err) or strerror_r(err).
 *
 * Thread-safe.  Never returns NULL.
 */
extern strerror_t
eaitostr(int eai, int err, ulen len)
{
  return eaitox(eai, err, len, 2) ;
} ;

/*-----------------------------------------------------------------------------
 * Common code for eaito<x> above.
 *
 *   want == 1 -- return just name
 *   want == 2 -- return just the gai_strerror()
 *   want == 3 -- return both, with the gai_strerror() in single quotes.
 *
 *   err != 0 => if EAI_SYSTEM, return result for errno == err instead.
 */
static strerror_t
eaitox(int eai, int err, ulen len, uint want)
{
  strerror_t QFB_QFS(st, qfs) ;
  int   errno_saved ;
  const char* q ;
  ulen ql ;

  /* Look out for mapping EAI_SYSTEM
   */
  if ((eai == EAI_SYSTEM) && (err != 0))
    return errtox(err, len, want) ;

  /* Prepare.
   */
  errno_saved = errno ;

  if ((len > 0) && (len < sizeof(st.str)))
    qfs_init(qfs, st.str, len + 1) ;    /* limit the size       */

  q  = "" ;
  ql = 0 ;

  /* If want the error name, do that now.
   */
  if (want & 1)
    {
      const char* name = eaino_name_lookup(eai) ;

      if (name != NULL)
        qfs_put_str(qfs, name) ;
      else
        qfs_printf(qfs, "EAI=%d", eai) ;
    } ;

  /* name and string ?
   */
  if (want == 3)
    {
      qfs_put_str(qfs, " ") ;
      q  = "'" ;
      ql = 2 ;
    } ;

  /* If want the error string, do that now
   */
  if (want & 2)
    {
      const char* eaim ;

      if (eai == 0)
        eaim = "no error" ;
      else
        eaim = gai_strerror(eai) ;

     /* Add strerror to the result... with quotes as required
      */
      if (ql != 0)
        qfs_put_str(qfs, q) ;

      qfs_put_str(qfs, eaim) ;

      if (ql != 0)
        qfs_put_str(qfs, q) ;

    } ;

  /* '\0' terminate -- if has overflowed, replace last few characters
   * by "..." -- noting that sizeof("...") includes the '\0'.
   */
  if (qfs_term(qfs) != 0)
    qfs_term_string(qfs, ellipsis, sizeof(ellipsis)) ;

  /* Put back errno and we are done
   */
  errno = errno_saved ;
  return st ;
} ;

/*==============================================================================
 * Miscellaneous thread-safe functions
 */

/*------------------------------------------------------------------------------
 * getenv_r -- fetch environment variable into the given buffer.
 *
 * If buffer is not long enough, fetches as much as can and '\0' terminates.
 *
 * Returns:   -1 => not found -- buffer set empty
 *          >= 0 == length of environment variable
 *
 * NB: this is NOT signal safe.  If need value of environment variable in
 *     a signal action -- make OTHER arrangements !!
 */
extern int
getenv_r(const char* name, char* buf, int buf_len)
{
  char* val ;
  int   len ;
  int   cl ;

  THREAD_SAFE_LOCK() ;

  val = getenv(name) ;
  if (val == NULL)
    {
      len = -1 ;
      cl  = 0 ;
    }
  else
    {
      len = strlen(val) ;
      cl  = (len < buf_len) ? len : buf_len - 1 ;
    } ;

  if (buf_len > 0)
    {
      if (cl > 0)
        memcpy(buf, val, cl) ;
      buf[cl] = '\0' ;
    } ;

  THREAD_SAFE_UNLOCK() ;

  return len ;
} ;

/*------------------------------------------------------------------------------
 * Thread safe version of strerror.  Never returns NULL.
 * Contents of result remains intact until another call of
 * a safe_ function.
 */
const char *
safe_strerror(int errnum)
{
  int   errno_saved ;
  const char* errm ;

  errno_saved = errno ;

  if (qpthreads_enabled)
    errm = qstrerror_r(errnum, thread_buff(), buff_size) ;
  else
    errm = qstrerror(errnum);

  errno = errno_saved ;

  return (errm != NULL) ? errm : "Unknown error" ;
}

/*------------------------------------------------------------------------------
 * Thread safe version of inet_ntoa.  Never returns NULL.
 * Contents of result remains intact until another call of
 * a safe_ function.
 */
const char *
safe_inet_ntoa (struct in_addr in)
{
  static const char * unknown = "Unknown address";
  const char * buff;

  buff = (qpthreads_enabled)
            ? inet_ntop(AF_INET, &in, thread_buff(), buff_size)
            : inet_ntoa(in);

  return buff != NULL
      ? buff
      : unknown;
}

/*------------------------------------------------------------------------------
 * Construct string for given IP family/address.
 *
 * Returns struct with embedded string.
 */
extern str_iptoa_t
siptoa(sa_family_t family, const void* address)
{
  str_iptoa_t QFB_QFS(ipa, qfs) ;

  switch (family)
    {
      case AF_INET:
        confirm(sizeof(ipa.str) >= INET_ADDRSTRLEN) ;
#ifdef HAVE_IPV6
      case AF_INET6:
        confirm(sizeof(ipa.str) >= INET6_ADDRSTRLEN) ;
#endif
        inet_ntop(family, address, ipa.str, sizeof(ipa.str));
        break;

      default:
        qfs_printf(qfs, "?unknown address family=%d?", family) ;
        qfs_term(qfs) ;
        break ;
    } ;

  return ipa;
} ;

/*------------------------------------------------------------------------------
 * Construct string for given IPv4 address (in_addr_t).
 *
 * Returns struct with embedded string.
 */
extern str_iptoa_t
sipv4toa(in_addr_t addr)
{
  return siptoa(AF_INET, &addr) ;
} ;

/*------------------------------------------------------------------------------
 * Return the thread's buffer, create it if necessary.
 * (pthread Thread Specific Data)
 */
static char *
thread_buff(void)
{
  char * buff = qpt_own_data_get_value(tsd);

  if (buff == NULL)
    {
      buff = XMALLOC(MTYPE_TSD, buff_size);
      qpt_own_data_set_value(tsd, buff);
    }

  return buff;
}

/*------------------------------------------------------------------------------
 * Do a getpwnam_r() using the given buffer if at all possible.
 *
 * If given buffer is not big enough, malloc() a buffer until get one which
 * is big enough.
 *
 * Returns: 0 => OK, setting p_pwd to the struct passwd
 *                   if that is not the same as the incoming buf, then must
 *                   XFREE(MTYPE_TMP, pwd) when finished.
 *       != 0 => failed, and this is the errno
 *                   no memory to tidy up if failed
 *
 * Note: can pass size == 0 (and buf == NULL) to force malloc()
 */
extern int
safe_getpwnam(const char* name, struct passwd** p_pwd, void* buf, ulen size)
{
  void* tmp ;
  int err ;

  if (size < (sizeof(struct passwd) + 100))
    {
      size = sizeof(struct passwd) + 200 ;
      tmp  = XMALLOC(MTYPE_TMP, size) ;
    }
  else
    tmp = buf ;

  while (1)
    {
      char*   b ;
      size_t  bl ;

      b   = (char*)tmp + sizeof(struct passwd) ;
      bl  =       size - sizeof(struct passwd) ;

      err = getpwnam_r(name, tmp, b, bl, p_pwd) ;
      if (err == EINTR)
        continue ;

      if (err != ERANGE)
        break ;

      size *= 2 ;
      if (tmp == buf)
        tmp = XMALLOC(MTYPE_TMP, size) ;
      else
        tmp = XREALLOC(MTYPE_TMP, tmp, size) ;
    } ;

  if (err != 0)
    {
      if (tmp != buf)
        XFREE(MTYPE_TMP, tmp) ;

      *p_pwd = buf ;
    } ;

  return err ;
} ;

/*------------------------------------------------------------------------------
 * Do a getpwuid_r() using the given buffer if at all possible.
 *
 * If given buffer is not big enough, malloc() a buffer until get one which
 * is big enough.
 *
 * Returns: 0 => OK, setting p_pwd to the struct passwd
 *                   if that is not the same as the incoming buf, then must
 *                   XFREE(MTYPE_TMP, pwd) when finished.
 *       != 0 => failed, and this is the errno
 *                   no memory to tidy up if failed
 *
 * Note: can pass size == 0 (and buf == NULL) to force malloc()
 */
extern int
safe_getpwuid(uid_t id, struct passwd** p_pwd, void* buf, ulen size)
{
  void* tmp ;
  int err ;

  if (size < (sizeof(struct passwd) + 100))
    {
      size = sizeof(struct passwd) + 200 ;
      tmp  = XMALLOC(MTYPE_TMP, size) ;
    }
  else
    tmp = buf ;

  while (1)
    {
      char*   b ;
      size_t  bl ;

      b   = (char*)tmp + sizeof(struct passwd) ;
      bl  =       size - sizeof(struct passwd) ;

      err = getpwuid_r(id, tmp, b, bl, p_pwd) ;
      if (err == EINTR)
        continue ;

      if (err != ERANGE)
        break ;

      size *= 2 ;
      if (tmp == buf)
        tmp = XMALLOC(MTYPE_TMP, size) ;
      else
        tmp = XREALLOC(MTYPE_TMP, tmp, size) ;
    } ;

  if (err != 0)
    {
      if (tmp != buf)
        XFREE(MTYPE_TMP, tmp) ;

      *p_pwd = buf ;
    } ;

  return err ;
} ;

/*------------------------------------------------------------------------------
 * crypt() wrapper -- create a qstring with results of crypt()
 *
 * If the given salt is NULL, creates new, random salt.
 *
 * Returns:  new qstring -- caller is responsible for freeing same.
 */
extern qstring
qcrypt(const char* text, const char* salt)
{
  uint32_t r ;
  char     new_salt[3];

  qstring     cypher ;

  static const unsigned char itoa64[] =
      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  extern char *crypt (const char *, const char *) ;

  if (salt == NULL)
    {
      r = qt_random((uintptr_t)text) ;

      new_salt[0] = itoa64[(r >> (32 -  5)) & 0x3F] ;   /* ms 5         */
      new_salt[1] = itoa64[(r >> (32 - 10)) & 0x3F] ;   /* next ms 5    */
      new_salt[2] = '\0';

      salt = new_salt ;
    } ;

  /* Can only may this thread-safe by locking.
   *
   * Minimises the chance of having to allocate memory while holding the lock.
   */
  cypher = qs_new(strlen(text) * 2) ;

  THREAD_SAFE_LOCK() ;

  qs_set_str(cypher, crypt(text, salt)) ;

  THREAD_SAFE_UNLOCK() ;

  return cypher ;
} ;

/*------------------------------------------------------------------------------
 * Local wrapper for strerror_r().
 *
 * Two variants of strerror_r are known:
 *
 *   (a) "GNU", which returns a char*
 *
 *   (b) POSIX, which returns an int.
 *
 * GNU does not say whether it returns an error if the errno is not known or if
 * the buffer is too small (though for buffer too small, suggests that silent
 * truncation is the order of the day).  We treat it like strerror().
 *
 * POSIX is not explicit about what happens if the buffer is not big enough to
 * accommodate the message, except that an ERANGE error may be raised.
 *
 * By experiment: glibc-2.10.2-1.x86_64 returns -1, with errno set to ERANGE
 * and no string at all if the buffer is too small.
 *
 * This function encapsulates the variants.
 *
 * Returns:  string if one was returned, and was not empty.
 *           NULL otherwise
 *
 *           In all cases: errno == 0 <=> OK
 *                         errno != 0 <=> some sort of error
 *
 *              EINVAL => unknown error, or NULL or empty string returned
 *              ERANGE => buffer too small !
 *
 * NB: sets errno to EINVAL if no other error is set, and the result is either
 *     NULL or '\0'.
 *
 * NB: POSIX recommends if the errno is not known, that errno be set to EINVAL
 *     *and* a message is returned saying "unknown", or something more helpful.
 *
 *     Caller can accept what was provided (if anything) or act on EINVAL and
 *     make up their own error message.
 */
static const char*
qstrerror_r(int err, char *buf, size_t n)
{
  const char* errm ;

  buf[0] = '\0' ;               /* in case nothing returned     */
  errno = 0 ;                   /* make sure                    */

#if STRERROR_R_CHAR_P
  errm = strerror_r(err, buf, n) ;
#else
  if (strerror_r(err, buf, n) >= 0)
    errno = 0 ;                 /* Should be, in any case !     */
  errm = buf ;
#endif

  if ((errno == 0) && ((errm == NULL) || (*errm == '\0')))
    {
      errno = EINVAL ;
      errm  = NULL ;
    } ;

  return errm ;
} ;

/*------------------------------------------------------------------------------
 * Local wrapper for strerror().
 *
 * The difficulty is that strerror() is underspecified, and may or may not
 * return something or may return an error if the errno is not known.
 *
 * Returns:  string if one was returned, and was not empty.
 *           NULL otherwise
 *
 *           In all cases: errno == 0 <=> OK
 *                         errno != 0 <=> some sort of error
 *
 *              EINVAL => unknown error, or NULL or empty string returned
 *              ERANGE => buffer too small !
 *
 * NB: sets errno to EINVAL if no other error is set, and the result is either
 *     NULL or '\0'.
 *
 * NB: POSIX recommends if the errno is not known, that errno be set to EINVAL
 *     *and* a message is returned saying "unknown", or something more helpful.
 *
 *     Caller can accept what was provided (if anything) or act on EINVAL and
 *     make up their own error message.
 */
static const char*
qstrerror(int err)
{
  const char* errm ;

  errno = 0 ;
  errm  = strerror(err) ;

  if ((errno == 0) && ((errm == NULL) || (*errm == '\0')))
    {
      errno = EINVAL ;
      errm  = NULL ;
    } ;

  return errm ;
} ;

/*------------------------------------------------------------------------------
 * A thread-safe version of getservbyname().
 *
 * Returns:  NULL  => getservbyname() returned NULL
 *           copy of what getservbyname() returned  -- MUST be XFREE'd.
 *
 * NB: what is returned is fully thread-safe -- it is an XMALLOC'd piece
 *     of memory containing a copy of what getservbyname() returns, and a
 *     copy of all the strings it returns.
 *
 *     The object returned appears to be a pointer to a 'struct servent', but
 *     is in fact a pointer to a larger piece of memory, which includes all the
 *     things pointed to by the 'struct servent' fields.
 *
 * NB: caller is responsible for XFREE(MTYPE_TMP, ....) when it is done
 *     with the returned value.
 */
static inline char*
servent_strcpy(char** p_dst, char* src, char* str, char* end)
{
  if (src == NULL)
    qassert(*p_dst == NULL) ;
  else
    {
      uint len ;

      len = strlen(src) ;
      assert((str + len + 1) <= end) ;

      strcpy(str, src) ;

      *p_dst = str ;
      str += len + 1 ;
    } ;

  return str ;
} ;

extern struct servent*
safe_getservbyname(const char* name, const char* proto)
{
  struct safe_sp
  {
    struct servent se ;
    void* body[] ;
  } ;

  struct servent* sp ;

  THREAD_SAFE_LOCK() ;          /* <-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<- */

  sp = getservbyname(name, proto) ;

  if (sp != NULL)
    {
      struct safe_sp* s ;
      struct servent* ssp ;

      /* To make this thread-safe we now need to copy a bunch of strings
       * from the given sp -- including an array of same.
       */
      uint   str_len, alias_count, size, i ;
      char*  str, * end ;

      enum { svp = sizeof(void*) } ;

      str_len = 0 ;

      if ((str = sp->s_name) != NULL)
        str_len += strlen(str) + 1 ;

      alias_count = 0 ;
      if (sp->s_aliases != NULL)
        {
          while ((str = sp->s_aliases[alias_count]) != NULL)
            {
              str_len += strlen(str) + 1 ;
              ++alias_count ;
            } ;
        } ;

      if ((str = sp->s_proto) != NULL)
        str_len += strlen(str) + 1 ;

      size = offsetof(struct safe_sp, body) + ((alias_count + 1) * svp)
                                            + str_len ;
      size = ((size + svp - 1) / svp) * svp ;
      s    = XCALLOC(MTYPE_TMP, size) ;
      ssp  = &s->se ;

      str  = (char*)(s->body[alias_count + 1]) ;
      end  = str + str_len ;

      assert(end <= ((char*)s + size)) ;

      str = servent_strcpy(&ssp->s_name, sp->s_name, str, end) ;

      ssp->s_aliases = (char**)s->body ;
      for (i = 0 ; i < alias_count ; ++i)
        str = servent_strcpy(&ssp->s_aliases[i], sp->s_aliases[i], str, end) ;

      qassert(ssp->s_aliases[alias_count] == NULL) ;

      ssp->s_port = sp->s_port ;

      str = servent_strcpy(&ssp->s_proto, sp->s_proto, str, end) ;

      sp = ssp ;
    } ;

  THREAD_SAFE_UNLOCK() ;        /* <-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<- */

  return sp ;
} ;

