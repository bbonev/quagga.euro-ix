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

#ifndef PTHREAD_SAFE_H_
#define PTHREAD_SAFE_H_

#include <netinet/in.h>
#include <pwd.h>
#include <netdb.h>

#include "qstring.h"
#include "qfstring.h"

QFB_T(150) strerror_t ;
QFB_T(50)  str_iptoa_t ;

extern void safe_init_r(void);
extern void safe_finish(void);

extern strerror_t errtoa(int err, ulen len) ;
extern strerror_t errtoname(int err, ulen len) ;
extern strerror_t errtostr(int err, ulen len) ;

extern strerror_t eaitoa(int eai, int err, ulen len) ;
extern strerror_t eaitoname(int eai, int err, ulen len) ;
extern strerror_t eaitostr(int eai, int err, ulen len) ;

extern int getenv_r(const char* name, char* buf, int buf_len) ;
extern const char * safe_strerror(int errnum);
extern const char * safe_inet_ntoa (struct in_addr in);

extern str_iptoa_t siptoa(sa_family_t family, const void* address) ;
extern str_iptoa_t sipv4toa(in_addr_t addr) ;

extern int safe_getpwnam(const char* name, struct passwd** p_pwd, void* buf,
                                                                     ulen size);
extern int safe_getpwuid(uid_t id, struct passwd** p_pwd, void* buf, ulen size);

extern qstring qcrypt(const char* text, const char* salt) ;

extern uint16_t safe_get_port(const char* port_str, const char* proto) ;
extern struct servent* safe_getservbyname(const char* name, const char* proto) ;

#endif /* PTHREAD_SAFE_H_ */
