/* iovec -- utility header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_IOVEC_H
#define _ZEBRA_IOVEC_H

#include "misc.h"
#include <sys/uio.h>            /* iovec stuff                  */
#include <limits.h>             /* want IOV_MAX, if present     */
#include "qlib_init.h"          /* want qlib_iov_max            */

/*==============================================================================
 * The main thing here is to drag in sys/uio.h, and to define IOV_MIN_MAX.
 *
 * So... POSIX says that IOV_MAX:
 *
 *   "shall be omitted from <limits.h> on specific implementations where
 *    the corresponding value is equal to or greater than the stated minimum,
 *    but is unspecified."
 *
 * this is to allow for some limits to vary from place to place, provided
 * at least the absolute minimum is guaranteed to be provided.
 *
 * POSIX requires: _XOPEN_IOV_MAX to be defined (16).
 *
 * Historically, we might have found UIO_MAXIOV -- in sys/uio.h
 *
 * We here construct IOV_MIN_MAX -- which is the minimum number believed
 * guaranteed.
 *
 * For other purposes there is qlib_iov_max.
 */
enum
{
  IOV_MIN_MAX
#if   defined(IOV_MAX)
            = IOV_MAX
#elif defined(_XOPEN_IOV_MAX)
            = _XOPEN_IOV_MAX
#elif defined(UIO_MAXIOV)
            = UIO_MAXIOV
#else
            = ???               /* want a value for IOV_MAX !!! */
#endif
} ;

/* Equivalent structure.
 *
 * Note: the base pointer is defined as 'const' -- this can make life a little
 *       easier for some write operations, and makes no difference otherwise,
 */
typedef struct iovec_x* iovec ;
typedef struct iovec_x  iovec_t ;

struct iovec_x
{
  const void* base ;
  size_t      len ;
} ;

CONFIRM(offsetof(iovec_t, base) == offsetof(struct iovec, iov_base)) ;
CONFIRM(offsetof(iovec_t, len)  == offsetof(struct iovec, iov_len)) ;
CONFIRM(sizeof  (iovec_t)       == sizeof  (struct iovec)) ;

#endif /* _ZEBRA_IOVEC_H */
