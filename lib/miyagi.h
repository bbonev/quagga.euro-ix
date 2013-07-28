/* Kludge to discard "const" from pointer
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
 *.
 * This file is part of GNU Zebra.
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

#ifndef _ZEBRA_MIYAGI_H
#define _ZEBRA_MIYAGI_H

#include "misc.h"

/*==============================================================================
 * Ghastly kludge to discard "const" from pointer
 */
Inline void* miyagi(const void* ptr) Always_Inline ;

Inline void*
miyagi(const void* ptr)
{
  return (void*)((uintptr_t)ptr) ;

#if 0
  union {
    const void* waxon ;
          void* waxoff ;
  } shammy ;

  shammy.waxon = ptr ;

  return shammy.waxoff ;
#endif
} ;

#endif /* _ZEBRA_MIYAGI_H */
