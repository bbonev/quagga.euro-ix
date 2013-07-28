/* Keyword in Tables
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
#include <string.h>

#include "keyword.h"

/*==============================================================================
 *
 *
 */

/*------------------------------------------------------------------------------
 *
 */
typedef struct keyword_index keyword_index_t ;

struct keyword_index
{
  ushort  prefix ;
  ushort  index ;
} ;


/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Lookup keyword
 */
extern keyword
keyword_lookup(keyword_table table, const char* str, ulen len, uint* result)
{
//keyword_index_t*  index ;
  uint il, ih ;

  ushort prefix ;

//  if (table->state != kwts_compiled)
//    keyword_table_compile(table) ;

  if ((table->index.len <= 1) || (len == 0))
    {
      *result = 0 ;
      return NULL ;             /* Nothing, nothing at all      */
    } ;

  /* So now we can go ahead and do the lookup !
   */
  prefix = (unsigned)str[0] << 8 ;
  if (len > 1)
    prefix += (unsigned)str[1] ;

  il = 0 ;
  ih = table->index.len - 1 ;

  while (1)
    {
      uint  iv ;
      int   c ;

      qassert(il < ih) ;

      iv = (il + ih) / 2 ;

      if (iv == il)     /* true if (ih == il+1)                 */
        {
          *result = 0 ;
          return NULL ;         /* Not found anything           */
        } ;

      qassert((il < iv) && (iv < ih)) ;

//    c = cmp(val, qlump_item(ql, iv, qt)) ;
      c = 0 ;
      if (c == 0)
        {
          *result = 0 ;
//        return iv ;   /* found !!                             */
        } ;

      if (c <  0)
        ih = iv ;       /* step down    iv > il, so new ih > il */
      else
        il = iv ;       /* step up      iv < ih, so new il < ih */
    } ;



  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Scan given '\0' terminated sting, looking for end of potential keyword.
 */
extern ulen
keyword_scan(const char* str, keyword_term_type_t term)
{
  static const char* ws       =     "\x01\x02\x03\x04\x05\x06\x07"
                                "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                                "\x10\x11\x12\x13\x14\x15\x16\x17"
                                "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
                                "\x20" ;

  static const char* punct    =     "\x01\x02\x03\x04\x05\x06\x07"
                                "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                                "\x10\x11\x12\x13\x14\x15\x16\x17"
                                "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
                                "\x20\x21\x22\x23\x24\x25\x26\x27"
                                "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
                                        "\x3A\x3B\x3C\x3D\x3E\x3F"
                                "\x40"
                                            "\x5B\x5C\x5D\x5E"
                                "\x60"
                                            "\x7B\x7C\x7D\x7E\x7F" ;

  confirm(('0' == 0x30) && ('9' == 0x39)) ;
  confirm(('A' == 0x41) && ('Z' == 0x5A)) ;
  confirm(('a' == 0x61) && ('z' == 0x7A)) ;
  confirm('_' == 0x5F) ;

  static const char* punct_nh =     "\x01\x02\x03\x04\x05\x06\x07"
                                "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                                "\x10\x11\x12\x13\x14\x15\x16\x17"
                                "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
                                "\x20\x21\x22\x23\x24\x25\x26\x27"
                                "\x28\x29\x2A\x2B\x2C"  "\x2E\x2F"
                                        "\x3A\x3B\x3C\x3D\x3E\x3F"
                                "\x40"
                                            "\x5B\x5C\x5D\x5E"
                                "\x60"
                                            "\x7B\x7C\x7D\x7E\x7F" ;
  confirm('-' == 0x2D) ;

  switch (term)
    {
      case kwtt_ws:
        return strcspn(str, ws) ;

      case kwtt_punct:
        return strcspn(str, punct) ;

      case kwtt_punct_nh:
        return strcspn(str, punct_nh) ;

      default:
        return 0 ;
    } ;
} ;

/*==============================================================================
 * Create and free
 */

