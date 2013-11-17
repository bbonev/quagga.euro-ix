/* Hash routine.
   Copyright (C) 1998 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; either version 2, or (at your
option) any later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef _ZEBRA_HASH_H
#define _ZEBRA_HASH_H

#include "miyagi.h"

/* Default hash table size.  */
#define HASHTABSIZE  1024

struct hash_backet
{
  /* Linked list.       */
  struct hash_backet *next;

  /* Hash key.          */
  unsigned int key;

  /* Data.              */
  void *item;
};

/* The methods for the hash:
 *
 *   * hash_key_func     -- takes the given "data" and returns a hash
 *                          value for it.
 *
 *   * hash_equal_func    -- takes an "item" and "data" and returns
 *                             true <=> equal
 *
 *   * hash_alloc_func   -- takes the given "data" and returns an "item"
 *                          containing that data.
 *
 * Note that in some cases, the "data" takes the form of an "item", and
 * in other cases the "data" is part of the "item" -- it is up to the
 * methods to deal with that.
 */
typedef unsigned int hash_key_func(const void* data) ;
typedef bool  hash_equal_func(const void* item, const void* data) ;
typedef void* hash_alloc_func(const void* data) ;
typedef void hash_free_func(void* item) ;

struct hash
{
  /* Hash backets.                      */
  struct hash_backet **index;

  /* Hash table size and item count     */
  unsigned int size;
  unsigned int count;

  /* Key make function.                 */
  hash_key_func* hash_key ;

  /* Data compare function.             */
  hash_equal_func* hash_equal ;
};

extern struct hash *hash_create (hash_key_func* hash_key,
                                 hash_equal_func* hash_equal);
extern struct hash *hash_create_size (unsigned int,
                                        hash_key_func* hash_key,
                                        hash_equal_func* hash_equal) ;

extern void *hash_get (struct hash *hash, const void* data,
                                                  hash_alloc_func* alloc_func) ;
extern void *hash_alloc_intern (const void* data);
extern void *hash_lookup (struct hash* hash, const void* data);
extern void *hash_release (struct hash* hash, const void* data);

extern void hash_iterate (struct hash *,
                   void (*) (struct hash_backet *, void *), void *);

extern void hash_clean (struct hash* hash, hash_free_func* free_func);
extern void hash_reset (struct hash *);
extern struct hash* hash_free (struct hash *);

extern void hash_finish(void) ;

extern unsigned int string_hash_make (const char *);

#endif /* _ZEBRA_HASH_H */
