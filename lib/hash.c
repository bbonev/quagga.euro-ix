/* Hash routine.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include <zebra.h>

#include "hash.h"
#include "memory.h"
#include "miyagi.h"

static struct hash_backet* hash_backet_malloc(void) ;
static void hash_backet_free(struct hash_backet* hb) ;

/* Allocate a new hash.  */
struct hash *
hash_create_size (unsigned int size,
                           hash_key_func* hash_key, hash_equal_func* hash_equal)
{
  struct hash *hash;

  size |= 1 ;           /* make sure is ODD !   */

  hash = XCALLOC (MTYPE_HASH, sizeof (struct hash));

  hash->index    = XCALLOC (MTYPE_HASH_INDEX,
                                        sizeof (struct hash_backet *) * size);
  hash->size       = size;
  hash->hash_key   = hash_key;
  hash->hash_equal = hash_equal;
  hash->count      = 0;

  return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *
hash_create (hash_key_func* hash_key, hash_equal_func* hash_equal)
{
  return hash_create_size (HASHTABSIZE, hash_key, hash_equal);
}

/*------------------------------------------------------------------------------
 * Utility function for hash_get().  When this function is specified
 * as alloc_func, return argument as it is.  This function is used for
 * intern already allocated value.
 */
void *
hash_alloc_intern (const void* data)
{
  return miyagi(data) ;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void *
hash_get (struct hash *hash, const void *data, hash_alloc_func* alloc_func)
{
  unsigned int key;
  unsigned int index ;
  void *new_item;
  struct hash_backet *backet;

  key   = (*hash->hash_key)(data);
  index = key % hash->size ;

  for (backet = hash->index[index]; backet != NULL;
                                               backet = backet->next)
    if ((backet->key == key) && (*hash->hash_equal)(backet->item, data))
      return backet->item;

  if (alloc_func)
    {
      new_item = (*alloc_func) (data);
      if (new_item == NULL)
        return NULL;

      backet = hash_backet_malloc() ;
      backet->item = new_item;
      backet->key  = key;

      backet->next = hash->index[index];
      hash->index[index] = backet;

      hash->count++;
      return backet->item;
    }
  return NULL;
}

/* Hash lookup.  */
void *
hash_lookup (struct hash *hash, const void *data)
{
  return hash_get (hash, data, NULL);
}

/* Simple Bernstein hash which is simple and fast for common case */
unsigned int string_hash_make (const char *str)
{
  unsigned int hash = 0;

  while (*str)
    hash = (hash * 33) ^ (unsigned int) *str++;

  return hash;
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *
hash_release (struct hash *hash, const void *data)
{
  void *item;
  unsigned int key;
  struct hash_backet *backet;
  struct hash_backet** pp;

  key = (*hash->hash_key) (data);

  pp = &hash->index[key % hash->size] ;
  while (1)
    {
      backet = *pp ;

      if (backet == NULL)
        return NULL ;

      if (backet->key == key)
        {
          item = backet->item ;
          if ((*hash->hash_equal)(item, data))
            break ;
        } ;

      pp = &backet->next ;
    } ;

  *pp = backet->next;
  hash->count--;
  hash_backet_free(backet) ;

  return item ;
}

/* Iterator function for hash.  */
void
hash_iterate (struct hash *hash,
              void (*func) (struct hash_backet *, void *), void *arg)
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *hbnext;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hbnext)
      {
        /* get pointer to next hash backet here, in case (*func)
         * decides to delete hb by calling hash_release
         */
        hbnext = hb->next;
        (*func) (hb, arg);
      }
}

/* Clean up hash.       */
void
hash_clean (struct hash *hash, hash_free_func* free_func)
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *next;

  for (i = 0; i < hash->size; i++)
    {
      for (hb = hash->index[i]; hb; hb = next)
        {
          next = hb->next;

          if (free_func != NULL)
            (*free_func) (hb->item);

          hash_backet_free(hb) ;
          hash->count--;
        }
      hash->index[i] = NULL;
    }
}

/* Reset hash.          */
void
hash_reset (struct hash *hash)
{
  memset(hash->index, 0, (hash->size * sizeof(struct hash_backet*))) ;
  hash->count = 0 ;
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
extern struct hash*
hash_free (struct hash *hash)
{
  XFREE (MTYPE_HASH_INDEX, hash->index);
  XFREE (MTYPE_HASH, hash);
  return NULL ;
}

/*==============================================================================
 * Pool of "hash backets".
 *
 * Note that each pool is zeroized when it is created, so any padding inside
 * each hash_backet is zeroized.  But when a backet is "malloc'd" it is not
 * zeroized, but all fields are immediately filled in.
 */
enum { hash_backet_pool_size = 1024 } ;

struct hash_backet_pool
{
  struct hash_backet_pool* next ;

  struct hash_backet backets[hash_backet_pool_size] ;
};

static struct hash_backet_pool* hb_pools     = NULL ;
static struct hash_backet*      hb_free      = NULL ;

static struct hash_backet*
hash_backet_malloc(void)
{
  struct hash_backet* hb ;

  hb = hb_free ;

  if (hb == NULL)
    {
      struct hash_backet_pool* pool ;
      uint i ;

      pool = XCALLOC(MTYPE_HASH_BACKET, sizeof(struct hash_backet_pool)) ;

      pool->next = hb_pools ;
      hb_pools   = pool ;

      for (i = 0 ; i < hash_backet_pool_size ; ++i)
        {
          hb = &pool->backets[i] ;

          hb->next = hb_free ;
          hb_free  = hb ;
        } ;
    } ;

  hb_free = hb->next ;
  return hb ;
} ;

static void
hash_backet_free(struct hash_backet* hb)
{
  hb->next = hb_free ;
  hb_free  = hb ;
} ;

extern void
hash_finish(void)
{
  struct hash_backet_pool* pool ;

  hb_free = NULL ;

  while ((pool = hb_pools) != NULL)
    {
      hb_pools = pool->next ;

      XFREE(MTYPE_HASH_BACKET, pool) ;
    } ;
} ;

