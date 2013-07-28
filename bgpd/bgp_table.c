/* BGP routing table
   Copyright (C) 1998, 2001 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "prefix.h"
#include "memory.h"
#include "sockunion.h"
#include "vty.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_table.h"

static void bgp_node_delete (struct bgp_node *);
static void bgp_table_free (struct bgp_table *);

/*------------------------------------------------------------------------------
 *
 */
extern bgp_table
bgp_table_init (qafx_t qafx)
{
  bgp_table table;

  table = XCALLOC (MTYPE_BGP_TABLE, sizeof (bgp_table_t));

  bgp_table_lock(table);

  table->type = BGP_TABLE_MAIN;
  table->qafx = qafx ;

  return table;
}

/*------------------------------------------------------------------------------
 *
 */
void
bgp_table_lock (bgp_table table)
{
  table->lock++;
}

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_table_unlock (bgp_table table)
{
  assert (table->lock > 0);
  table->lock--;

  if (table->lock == 0)
    bgp_table_free (table);
}

/*------------------------------------------------------------------------------
 *
 */
extern bgp_table
bgp_table_finish (bgp_table table)
{
  if (table != NULL)
    bgp_table_unlock(table);

  return NULL ;
}

/*------------------------------------------------------------------------------
 *
 */
static struct bgp_node *
bgp_node_create (bgp_table table)
{
  bgp_node  node;

  node = XCALLOC (MTYPE_BGP_NODE, sizeof (bgp_node_t));

  node->table = table;
  node->qafx  = table->qafx ;

  return node ;
}

/*------------------------------------------------------------------------------
 * Allocate new route node with prefix set.
 */
static struct bgp_node *
bgp_node_set (struct bgp_table *table, prefix_c prefix)
{
  bgp_node  node;

  node = bgp_node_create (table);

  prefix_copy (&node->p, prefix);

  return node;
}

/*------------------------------------------------------------------------------
 * Free route node.
 */
static void
bgp_node_free (struct bgp_node *node)
{
  node->lock = -54321 ;
  XFREE (MTYPE_BGP_NODE, node);
}

/*------------------------------------------------------------------------------
 * Free route table.
 */
static void
bgp_table_free (struct bgp_table *rt)
{
  struct bgp_node *tmp_node;
  struct bgp_node *node;

  if (rt == NULL)
    return;

  node = rt->top;

  /* Bulk deletion of nodes remaining in this table.  This function is not
     called until workers have completed their dependency on this table.
     A final bgp_unlock_node() will not be called for these nodes. */
  while (node)
    {
      if (node->l_left)
        {
          node = node->l_left;
          continue;
        }

      if (node->l_right)
        {
          node = node->l_right;
          continue;
        }

      assert(  (node->info     == NULL)
            && (node->adj_out  == NULL)
            && (node->adj_in   == NULL)
            && (node->on_wq    == 0) ) ;

      tmp_node = node;
      node = node->parent;

      tmp_node->table->count--;
      tmp_node->lock = 0;  /* to cause assert if unlocked after this */

      bgp_node_free (tmp_node);

      if (node != NULL)
        {
          if (node->l_left == tmp_node)
            node->l_left = NULL;
          else
            node->l_right = NULL;
        }
      else
        {
          break;
        }
    }

  assert (rt->count == 0);

  if (rt->owner)
    {
      bgp_peer_unlock (rt->owner);
      rt->owner = NULL;
    }

  rt->lock = -54321 ;
  XFREE (MTYPE_BGP_TABLE, rt);
  return;
}

/* Utility mask array. */
static const u_char maskbit[] =
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/*------------------------------------------------------------------------------
 * Common prefix route generation.
 */
static void
route_common (prefix new, prefix_c n, prefix_c p)
{
  uint i;
  byte diff;
  byte mask;

  const byte* np = (const byte*)&n->u.prefix;
  const byte* pp = (const byte*)&p->u.prefix;
  byte*     newp =       (byte*)&new->u.prefix;

  for (i = 0; i < p->prefixlen / 8; i++)
    {
      if (np[i] == pp[i])
        newp[i] = np[i];
      else
        break;
    }

  new->prefixlen = i * 8;

  if (new->prefixlen != p->prefixlen)
    {
      diff = np[i] ^ pp[i];
      mask = 0x80;
      while (new->prefixlen < p->prefixlen && !(mask & diff))
        {
          mask >>= 1;
          new->prefixlen++;
        }
      newp[i] = np[i] & maskbit[new->prefixlen % 8];
    }
}

/*------------------------------------------------------------------------------
 *
 */
static void
set_link (struct bgp_node *node, struct bgp_node *new)
{
  unsigned int bit = prefix_bit (&new->p.u.prefix, node->p.prefixlen);

  node->link[bit] = new;
  new->parent = node;
}

/*------------------------------------------------------------------------------
 * Lock node.
 */
struct bgp_node *
bgp_lock_node (struct bgp_node *node)
{
  node->lock++;
  return node;
}

/*------------------------------------------------------------------------------
 * Unlock node.
 */
void
bgp_unlock_node (struct bgp_node *node)
{
  assert (node->lock > 0);
  node->lock--;

  if (node->lock == 0)
    bgp_node_delete (node);
}

/*------------------------------------------------------------------------------
 * Find matched prefix -- finds longest prefix match
 */
struct bgp_node *
bgp_node_match (const struct bgp_table *table, prefix_c p)
{
  struct bgp_node *node;
  struct bgp_node *matched;

  matched = NULL;
  node = table->top;

  /* Walk down tree.  If there is matched route then store it to matched.
   */
  while ((node != NULL) && (node->p.prefixlen <= p->prefixlen)
                        && prefix_match (&node->p, p))
    {
      if (node->info)
        matched = node;
      node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
    }

  /* If matched route found, return it. */
  if (matched)
    return bgp_lock_node (matched);

  return NULL;
}

/*------------------------------------------------------------------------------
 */
struct bgp_node *
bgp_node_match_ipv4 (const struct bgp_table *table, struct in_addr *addr)
{
  struct prefix_ipv4 p;

  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *addr;

  return bgp_node_match (table, (struct prefix *) &p);
}

#ifdef HAVE_IPV6
/*------------------------------------------------------------------------------
 *
 */
struct bgp_node *
bgp_node_match_ipv6 (const struct bgp_table *table, struct in6_addr *addr)
{
  struct prefix_ipv6 p;

  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  p.prefix = *addr;

  return bgp_node_match (table, (struct prefix *) &p);
}
#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * Look up prefix in the given table (if any) -- return NULL if not found.
 *
 * If returns bgp_node, that node has just been locked.
 *
 * Returns:  newly locked node (with node->info != NULL)
 *       or: NULL did not find node (or node->info was NULL)
 *
 * NB: does not find nodes with NULL node->info.
 */
extern bgp_node
bgp_node_lookup (bgp_table table, prefix_c p)
{
  bgp_node node;

  if (table == NULL)
    return NULL ;

  node = table->top;

  while ((node != NULL) && (node->p.prefixlen <= p->prefixlen)
                        && prefix_match (&node->p, p))
    {
      if (node->p.prefixlen == p->prefixlen)
        {
          if (node->info != NULL)
            return bgp_lock_node (node);
          else
            return NULL ;
        } ;

      node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
    }

  return NULL;
}

/*------------------------------------------------------------------------------
 * Look up prefix in the given table -- add bgp_node if not found.
 *
 * If returns bgp_node, that node has just been locked.
 *
 * Returns:  newly locked node -- which may be a new node.
 */
extern bgp_node
bgp_node_get (bgp_table table, prefix_c p)
{
  bgp_node  new, node, match;

  qassert(table != NULL) ;

  match = NULL;
  node = table->top;
  while ((node != NULL) && (node->p.prefixlen <= p->prefixlen)
                        && prefix_match (&node->p, p))
    {
      if (node->p.prefixlen == p->prefixlen)
        {
          bgp_lock_node (node);
          return node;
        } ;

      match = node;
      node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
    } ;

  if (node == NULL)
    {
      new = bgp_node_set (table, p);
      if (match)
        set_link (match, new);
      else
        table->top = new;
    }
  else
    {
      new = bgp_node_create (table) ;

      route_common (&new->p, &node->p, p);
      new->p.family = p->family;
      set_link (new, node);

      if (match)
        set_link (match, new);
      else
        table->top = new;

      if (new->p.prefixlen != p->prefixlen)
        {
          match = new;
          new = bgp_node_set (table, p);
          set_link (match, new);
          table->count++;
        }
    }
  table->count++;
  bgp_lock_node (new);

  return new;
}

/*------------------------------------------------------------------------------
 * Look up parent of the given prefix in the given table.
 *
 * To count as a parent a node must have non-NULL node->info.
 *
 * If returns bgp_node, that node has just been locked.
 *
 * Returns:  newly locked node
 *       or: NULL did not find parent
 */
extern bgp_node
bgp_node_lookup_parent (bgp_table table, prefix_c p)
{
  bgp_node node, parent ;

  node   = table->top;
  parent = NULL ;
  while ((node != NULL) && (node->p.prefixlen <= p->prefixlen)
                        && prefix_match (&node->p, p))
    {
      if (node->p.prefixlen == p->prefixlen)
        break ;

      parent = node ;
      node   = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
    }

  while (parent != NULL)
    {
      if (parent->info != NULL)
        return bgp_lock_node (parent);

      parent = parent->parent ;         /* back up to significant parent  */
    }

  return NULL ;
} ;

/* Delete node from the routing table. */
static void
bgp_node_delete (struct bgp_node *node)
{
  struct bgp_node *child;
  struct bgp_node *parent;

  assert (node->lock == 0);
  assert (node->info == NULL);
  assert (node->on_wq == 0) ;

  if (node->l_left && node->l_right)
    return;

  if (node->l_left)
    child = node->l_left;
  else
    child = node->l_right;

  parent = node->parent;

  if (child)
    child->parent = parent;

  if (parent)
    {
      if (parent->l_left == node)
        parent->l_left = child;
      else
        parent->l_right = child;
    }
  else
    node->table->top = child;

  node->table->count--;

  bgp_node_free (node);

  /* If parent node is stub then delete it also. */
  if (parent && parent->lock == 0)
    bgp_node_delete (parent);
}

/*------------------------------------------------------------------------------
 * Get first node (if any) in given table (if any) and lock it.
 */
struct bgp_node *
bgp_table_top (const struct bgp_table *const table)
{
  /* If there is no table or no node in the table return NULL.
   */
  if ((table == NULL) || (table->top == NULL))
    return NULL;

  /* Lock the top node and return it. */
  bgp_lock_node (table->top);
  return table->top;
}

/*------------------------------------------------------------------------------
 * Unlock current node and lock next node then return it.
 */
struct bgp_node *
bgp_route_next (struct bgp_node *node)
{
  struct bgp_node *next;
  struct bgp_node *start;

  /* Node may be deleted from bgp_unlock_node so we have to preserve
     next node's pointer. */

  if (node->l_left)
    {
      next = node->l_left;
      bgp_lock_node (next);
      bgp_unlock_node (node);
      return next;                      /* go left              */
    } ;

  if (node->l_right)
    {
      next = node->l_right;
      bgp_lock_node (next);
      bgp_unlock_node (node);
      return next;                      /* go right             */
    } ;

  /* Go up and right
   */
  start = node;
  while (node->parent != NULL)
    {
      /* If we are moving up from the left child, and there is a right
       * child, go to that right sibling.
       */
      if ((node->parent->l_left == node) && (node->parent->l_right))
        {
          next = node->parent->l_right;
          bgp_lock_node (next);
          bgp_unlock_node (start);
          return next;
        } ;

      node = node->parent;
    } ;

  bgp_unlock_node (start);
  return NULL;
}

/*------------------------------------------------------------------------------
 * Unlock current node and lock next node until limit.
 */
struct bgp_node *
bgp_route_next_until (struct bgp_node *node, struct bgp_node *limit)
{
  struct bgp_node *next;
  struct bgp_node *start;

  /* Node may be deleted from bgp_unlock_node so we have to preserve
   * next node's pointer.
   */
  if (node->l_left)
    {
      next = node->l_left;
      bgp_lock_node (next);
      bgp_unlock_node (node);
      return next;              /* go left              */
    }

  if (node->l_right)
    {
      next = node->l_right;
      bgp_lock_node (next);
      bgp_unlock_node (node);
      return next;              /* go right             */
    }

  /* Go up and right -- stopping if we are on or move up to the given limit.
   */
  start = node;
  while ((node->parent != NULL) && (node != limit))
    {
      if (node->parent->l_left == node && node->parent->l_right)
        {
          next = node->parent->l_right;
          bgp_lock_node (next);
          bgp_unlock_node (start);
          return next;
        }
      node = node->parent;
    } ;

  bgp_unlock_node (start);
  return NULL;
}

unsigned long
bgp_table_count (const struct bgp_table *table)
{
  return table->count;
}
