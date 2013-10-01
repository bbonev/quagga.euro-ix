/* BGP Route-Context Handling
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

/*==============================================================================
 */
#include "misc.h"

#include "bgpd/bgp_rcontext.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"

#include "lib/vhash.h"
#include "lib/memory.h"
#include "lib/svector.h"
#include "lib/tstring.h"

/*==============================================================================
 * BGP Route Context Index
 *
 * The Route Context Index comprises:
 *
 *   * an global svec for looking up by rc-id and for managing same.
 *
 *   * a vhash_table in each bgp instance, for looking up rcontexts by "name".
 */
static svec4_t  bgp_rcontext_id_index[1] ;

CONFIRM(bgp_rc_id_null == (uint)SVEC_NULL) ;

/* The vhash table magic
 */
static vhash_new_func   bgp_rcontext_new ;
static vhash_free_func  bgp_rcontext_free ;
static vhash_equal_func bgp_rcontext_equal ;

static const vhash_params_t bgp_rcontext_vhash_params =
{
  .hash   = vhash_hash_string,
  .equal  = bgp_rcontext_equal,
  .new    = bgp_rcontext_new,
  .free   = bgp_rcontext_free,
  .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * Initialise the route-context indexes.
 *
 * This must be done before any route contexts are configured !
 */
extern void
bgp_rcontext_init(void)
{
  svec_init(bgp_rcontext_id_index) ;
} ;

/*------------------------------------------------------------------------------
 * Shut down the route-context indexes -- freeing all memory etc.
 *
 * For shutdown, *only*.  To be called after all peers have been finished off,
 * so that there should be no route-contexts left.
 *
 * NB: assumes is running in the one remaining thread at shutdown
 */
extern void
bgp_rcontext_finish(void)
{
  /* If there are no known rcontext_ids left, can free off the body of the
   * svec, if any.
   */
  if (svl_head(bgp_rcontext_id_index->base, bgp_rcontext_id_index) == NULL)
    svec_clear(bgp_rcontext_id_index) ;
} ;

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_rcontext_xxx(bgp_inst bgp)
{
  bgp->rc_name_index = vhash_table_reset(bgp->rc_name_index, free_it) ;
}

/*------------------------------------------------------------------------------
 * Lookup given route-context -- creating a new one if required.
 *
 * If finds or creates, increments the lock.
 *
 * If 'added' is NULL, will not create if is not already there.
 *
 * If 'added' is not NULL, will create if not already there, and sets whether
 * added or not.
 *
 * Returns:  route context if found or created, complete with an extra lock.
 *           NULL <=> not found
 */
extern bgp_rcontext
bgp_rcontext_lookup(bgp_inst bgp, const char* name, bgp_rcontext_type_t type,
                                                                    bool* added)
{
  bgp_rcontext rc ;
  tstring_t(rs_name, 50) ;

  /* If we don't have a table and we are required to add, better create a
   * table to add to.
   */
  if (bgp->rc_name_index == NULL)
    {
      if (added == NULL)
        return NULL ;

      bgp->rc_name_index = vhash_table_new(
            bgp,
            50,                 /* start ready for a few contexts       */
            200,                /* allow to be quite dense              */
            &bgp_rcontext_vhash_params) ;
    } ;

  /* Lookup, creating rcontext and allocating rc-id if required.
   *
   * For RS clients we make sure the name is distinct from ordinary
   * route-context names
   */
  if (type == rc_is_rs_client)
    {
      /* Note that a real route context names cannot include ' '.
       */
      tstring_set_str(rs_name, "RS ") ;
      tstring_append_str(rs_name, name) ;

      name = rs_name->str ;
    } ;

  rc = vhash_lookup(bgp->rc_name_index, name, added) ;

  tstring_free(rs_name) ;

  if (rc == NULL)
    return NULL ;

  /* Lookup, creating rcontext and allocated id if required.
   *
   * If creates new rcontext, fills in the unset fields in the value.
   */
  if ((added != NULL) && *added)
    {
      rc->bgp  = bgp ;
      rc->type = type ;

      vhash_set(rc) ;
    } ;

  return vhash_inc_ref(rc) ;
} ;

/*------------------------------------------------------------------------------
 * Get rcontext by its id.
 */
extern bgp_rcontext
bgp_rcontext_get(bgp_rc_id_t rc_id)
{
  return svec_get(bgp_rcontext_id_index, rc_id) ;
} ;

/*------------------------------------------------------------------------------
 * Reduce lock on the given route-context because no longer using same.
 *
 * The route-context may, or may not, vanish.
 */
extern bgp_rcontext
bgp_rcontext_unlock(bgp_rcontext rc)
{
  vhash_dec_ref(rc, rc->bgp->rc_name_index) ;
  return NULL ;
} ;

/*==============================================================================
 * Create/Destroy/etc lcontext
 */

/*------------------------------------------------------------------------------
 * Create a new lcontext for the given rib, for the given rcontext (if any).
 *
 * If no rcontext is given, this creates the lc_view_id local context.  This
 * is done when the given rib is created.
 *
 * If an rcontext is given, this must be the first use of the rcontext in
 * this rib, and a new local context is required.  The rcontext cannot be
 * the rc_is_view context.
 *
 * Updates the rib and rcontext as required for the new lcontext.
 *
 * Returns:  new local_context filled in with its lc-id etc.
 */
extern bgp_lcontext
bgp_lcontext_new(bgp_rib rib, bgp_rcontext rc)
{
  bgp_lcontext  lc ;

  lc = XCALLOC(MTYPE_BGP_LCONTEXT, sizeof(bgp_lcontext_t)) ;

  /* Zeroizing has set:
   *
   *   * rib                    -- X            -- set below
   *   * qafx                   -- X            -- set below
   *
   *   * rc_id                  -- X            -- set below
   *   * id                     -- lc_view_id
   *   * lcs                    -- SVEC_NULL
   *
   *   * pribs                  -- NULLs        -- no pribs, yet
   *
   *   * in_to                  -- NULL         -- none, yet
   *   * in_from                -- NULL         -- none, yet
   */
  confirm(bgp_rc_id_null == 0) ;
  confirm(lc_view_id     == 0) ;
  confirm(SVEC_NULL      == 0) ;

  lc->rib   = rib ;
  lc->qafx  = rib->qafx ;

  if (rc != NULL)
    {
      qassert(rc->type != rc_is_view) ;

      /* Need a new local-context for this global one.
       */
      lc->id = svec_add(rib->lc_map, lc) ;
      svl_append(rib->lc_map->base, rib->lc_map, lc->id, bgp_lcontext_t, lcs) ;

      /* And link the local and route contexts together.
       */
      qassert(rc->lcontexts[lc->qafx] == NULL) ;

      lc->rc_id = rc->id ;
      rc->lcontexts[lc->qafx] = lc ;
    }
  else
    {
      /* Creating local context for lc_view_id.
       */
      qassert(rib->lc_view == NULL) ;
      rib->lc_view = lc ;
    } ;

  if (lc->id >= rib->local_context_count)
    rib->local_context_count = lc->id + 1 ;

  return lc ;
} ;

/*==============================================================================
 * Attach/Detach rib and prib to/from rcontext.
 */

/*------------------------------------------------------------------------------
 * Attach prib to rcontext -- create lcontext for this if required.
 *
 * A prib is always associated with an lcontext, so this detaches it from the
 * its current lcontext before attaching to the new one.
 */
extern bgp_lcontext
bgp_rcontext_attach_prib(bgp_rcontext rc, bgp_prib prib)
{
  bgp_lcontext lc ;

  qassert(rc != NULL) ;         /* this is for real route contexts      */

  /* If there isn't a local context for this rcontext, then we'd better make
   * one.
   */
  lc = rc->lcontexts[prib->qafx] ;
  if (lc == NULL)
    lc = bgp_lcontext_new(rc, prib->rib) ;

  /* Attach this prib to the (new) lcontext
   */
  return bgp_lcontext_attach_prib(lc, prib) ;
} ;

/*------------------------------------------------------------------------------
 * Attach prib to the given lcontext.
 *
 * A prib is always associated with an lcontext, so this detaches it from the
 * its current lcontext before attaching to the new one.
 */
extern bgp_lcontext
bgp_lcontext_attach_prib(bgp_lcontext lc, bgp_prib prib)
{
  bgp_lcontext_detach_prib(prib) ;

  prib->lc_id = lc->id ;
  ddl_append(lc->pribs, prib, lc_list) ;
} ;

/*------------------------------------------------------------------------------
 * Detach prib from its current lcontext.
 *
 * NB: a prib MUST always be associated with an lcontext, so this is putting
 *     the prib into an invalid state... presumably to be destroyed or moved
 *     to a new lcontext.
 */
extern void
bgp_lcontext_detach_prib(bgp_prib prib)
{
  bgp_lcontext lc ;

  if (prib->lc_id <= lc_last_id)
    {
      lc = bgp_lcontext_get(prib->rib, prib->lc_id) ;

      prib->lc_id = lc_end_id ;         /* not a valid lc_id !  */
      confirm(lc_end_id > lc_last_id) ;

      ddl_del(lc->pribs, prib, lc_list) ;
    } ;
} ;

/*==============================================================================
 * The vhash and other magic.
 */
static vhash_equal_func bgp_rcontext_equal ;
static vhash_new_func   bgp_rcontext_new ;
static vhash_free_func  bgp_rcontext_free ;

/*------------------------------------------------------------------------------
 * Create a new entry in the bgp_rcontext_id_index, for the given name
 *                                                            -- vhash_new_func
 *
 * Allocates the next rcontext-id.
 */
static vhash_item
bgp_rcontext_new(vhash_table table, vhash_data_c data)
{
  bgp_rcontext  rc ;
  const char*   name ;

  name = data ;

  /* Allocate a new route-context object.
   */
  rc = XCALLOC(MTYPE_BGP_RCONTEXT,
                offsetof(bgp_rcontext_t, name[uround_up_up(strlen(name), 4)])) ;

  /* Zeroizing has set:
   *
   *   * vhash          -- X            -- set on return
   *
   *   * id             -- X            -- set below
   *   * known          -- X            -- set below
   *
   *   * lcontexts[]    -- all NULL     -- none, yet
   *
   *   * bgp            -- NULL         -- MUST be set after vhash_lookup()
   *   * type           -- rc_is_view   -- MUST be set after vhash_lookup()
   *
   *   * name           -- all '\0'     -- set below
   */
  strcpy(rc->name, name) ;

  rc->id = svec_add(bgp_rcontext_id_index, rc) ;
  svl_append(bgp_rcontext_id_index->base, bgp_rcontext_id_index, rc->id,
                                                        bgp_rcontext_t, known) ;
  return rc ;
} ;

/*------------------------------------------------------------------------------
 * Give back the route-context-id -- the vhash_item is an rcontext
 *                                                            -- vhash_free_func
 *
 * If the item is "set", then it is being reamed out, and we are happy to do
 * that now.
 */
static vhash_item
bgp_rcontext_free(vhash_item item, vhash_table table)
{
  bgp_rcontext  rc ;

  rc = item ;

  svl_del(bgp_rcontext_id_index->base, bgp_rcontext_id_index, rc->id,
                                                        bgp_rcontext_t, known) ;
  svec_del(bgp_rcontext_id_index, rc->id) ;

  XFREE(MTYPE_BGP_RCONTEXT, rc) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function -- vhash_equal_func
 */
static int
bgp_rcontext_equal(vhash_item_c item, vhash_data_c data)
{
  bgp_rcontext  rc ;
  const char*   name ;

  rc   = item ;
  name = data ;

  return strcmp(rc->name, name) ;
} ;
