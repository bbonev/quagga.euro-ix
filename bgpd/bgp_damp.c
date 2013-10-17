/* BGP flap damping
   Copyright (C) 2001 IP Infusion Inc.

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
#include <math.h>

#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "log.h"
#include "thread.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_vty.h"

/* Global variable to access damping configuration */
struct bgp_damp_config bgp_damp_cfg;
static struct bgp_damp_config *damp = &bgp_damp_cfg;

/* Utility macro to add and delete BGP damping information to no
   used list.  */
#define BGP_DAMP_LIST_ADD(N,A)                        \
  do {                                                \
    (A)->prev = NULL;                                 \
    (A)->next = (N)->no_reuse_list;                   \
    if ((N)->no_reuse_list)                           \
      (N)->no_reuse_list->prev = (A);                 \
    (N)->no_reuse_list = (A);                         \
  } while (0)

#define BGP_DAMP_LIST_DEL(N,A)                        \
  do {                                                \
    if ((A)->next)                                    \
      (A)->next->prev = (A)->prev;                    \
    if ((A)->prev)                                    \
      (A)->prev->next = (A)->next;                    \
    else                                              \
      (N)->no_reuse_list = (A)->next;                 \
  } while (0)

/* Calculate reuse list index by penalty value.  */
static int
bgp_reuse_index (int penalty)
{
  unsigned int i;
  int index;

  i = (int)(((double) penalty / damp->reuse_limit - 1.0) * damp->scale_factor);

  if ( i >= damp->reuse_index_size )
    i = damp->reuse_index_size - 1;

  index = damp->reuse_index[i] - damp->reuse_index[0];

  return (damp->reuse_offset + index) % damp->reuse_list_size;
}

/* Add BGP damping information to reuse list.  */
static void
bgp_reuse_list_add (struct bgp_damp_info *bdi)
{
  int index;

  index = bdi->index = bgp_reuse_index (bdi->penalty);

  bdi->prev = NULL;
  bdi->next = damp->reuse_list[index];
  if (damp->reuse_list[index])
    damp->reuse_list[index]->prev = bdi;
  damp->reuse_list[index] = bdi;
}

/* Delete BGP damping information from reuse list.  */
static void
bgp_reuse_list_delete (struct bgp_damp_info *bdi)
{
  if (bdi->next)
    bdi->next->prev = bdi->prev;
  if (bdi->prev)
    bdi->prev->next = bdi->next;
  else
    damp->reuse_list[bdi->index] = bdi->next;
}

/* Return decayed penalty value.  */
int
bgp_damp_decay (time_t tdiff, int penalty)
{
  unsigned int i;

  i = (int) ((double) tdiff / DELTA_T);

  if (i == 0)
    return penalty;

  if (i >= damp->decay_array_size)
    return 0;

  return (int) (penalty * damp->decay_array[i]);
}

/* Handler of reuse timer event.  Each route in the current reuse-list
   is evaluated.  RFC2439 Section 4.8.7.  */
static int
bgp_reuse_timer (struct thread *t)
{
  struct bgp_damp_info *bdi;
  struct bgp_damp_info *next;
  time_t t_now  Unused ;
  time_t t_diff  Unused ;

  damp->t_reuse = NULL;
  damp->t_reuse =
    thread_add_timer (master, bgp_reuse_timer, NULL, DELTA_REUSE);

  t_now = bgp_clock ();

  /* 1.  save a pointer to the current zeroth queue head and zero the
     list head entry.  */
  bdi = damp->reuse_list[damp->reuse_offset];
  damp->reuse_list[damp->reuse_offset] = NULL;

  /* 2.  set offset = modulo reuse-list-size ( offset + 1 ), thereby
     rotating the circular queue of list-heads.  */
  damp->reuse_offset = (damp->reuse_offset + 1) % damp->reuse_list_size;

  /* 3. if ( the saved list head pointer is non-empty ) */
  for (; bdi; bdi = next)
    {
      next = NULL ;
/* TODO reinstate route-flap damping            */
#if 0
      bgp_inst bgp = bdi->binfo->peer->bgp;

      next = bdi->next;

      /* Set t-diff = t-now - t-updated.  */
      t_diff = t_now - bdi->t_updated;

      /* Set figure-of-merit = figure-of-merit * decay-array-ok [t-diff] */
      bdi->penalty = bgp_damp_decay (t_diff, bdi->penalty);

      /* Set t-updated = t-now.  */
      bdi->t_updated = t_now;

      /* if (figure-of-merit < reuse).  */
      if (bdi->penalty < damp->reuse_limit)
        {
          /* Reuse the route.  */
          bgp_info_unset_flag (bdi->rn, bdi->binfo, BGP_INFO_DAMPED);
          bdi->suppress_time = 0;

          if (bdi->lastrecord == BGP_RECORD_UPDATE)
            {
              bgp_info_unset_flag (bdi->rn, bdi->binfo, BGP_INFO_HISTORY);
              bgp_aggregate_increment (bgp, &bdi->rn->p, bdi->binfo,
                                                                    bdi->qafx) ;
// xxx        bgp_process_dispatch (bgp, bdi->rn);
            }

          if (bdi->penalty <= damp->reuse_limit / 2.0)
            bgp_damp_info_free (bdi, true /* withdraw */);
          else
            BGP_DAMP_LIST_ADD (damp, bdi);
        }
      else
        /* Re-insert into another list (See RFC2439 Section 4.8.6).  */
        bgp_reuse_list_add (bdi);
#endif
    }

  return 0;
}

/* A route becomes unreachable (RFC2439 Section 4.8.2).  */
extern int
bgp_damp_withdraw (struct bgp_info *binfo, bgp_node rn, qafx_t qafx,
                                                              bool attr_change)
{
  time_t t_now;
  struct bgp_damp_info *bdi = NULL;
  double last_penalty = 0;

  t_now = bgp_clock ();

  /* Processing Unreachable Messages.
   */
#if 0
  if (binfo->extra)
    bdi = binfo->extra->damp_info;
#else
  bdi = NULL ;
#endif

  if (bdi == NULL)
    {
      /* If there is no previous stability history.
       *
       * RFC2439 said:
       *  1. allocate a damping structure.
       *  2. set figure-of-merit = 1.
       *  3. withdraw the route.
       */
      bdi = XCALLOC (MTYPE_BGP_DAMP_INFO, sizeof (struct bgp_damp_info));
      bdi->binfo = binfo;
      bdi->rn = rn;
      bdi->penalty = (attr_change ? DEFAULT_PENALTY / 2 : DEFAULT_PENALTY);
      bdi->flap = 1;
      bdi->start_time = t_now;
      bdi->suppress_time = 0;
      bdi->index = -1;
      bdi->qafx  = qafx ;
/* TODO reinstate route flap damping            */
#if 0
      (bgp_info_extra_get (binfo))->damp_info = bdi;
      BGP_DAMP_LIST_ADD (damp, bdi);
#endif
    }
  else
    {
      last_penalty = bdi->penalty;

      /* 1. Set t-diff = t-now - t-updated.
       */
      bdi->penalty =
        (bgp_damp_decay (t_now - bdi->t_updated, bdi->penalty)
         + (attr_change ? DEFAULT_PENALTY / 2 : DEFAULT_PENALTY));

      if (bdi->penalty > damp->ceiling)
        bdi->penalty = damp->ceiling;

      bdi->flap++;
    }

  assert ((rn == bdi->rn) && (binfo == bdi->binfo));

  bdi->lastrecord = BGP_RECORD_WITHDRAW;
  bdi->t_updated = t_now;

  /* Make this route as historical status.  */
/* TODO reinstate route flap damping            */
#if 0
  bgp_info_set_flag (rn, binfo, BGP_INFO_HISTORY);
#endif

  /* Remove the route from a reuse list if it is on one.  */
#if 0
  if (CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED))
#else
  if (false)
#endif
    {
      /* If decay rate isn't equal to 0, reinsert brn. */
      if (bdi->penalty != last_penalty)
        {
          bgp_reuse_list_delete (bdi);
          bgp_reuse_list_add (bdi);
        }
      return BGP_DAMP_SUPPRESSED;
    }

  /* If not suppressed before, do annonunce this withdraw and
     insert into reuse_list.  */
  if (bdi->penalty >= damp->suppress_value)
    {
/* TODO reinstate route flap damping            */
#if 0
      bgp_info_set_flag (rn, binfo, BGP_INFO_DAMPED);
#endif
      bdi->suppress_time = t_now;
      BGP_DAMP_LIST_DEL (damp, bdi);
      bgp_reuse_list_add (bdi);
    }

  return BGP_DAMP_USED;
}

extern int
bgp_damp_update (struct bgp_info *binfo, bgp_node rn)
{
  time_t t_now;
  struct bgp_damp_info *bdi;
  int status;

#if 0
  if (!binfo->extra || !((bdi = binfo->extra->damp_info)))
#else
  if (!(bdi = NULL))
#endif
    return BGP_DAMP_USED;

  t_now = bgp_clock ();
/* TODO reinstate route flap damping            */
#if 0
  bgp_info_unset_flag (rn, binfo, BGP_INFO_HISTORY);
#endif

  bdi->lastrecord = BGP_RECORD_UPDATE;
  bdi->penalty = bgp_damp_decay (t_now - bdi->t_updated, bdi->penalty);

#if 0
  if (! CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED)
      && (bdi->penalty < damp->suppress_value))
#else
  if (false)
#endif
    status = BGP_DAMP_USED;
#if 0
  else if (CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED)
           && (bdi->penalty < damp->reuse_limit) )
#else
  else if (false)
#endif
    {
/* TODO reinstate route flap damping            */
#if 0
      bgp_info_unset_flag (rn, binfo, BGP_INFO_DAMPED);
#endif
      bgp_reuse_list_delete (bdi);
      BGP_DAMP_LIST_ADD (damp, bdi);
      bdi->suppress_time = 0;
      status = BGP_DAMP_USED;
    }
  else
    status = BGP_DAMP_SUPPRESSED;

  if (bdi->penalty > damp->reuse_limit / 2.0)
    bdi->t_updated = t_now;
  else
    bgp_damp_info_free (bdi, false /* not withdraw */);

  return status;
}

/*------------------------------------------------------------------------------
 * Remove damping information and history route.
 */
extern int
bgp_damp_scan (struct bgp_info *binfo, qafx_t qafx)
{
  time_t t_now, t_diff;
  struct bgp_damp_info *bdi;

#if 0
  assert (binfo->extra && binfo->extra->damp_info);
#endif

  t_now = bgp_clock ();
#if 0
  bdi = binfo->extra->damp_info;
#else
  bdi = NULL ;
#endif

#if 0
  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
#else
  if (false)
#endif
    {
      t_diff = t_now - bdi->suppress_time;

      if (t_diff >= damp->max_suppress_time)
        {
/* TODO reinstate route flap damping            */
#if 0
          bgp_info_unset_flag (bdi->rn, binfo, BGP_INFO_DAMPED);
#endif
          bgp_reuse_list_delete (bdi);
          BGP_DAMP_LIST_ADD (damp, bdi);
          bdi->penalty = damp->reuse_limit;
          bdi->suppress_time = 0;
          bdi->t_updated = t_now;

          /* Need to announce UPDATE once this binfo is usable again. */
          if (bdi->lastrecord == BGP_RECORD_UPDATE)
            return 1;
          else
            return 0;
        }
    }
  else
    {
      t_diff = t_now - bdi->t_updated;
      bdi->penalty = bgp_damp_decay (t_diff, bdi->penalty);

      if (bdi->penalty <= damp->reuse_limit / 2.0)
        {
          /* release the bdi, bdi->binfo. */
          bgp_damp_info_free (bdi, true /* withdraw */);
          return 0;
        }
      else
        bdi->t_updated = t_now;
    }
  return 0;
}

extern void
bgp_damp_info_free (struct bgp_damp_info *bdi, bool withdraw)
{
  struct bgp_info *binfo  Unused;

  if (! bdi)
    return;

  binfo = bdi->binfo;
#if 0
  binfo->extra->damp_info = NULL;
#endif

#if 0
  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
#else
  if (false)
#endif
    bgp_reuse_list_delete (bdi);
  else
    BGP_DAMP_LIST_DEL (damp, bdi);

/* TODO reinstate route flap damping            */
#if 0
  bgp_info_unset_flag (bdi->rn, binfo, BGP_INFO_HISTORY|BGP_INFO_DAMPED);

  if (bdi->lastrecord == BGP_RECORD_WITHDRAW && withdraw)
    bgp_info_delete (bdi->rn, binfo);
#endif

  XFREE (MTYPE_BGP_DAMP_INFO, bdi);
}

static void
bgp_damp_parameter_set (int hlife, int reuse, int sup, int maxsup)
{
  double reuse_max_ratio;
  unsigned int i;
  double j;

  damp->suppress_value = sup;
  damp->half_life = hlife;
  damp->reuse_limit = reuse;
  damp->max_suppress_time = maxsup;

  /* Initialize params per bgp_damp_config. */
  damp->reuse_index_size = REUSE_ARRAY_SIZE;

  damp->ceiling = (int)(damp->reuse_limit * (pow(2, (double)damp->max_suppress_time/damp->half_life)));

  /* Decay-array computations */
  damp->decay_array_size = ceil ((double) damp->max_suppress_time / DELTA_T);
  damp->decay_array = XCALLOC (MTYPE_BGP_DAMP_ARRAY,
                               sizeof(double) * (damp->decay_array_size));
  damp->decay_array[0] = 1.0;
  damp->decay_array[1] = exp ((1.0/((double)damp->half_life/DELTA_T)) * log(0.5));

  /* Calculate decay values for all possible times */
  for (i = 2; i < damp->decay_array_size; i++)
    damp->decay_array[i] = damp->decay_array[i-1] * damp->decay_array[1];

  /* Reuse-list computations */
  i = ceil ((double)damp->max_suppress_time / DELTA_REUSE) + 1;
  if (i > REUSE_LIST_SIZE || i == 0)
    i = REUSE_LIST_SIZE;
  damp->reuse_list_size = i;

  damp->reuse_list = XCALLOC (MTYPE_BGP_DAMP_ARRAY,
                              damp->reuse_list_size
                              * sizeof (struct bgp_reuse_node *));

  /* Reuse-array computations */
  damp->reuse_index = XCALLOC (MTYPE_BGP_DAMP_ARRAY,
                               sizeof(int) * damp->reuse_index_size);

  reuse_max_ratio = (double)damp->ceiling/damp->reuse_limit;
  j = (exp((double)damp->max_suppress_time/damp->half_life) * log10(2.0));
  if ( reuse_max_ratio > j && j != 0 )
    reuse_max_ratio = j;

  damp->scale_factor = (double)damp->reuse_index_size/(reuse_max_ratio - 1);

  for (i = 0; i < damp->reuse_index_size; i++)
    {
      damp->reuse_index[i] =
        (int)(((double)damp->half_life / DELTA_REUSE)
              * log10 (1.0 / (damp->reuse_limit * ( 1.0 + ((double)i/damp->scale_factor)))) / log10(0.5));
    }
}

extern int
bgp_damp_enable (bgp_inst bgp, qafx_t qafx, time_t half,
                 unsigned int reuse, unsigned int suppress, time_t max)
{
#if 0
  if (bafcs_is_on(bgp->c->afc[qafx], bafcs_DAMPING))
#else
  if (false)
#endif
    {
      if (damp->half_life == half
          && damp->reuse_limit == reuse
          && damp->suppress_value == suppress
          && damp->max_suppress_time == max)
        return 0;

      bgp_damp_disable (bgp, qafx);
    }

#if 0
  bgp->config->c_af_flags[qafx] |= BGP_AFF_DAMPING ;
#endif
  bgp_damp_parameter_set (half, reuse, suppress, max);

  /* Register reuse timer.  */
  if (! damp->t_reuse)
    damp->t_reuse =
      thread_add_timer (master, bgp_reuse_timer, NULL, DELTA_REUSE);

  return 0;
}

static void
bgp_damp_config_clean (struct bgp_damp_config *damp)
{
  /* Free decay array */
  XFREE (MTYPE_BGP_DAMP_ARRAY, damp->decay_array);

  /* Free reuse index array */
  XFREE (MTYPE_BGP_DAMP_ARRAY, damp->reuse_index);

  /* Free reuse list array. */
  XFREE (MTYPE_BGP_DAMP_ARRAY, damp->reuse_list);
}

/* Clean all the bgp_damp_info stored in reuse_list. */
void
bgp_damp_info_clean (void)
{
  unsigned int i;
  struct bgp_damp_info *bdi, *next;

  damp->reuse_offset = 0;

  for (i = 0; i < damp->reuse_list_size; i++)
    {
      if (! damp->reuse_list[i])
        continue;

      for (bdi = damp->reuse_list[i]; bdi; bdi = next)
        {
          next = bdi->next;
          bgp_damp_info_free (bdi, true /* withdraw */);
        }
      damp->reuse_list[i] = NULL;
    }

  for (bdi = damp->no_reuse_list; bdi; bdi = next)
    {
      next = bdi->next;
      bgp_damp_info_free (bdi, true /* withdraw */);
    }
  damp->no_reuse_list = NULL;
}

extern int
bgp_damp_disable (bgp_inst bgp, qafx_t qafx)
{
  /* Cancel reuse thread. */
  if (damp->t_reuse )
    thread_cancel (damp->t_reuse);
  damp->t_reuse = NULL;

  /* Clean BGP damping information.  */
  bgp_damp_info_clean ();

  /* Clear configuration */
  bgp_damp_config_clean (&bgp_damp_cfg);

#if 0
  bgp->config->c_af_flags[qafx] &= ~BGP_AFF_DAMPING ;
#endif
  return 0;
}

void
bgp_config_write_damp (struct vty *vty)
{
  if (bgp_damp_cfg.half_life == DEFAULT_HALF_LIFE*60
      && bgp_damp_cfg.reuse_limit == DEFAULT_REUSE
      && bgp_damp_cfg.suppress_value == DEFAULT_SUPPRESS
      && bgp_damp_cfg.max_suppress_time == bgp_damp_cfg.half_life*4)
    vty_out (vty, " bgp damping%s", VTY_NEWLINE);
  else if (bgp_damp_cfg.half_life != DEFAULT_HALF_LIFE*60
           && bgp_damp_cfg.reuse_limit == DEFAULT_REUSE
           && bgp_damp_cfg.suppress_value == DEFAULT_SUPPRESS
           && bgp_damp_cfg.max_suppress_time == bgp_damp_cfg.half_life*4)
    vty_out (vty, " bgp damping %ld%s",
             bgp_damp_cfg.half_life/60,
             VTY_NEWLINE);
  else
    vty_out (vty, " bgp damping %ld %d %d %ld%s",
             bgp_damp_cfg.half_life/60,
             bgp_damp_cfg.reuse_limit,
             bgp_damp_cfg.suppress_value,
             bgp_damp_cfg.max_suppress_time/60,
             VTY_NEWLINE);
}

static const char *
bgp_get_reuse_time (unsigned int penalty, char *buf, size_t len)
{
  time_t reuse_time = 0;
  struct tm *tm = NULL;

  if (penalty > damp->reuse_limit)
    {
      reuse_time = (int) (DELTA_T * ((log((double)damp->reuse_limit/penalty))/(log(damp->decay_array[1]))));

      if (reuse_time > damp->max_suppress_time)
        reuse_time = damp->max_suppress_time;

      tm = gmtime (&reuse_time);
    }
  else
    reuse_time = 0;

  /* Making formatted timer strings. */
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
  if (reuse_time == 0)
    snprintf (buf, len, "00:00:00");
  else if (reuse_time < ONE_DAY_SECOND)
    snprintf (buf, len, "%02d:%02d:%02d",
              tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (reuse_time < ONE_WEEK_SECOND)
    snprintf (buf, len, "%dd%02dh%02dm",
              tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    snprintf (buf, len, "%02dw%dd%02dh",
              tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);

  return buf;
}

extern void
bgp_damp_info_vty (struct vty *vty, route_info ri)
{
  struct bgp_damp_info *bdi;
  time_t t_now, t_diff;
  int penalty;
  char timebuf[50] ;

  if (ri->extra == NULL)
    return;

  /* BGP damping information.
   */
/* TODO .... reconstruct Route Flap Damping !!          */
#if 0
  bdi = ri->extra->damp_info;
#else
  bdi = NULL ;
#endif

  /* If damping is not enabled or there is no damping information,
     return immediately.  */
  if (! damp || ! bdi)
    return;

  /* Calculate new penalty.  */
  t_now = bgp_clock ();
  t_diff = t_now - bdi->t_updated;
  penalty = bgp_damp_decay (t_diff, bdi->penalty);

  vty_out (vty, "      Dampinfo: penalty %d, flapped %d times in %s",
           penalty, bdi->flap, peer_uptime(bdi->start_time).str);

  if (CHECK_FLAG (ri->current.flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (ri->current.flags, BGP_INFO_HISTORY))
    vty_out (vty, ", reuse in %s",
             bgp_get_reuse_time (penalty, timebuf, sizeof(timebuf)));

  vty_out (vty, "%s", VTY_NEWLINE);
}

extern const char *
bgp_damp_reuse_time_vty (struct vty *vty, route_info ri,
                                                      char *timebuf, size_t len)
{
  struct bgp_damp_info *bdi;
  time_t t_now, t_diff;
  int penalty;

  if (ri->extra == NULL)
    return NULL;

  /* BGP damping information.
   */
/* TODO .... reconstruct Route Flap Damping !!          */
#if 0
  bdi = ri->extra->damp_info;
#else
  bdi = NULL ;
#endif

  /* If damping is not enabled or there is no damping information,
     return immediately.  */
  if (! damp || ! bdi)
    return NULL;

  /* Calculate new penalty.  */
  t_now = bgp_clock ();
  t_diff = t_now - bdi->t_updated;
  penalty = bgp_damp_decay (t_diff, bdi->penalty);

  return  bgp_get_reuse_time (penalty, timebuf, len);
}

/*==============================================================================
 *
 */

extern cmd_ret_t
bgp_damp_warning(vty vty)
{
  vty_out (vty, "%% Route Flap Damping is not implemented -- TBD\n");
  return CMD_WARNING;
} ;

/* Display specified route of BGP table. */
static cmd_ret_t
bgp_clear_damp_route (vty vty, chs_c view_name,
                      chs_c ip_str, afi_t q_afi, safi_t q_safi,
                      struct prefix_rd *prd, int prefix_check)
{
#if 1
  return bgp_damp_warning(vty) ;
#else
  int ret;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_info *ri_temp;
  bgp_inst bgp;
  struct bgp_table *table;
  qafx_t qafx ;

  qafx = qafx_from_q(q_afi, q_safi) ;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
        {
          vty_out (vty, "%% Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = get_qafx_sa_family(qafx) ;

  if (qafx_is_mpls_vpn(qafx))
    {
      for (rn = bgp_table_top (bgp->rib[qafx]); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            if ((rm = bgp_node_match (table, &match)) != NULL)
              {
                if (! prefix_check || rm->p.prefixlen == match.prefixlen)
                  {
                    ri = rm->info;
                    while (ri)
                      {
                        if (ri->extra && ri->extra->damp_info)
                          {
                            ri_temp = ri->info.next;
                            bgp_damp_info_free (ri->extra->damp_info, 1);
                            ri = ri_temp;
                          }
                        else
                          ri = ri->info.next;
                      }
                  }
                bgp_unlock_node (rm);
              }
        }
    }
  else
    {
      if ((rn = bgp_node_match (bgp->rib[qafx][rib_main], &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              ri = rn->info;
              while (ri)
                {
                  if (ri->extra && ri->extra->damp_info)
                    {
                      ri_temp = ri->info.next;
                      bgp_damp_info_free (ri->extra->damp_info, 1);
                      ri = ri_temp;
                    }
                  else
                    ri = ri->info.next;
                }
            }
          bgp_unlock_node (rn);
        }
    }

  return CMD_SUCCESS;
#endif
}

DEFUN (clear_ip_bgp_dampening,
       clear_ip_bgp_dampening_cmd,
       "clear ip bgp dampening",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n")
{
  bgp_damp_info_clean ();
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening_prefix,
       clear_ip_bgp_dampening_prefix_cmd,
       "clear ip bgp dampening A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
                               SAFI_UNICAST, NULL, 1);
}

DEFUN (clear_ip_bgp_dampening_address,
       clear_ip_bgp_dampening_address_cmd,
       "clear ip bgp dampening A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
                               SAFI_UNICAST, NULL, 0);
}

DEFUN (clear_ip_bgp_dampening_address_mask,
       clear_ip_bgp_dampening_address_mask_cmd,
       "clear ip bgp dampening A.B.C.D A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_clear_damp_route (vty, NULL, prefix_str, AFI_IP,
                               SAFI_UNICAST, NULL, 0);
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  bgp_inst bgp;
  int half = DEFAULT_HALF_LIFE * 60;
  int reuse = DEFAULT_REUSE;
  int suppress = DEFAULT_SUPPRESS;
  int max = 4 * half;

  return bgp_damp_warning(vty) ;

  if (argc == 4)
    {
      half = atoi (argv[0]) * 60;
      reuse = atoi (argv[1]);
      suppress = atoi (argv[2]);
      max = atoi (argv[3]) * 60;
    }
  else if (argc == 1)
    {
      half = atoi (argv[0]) * 60;
      max = 4 * half;
    }

  bgp = vty->index;
  return bgp_damp_enable (bgp, bgp_node_qafx(vty), half, reuse, suppress, max);
}

ALIAS (bgp_damp_set,
       bgp_damp_set2_cmd,
       "bgp dampening <1-45>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n")

ALIAS (bgp_damp_set,
       bgp_damp_set3_cmd,
       "bgp dampening",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")
{
  bgp_inst bgp;

  return bgp_damp_warning(vty) ;

  bgp = vty->index;
  return bgp_damp_disable (bgp, bgp_node_qafx(vty));
}

ALIAS (bgp_damp_unset,
       bgp_damp_unset2_cmd,
       "no bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")

/*------------------------------------------------------------------------------
 * Table of damping commands
 */
CMD_INSTALL_TABLE(static, bgp_damping_cmd_table, BGPD) =
{
  /* IPv4 BGP commands. */
 /* BGP dampening clear commands */
  { ENABLE_NODE,     &clear_ip_bgp_dampening_cmd                        },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_prefix_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_address_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_address_mask_cmd           },

  { BGP_NODE,        &bgp_damp_set_cmd                                  },
  { BGP_NODE,        &bgp_damp_set2_cmd                                 },
  { BGP_NODE,        &bgp_damp_set3_cmd                                 },
  { BGP_NODE,        &bgp_damp_unset_cmd                                },
  { BGP_NODE,        &bgp_damp_unset2_cmd                               },
  { BGP_IPV4_NODE,   &bgp_damp_set_cmd                                  },
  { BGP_IPV4_NODE,   &bgp_damp_set2_cmd                                 },
  { BGP_IPV4_NODE,   &bgp_damp_set3_cmd                                 },
  { BGP_IPV4_NODE,   &bgp_damp_unset_cmd                                },
  { BGP_IPV4_NODE,   &bgp_damp_unset2_cmd                               },

  CMD_INSTALL_END
} ;


extern void
bgp_damping_cmd_init (void)
{
  cmd_install_table(bgp_damping_cmd_table) ;
}



