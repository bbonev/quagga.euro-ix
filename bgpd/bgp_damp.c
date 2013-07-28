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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"

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
  time_t t_now, t_diff;

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
      struct bgp *bgp = bdi->binfo->peer->bgp;

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
              bgp_process_dispatch (bgp, bdi->rn);
            }

          if (bdi->penalty <= damp->reuse_limit / 2.0)
            bgp_damp_info_free (bdi, true /* withdraw */);
          else
            BGP_DAMP_LIST_ADD (damp, bdi);
        }
      else
        /* Re-insert into another list (See RFC2439 Section 4.8.6).  */
        bgp_reuse_list_add (bdi);
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
  if (binfo->extra)
    bdi = binfo->extra->damp_info;

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
      (bgp_info_extra_get (binfo))->damp_info = bdi;
      BGP_DAMP_LIST_ADD (damp, bdi);
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
  bgp_info_set_flag (rn, binfo, BGP_INFO_HISTORY);

  /* Remove the route from a reuse list if it is on one.  */
  if (CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED))
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
      bgp_info_set_flag (rn, binfo, BGP_INFO_DAMPED);
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

  if (!binfo->extra || !((bdi = binfo->extra->damp_info)))
    return BGP_DAMP_USED;

  t_now = bgp_clock ();
  bgp_info_unset_flag (rn, binfo, BGP_INFO_HISTORY);

  bdi->lastrecord = BGP_RECORD_UPDATE;
  bdi->penalty = bgp_damp_decay (t_now - bdi->t_updated, bdi->penalty);

  if (! CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED)
      && (bdi->penalty < damp->suppress_value))
    status = BGP_DAMP_USED;
  else if (CHECK_FLAG (bdi->binfo->flags, BGP_INFO_DAMPED)
           && (bdi->penalty < damp->reuse_limit) )
    {
      bgp_info_unset_flag (rn, binfo, BGP_INFO_DAMPED);
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

  assert (binfo->extra && binfo->extra->damp_info);

  t_now = bgp_clock ();
  bdi = binfo->extra->damp_info;

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    {
      t_diff = t_now - bdi->suppress_time;

      if (t_diff >= damp->max_suppress_time)
        {
          bgp_info_unset_flag (bdi->rn, binfo, BGP_INFO_DAMPED);
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
  struct bgp_info *binfo;

  if (! bdi)
    return;

  binfo = bdi->binfo;
  binfo->extra->damp_info = NULL;

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    bgp_reuse_list_delete (bdi);
  else
    BGP_DAMP_LIST_DEL (damp, bdi);

  bgp_info_unset_flag (bdi->rn, binfo, BGP_INFO_HISTORY|BGP_INFO_DAMPED);

  if (bdi->lastrecord == BGP_RECORD_WITHDRAW && withdraw)
    bgp_info_delete (bdi->rn, binfo);

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
bgp_damp_enable (struct bgp *bgp, qafx_t qafx, time_t half,
                 unsigned int reuse, unsigned int suppress, time_t max)
{
  if (CHECK_FLAG (bgp->af_flags[qafx], BGP_CONFIG_DAMPING))
    {
      if (damp->half_life == half
          && damp->reuse_limit == reuse
          && damp->suppress_value == suppress
          && damp->max_suppress_time == max)
        return 0;

      bgp_damp_disable (bgp, qafx);
    }

  SET_FLAG (bgp->af_flags[qafx], BGP_CONFIG_DAMPING);
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
bgp_damp_disable (struct bgp *bgp, qafx_t qafx)
{
  /* Cancel reuse thread. */
  if (damp->t_reuse )
    thread_cancel (damp->t_reuse);
  damp->t_reuse = NULL;

  /* Clean BGP damping information.  */
  bgp_damp_info_clean ();

  /* Clear configuration */
  bgp_damp_config_clean (&bgp_damp_cfg);

  UNSET_FLAG (bgp->af_flags[qafx], BGP_CONFIG_DAMPING);
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

void
bgp_damp_info_vty (struct vty *vty, struct bgp_info *binfo)
{
  struct bgp_damp_info *bdi;
  time_t t_now, t_diff;
  char timebuf[BGP_UPTIME_LEN];
  int penalty;

  if (!binfo->extra)
    return;

  /* BGP damping information.  */
  bdi = binfo->extra->damp_info;

  /* If damping is not enabled or there is no damping information,
     return immediately.  */
  if (! damp || ! bdi)
    return;

  /* Calculate new penalty.  */
  t_now = bgp_clock ();
  t_diff = t_now - bdi->t_updated;
  penalty = bgp_damp_decay (t_diff, bdi->penalty);

  vty_out (vty, "      Dampinfo: penalty %d, flapped %d times in %s",
           penalty, bdi->flap,
           peer_uptime (bdi->start_time, timebuf, BGP_UPTIME_LEN));

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, ", reuse in %s",
             bgp_get_reuse_time (penalty, timebuf, BGP_UPTIME_LEN));

  vty_out (vty, "%s", VTY_NEWLINE);
}

const char *
bgp_damp_reuse_time_vty (struct vty *vty, struct bgp_info *binfo,
                         char *timebuf, size_t len)
{
  struct bgp_damp_info *bdi;
  time_t t_now, t_diff;
  int penalty;

  if (!binfo->extra)
    return NULL;

  /* BGP damping information.  */
  bdi = binfo->extra->damp_info;

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
