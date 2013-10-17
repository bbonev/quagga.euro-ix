## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib @SNMP_INCLUDES@
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)

noinst_LIBRARIES = libbgp.a
sbin_PROGRAMS = bgpd

libbgp_a_SOURCES = \
  bgp_adj_in.c  bgp_adj_out.c  bgp_aspath.c  bgp_attr.c  \
  bgp_attr_store.c  bgp_clist.c  bgp_clist_vty.c  bgp_cluster.c  \
  bgp_common.c  bgp_community.c  bgp_config.c  \
  bgp_config_vty.c  bgp_connection.c  bgp_damp.c  bgpd.c  bgp_debug.c  \
  bgp_dump.c  bgp_ecommunity.c  bgp_engine.c  bgp_filter.c  bgp_fsm.c  \
  bgp_inst_config.c  \
  bgp_mplsvpn.c  bgp_msg_read.c  bgp_msg_write.c  bgp_names.c  \
  bgp_network.c  bgp_nexthop.c  bgp_notification.c  \
  bgp_open_state.c  bgp_packet.c  bgp_peer.c  bgp_peer_config.c  \
  bgp_peer_index.c  bgp_prun.c  bgp_rcontext.c  bgp_regex.c  bgp_rib.c  \
  bgp_route.c  bgp_route_aggr.c  bgp_route_refresh.c  \
  bgp_route_static.c  bgp_routemap.c  bgp_run.c  bgp_run_vty.c  \
  bgp_session.c  bgp_show.c  bgp_snmp.c  bgp_table.c  \
  bgp_unknown.c  bgp_vty.c  bgp_zebra.c

noinst_HEADERS = \
  bgp.h  \
  bgp_adj_in.h  bgp_adj_out.h  bgp_aspath.h  bgp_attr.h  \
  bgp_attr_store.h  bgp_clist.h  bgp_clist_vty.h  bgp_cluster.h  \
  bgp_common.h  bgp_community.h  bgp_config.h  \
  bgp_config_vty.h  bgp_connection.h  bgp_damp.h  bgpd.h  bgp_debug.h  \
  bgp_dump.h  bgp_ecommunity.h  bgp_engine.h  bgp_filter.h  bgp_fsm.h  \
  bgp_inst_config.h  \
  bgp_mplsvpn.h  bgp_mrt.h  bgp_msg_read.h  bgp_msg_write.h  \
  bgp_names.h  bgp_network.h  bgp_nexthop.h  bgp_notification.h  \
  bgp_open_state.h  bgp_packet.h  bgp_peer.h  bgp_peer_config.h  \
  bgp_peer_index.h  bgp_prun.h  bgp_rcontext.h  bgp_regex.h  bgp_rib.h  \
  bgp_route.h  bgp_route_aggr.h  bgp_route_refresh.h  \
  bgp_route_static.h  bgp_routemap.h  bgp_run.h  bgp_run_vty.h  \
  bgp_session.h  bgp_show.h  bgp_snmp.h  bgp_table.h  \
  bgp_unknown.h  bgp_vty.h  bgp_zebra.h

bgpd_SOURCES = bgp_main.c
bgpd_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@

examplesdir = $(exampledir)
dist_examples_DATA = bgpd.conf.sample bgpd.conf.sample2

EXTRA_DIST = BGP4-MIB.txt

