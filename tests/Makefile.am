INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"

AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)

noinst_PROGRAMS = testsig testbuffer testmemory heavy heavywq heavythread \
                  testprivs teststream testbgpcap \
                  testchecksum testsvector testvector testheap \
                  testlistutil testqpath testqlump testavl testqfs testprefix \
                  testpqueue testpfifo

testsig_SOURCES          = test-sig.c
testbuffer_SOURCES       = test-buffer.c
testmemory_SOURCES       = test-memory.c
testprivs_SOURCES        = test-privs.c
teststream_SOURCES       = test-stream.c
heavy_SOURCES            = heavy.c main.c
##heavywq_SOURCES          = heavy-wq.c main.c
heavythread_SOURCES      = heavy-thread.c main.c

##testbgpcap_SOURCES       = bgp_capability_test.c
testchecksum_SOURCES     = test-checksum.c
testvector_SOURCES       = test-vector.c
testheap_SOURCES         = test-heap.c
testlistutil_SOURCES     = test-list_util.c
testqpath_SOURCES        = test-qpath.c
testqlump_SOURCES        = test-qlump.c
testavl_SOURCES          = test-avl.c
testqfs_SOURCES          = test-qfs.c
testprefix_SOURCES       = test-prefix.c
testsvector_SOURCES      = test-svector.c

##testbgpmpattr_SOURCES    = bgp_mp_attr_test.c
##testbgpunk_SOURCES       = test_bgp_unknown.c
##testbgpclust_SOURCES     = test_bgp_cluster.c
##testbgpcomm_SOURCES      = test_bgp_community.c
##testbgpecomm_SOURCES     = test_bgp_ecommunity.c
##testbgpaspath_SOURCES    = test_bgp_as_path.c
##testbgpattrstore_SOURCES = test_bgp_attr_store.c

testpqueue_SOURCES       = test-pqueue.c
testpfifo_SOURCES        = test-pfifo.c

testsig_LDADD          = ../lib/libzebra.la @LIBCAP@
testbuffer_LDADD       = ../lib/libzebra.la @LIBCAP@
testmemory_LDADD       = ../lib/libzebra.la @LIBCAP@
testprivs_LDADD        = ../lib/libzebra.la @LIBCAP@
teststream_LDADD       = ../lib/libzebra.la @LIBCAP@
heavy_LDADD            = ../lib/libzebra.la @LIBCAP@ -lm
##heavywq_LDADD          = ../lib/libzebra.la @LIBCAP@ -lm
heavythread_LDADD      = ../lib/libzebra.la @LIBCAP@ -lm
##testbgpcap_LDADD       = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a -lm
testchecksum_LDADD     = ../lib/libzebra.la @LIBCAP@
testvector_LDADD       = ../lib/libzebra.la @LIBCAP@
testheap_LDADD         = ../lib/libzebra.la @LIBCAP@
testlistutil_LDADD     = ../lib/libzebra.la @LIBCAP@
testqpath_LDADD        = ../lib/libzebra.la @LIBCAP@
testqlump_LDADD        = ../lib/libzebra.la @LIBCAP@
testavl_LDADD          = ../lib/libzebra.la @LIBCAP@
testqfs_LDADD          = ../lib/libzebra.la @LIBCAP@
testprefix_LDADD       = ../lib/libzebra.la @LIBCAP@
testsvector_LDADD      = ../lib/libzebra.la @LIBCAP@

##testbgpmpattr_LDADD    = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpunk_LDADD       = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpclust_LDADD     = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpcomm_LDADD      = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpecomm_LDADD     = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpaspath_LDADD    = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm
##testbgpattrstore_LDADD = ../lib/libzebra.la @LIBCAP@ ../bgpd/libbgp.a  -lm

testpqueue_LDADD       = ../lib/libzebra.la @LIBCAP@
testpfifo_LDADD        = ../lib/libzebra.la @LIBCAP@
