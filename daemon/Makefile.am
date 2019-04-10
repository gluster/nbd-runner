sbin_PROGRAMS = nbd-runner

nbd_runner_SOURCES = nbd-runner.c nbd-svc-routines.c

nbd_runner_CFLAGS = $(GFAPI_CFLAGS) $(EVENT_CFLAGS) $(GLIB2_CFLAGS)     \
					$(TIRPC_CFLAGS) $(JSONC_CFLAGS)	-I$(top_srcdir)/rpc \
                    -DNBD_RUNNER_LIBDIR=\"$(NBD_RUNNER_LIBDIR)\"        \
                    -I$(top_builddir)/ -I$(top_srcdir)/utils/

nbd_runner_LDADD = $(GFAPI_LIBS) $(PTHREAD) $(EVENT_LIBS) $(GLIB2_LIBS) \
                   $(TIRPC_LIBS) $(JSONC_LIBS) $(LIB_DL)                \
                   $(top_builddir)/rpc/libnbdrpcxdr.la    				\
                   $(top_builddir)/utils/libutils.la

if WITH_GLUSTER
lib_LTLIBRARIES = libgluster_handler.la

libgluster_handler_la_LIBADD = $(GFAPI_LIBS) $(GLIB2_LIBS) $(TIRPC_LIBS)       \
                               $(top_builddir)/utils/libutils.la

libgluster_handler_la_LDFLAGS = -avoid-version -rdynamic

libgluster_handler_la_CFLAGS = $(GFAPI_CFLAGS) $(GLIB2_CFLAGS) $(TIRPC_CFLAGS) \
                               -I$(top_builddir)/ -I$(top_builddir)/utils      \
                               -I$(top_builddir)/daemon -I$(top_srcdir)/rpc

libgluster_handler_la_SOURCES = gluster.c
endif

DISTCLEANFILES = Makefile.in

CLEANFILES = *~
