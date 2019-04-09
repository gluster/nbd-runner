sbin_PROGRAMS = nbd-runner

nbd_runner_SOURCES = nbd-runner.c nbd-svc-routines.c

nbd_runner_CFLAGS = $(EVENT_CFLAGS) $(GLIB2_CFLAGS) $(TIRPC_CFLAGS)     \
                    -DNBD_RUNNER_LIBDIR=\"$(NBD_RUNNER_LIBDIR)\"        \
                    $(JSONC_CFLAGS)	-I$(top_srcdir)/rpc                 \
                    -I$(top_builddir)/ -I$(top_srcdir)/utils/

nbd_runner_LDADD = $(PTHREAD) $(EVENT_LIBS) $(GLIB2_LIBS) -ldl          \
                   $(TIRPC_LIBS) $(JSONC_LIBS)							\
                   $(top_builddir)/rpc/libnbdrpcxdr.la    				\
                   $(top_builddir)/utils/libutils.la 

lib_LTLIBRARIES = libgluster_handler.la

libgluster_handler_la_LDFLAGS = $(GFAPI_LIBS) $(GLIB2_LIBS) $(TIRPC_CFLAGS)
libgluster_handler_la_LIBADD = $(top_builddir)/utils/libutils.la 
libgluster_handler_la_CFLAGS = $(GFAPI_CFLAGS) $(GLIB2_CFLAGS) $(TIRPC_LIBS)   \
                              -I$(top_builddir)/ -I$(top_builddir)/utils       \
                              -I$(top_builddir)/daemon -I$(top_srcdir)/rpc

libgluster_handler_la_SOURCES = gluster.c

DISTCLEANFILES = Makefile.in

CLEANFILES = *~
