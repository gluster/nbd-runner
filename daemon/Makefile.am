sbin_PROGRAMS = nbd-runner

nbd_runner_SOURCES = nbd-runner.c nbd-svc-routines.c gluster.c

nbd_runner_CFLAGS = $(GFAPI_CFLAGS) $(EVENT_CFLAGS) $(GLIB2_CFLAGS) 	\
                    $(TIRPC_CFLAGS) -DDATADIR=\"$(localstatedir)\"      \
                    -I$(top_builddir)/ -I$(top_srcdir)/utils/           \
                    -I$(top_srcdir)/rpc

nbd_runner_LDADD = $(PTHREAD) $(GFAPI_LIBS) $(EVENT_LIBS) $(GLIB2_LIBS) \
                   $(TIRPC_LIBS) $(top_builddir)/rpc/libnbdrpcxdr.la    \
                   $(top_builddir)/utils/libutils.la 

DISTCLEANFILES = Makefile.in

CLEANFILES = *~
