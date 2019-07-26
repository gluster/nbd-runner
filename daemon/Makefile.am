sbin_PROGRAMS = nbd-runner

nbd_runner_SOURCES = nbd-runner.c nbd-svc-routines.c

noinst_HEADERS = nbd-svc-routines.h

nbd_runner_CFLAGS = $(EVENT_CFLAGS) $(GLIB2_CFLAGS) $(TIRPC_CFLAGS)   \
                    $(JSONC_CFLAGS) -I$(top_srcdir)/rpc               \
                    -DNBD_RUNNER_LIBDIR=\"$(NBD_RUNNER_LIBDIR)\"      \
                    -I$(top_builddir)/ -I$(top_srcdir)/utils

nbd_runner_LDADD = $(PTHREAD) $(EVENT_LIBS) $(GLIB2_LIBS) $(LIB_DL)   \
                   $(TIRPC_LIBS) $(top_builddir)/utils/libutils.la    \
                   $(JSONC_LIBS) $(top_builddir)/rpc/libnbdrpcxdr.la

DISTCLEANFILES = Makefile.in

CLEANFILES = *~
