noinst_LTLIBRARIES = libutils.la

libutils_la_SOURCES = utils.c time.c nbd-sysconfig.c

noinst_HEADERS = utils.h nbd-log.h nbd-sysconfig.h

libutils_la_CFLAGS = $(TIRPC_CFLAGS) $(GLIB2_CFLAGS)            \
                     -DDATADIR=\"$(localstatedir)\"             \
                     -DCONFDIR=\"$(NBD_RUNNER_WORKDIR)\"        \
                     -I$(top_builddir)/ -I$(top_builddir)/rpc

libutils_la_LIBADD = $(TIRPC_LIBS) $(GLIB2_LIBS)

libutils_ladir = $(includedir)/utils

DISTCLEANFILES = Makefile.in
CLEANFILES = *~
