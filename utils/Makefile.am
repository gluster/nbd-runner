noinst_LTLIBRARIES = libutils.la

libutils_la_SOURCES = utils.c time.c nbd-sysconfig.c strlcpy.c \
                      nbd-log.c socket.c timer.c

noinst_HEADERS = utils.h nbd-log.h nbd-sysconfig.h strlcpy.h

libutils_la_CFLAGS = $(TIRPC_CFLAGS) $(GLIB2_CFLAGS) $(LIBUV_CFLAGS)  \
                     -DDATADIR=\"$(localstatedir)\"                   \
                     -DCONFDIR=\"$(NBD_RUNNER_WORKDIR)\"              \
                     -I$(top_builddir)/ -I$(top_builddir)/rpc         \
                     -I$(top_builddir)/daemon

libutils_la_LIBADD = $(TIRPC_LIBS) $(GLIB2_LIBS) $(LIBUV_LIBS)

libutils_ladir = $(includedir)/utils

DISTCLEANFILES = Makefile.in
CLEANFILES = *~
