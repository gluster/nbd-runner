noinst_LTLIBRARIES = libutils.la

libutils_la_SOURCES = utils.c time.c nbd-sysconfig.c strlcpy.c \
                      nbd-log.c socket.c

noinst_HEADERS = utils.h nbd-log.h nbd-sysconfig.h strlcpy.h list.h

libutils_la_CFLAGS = $(TIRPC_CFLAGS) $(GLIB2_CFLAGS)            \
                     -I$(top_builddir)/ -I$(top_builddir)/rpc   \
                     -I$(top_builddir)/daemon

libutils_la_LIBADD = $(TIRPC_LIBS) $(GLIB2_LIBS)

libutils_ladir = $(includedir)/utils

DISTCLEANFILES = Makefile.in
CLEANFILES = *~
