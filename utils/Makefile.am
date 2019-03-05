noinst_LTLIBRARIES = libutils.la

libutils_la_SOURCES = utils.c

noinst_HEADERS = utils.h nbd-log.h

libutils_la_CFLAGS = $(TIPRC_CFLAGS) -DDATADIR=\"$(localstatedir)\"    \
		  			 -DCONFDIR=\"$(NBD_RUNNER_WORKDIR)\"	   		   \
		  			 -I$(top_builddir)/ -I$(top_builddir)/rpc

libutils_ladir = $(includedir)/utils

DISTCLEANFILES = Makefile.in
CLEANFILES = *~
