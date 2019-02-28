sbin_PROGRAMS = nbd-cli

nbd_cli_SOURCES = nbd-cli.c

nbd_cli_CFLAGS = $(KMOD_CFLAGS) $(LIBNL3_CFLAGS) -DDATADIR=\"$(localstatedir)\"         \
                        -I$(top_builddir)/ -I$(top_srcdir)/utils/              \
                        -I$(top_srcdir)/rpc

nbd_cli_LDADD = $(KMOD_LIBS) $(LIBNL3_LIBS) $(top_builddir)/rpc/libgbrpcxdr.la \
				   $(top_builddir)/utils/libutils.la 

DISTCLEANFILES = Makefile.in

CLEANFILES = *~

