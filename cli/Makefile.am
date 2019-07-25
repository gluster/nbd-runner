sbin_PROGRAMS = nbd-cli

nbd_cli_SOURCES = nbd-cli.c nbd-cli-cmd.c nbd-cli-gluster.c nbd-cli-azblk.c

noinst_HEADERS = nbd-cli-cmd.h nbd-netlink.h

nbd_cli_CFLAGS = $(KMOD_CFLAGS) $(LIBNL3_CFLAGS) $(TIRPC_CFLAGS)        \
                 $(GLIB2_CFLAGS) $(JSONC_CFLAGS) -I$(top_builddir)      \
                 -I$(top_srcdir)/utils -I$(top_srcdir)/rpc

nbd_cli_LDADD = $(KMOD_LIBS) $(LIBNL3_LIBS) $(TIRPC_LIBS) $(JSONC_LIBS) \
                $(GLIB2_LIBS) $(top_builddir)/rpc/libnbdrpcxdr.la       \
                $(top_builddir)/utils/libutils.la 

DISTCLEANFILES = Makefile.in

CLEANFILES = *~

