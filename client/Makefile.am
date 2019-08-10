sbin_PROGRAMS = nbd-cli nbd-clid

noinst_HEADERS = nbd-netlink.h nbd-cli-common.h ipc.h

nbd_cli_SOURCES = nbd-cli.c nbd-cli-common.c gluster.c azblk.c ipc.c
nbd_clid_SOURCES = nbd-clid.c nbd-cli-common.c ipc.c

nbd_cli_CFLAGS = $(KMOD_CFLAGS) $(LIBNL3_CFLAGS) $(TIRPC_CFLAGS)        \
                 $(GLIB2_CFLAGS) $(JSONC_CFLAGS) -I$(top_builddir)      \
                 -I$(top_srcdir)/utils -I$(top_srcdir)/rpc

nbd_cli_LDADD = $(KMOD_LIBS) $(LIBNL3_LIBS) $(TIRPC_LIBS) $(JSONC_LIBS) \
                $(GLIB2_LIBS) $(top_builddir)/rpc/libnbdrpcxdr.la       \
                $(top_builddir)/utils/libutils.la 

nbd_clid_CFLAGS = $(KMOD_CFLAGS) $(LIBNL3_CFLAGS) $(TIRPC_CFLAGS)        \
                  $(GLIB2_CFLAGS) $(JSONC_CFLAGS) -I$(top_builddir)      \
                  -I$(top_srcdir)/utils -I$(top_srcdir)/rpc

nbd_clid_LDADD = $(KMOD_LIBS) $(LIBNL3_LIBS) $(TIRPC_LIBS) $(JSONC_LIBS) \
                 $(GLIB2_LIBS) $(top_builddir)/rpc/libnbdrpcxdr.la       \
                 $(top_builddir)/utils/libutils.la 

DISTCLEANFILES = Makefile.in

CLEANFILES = *~

