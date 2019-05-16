libnbdrpcxdr_la_SOURCES = rpc_nbd_clnt.c rpc_nbd_xdr.c rpc_nbd_svc.c

noinst_LTLIBRARIES = libnbdrpcxdr.la
noinst_HEADERS = rpc_nbd.h rpc_nbd_svc.h rpc-pragmas.h

EXTRA_DIST = rpc_nbd.x
BUILT_SOURCES = rpc_nbd.h rpc_nbd_clnt.c rpc_nbd_svc.c rpc_nbd_xdr.c

libnbdrpcxdr_la_CFLAGS = $(TIRPC_CFLAGS)
libnbdrpcxdr_la_LDFLAGS = $(TIRPC_LIBS)

DISTCLEANFILES = Makefile.in $(BUILT_SOURCES)
CLEANFILES = *~ $(BUILT_SOURCES)

rpc_nbd.h: rpc_nbd.x
	rpcgen -hM -o $(top_builddir)/rpc/$@ $^

rpc_nbd_xdr.c: rpc_nbd.x
	rpcgen -cM -o $(top_builddir)/rpc/$@ $^

rpc_nbd_clnt.c: rpc_nbd.x
	rpcgen -lM -o $(top_builddir)/rpc/$@ $^
	$(SED) -i 's|TIMEOUT = { 25, 0 }|TIMEOUT = { 300, 0 }|'  \
	    $(top_builddir)/rpc/$@

rpc_nbd_svc.c: rpc_nbd.x
	rpcgen -mM -o $(top_builddir)/rpc/$@ $^

dist-hook:
	find $(distdir) -type f -not -name 'rpc_nbd.x'            \
	    -not -name 'rpc-pragmas.h' -not -name 'rpc_nbd_svc.h' \
	    -not -name 'Makefile.*' -delete
