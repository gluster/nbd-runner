ACLOCAL_AMFLAGS = -I m4

SUBDIRS = rpc utils cli daemon

DISTCLEANFILES = Makefile.in autom4te.cache

EXTRA_DIST = autogen.sh README.md COPYING-GPLV2 COPYING-LGPLV3 \
			 INSTALL nbd-runner.sysconfig

if USE_SYSTEMD
RPM_WITH_FLAGS = --with systemd
else
RPM_WITH_FLAGS = --with initd
endif

install-data-local:
	$(MKDIR_P) $(DESTDIR)${sysconfigdir};        \
	$(INSTALL_DATA) nbd-runner.sysconfig         \
	$(DESTDIR)${sysconfigdir}/nbd-runner;

uninstall-local:
	cd $(DESTDIR)$(bindir) && rm -f nbd-runner nbd-cli \
	rm -f $(DESTDIR)${sysconfigdir}/nbd-runner

gitclean: clean distclean
	find . -path gnulib -prune -name Makefile.in -exec rm -f {} \;
	find . -path gnulib -prune -name Makefile -exec rm -f {} \;
	rm -f aclocal.m4 compile config.* configure depcomp install-sh libtool \
		ltmain.sh missing stamp-h1
	rm -rf autom4te.cache ar-lib *.tar.gz m4

dist-hook: gen-ChangeLog gen-VERSION

.PHONY: gen-ChangeLog gen-VERSION

gen-ChangeLog:
	(cd $(srcdir) && git diff && echo ===== git log ==== && git log) > $(distdir)/ChangeLog

gen-VERSION:
	(cd $(srcdir) && git describe --always --tags | cut -f2 -d'v' | cut -f1 -d'-') > $(distdir)/VERSION
