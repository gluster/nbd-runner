ACLOCAL_AMFLAGS = -I m4

SUBDIRS = rpc utils client server handlers

EXTRA_DIST = autogen.sh README.md COPYING-GPLV2 COPYING-LGPLV3     \
			 INSTALL nbd-runner.sysconfig.in nbd-runner.service.in \
			 nbd-clid.service.in build-aux/pkg-version nbd-runner.8\
			 nbd-cli.8

systemd_DATA = nbd-runner.service nbd-clid.service

man8_MANS = nbd-runner.8 nbd-cli.8 nbd-clid.8

install-data-local:
	$(mkdir_p) $(DESTDIR)${sysconfigdir}
	$(INSTALL_DATA) nbd-runner.sysconfig.in $(DESTDIR)${sysconfigdir}/nbd-runner
	$(INSTALL_DATA) nbd-clid.sysconfig.in $(DESTDIR)${sysconfigdir}/nbd-clid
	$(mkdir_p) $(DESTDIR)${NBD_LOG_DIR_DEFAULT}
	touch $(DESTDIR)$(NBD_LOG_DIR_DEFAULT)/nbd-runner.log
	touch $(DESTDIR)$(NBD_LOG_DIR_DEFAULT)/nbd-clid.log
	touch $(DESTDIR)$(NBD_LOG_DIR_DEFAULT)/nbd-runner-glfs.log


uninstall-local:
	rm -f $(DESTDIR)${sysconfigdir}/nbd-runner
	rm -f $(DESTDIR)${sysconfigdir}/nbd-cli
	rm -f $(DESTDIR)${sysconfigdir}/nbd-clid
	rm -f $(DESTDIR)${systemddir}/nbd-runner.service
	rm -f $(DESTDIR)${systemddir}/nbd-clid.service

distclean-local:
	rm -rf Makefile.in autom4te.cache nbd-runner.service nbd-clid.service

gitclean: clean distclean
	find . -path gnulib -prune -name Makefile.in -exec rm -f {} \;
	find . -path gnulib -prune -name Makefile -exec rm -f {} \;
	rm -f aclocal.m4 compile config.* configure depcomp install-sh libtool \
		ltmain.sh missing stamp-h1
	rm -rf autom4te.cache ar-lib *.tar.gz m4

dist-hook: gen-VERSION gen-ChangeLog
	cp -f $(top_srcdir)/build-aux/config.sub.dist $(distdir)/config.sub
	cp -f $(top_srcdir)/build-aux/config.guess.dist $(distdir)/config.guess

.PHONY: gen-ChangeLog gen-VERSION

gen-ChangeLog:
	(cd $(srcdir) && git diff && echo ===== git log ==== && git log) > $(distdir)/ChangeLog

gen-VERSION:
	if test -d $(top_srcdir)/.git; then                                            \
		cd $(top_srcdir);                                                          \
		./build-aux/pkg-version --full > $(abs_top_builddir)/$(distdir)/VERSION;   \
	fi
