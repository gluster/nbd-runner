dnl  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
dnl  This file is part of nbd-runner.
dnl
dnl  This file is licensed to you under your choice of the GNU Lesser
dnl  General Public License, version 3 or any later version (LGPLv3 or
dnl  later), or the GNU General Public License, version 2 (GPLv2), in all
dnl  cases as published by the Free Software Foundation.

AC_PREREQ([2.69])
AC_INIT([nbd-runner],
        m4_esyscmd(echo -n $(cat VERSION 2>/dev/null || git describe --always --tags | cut -f2 -d'v' | cut -f1 -d'-')),
        [xiubli@redhat.com],,
        [https://github.com/gluster/nbd-runner.git])

AC_SUBST([PACKAGE_RELEASE], 1)

AC_ARG_WITH(systemddir,
            AC_HELP_STRING([--with-systemddir=DIR],
                           [systemd service files in DIR @<:@PREFIX/lib/systemd/system@:>@]),
            [systemddir=$withval],
            [systemddir='${prefix}/lib/systemd/system'])
AC_SUBST(systemddir)
AM_CONDITIONAL([USE_SYSTEMD], test [ -d '/usr/lib/systemd/system' ])

AC_ARG_WITH(initddir,
            AC_HELP_STRING([--with-initddir=DIR],
                           [initd service files in DIR @<:@/etc/rc.d/init.d@:>@]),
            [initddir=$withval],
            [initddir='/etc/rc.d/init.d'])
AC_SUBST(initddir)

AC_ARG_WITH(sysconfigdir,
            AC_HELP_STRING([--with-sysconfigdir=DIR],
                           [system service configuration in DIR @<:@/etc/sysconfig@:>@]),
            [sysconfigdir=$withval],
            [sysconfigdir='/etc/sysconfig'])
AC_SUBST(sysconfigdir)

PKG_CHECK_MODULES([JSONC], [json-c],,
                  [AC_MSG_ERROR([json-c library is required to build nbd-runner])])
AC_SUBST(JSONC_CFLAGS)
AC_SUBST(JSONC_LIBS)  

PKG_CHECK_MODULES(KMOD, [libkmod],,
                  [AC_MSG_ERROR([kmod library is required to build nbd-runner])])
AC_SUBST(KMOD_CFLAGS)
AC_SUBST(KMOD_LIBS)

PKG_CHECK_MODULES(EVENT, [libevent],,
                  [AC_MSG_ERROR([libevent library is required to build nbd-runner])])
AC_SUBST(EVENT_CFLAGS)
AC_SUBST(EVENT_LIBS)

PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= 2.26.0 gthread-2.0 >= 2.26.0],,
                  AC_MSG_ERROR([glib2 library is required to build nbd-runner]))
AC_SUBST(GLIB2_CFLAGS)
AC_SUBST(GLIB2_LIBS)

PKG_CHECK_MODULES(LIBNL3, [libnl-genl-3.0 >= 3.1],,
                  AC_MSG_ERROR([libnl3 library is required to build nbd-runner]))
AC_SUBST(LIBNL3_CFLAGS)
AC_SUBST(LIBNL3_LIBS)

AC_ARG_WITH([tirpc],
    [AS_HELP_STRING([--with-tirpc], [do use tirpc, default yes])],
    [with_tirpc=$withval],
    [with_tirpc=missing])

if test "x$with_tirpc" == "xyes" || test "x$with_tirpc" == "xmissing"; then
    PKG_CHECK_MODULES(TIRPC, [libtirpc >= 1.0.0],
        [with_tirpc="yes" AC_DEFINE(HAVE_TIRPC, 1, [Define to 1 if we have tirpc support])],
        [with_tirpc="no" AC_DEFINE(HAVE_TIRPC, 0)
	 AC_MSG_ERROR([Missing libtirpc or libtirpc is too old, please try to use glibc])])

    AC_SUBST(TIRPC_CFLAGS)
    AC_SUBST(TIRPC_LIBS)
else
    with_tirpc="no"
    AC_DEFINE(HAVE_TIRPC, 0, [Define to 1 if we have tirpc support])
fi

# Checks for libraries.
AC_ARG_WITH([gfapi6],
    [AS_HELP_STRING([--with-gfapi6], [do use new glfs APIs, default yes])],
    [with_gfapi6=$withval],
    [with_gfapi6=missing])

if test "x$with_gfapi6" == "xyes" || test "x$with_gfapi6" == "xmissing"; then
    # glusterfs-api versions have a prefix of "7."
    PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.6],
        [with_gfapi6="yes" AC_DEFINE(GFAPI_VER6, 1, [Define to 1 if we have gfapi library >= 6.0 support])],
        [with_gfapi6="no" AC_DEFINE(GFAPI_VER6, 0) AC_MSG_ERROR([gfapi library >= 6.0 is required to build nbd-runner])])
    AC_SUBST(GFAPI_CFLAGS)
    AC_SUBST(GFAPI_LIBS)
else
    PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.4.1],,
                      [AC_MSG_ERROR([gfapi library >= 4.1 is required to build nbd-runner])])
    AC_SUBST(GFAPI_CFLAGS)
    AC_SUBST(GFAPI_LIBS)
fi

AC_CHECK_LIB([pthread], [pthread_mutex_init],[PTHREAD="-lpthread"],
             AC_MSG_ERROR([Posix threads library is required to build nbd-runner]))
AC_SUBST(PTHREAD)

AM_INIT_AUTOMAKE([-Wall -Werror foreign nostdinc silent-rules])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 rpc/Makefile
                 cli/Makefile
                 daemon/Makefile
                 utils/Makefile])

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AM_MAINTAINER_MODE

# Configure libtool
LT_INIT

# Checks for programs.
AC_PROG_CC

# For legacy reasons.
AM_PROG_CC_C_O

AC_CHECK_PROG(RPCGEN, rpcgen, yes, no)
if test "x$RPCGEN" = "xno"; then
  AC_MSG_ERROR([rpcgen not found, needed for building])
fi

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h stdbool.h stddef.h libkmod.h \
                  unistd.h errno.h memory.h time.hnetdb.h sys/utsname.h  \
                  netdb.h netinet/in.h sys/socket.h sys/socket.h netinet/in.h \
                  pthread.h sys/utsname.h glusterfs/api/glfs.h netlink/netlink.h \
                  rpc/pmap_clnt.h inttypes.h fcntl.h linux/nbd.h signal.h glib.h \
		  rpc/rpc.h])

# Dirty hacky stuff to make STATEDIR work
if test "x$prefix" = xNONE; then
   test $localstatedir = '${prefix}/var' && localstatedir=$ac_default_prefix/var
   localstatedir=/var
fi

localstatedir="$(eval echo ${localstatedir})"
LOCALSTATEDIR=${localstatedir}

GLUSTER_BLOCKD_WORKDIR="${LOCALSTATEDIR}/lib/nbd-runner"
AC_SUBST(GLUSTER_BLOCKD_WORKDIR)

if test "x$prefix" = xNONE; then
   test $libexecdir = '${prefix}/libexec' && localstatedir=$ac_default_prefix/libexec
   libexecdir=/usr/libexec
fi

GLUSTER_BLOCKD_LIBEXECDIR="$(eval echo ${libexecdir}/nbd-runner)"
AC_SUBST(GLUSTER_BLOCKD_LIBEXECDIR)

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_STRTOD
AC_CHECK_FUNCS([gethostbyname memset socket strchr strdup strerror])
AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Use TIRPC......: $with_tirpc
  Use GFAPI6.....: $with_gfapi6
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
