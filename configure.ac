dnl  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
dnl  This file is part of nbd-runner.
dnl
dnl  This file is licensed to you under your choice of the GNU Lesser
dnl  General Public License, version 3 or any later version (LGPLv3 or
dnl  later), or the GNU General Public License, version 2 (GPLv2), in all
dnl  cases as published by the Free Software Foundation.

AC_INIT([nbd-runner],
        [m4_esyscmd([build-aux/pkg-version --version])],
        [xiubli@redhat.com],,
        [https://github.com/gluster/nbd-runner.git])

AC_SUBST([PACKAGE_RELEASE],
         [m4_esyscmd([build-aux/pkg-version --release])])

CFLAGS="${CLFAGS} -Werror -Wall -Wdeclaration-after-statement"

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

AC_ARG_WITH([clang],
    [AS_HELP_STRING([--with-clang], [do use clang, default no])],
    [with_clang=$withval],
    [with_clang=no])

if test "x$with_clang" = "xyes"; then
    AC_CHECK_PROG(CLANG, clang, yes, no)
    if test "x$CLANG" = "xno"; then
        AC_MSG_ERROR([clang not found, needed for building])
    else
        CC="clang"
    fi
fi

AC_ARG_WITH([tirpc],
    [AS_HELP_STRING([--with-tirpc], [do use tirpc, default yes])],
    [with_tirpc=$withval],
    [with_tirpc=yes])

if test "x$with_tirpc" = "xyes"; then
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

AC_CHECK_LIB([dl], [dlopen], [LIB_DL=-ldl])                                                                                                                             
AC_SUBST(LIB_DL)

# Checks for libraries.
AC_ARG_WITH([gluster],
            [AS_HELP_STRING([--with-gluster], [Enable/Disable gluster handler, default yes])],
            [with_gluster=$withval],
            [with_gluster=yes])

AM_CONDITIONAL([WITH_GLUSTER], [test x$with_gluster = xyes])

if test "x$with_gluster" = "xyes"; then
    # glusterfs-api versions have a prefix of "7."
    PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.6],
                      [AC_DEFINE(GFAPI_VERSION760, 1, [Define to 1 if gfapi >=7.6.0])],
                      [PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.3.6],,
                                         [AC_MSG_ERROR([gfapi library >= 3.6 is required to build gluster-block])])])   
                      AC_SUBST(GFAPI_CFLAGS)
                      AC_SUBST(GFAPI_LIBS)
fi

AC_CHECK_LIB([pthread], [pthread_mutex_init],[PTHREAD="-lpthread"],
             AC_MSG_ERROR([Posix threads library is required to build nbd-runner]))
AC_SUBST(PTHREAD)

AM_INIT_AUTOMAKE([-Wall -Werror foreign nostdinc])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])
if make --help 2>&1 | grep -q no-print-directory; then
    AM_MAKEFLAGS="$AM_MAKEFLAGS --no-print-directory"
fi
AC_SUBST(AM_MAKEFLAGS)

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 rpc/Makefile
                 cli/Makefile
                 daemon/Makefile
                 handlers/Makefile
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

libdir=$ac_default_prefix/lib64/nbd-runner
if test "x$prefix" != xNONE; then
    libdir=$prefix/lib64/nbd-runner
fi
NBD_RUNNER_LIBDIR="$(eval echo ${libdir})"
AC_SUBST(NBD_RUNNER_LIBDIR)

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
  Prefix............: $prefix
  Gluster handler...: $with_gluster
  Use TIRPC.........: $with_tirpc
  C Compiler........: $CC $CFLAGS $CPPFLAGS
  Linker............: $LD $LDFLAGS $LIBS
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
