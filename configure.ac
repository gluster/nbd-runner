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

AC_ARG_WITH(systemddir,
            AC_HELP_STRING([--with-systemddir=DIR],
                           [systemd service files in DIR @<:@PREFIX/lib/systemd/system@:>@]),
            [systemddir=$withval],
            [systemddir='${prefix}/lib/systemd/system'])
AC_SUBST(systemddir)
AM_CONDITIONAL([USE_SYSTEMD], test [ -d '/usr/lib/systemd/system' ])

if test "x$prefix" = xNONE; then
	test $localstatedir = '${prefix}/var' && localstatedir=$ac_default_prefix/var
	localstatedir=/var
fi

localstatedir="$(eval echo ${localstatedir})"

AC_DEFINE_UNQUOTED(NBD_LOG_DIR_DEFAULT, ["/var/log/nbd-runner"], [The default log directory])
NBD_LOG_DIR_DEFAULT="/var/log/nbd-runner"
AC_SUBST(NBD_LOG_DIR_DEFAULT)

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

AC_ARG_WITH([azblk],
            [AS_HELP_STRING([--with-azblk=ARG], [Enable/Disable azblk handler, default ARG=yes])],
            [with_azblk=$withval],
            [with_azblk=yes])

AM_CONDITIONAL([WITH_AZBLK], [test x$with_azblk = xyes])

if test "x$with_azblk" = "xyes"; then
    PKG_CHECK_MODULES(CURL, [libcurl],,
                  [AC_MSG_ERROR([libcurl library is required to build nbd-runner])])
    AC_SUBST(CURL_CFLAGS)
    AC_SUBST(CURL_LIBS)

    PKG_CHECK_MODULES(UV, [libuv],,
                  [AC_MSG_ERROR([libuv library is required to build nbd-runner])])
    AC_SUBST(UV_CFLAGS)
    AC_SUBST(UV_LIBS)
fi

AC_ARG_WITH([clang],
    [AS_HELP_STRING([--with-clang=ARG], [do use clang, default ARG=no])],
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
    [AS_HELP_STRING([--with-tirpc=ARG], [do use tirpc, default ARG=yes])],
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

# This is only used for the travis build
AC_ARG_WITH([travis],
            [AS_HELP_STRING([--with-travis=ARG], [Enable/Disable travis build, default ARG=no])],
            [with_travis=$withval],
            [with_travis=no])

# Checks for libraries.
AC_ARG_WITH([gluster],
            [AS_HELP_STRING([--with-gluster=ARG], [Enable/Disable gluster handler, default ARG=yes])],
            [with_gluster=$withval],
            [with_gluster=yes])

AM_CONDITIONAL([WITH_GLUSTER], [test x$with_gluster = xyes])

if test "x$with_gluster" = "xyes"; then
    if test "$with_travis" = "yes"; then
        # glusterfs-api versions have a prefix of "7."
        PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.6],
                          [AC_DEFINE(GFAPI_VERSION760, 1, [Define to 1 if gfapi >=7.6.0])],
                          [PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.3.6],,
                                             [AC_MSG_ERROR([gfapi library >= 3.6 is required to build nbd-runner])])])
    else
        # glusterfs-api versions have a prefix of "7."
        PKG_CHECK_MODULES([GFAPI], [glusterfs-api >= 7.6.6],
                          [AC_DEFINE(GFAPI_VERSION766, 1, [Define to 1 if gfapi >=7.6.6])],
                          [AC_MSG_ERROR([gfapi library >= 6.6 is required to build nbd-runner])])
    fi
    AC_SUBST(GFAPI_CFLAGS)
    AC_SUBST(GFAPI_LIBS)
fi

AC_CHECK_LIB([pthread], [pthread_mutex_init],[PTHREAD="-lpthread"],
             AC_MSG_ERROR([Posix threads library is required to build nbd-runner]))
AC_SUBST(PTHREAD)

AM_INIT_AUTOMAKE([tar-pax foreign -Werror -Wall -Wno-portability])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])
if make --help 2>&1 | grep -q no-print-directory; then
    AM_MAKEFLAGS="$AM_MAKEFLAGS --no-print-directory"
fi
AC_SUBST(AM_MAKEFLAGS)

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 nbd-runner.service
                 nbd-clid.service
                 rpc/Makefile
                 client/Makefile
                 server/Makefile
                 handlers/Makefile
                 utils/Makefile])

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC

AC_CHECK_PROG(RPCGEN, rpcgen, yes, no)
if test "x$RPCGEN" = "xno"; then
  AC_MSG_ERROR([rpcgen not found, needed for building])
fi

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h stdbool.h stddef.h libkmod.h \
                  unistd.h errno.h memory.h time.h netdb.h sys/utsname.h  \
                  netdb.h netinet/in.h sys/socket.h sys/socket.h netinet/in.h \
                  pthread.h sys/utsname.h glusterfs/api/glfs.h netlink/netlink.h \
                  rpc/pmap_clnt.h inttypes.h fcntl.h linux/nbd.h signal.h glib.h \
                  rpc/rpc.h])

LOCAL_ARCH="$(eval uname -p)"
libdir_bit=lib64
if test "x$LOCAL_ARCH" = "xi686" -o "x$LOCAL_ARCH" = "xarmv7l"; then
    libdir_bit=lib
fi

libdir=$ac_default_prefix/$libdir_bit/nbd-runner
if test "x$prefix" != xNONE; then
    libdir=$prefix/$libdir_bit/nbd-runner
fi
NBD_RUNNER_LIBDIR="$(eval echo ${libdir})"
AC_SUBST(NBD_RUNNER_LIBDIR)

AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix............: $prefix
  Gluster handler...: $with_gluster
  Azblk handler.....: $with_azblk
  Use TIRPC.........: $with_tirpc
  Travis build......: $with_travis
  C Compiler........: $CC $CFLAGS $CPPFLAGS
  Linker............: $LD $LDFLAGS $LIBS
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
