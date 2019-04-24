#!/bin/sh

if [ "$1" == "--help" -o "$1" == "help" ]; then
	echo ""
	echo "  USAGE:"
	echo ""
	echo "  # cd nbd-runner/extra/"
	echo "  # ./make_runnerrpms.sh [--without (tirpc|gluster)]"
	echo ""
	echo "  Will build the RPMs in current dir by using the HEAD commit ID as default."
	echo ""
	exit
fi

TOPDIR=`pwd`/../

if [ ! -e $TOPDIR/.git ]; then
	echo ""
	echo "For now this will only support the git repo code."
	echo ""
	exit
fi

VERSION=`git describe --tags --match "v[0-9]*"`
VERSION=`echo $VERSION | awk -F'-' '{print $1}'`
VERSION=`echo $VERSION | sed "s/v//"`

RELEASE=`git describe --tags --match "v[0-9]*"`
RELEASE=`echo $RELEASE | awk -F'-' '{print $2"."$3}'`
NBDRUNNER_TAR=nbd-runner-$VERSION.tar.gz
rpmbuild_path=`pwd`/rpmbuild

# Try to clear the old rpmbuild data.
if [ -e $rpmbuild_path ]; then
	rm -rf $rpmbuild_path/*
fi

mkdir -p $rpmbuild_path/BUILD
mkdir -p $rpmbuild_path/SPECS
mkdir -p $rpmbuild_path/RPMS
mkdir -p $rpmbuild_path/SRPMS
mkdir -p $rpmbuild_path/SOURCES

cp $TOPDIR/nbd-runner.spec.in $rpmbuild_path/SPECS/nbd-runner.spec
SPEC=$rpmbuild_path/SPECS/nbd-runner.spec

# Replace the Version
sed -i "s/Version:.*$/Version:       ${VERSION}/" $SPEC
sed -i "s/Release:.*$/Release:       ${RELEASE}%{dist}/" $SPEC

# Generate the source package
TMPDIR=/tmp/nbd-runner-build
PKG_NAME=nbd-runner-$VERSION
mkdir -p $TMPDIR/$PKG_NAME
git clone $TOPDIR/.git $TMPDIR/$PKG_NAME
rm -rf $TMPDIR/$PKG_NAME/.git*
cd $TMPDIR
tar -czvf $rpmbuild_path/SOURCES/$NBDRUNNER_TAR $PKG_NAME 2&> /dev/null
cd $TOPDIR/extra
rm -rf $TMPDIR

# Build the RPMs
rpmbuild --define="_topdir $rpmbuild_path" -ba $SPEC "$@"
