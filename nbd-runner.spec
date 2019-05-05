%define _unpackaged_files_terminate_build 0

# without glusterfs dependency
# if you wish to exclude gluster handler in RPM, use below command
# rpmbuild -ta @PACKAGE_NAME@-@PACKAGE_VERSION@.tar.gz --without gluster
%{?_without_gluster:%global _without_gluster --with-gluster=no}

# without tirpc dependency
# if you wish to build without tirpc library, use below command
# rpmbuild -ta @PACKAGE_NAME@-@PACKAGE_VERSION@.tar.gz --without tirpc
%{?_without_tirpc:%global _without_tirpc --with-tirpc=no}

%if ( 0%{?fedora} && 0%{?fedora} <= 27 ) || ( 0%{?rhel} && 0%{?rhel} <= 7 )
%global _without_tirpc --with-tirpc=no
%endif

Name:          nbd-runner
Summary:       A daemon that handles the NBD device's IO requests in server side
License:       LGPLv2+
Version:       0.3
Release:       1%{?dist}
URL:           https://github.com/gluster/nbd-runner.git

Source:        https://github.com/gluster/nbd-runner/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: kmod-devel
BuildRequires: libnl3-devel
BuildRequires: libevent-devel
BuildRequires: glib2-devel
BuildRequires: json-c-devel

%if ( 0%{!?_without_tirpc:1} )
BuildRequires: libtirpc-devel
BuildRequires: rpcgen
Requires:      libtirpc
%endif

Requires:      kmod
Requires:      json-c
Requires:      rsyslog

%description
A daemon that handles the userspace side of the NBD(Network Block Device)
backstore.

%if ( 0%{!?_without_gluster:1} )
%package gluster-handler
Summary:       Gluster backstore handler
BuildRequires: glusterfs-api-devel
Requires:      glusterfs-api
Requires:      %{name} = %{version}-%{release}

%description gluster-handler
Gluster backend handler for processing IO requests from the NBD device.
%endif

%prep
%setup -q -n %{name}-%{version}

%build
./autogen.sh
%configure %{?_without_tirpc} %{?_without_gluster}
%make_build

%install
%make_install

%files
%{_sbindir}/nbd-runner
%{_sbindir}/nbd-cli
%{_unitdir}/nbd-runner.service
%{_mandir}/man8/nbd-*.8.*
%doc README.md
%license COPYING-GPLV2 COPYING-LGPLV3
%config(noreplace) %{_sysconfdir}/sysconfig/nbd-runner

%if ( 0%{!?_without_gluster:1} )
%files gluster-handler
%dir %{_libdir}/nbd-runner/
%{_libdir}/nbd-runner/libgluster_handler.so
%endif

%changelog
* Wed Apr 24 2019 Xiubo Li <xiubli@redhat.com> - 0.3-1
- Initial package
