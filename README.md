# nbd-runner

A daemon that handles the userspace side of the NBD(Network Block Device) backstore.

# nbd-cli

A cli utility, which aims at making Gluster backed file creation/deletion/mapping/unmaping/listing.

## License
nbd-runner is licensed to you under your choice of the GNU Lesser General Public License, version 3 or any later version ([LGPLv3](https://opensource.org/licenses/lgpl-3.0.html) or later), or the GNU General Public License, version 2 ([GPLv2](https://opensource.org/licenses/GPL-2.0)), in all cases as published by the Free Software Foundation.

## Gluster
[Gluster](http://gluster.readthedocs.io/en/latest/) is a well known scale-out distributed storage system, flexible in its design and easy to use. One of its key goals is to provide high availability of data. Gluster is very easy to setup and use. Addition and removal of storage servers from a Gluster cluster is intuitive. These capabilities along with other data services that Gluster provides makes it a reliable software defined storage platform.

> A unique distributed storage solution build on traditional filesystems

### How we provide block storage in gluster ?

1. Create a file in the gluster volume
2. We expose the file in the gluster volume as NBD device using nbd-runner, exporting the target file as block device in /dev/nbdXX

### Install
------
<pre>
# git clone https://github.com/gluster/nbd-runner.git
# cd nbd-runner/
# dnf install autoconf automake libtool glusterfs-api-devel kmod-devel libnl3-devel libevent-devel glib2-devel
# ./autogen.sh
# ./configure [--with-tirpc=yes] # glibc >= 2.26
# make -j
# make install
#
# NOTE: Glibc has removed the rpc functions from the [2.26 release](https://sourceware.org/ml/libc-alpha/2017-08/msg00010.html). Instead of relying on glibc providing these, the modern libtirpc library should be used instead. For the old glibc version or some distribute we will still use the glibc instead.
</pre>

### Usage
------
**Prerequisites:** *this guide assumes that the following are already present*
- [x] *A gluster volume with name 'vol-test'*
- [x] *Open 24007(for glusterd) 24110 and 24111(nbd-runnerd) 111(rpcbind) ports and glusterfs service in your firewall*

<b>Daemon</b>: run nbd-runner on the node where you can access the gluster through gfapi
```script
# nbd-runner
```

<b>CLI</b>: you can choose to run nbd-cli from any node where the newer nbd.ko module is availible
```script
# nbd-runner help
Usage:
	nbd-runner [<args>]

Commands:
	help
		display help for nbd-runner command

	threads <NUM>
		specify the IOs threads number

	host <LISTEN_HOST>
		specify the listenning IP for new comming map opt

	version
		show version info and exit.



# nbd-cli help
Usage:
	nbd <command> [<args>]

Commands:
	help
		display help for nbd commands

	create <volname@host:/path> [prealloc] <size SIZE> <host HOST>
		create path file on the volname volume, prealloc is false as default,
		and the SIZE is valid with B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB)

	delete <volname@host:/path> <host HOST>
		delete path file on the volname volume

	map <volname@host:/path> [nbd-device] [threads NUM] [timeout TIME] <host HOST> [readonly]
		map path file to the nbd device, as default the threads 4, timeout 0, none readonly

	umap <nbd-device>
		umap the nbd device

	list <map|umap|all>
		list the mapped|umapped|all nbd devices, all as default

	version
		show version info and exit.

	<host HOST> means the RPC server IP.
```

# TODO:

1. add systemd service support
2. split the gluster code as one separate handler
3. add logger file support
4. add sysconfig file support
5. add 'nbd-cli list <map|umap|create|all>'
6. ...
