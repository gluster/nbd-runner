# nbd-runner

A daemon that handles the userspace side of the NBD(Network Block Device) backstore.

# nbd-cli

A cli utility, which aims at making Gluster backed file creation/deletion/mapping/unmaping/listing.

## License
nbd-runner is licensed to you under your choice of the GNU Lesser General Public License, version 3 or any later version ([LGPLv3](https://opensource.org/licenses/lgpl-3.0.html) or later), or the GNU General Public License, version 2 ([GPLv2](https://opensource.org/licenses/GPL-2.0)), in all cases as published by the Free Software Foundation.

### Install
------
<pre>
# git clone https://github.com/gluster/nbd-runner.git
# cd nbd-runner/
# dnf install autoconf automake libtool glusterfs-api-devel kmod-devel libnl3-devel libevent-devel glib2-devel libtirpc-devel
# ./autogen.sh
# ./configure # '--with-tirpc=no' means try to use legacy glibc, otherwise use libtirpc by default
# make -j
# make install
#
# NOTE: Glibc has removed the rpc functions from the [2.26 release](https://sourceware.org/ml/libc-alpha/2017-08/msg00010.html). Instead of relying on glibc providing these, the modern libtirpc library should be used instead. For the old glibc version or some distribute Linux we will still use the glibc instead to privide the RPC library.
</pre>

### Usage
------
**Prerequisites:** *this guide assumes that the following are already present*
- [x] *The kernel or the nbd.ko module must be new enough, which have add the netlink feature supported*
- [x] *Open 24110 and 24111(nbd-runnerd) 111(rpcbind) ports in your firewall*

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
 gluster help		-display help for gluster commands
 ceph help		-display help for ceph commands, TODO
 global help		-display help for global commands, TODO
 version		-display the version of nbd-cli
```

## Gluster
[Gluster](http://gluster.readthedocs.io/en/latest/) is a well known scale-out distributed storage system, flexible in its design and easy to use. One of its key goals is to provide high availability of data. Gluster is very easy to setup and use. Addition and removal of storage servers from a Gluster cluster is intuitive. These capabilities along with other data services that Gluster provides makes it a reliable software defined storage platform.

> A unique distributed storage solution build on traditional filesystems

### How we provide block storage in gluster ?

**Prerequisites:** *this guide assumes that the following are already present*
- [x] *A gluster volume must be created/started first*
- [x] *Open 24007(for glusterd) port and glusterfs service in your firewall*

1. Create a volume in the gluster stoarge cluster.
2. Run the nbd-runner daemon in any of the gluster storage cluster node, or any other node that can access the gluster volume via the gfapi library.
   
    `# nbd-runner [<args>]`

3. Create one file in the volume by using the gluster cli tool or just use the 'nbd-cli gluster create' tool.

    `# mount.glusterfs HOST:/VOLUME /mnt && fallocate -l 1G /mnt/FILEPATH`

   or

    `# nbd-cli gluster create <VOLUME@HOST:/FILEPATH> [prealloc] <size SIZE> <host RPC_HOST>`

4. Map the file created in backstore gluster volume to the NBD device, you can specify one unmapped /dev/nbdXX or just ignore and the NBD.ko will allocate one for you.

    `# nbd-cli gluster map <VOLUME@HOST:/FILEPATH> [nbd-device] [timeout TIME] <host RPC_HOST> [readonly]`

5. You will see the mapped device returned, or you can check the mapped device:

    `# nbd-cli gluster list <map|unmap|all>`

6. We expose the file in the gluster volume as NBD device using nbd-runner, exporting the target file as block device in /dev/nbdXX

<b> Gluster CLI</b>: the gluster specified cli commands
```script
# nbd-cli gluster help
Usage: 

	gluster help
		display help for gluster commands
	gluster create <VOLUME@HOST:/FILEPATH> [prealloc] <size SIZE> <host RPC_HOST>
		create FILEPATH in the VOLUME, prealloc is false as default, and the SIZE is valid with B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB)
	gluster delete <VOLUME@HOST:/FILEPATH> <host RPC_HOST>
		delete FILEPATH from the VOLUME
	gluster map <VOLUME@HOST:/FILEPATH> [nbd-device] [timeout TIME] <host RPC_HOST> [readonly]
		map FILEPATH to the nbd device, as default the timeout 0, none readonly
	gluster unmap <nbd-device>
		unmap the nbd device
	gluster list [map|unmap|all] [host RPC_HOST]
		list the mapped|unmapped|all nbd devices, all as default, if the host is omit, it will only list the local nbd device info.
```
