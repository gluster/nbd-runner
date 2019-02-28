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
# ./autogen.sh && ./configure && make -j && make install
</pre>

### Usage
------
**Prerequisites:** *this guide assumes that the following are already present*
- [x] *A gluster volume with name 'block-test'*
- [x] *Open 24007(for glusterd) 24110 and 24111(nbd-runnerd) 111(rpcbind) ports and glusterfs service in your firewall*

<b>Daemon</b>: run nbd-runnerd on all the nodes
```script
# nbd-runnerd --help
nbd-runnerd (0.3)
usage:
  nbd-runnerd [--glfs-lru-count <COUNT>]
                 [--log-level <LOGLEVEL>]
                 [--no-remote-rpc]

commands:
  --glfs-lru-count <COUNT>
        Glfs objects cache capacity [max: 512] [default: 5]
  --log-level <LOGLEVEL>
        Logging severity. Valid options are,
        TRACE, DEBUG, INFO, WARNING, ERROR and NONE [default: INFO]
  --no-remote-rpc
        Ignore remote rpc communication, capabilities check and
        other node sanity checks
  --help
        Show this message and exit.
  --version
        Show version info and exit.
```

You can run nbd-runnerd as systemd service, note '/etc/sysconfig/nbd-runnerd' is the configuration file where you can choose to edit various options, while systemd will take care of parsing them all and supply to daemon.
<pre>
# cat /etc/sysconfig/nbd-runnerd
# systemctl daemon-reload
# systemctl restart nbd-runnerd
</pre>

<b>CLI</b>: you can choose to run nbd-runner(cli) from any node which has nbd-runnerd running
```script
# nbd-cli --help
Usage:
	nbd <command> [<args>]

Commands:
	help
		display help for nbd commands

	create <volname@host:/path> [prealloc <yes|no>] <size SIZE>
		create path file on the volname volume, prealloc is no as default,
		and the SIZE is valid with B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB)

	delete <volname@host:/path>
		delete path file on the volname volume

	map <volname@host:/path> [nbd-device] [threads NUM] [timeout TIME] [daemon on|off]
		map path file to the nbd device, as default the threads 4, timeout 0 and daemon on

	umap <nbd-device>
		umap the nbd device

	list <map|umap|all>
		list the mapped|umapped|all nbd devices, all as default

	version
		show version info and exit.

	NOTE: please make sure the 'debug' always be the last one.
```
