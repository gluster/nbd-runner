# nbd-runner

A daemon that handles the userspace side of the NBD(Network Block Device) backstore.

# nbd-cli

A cli utility, which aims at making backstore creation/deletion/mapping/unmaping/listing.

# One simple graph:

```script
                         nbd-runner                                   nbd-cli
                  +----------------------+                     +---------------------+
                  |                      |                     |                     |
                  |                      |                     |                     |
+-----------+     |      RUNNER HOST IP  |  RPC control route  | create/delete       |
|           |     |      listen on       <---------------------> map/unmap/list, etc |
|  Gluster  <----->      TCP/24110 port  |                     |  +                  |
|           |     |                      |                     |  |                  |
+-----------+     |                      |                     |  |                  |
                  |                      |                     |  | MAP will         |
                  |                      |                     |  | setup            |
                  |                      |                     |  | the NBD          |
                  |                      |                     |  | devices          |
                  |                      |                     |  |                  |
+-----------+     |                      |                     |  |                  |
|           |     |                      |                     |  |                  |
|   Ceph    <----->                      |                     |  |          READ    |
|           |     |       IO HOST IP     | MAPPED NBD(IO) route|  v          WRITE   |
+-----------+     |       listen on      <-------------------->+ /dev/nbdXX  FLUSH   |
                  |       TCP/24111 port |                     |             TRIM    |
                  |                      |                     |             ...     |
                  |                      |                     |                     |
                  +----------------------+                     +---------------------+

```
<b>NOTE:</b> The 'RUNNER HOST IP' and the 'IO HOST IP' could be same or different, and the 'nbd-runner' and 'nbd-cli' could run on the same node or in different nodes, both are up to your use case. And please make sure that the 'nbd-runner' runs on one of the gluster/ceph server nodes.

# License
nbd-runner is licensed to you under your choice of the GNU Lesser General Public License, version 3 or any later version ([LGPLv3](https://opensource.org/licenses/lgpl-3.0.html) or later), or the GNU General Public License, version 2 ([GPLv2](https://opensource.org/licenses/GPL-2.0)), in all cases as published by the Free Software Foundation.

# Install
------
<pre>
$ git clone https://github.com/gluster/nbd-runner.git
$ cd nbd-runner/
$ dnf install autoconf automake libtool kmod-devel libnl3-devel libevent-devel glib2-devel json-c-devel
$ dnf install libtirpc-devel rpcgen # only in Fedora or some other Distributions that the glibc version >= 2.26
$ dnf install glusterfs-api-devel # only when the --with-gluster=yes or absent you need to install this
$ ./autogen.sh
$ ./configure # '--with-tirpc=no' means try to use legacy glibc, yes by default; --with-gluster means enable the gluster handler, yes by default.
$ make -j
$ make install
</pre>

<b>NOTE:</b> Glibc has removed the rpc functions from the [2.26 release](https://sourceware.org/ml/libc-alpha/2017-08/msg00010.html). Instead of relying on glibc providing these, the modern libtirpc library should be used instead. For the old glibc version or some distribute Linux we will still use the glibc instead to privide the RPC library.

# Usage
------
**Prerequisites:** *this guide assumes that the following are already present*
- [x] *The kernel or the nbd.ko module must be new enough, which have add the netlink feature supported*
- [x] *Open 24110 and 24111(nbd-runnerd) 111(rpcbind) ports in your firewall*

<b>Daemon</b>: run nbd-runner on the node where you can access the gluster through gfapi
```script
$ nbd-runner help
Usage:
	nbd-runner [<args>]

Commands:
	help
		Display help for nbd-runner command

	threads <NUMBER>
		Specify the IO thread number for each mapped backstore, 1 as default

	rpchost <RUNNER_HOST>
		Specify the listenning IP for the nbd-runner server to receive/reply the control
		commands(create/delete/map/unmap/list, etc) from nbd-cli, INADDR_ANY as default

	iohost <IO_HOST>
		Specify the listenning IP for the nbd-runner server to receive/reply the NBD device's
		IO operations(WRITE/READ/FLUSH/TRIM, etc), INADDR_ANY as default

	version
		Show version info and exit.

	NOTE:
		The RUNNER_HOST and the IO_HOST will be useful if you'd like the control commands
		route different from the IOs route via different NICs, or just omit them as default
```

<b>CLI</b>: you can choose to run nbd-cli from any node where the newer nbd.ko module is availible
```script
$ nbd-cli help
Usage:

	gluster help
		Display help for gluster commands

	ceph help [TODO]
		Display help for ceph commands

	global help [TODO]
		Display help for global commands

	version
		Display the version of nbd-cli
```

# Writing a new nbd handler

### Hanler library name:

The handler library name must be "libXXX_handler.so".

### Define your own struct nbd_handler like:

    struct nbd_handler dummy_handler = {
        .name           = "Dummy handler",
        .subtype        = NBD_BACKSTORE_DUMMY,

        .cfg_parse      = dummy_cfg_parse,
        .create         = dummy_create,
        .delete         = dummy_delete,
        .map            = dummy_map,
        .unmap          = dummy_unmap,
        .get_size       = dummy_get_size,
        .get_blksize    = dummy_get_blksize,
        .handle_request = dummy_handle_request,

        .load_json      = dummy_load_json,
        .update_json    = dummy_update_json,

    }

**.name:** The name of your handler.

**.subtype:** You should append a new backstore type in enum handler_t {} in ./rpc/rpc_nbd.x file.

**.cfg_parse:** This helper should help you to parse the cfgstring received from the nbd-cli command, and setup the dev->priv if needed.

**.create:** Create one new bacostore storage device/file.

**.delete:** Delete the backstore storage device/file.

**.map:** This is called by "nbd-cli map" command, the "nbd-cli map" will map the backstore storage device/file to the NBD device(/dev/nbdX), here you need to make sure that the backstore storage device/file is exist and then open it.

**.unmap:** When unmapping, you should close the backstore storage device/file.

**.get_size:** Will get the backstore storage device/file size.

**.get_blksize:** Will get the backstore storage device/file blksize, you can just return 0 then it will be set as default 512.

**.handle_request:** This will be called to do the actual IOs, such as READ/WRITE/FLUSH...

**.load_json:** When the nbd-runner service is starting, it will reload the /etc/nbd-runner/saveconfig.json to setup the device info, you should privide one method to restore the dev->priv private data if needed.

**.update_json:** All the backstore storage device/file info will be saved to the /etc/nbd-runner/saveconfig.json file, you should privide one method to save this for the dev->priv private data if needed.

**NOTE:** the create/delete helpers are not must, you can use other tools to create/delete the backstore storage devices/files, and then use the map/unmap to map/unmap them to the NBD devices.


### Define handler_init callout:

There must have one entry point named "handler_init", it will be:

    struct nbd_handler *handler_init(const struct nbd_config *cfg)
    {
        /* Add your init code here*/

        [...]

        return &dummy_handler;
    }

# Gluster
[Gluster](http://gluster.readthedocs.io/en/latest/) is a well known scale-out distributed storage system, flexible in its design and easy to use. One of its key goals is to provide high availability of data. Gluster is very easy to setup and use. Addition and removal of storage servers from a Gluster cluster is intuitive. These capabilities along with other data services that Gluster provides makes it a reliable software defined storage platform.

> A unique distributed storage solution build on traditional filesystems

### How we provide block storage in gluster ?

**Prerequisites:** *this guide assumes that the following are already present*
- [x] *A gluster volume must be created/started first*
- [x] *Open 24007(for glusterd) port and glusterfs service in your firewall*

1. Create a volume in the gluster stoarge cluster.
2. Run the nbd-runner daemon in any of the gluster storage cluster node, or any other node that can access the gluster volume via the gfapi library.
   
    `$ nbd-runner [<args>]`

3. Create one file in the volume by using the gluster cli tool or just use the 'nbd-cli gluster create' tool.

    `$ mount.glusterfs HOST:/VOLUME /mnt && fallocate -l 1G /mnt/FILEPATH`

   or

    `$ nbd-cli gluster create <VOLUME/FILEPATH> [prealloc] <size SIZE> <host RUNNER_HOST>`

4. Map the file created in backstore gluster volume to the NBD device(in local host), you can specify one unmapped /dev/nbdXX or just omit it and then the NBD kernel module will allocate one for you.

    `$ nbd-cli gluster map <VOLUME/FILEPATH> [nbd-device] [timeout TIME] [readonly] <host RUNNER_HOST>`

5. You will see the mapped NBD device returned and displayed, or you can check the mapped device info by:

    `$ nbd-cli gluster list <map|unmap|create|dead|live|all> <host RUNNER_HOST>`

6. We expose the file in the gluster volume as NBD device using nbd-runner, exporting the target file as block device via /dev/nbdXX

<b> Gluster CLI</b>: the gluster specified cli commands
```script
$ nbd-cli gluster help
Usage: 

	gluster help
		Display help for gluster commands

	gluster create <VOLUME/FILEPATH> [prealloc] <size SIZE> [host RUNNER_HOST]
		Create FILEPATH in the VOLUME, prealloc is false as default, and the SIZE is valid
		with B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB), RUNNER_HOST will
		be 'localhost' as default

	gluster delete <VOLUME/FILEPATH> [host RUNNER_HOST]
		Delete FILEPATH from the VOLUME, RUNNER_HOST will be 'localhost' as default

	gluster map <VOLUME/FILEPATH> [nbd-device] [timeout TIME] [readonly] [host RUNNER_HOST]
		Map FILEPATH to the nbd device, as default the timeout 0, none readonly, RUNNER_HOST
		will be 'localhost' as default

	gluster unmap <nbd-device|VOLUME/FILEPATH> [host RUNNER_HOST]
		Unmap the nbd device or VOLUME/FILEPATH, RUNNER_HOST will be 'localhost' as default

	gluster list [map|unmap|create|dead|live|all] [host RUNNER_HOST]
		List the mapped|unmapped NBD devices or the created|dead|live backstores, all as
		default. 'create' means the backstores are just created or unmapped. 'dead' means
		the IO connection is lost, this is mainly due to the nbd-runner service is restart
		without unmapping. 'live' means everything is okay for both mapped and IO connection,
		RUNNER_HOST will be 'localhost' as default
```
