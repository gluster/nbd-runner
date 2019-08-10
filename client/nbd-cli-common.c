/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <linux/nbd.h>
#include <netdb.h>
#include <libkmod.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <json-c/json.h>

#include "rpc_nbd.h"
#include "utils.h"
#include "nbd-log.h"
#include "nbd-netlink.h"
#include "nbd-cli-common.h"

struct addrinfo *nbd_get_sock_addr(const char *host)
{
  int ret;
  struct addrinfo hints, *res;
  char port[32];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(port, 32, "%d", NBD_RPC_SVC_PORT);

  ret = getaddrinfo(host, port, &hints, &res);
  if (ret) {
    nbd_err("getaddrinfo(%s) failed (%s)", host, gai_strerror(ret));
    return NULL;
  }

  return res;
}

struct nl_sock *nbd_setup_netlink(int *driver_id, list_nl_cbk_t fn, int htype,
                                  char *cfg, CLIENT *clnt, int *ret)
{
    struct map_args *args;
    struct nl_sock *netfd;

    if (!driver_id) {
        if (ret)
            *ret = -EINVAL;
        return NULL;
    }

    args = malloc(sizeof(struct map_args));
    if (!args) {
        if (ret)
            *ret = -ENOMEM;
        nbd_err("Couldn't alloc args, %s!\n", strerror(errno));
        return NULL;
    }

    args->htype = htype;
    args->cfg = cfg;
    args->clnt = clnt;
    netfd = nl_socket_alloc();
    if (!netfd) {
        if (ret)
            *ret = -errno;
        nbd_err("Couldn't alloc socket, %s!\n", strerror(errno));
        goto err;
    }

    nl_socket_modify_cb(netfd, NL_CB_VALID, NL_CB_CUSTOM, fn, args);

    if (genl_connect(netfd)) {
        if (ret)
            *ret = -errno;
        nbd_err("Couldn't connect to the nbd netlink socket, %s!\n",
                strerror(errno));
        goto err;
    }

    *driver_id = genl_ctrl_resolve(netfd, "nbd");
    if (*driver_id < 0) {
        if (ret)
            *ret = -errno;
        nbd_err("Couldn't resolve the nbd netlink family, %s!\n",
                strerror(errno));
        goto err;
    }

    return netfd;
err:
    free(args);
    nl_socket_free(netfd);
    return NULL;
}

int nbd_device_connect(char *cfg, struct nl_sock *netfd, int sockfd,
                       int driver_id, ssize_t size, ssize_t blk_size,
                       int timeout, int dev_index, bool readonly)
{
    struct nlattr *sock_attr;
    struct nlattr *sock_opt;
    struct nl_msg *msg;
    int flags = readonly ? NBD_FLAG_READ_ONLY : 0;
    struct nego_request nhdr;
    struct nego_reply nrep;
    char *buf;

    nhdr.len = strlen(cfg);
    nbd_socket_write(sockfd, &nhdr, sizeof(struct nego_request));
    nbd_socket_write(sockfd, cfg, nhdr.len);

    nbd_socket_read(sockfd, &nrep, sizeof(struct nego_reply));
    if (nrep.exit) {
        if (nrep.len) {
            buf = malloc(nrep.len + 1);
            nbd_socket_read(sockfd, &buf, nrep.len);
            nbd_err("nego failed: %s, %d\n", buf, nrep.exit);
            free(buf);
        } else {
            nbd_err("nego failed %d\n", nrep.exit);
        }
        goto nla_put_failure;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nbd_err("Couldn't allocate netlink message, %s!\n",
                strerror(errno));
        goto nla_put_failure;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
            NBD_CMD_CONNECT, 0);

    /* -1 means alloc the device dynamically */
    if (dev_index < -1)
        dev_index = -1;
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, dev_index);
    NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, size);
    NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES,
                blk_size ? blk_size : NBD_DEFAULT_SECTOR_SIZE);
    NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, flags);
    if (timeout)
        NLA_PUT_U64(msg, NBD_ATTR_TIMEOUT, timeout);

    sock_attr = nla_nest_start(msg, NBD_ATTR_SOCKETS);
    if (!sock_attr) {
        nbd_err("Couldn't nest the socket!\n");
        goto nla_put_failure;
    }
    sock_opt = nla_nest_start(msg, NBD_SOCK_ITEM);
    if (!sock_opt) {
        nbd_err("Couldn't nest the socket item!\n");
        goto nla_put_failure;
    }

    NLA_PUT_U32(msg, NBD_SOCK_FD, sockfd);
    nla_nest_end(msg, sock_opt);
    nla_nest_end(msg, sock_attr);

    if (nl_send_sync(netfd, msg) < 0) {
        nbd_err("Failed to setup device, check dmesg!\n");
        goto nla_put_failure;
    }

    return 0;

nla_put_failure:
    return -1;
}

int load_our_module(void)
{
    struct kmod_list *list = NULL, *itr;
    struct kmod_ctx *ctx;
    struct stat sb;
    struct utsname u;
    int ret;

    ctx = kmod_new(NULL, NULL);
    if (!ctx) {
        nbd_err("kmod_new() failed: %m\n");
        return -1;
    }

    ret = kmod_module_new_from_lookup(ctx, "nbd", &list);
    if (ret < 0) {
        /* In some environments like containers, /lib/modules/`uname -r`
         * will not exist, in such cases the load module job be taken
         * care by admin, either by manual load or makesure it's builtin
         */
        if (ENOENT == errno) {
            if (uname(&u) < 0) {
                nbd_err("uname() failed: %m\n");
            } else {
                nbd_info("no modules dir '/lib/modules/%s', checking in '/sys/modules/'\n",
                        u.release);
                ret = stat(CFGFS_NBD_MOD, &sb);
                if (ret) {
                    nbd_err("stat() on '%s' failed: %m\n", CFGFS_NBD_MOD);
                } else {
                    nbd_info("Module nbd already loaded\n");
                }
            }
        } else {
            nbd_err("kmod_module_new_from_lookup() failed to lookup alias nbd %m\n");
        }

        kmod_unref(ctx);
        return ret;
    }

    if (!list) {
        nbd_err("kmod_module_new_from_lookup() failed to find module nbd\n");
        kmod_unref(ctx);
        return -1;
    }

    kmod_list_foreach(itr, list) {
        int state, err;
        struct kmod_module *mod = kmod_module_get_module(itr);

        state = kmod_module_get_initstate(mod);
        switch (state) {
        case KMOD_MODULE_BUILTIN:
            nbd_dbg("Module '%s' is builtin\n", kmod_module_get_name(mod));
            break;

        case KMOD_MODULE_LIVE:
            nbd_dbg("Module '%s' is already loaded\n", kmod_module_get_name(mod));
            break;

        default:
	    /*
	     * Initialize 0 nbd device when insearting the nbd module to
	     * avoid the following issue:
	     *
	     * For the first time to execute the 'nbd-cli ... list' command
	     * just after the nbd.ko is inserted we will randomly hit some
	     * unused /dev/nbdX devices are listed as mapped, due to nbd
	     * kernel module bug.
	     */
            err = kmod_module_probe_insert_module(mod,
                    KMOD_PROBE_APPLY_BLACKLIST,
                    "nbds_max=0", NULL, NULL, NULL);

            if (err == 0) {
                nbd_info("Inserted module '%s'\n", kmod_module_get_name(mod));
            } else if (err < 0) {
                nbd_err("Failed to insert '%s': %s\n",
                        kmod_module_get_name(mod), strerror(-err));
                ret = -1;
            } else {
                switch (err) {
                    case KMOD_PROBE_APPLY_BLACKLIST:
                        nbd_err("Module '%s' is blacklisted\n",
                                kmod_module_get_name(mod));
                        break;
                    default:
                        nbd_err("Module '%s' is stopped by a reason: 0x%x\n",
                                kmod_module_get_name(mod), err);
                        break;
                }
                ret = -1;
            }
	    /*
	     * Currently in nbd.ko module for the first time when loading,
	     * it will add and initialize nbds_max(16 as default) nbd devices
	     * defautly, and the udev service will try to open/close the
	     * /dev/nbdX to do some sanity check.
	     *
	     * And if we do the list or map at the same time we will hit some
	     * errors, such the device is mapped, but it is actually not.
	     *
	     * So if the no extra_options is NULL in kmod_module_probe_insert_module,
	     * the following sleep(1) should be uncommented here.
	     */
	//  sleep(1);
        }
        kmod_module_unref(mod);
    }

    kmod_module_unref_list(list);
    kmod_unref(ctx);

    return ret;
}
