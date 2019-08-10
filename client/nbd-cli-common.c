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
#include <linux/nbd-netlink.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <json-c/json.h>

#include "rpc_nbd.h"
#include "utils.h"
#include "nbd-log.h"
#include "nbd-cli-common.h"

static void free_key(gpointer key)
{
    free(key);
}

static void free_value(gpointer value)
{
    free(value);
}

struct addrinfo *nbd_get_sock_addr(const char *host, int port)
{
  int ret;
  struct addrinfo hints, *res;
  char pport[32];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(pport, 32, "%d", port);

  ret = getaddrinfo(host, pport, &hints, &res);
  if (ret) {
    nbd_err("getaddrinfo(%s) failed (%s)", host, gai_strerror(ret));
    return NULL;
  }

  return res;
}

static struct nla_policy nbd_device_policy[NBD_DEVICE_ATTR_MAX + 1] = {
    [NBD_DEVICE_INDEX]              =       { .type = NLA_U32 },
    [NBD_DEVICE_CONNECTED]          =       { .type = NLA_U8 },
};

static int list_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    struct nl_cbk_args *args = arg;
    uint32_t index;
    struct nlattr *attr;
    int rem;
    char *key;
    int *value;
    int status;
    int ret = NL_OK;

    if (!args || !args->list_hash)
        return NL_OK;

    if (nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        nbd_err("Invalid response from the kernel\n");
        return NL_STOP;
    }

    if (!msg_attr[NBD_ATTR_DEVICE_LIST]) {
        nbd_err("NBD_ATTR_DEVICE_LIST not set in cmd!\n");
        return NL_STOP;
    }

    nla_for_each_nested(attr, msg_attr[NBD_ATTR_DEVICE_LIST], rem) {
        struct nlattr *devices[NBD_DEVICE_ATTR_MAX + 1];

        if (nla_type(attr) != NBD_DEVICE_ITEM) {
            nbd_err("NBD_DEVICE_ITEM not set!\n");
            ret = NL_STOP;
            goto err;
        }

        if (nla_parse_nested(devices, NBD_DEVICE_ATTR_MAX, attr,
                             nbd_device_policy) < 0) {
            nbd_err("nbd: error processing device list\n");
            ret = NL_STOP;
            goto err;
        }

        index = (int)nla_get_u32(devices[NBD_DEVICE_INDEX]);
        status = (int)nla_get_u8(devices[NBD_DEVICE_CONNECTED]);

        key = malloc(NBD_DLEN_MAX);
        snprintf(key, NBD_DLEN_MAX, "/dev/nbd%d", index);
        value = malloc(sizeof(int));
        *value = status;

        g_hash_table_insert(args->list_hash, key, value);
    }

err:
    return ret;
}

int nbd_get_device_list(GHashTable **list_hash)
{
    struct nl_sock *netfd = NULL;
    GHashTable *tmp = NULL;
    struct nl_msg *msg;
    int driver_id;
    int ret = 0;

    if (!list_hash) {
        ret = -EINVAL;
        nbd_err("list_hash shouldn't be NULL!\n");
        goto nla_put_failure;
    }

    tmp = g_hash_table_new_full(g_str_hash, g_str_equal, free_key, free_value);
    if (!tmp) {
        ret = -ENOMEM;
        nbd_err("failed to create list_hash table!\n");
        goto nla_put_failure;
    }

    netfd = nbd_setup_netlink(&driver_id, list_nl_callback, -1, NULL, NULL,
                              tmp, &ret);
    if (!netfd)
        goto nla_put_failure;

    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        nbd_err("Couldn't allocate netlink message, %s!\n", strerror(errno));
        goto nla_put_failure;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
                NBD_CMD_STATUS, 0);
    /*
     * -1 means list all the devices mapped and
     *  unmapped in kernel space
     */
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, -1);

    if ((ret = nl_send_sync(netfd, msg)) < 0) {
        nbd_err("Failed to setup device, check dmesg\n");
        goto nla_put_failure;
    }

    ret = 0;

nla_put_failure:
    if (!ret)
        *list_hash = tmp;
    else if (tmp)
        g_hash_table_destroy(tmp);
    nl_socket_free(netfd);
    return ret;
}

struct nl_sock *nbd_setup_netlink(int *driver_id, list_nl_cbk_t fn, handler_t htype,
                                  char *cfg, CLIENT *clnt, GHashTable *list_hash,
                                  int *ret)
{
    struct nl_cbk_args *args;
    struct nl_sock *netfd;

    if (!driver_id) {
        if (ret)
            *ret = -EINVAL;
        return NULL;
    }

    args = malloc(sizeof(struct nl_cbk_args));
    if (!args) {
        if (ret)
            *ret = -ENOMEM;
        nbd_err("Couldn't alloc args, %s!\n", strerror(errno));
        return NULL;
    }

    args->htype = htype;
    args->cfg = cfg;
    args->clnt = clnt;
    args->list_hash = list_hash;
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
