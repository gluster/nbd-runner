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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/nbd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <json-c/json.h>

#include "nbd-cli-common.h"
#include "config.h"
#include "rpc_nbd.h"
#include "utils.h"
#include "nbd-log.h"
#include "nbd-netlink.h"
#include "ipc.h"

static GPtrArray *cmds_list;

static struct cli_reply *
nbd_request_and_wait(int sock, struct cli_request *req)
{
    struct cli_reply hdr = {0,};
    struct cli_reply *rep;

    nbd_socket_write(sock, req, sizeof(struct cli_request));
    nbd_socket_read(sock, &hdr, sizeof(struct cli_reply));

    rep = calloc(1, sizeof(hdr) + hdr.len + 1);
    if (!rep)
        return NULL;

    rep->exit = hdr.exit;
    rep->len = hdr.len;

    if (hdr.len)
        nbd_socket_read(sock, rep->buf, hdr.len);

    return rep;
}

static int
nbd_cli_create_backstore(int sock, int count, char **options, handler_t htype)
{
    struct cli_request req = {0, };
    struct cli_reply *rep = NULL;
    ssize_t size;
    int ret = 0;
    int ind;
    int len;
    int max_len = 1024;

    /* strict check */
    if (count < 3 || count > 6 ) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    req.htype = htype;
    req.cmd = NBD_CLI_CREATE;
    req.create.prealloc = false;

    len = snprintf(req.create.cfgstring, max_len, "%s", options[0]);
    if (len < 0) {
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        ret = -errno;
        goto err;
    }

    ind = 1;
    while (ind < count) {
        if (!strcmp("host", options[ind])) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto err;
            }

            snprintf(req.rhost, 255, options[ind + 1]);

            if (!nbd_is_valid_host(req.rhost)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", req.rhost);
                goto err;
            }

            ind += 2;
        } else if (!strcmp("prealloc", options[ind])) {
            req.create.prealloc = true;
            ind += 1;
        } else if (!strcmp("size", options[ind])) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument 'size <SIZE>'!\n\n");
                goto err;
            }

            if (!nbd_valid_size(options[ind + 1])) {
                nbd_err("Invalid size!\n");
                ret = -EINVAL;
                goto err;
            }

            size = nbd_parse_size(options[ind + 1], 0);
            if (size < 0) {
                nbd_err("Invalid size value: %s!\n", options[ind + 1]);
                ret = -EINVAL;
                goto err;
            }

            req.create.size = size;

            ind += 2;
        } else {
            nbd_err("Invalid option : %s\n", options[ind]);
            ret = -EINVAL;
            goto err;
        }
    }

    if (!req.rhost[0])
        snprintf(req.rhost, 255, "localhost");

    rep = nbd_request_and_wait(sock, &req);
    if (!rep) {
        ret = -ENOMEM;
        nbd_err("No memory for the reply!\n");
        goto err;
    }

    ret = rep->exit;
    if (ret)
        nbd_err("Create failed: %s!\n", rep->len ? (char *)rep->buf : "Unknown error");
    else
        nbd_info("Create succeeded!\n");

err:
    free(rep);
    return ret;
}

static int
nbd_cli_delete_backstore(int sock, int count, char **options, handler_t htype)
{
    struct cli_request req = {0, };
    struct cli_reply *rep = NULL;
    int ret = 0;
    int len;
    int max_len = 1024;

    /* strict check */
    if (count != 1 && count != 3) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    req.htype = htype;
    req.cmd = NBD_CLI_DELETE;

    len = snprintf(req.delete.cfgstring, max_len, "%s", options[0]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        goto err;
    }

    if (count == 3) {
        if(!strcmp("host", options[1])) {
            snprintf(req.rhost, 255, options[2]);

            if (!nbd_is_valid_host(req.rhost)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", req.rhost);
                goto err;
            }
        } else {
                ret = -EINVAL;
                nbd_err("Invalid parameter '%s %s'!\n", options[1], options[2]);
                goto err;
        }
    }

    if (!req.rhost[0])
        snprintf(req.rhost, 255, "localhost");

    rep = nbd_request_and_wait(sock, &req);
    if (!rep) {
        ret = -ENOMEM;
        nbd_err("No memory for the reply!\n");
        goto err;
    }

    ret = rep->exit;
    if (ret)
        nbd_err("Delete failed: %s!\n", rep->len ? (char *)rep->buf : "Unknown error");
    else
        nbd_info("Delete succeeded!\n");

err:
    free(rep);
    return ret;
}

static int
nbd_cli_map_device(int sock, int count, char **options, handler_t htype)
{
    struct cli_request req = {0, };
    struct cli_reply *rep = NULL;
    int ret = 0;
    int len;
    int max_len = 1024;
    int dev_index = -1;
    int tmp_index;
    int timeout = 30; //This is the default timeout value in kernel space for each IO request
    bool readonly = false;
    int ind;

    /* strict check */
    if (count < 1 || count > 7 ) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    req.htype = htype;
    req.cmd = NBD_CLI_MAP;
    req.map.nbd_index = -1;
    req.map.readonly = false;
    req.map.timeout = 0;

    len = snprintf(req.map.cfgstring, max_len, "%s", options[0]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        goto err;
    }

    ind = 1;
    while (ind < count) {
        if (!strncmp("/dev/nbd", options[ind], strlen("/dev/nbd"))) {
            if (sscanf(options[ind], "/dev/nbd%d", &req.map.nbd_index) != 1) {
                ret = -errno;
                nbd_err("Invalid nbd-device!\n");
                goto err;
            }

            ind += 1;
        } else if (!strcmp("host", options[ind])) {
            if (ind + 1 >= count) {
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto err;
            }

            snprintf(req.rhost, 255, options[ind + 1]);

            if (!nbd_is_valid_host(req.rhost)) {
                nbd_err("Invalid host '%s'!\n", req.rhost);
                goto err;
            }

            ind += 2;
        } else if (!strcmp("readonly", options[ind])) {
            req.map.readonly = true;
            ind += 1;
        } else if (!strcmp("timeout", options[ind])) {
            if (ind + 1 >= count) {
                nbd_err("Invalid argument 'timeout <TIME>'!\n\n");
                goto err;
            }

            timeout = atoi(options[ind + 1]);
            if (timeout < 0) {
                ret = -EINVAL;
                nbd_err("Invalid timeout value!\n");
                goto err;
            }
            req.map.timeout = timeout;

            ind += 2;
        } else {
            ret = -EINVAL;
            nbd_err("Invalid argument '%s'!\n", options[ind]);
            goto err;
        }
    }

    if (!req.rhost[0])
        snprintf(req.rhost, 255, "localhost");

    rep = nbd_request_and_wait(sock, &req);
    if (!rep) {
        ret = -ENOMEM;
        nbd_err("No memory for the reply!\n");
        goto err;
    }

    ret = rep->exit;
    if (ret)
        nbd_err("Map failed: %s!\n", rep->len ? (char *)rep->buf : "Unknown error");
    else
        nbd_info("Map succeeded!\n");

err:
    free(rep);
    return ret;
}

static int
nbd_cli_unmap_device(int sock, int count, char **options, handler_t htype)
{
    struct cli_request req = {0, };
    struct cli_reply *rep = NULL;
    int ret = 0;
    int len;
    int max_len = 1024;
    int ind;

    /* strict check */
    if (count != 1 && count != 3) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    req.htype = htype;
    req.cmd = NBD_CLI_UNMAP;
    req.unmap.nbd_index = -1;

    ind = 0;
    if (!strncmp("/dev/nbd", options[ind], strlen("/dev/nbd"))) {
        if (sscanf(options[ind], "/dev/nbd%d", &req.unmap.nbd_index) != 1) {
            ret = -errno;
            nbd_err("Invalid nbd-device!\n");
            goto err;
        }
    } else {
        len = snprintf(req.unmap.cfgstring, max_len, "%s", options[ind]);
        if (len < 0) {
            ret = -errno;
            nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
            goto err;
        }
    }

    ind = 1;
    while (ind < count) {
        if (!strcmp("host", options[ind])) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto err;
            }

            snprintf(req.rhost, 255, options[ind + 1]);

            if (!nbd_is_valid_host(req.rhost)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", req.rhost);
                goto err;
            }

            ind += 2;
        } else {
            ret = -EINVAL;
            nbd_err("Invalid argument '%s'!\n", options[ind]);
            goto err;
        }
    }

    if (!req.rhost[0])
        snprintf(req.rhost, 255, "localhost");

    rep = nbd_request_and_wait(sock, &req);
    if (!rep) {
        ret = -ENOMEM;
        nbd_err("No memory for the reply!\n");
        goto err;
    }

    ret = rep->exit;
    if (ret)
        nbd_err("Unmap failed: %s!\n", rep->len ? (char *)rep->buf : "Unknown error");
    else
        nbd_info("Unmap succeeded!\n");

err:
    free(rep);
    return ret;
}

static void list_info(const char *info, GHashTable *list_hash, list_type ltype)
{
    json_object *globalobj = NULL;
    json_object *dobj = NULL;
    json_object *obj = NULL;
    GHashTableIter iter;
    gpointer key, value, stp;
    const char *tmp, *tmp1;
    int status;
    unsigned long long size;

    if (!info) {
        nbd_err("Invalid argument and info is NULL!\n");
        return;
    }

    nbd_info("%-20s%-15s%-25s%-15s%-15s%s\n",
             "NBD-DEVS", "NBD-STAT", "NBD-MAPTIME", "BS-STAT", "BS-SIZE", "BACKSTORE");
    nbd_info("%-20s%-15s%-25s%-15s%-15s%s\n",
             "--------", "--------", "-----------", "-------", "-------", "---------");

    globalobj = json_tokener_parse(info);

    switch (ltype) {
    case NBD_LIST_INUSE:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "nbd", &obj);
                tmp = json_object_get_string(obj);
                if (tmp && tmp[0]) {
                    stp = g_hash_table_lookup(list_hash, tmp);
                    if (stp && !(*(int *)stp))
                        continue;

                    nbd_info("%-20s%-15s", tmp, "Inuse");
                    g_hash_table_remove(list_hash, tmp);

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "--");

                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    if (!strcmp(tmp, "dead"))
                        nbd_info("%-15s%-15llu%s\n", "Dead", size, objkey);
                    else if (!strcmp(tmp, "mapped"))
                        nbd_info("%-15s%-15llu%s\n", "Live", size, objkey);
                    else
                        nbd_info("%-15s%-15s%s", "--", "--", "--");
                }
            }
        }
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (status) {
                nbd_info("%-20s%-15s", (char *)key, "Inuse");
                if (json_object_object_get_ex(globalobj, key, &dobj)) {
                    json_object_object_get_ex(dobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "--");

                    json_object_object_get_ex(dobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-15s", tmp ? tmp : "--");

                    json_object_object_get_ex(dobj, "backstore", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%s\n", tmp ? tmp : "--");
                } else {
                    nbd_info("%-25s%-15s%-15s%s\n", "--", "--", "--", "--");
                }
            }
        }
        break;
    case NBD_LIST_FREE:
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (!status)
                nbd_info("%-20s%-15s%-25s%-15s%-15s%s\n", (char *)key, "Free",
                        "--", "--", "--", "--");
        }
        break;
    case NBD_LIST_CREATED:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "status", &obj);
                tmp = json_object_get_string(obj);
                if (!strcmp(tmp, "created")) {
                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    nbd_info("%-20s%-15s%-25s%-15s%-15llu%s\n", "--", "--", "--",
                            "Created", size, objkey);
                }
            }
        }
        break;
    case NBD_LIST_DEAD:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "status", &obj);
                tmp = json_object_get_string(obj);
                if (!strcmp(tmp, "dead")) {
                    json_object_object_get_ex(devobj, "nbd", &obj);
                    tmp = json_object_get_string(obj);
                    stp = g_hash_table_lookup(list_hash, tmp);
                    if (stp && *(int *)stp)
                        nbd_info("%-20s%-15s", tmp ? tmp : "--", "Inuse");
                    else
                        nbd_info("%-20s%-15s", tmp ? tmp : "--", "Free");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    nbd_info("%-25s%-15s%-15llu%s\n", tmp ? tmp : "--",
                             "Dead", size, objkey);
                }
            }
        }
        break;
    case NBD_LIST_LIVE:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "nbd", &obj);
                tmp = json_object_get_string(obj);
                if (tmp && tmp[0]) {
                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp1 = json_object_get_string(obj);
                    if (strcmp(tmp1, "mapped"))
                        continue;

                    stp = g_hash_table_lookup(list_hash, tmp);
                    if (stp && !(*(int *)stp))
                        continue;

                    nbd_info("%-20s%-15s", tmp, "Inuse");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "--");

                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    nbd_info("%-15s%-15llu%s\n", "Live", size, objkey);
                }
            }
        }
        break;
    case NBD_LIST_ALL:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "nbd", &obj);
                tmp = json_object_get_string(obj);
                if (tmp && tmp[0]) {
                    stp = g_hash_table_lookup(list_hash, tmp);
                    if (stp && *(int *)stp)
                        nbd_info("%-20s%-15s", tmp, "Inuse");
                    else
                        nbd_info("%-20s%-15s", tmp, "Free");

                    g_hash_table_remove(list_hash, tmp);

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "--");

                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    if (!strcmp(tmp, "dead"))
                        nbd_info("%-15s%-15llu%s\n", "Dead", size, objkey);
                    else if (!strcmp(tmp, "mapping"))
                        nbd_info("%-15s%-15llu%s\n", "Mapping", size, objkey);
                    else if (!strcmp(tmp, "mapped"))
                        nbd_info("%-15s%-15llu%s\n", "Live", size, objkey);
                    else if (!strcmp(tmp, "unmapping"))
                        nbd_info("%-15s%-15llu%s\n", "Unpapping", size, objkey);
                    else
                        nbd_info("%-15s%-15s%s\n", "--", "--", "--");
                } else {
                    nbd_info("%-20s%-15s%-25s", "--", "--", "--");
                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    if (!strcmp(tmp, "created"))
                        nbd_info("%-15s", "Created");
                    else if (!strcmp(tmp, "mapping"))
                        nbd_info("%-15s%", "Mapping");
                    else if (!strcmp(tmp, "dead"))
                        nbd_info("%-15s%", "Dead");
                    else
                        nbd_info("%-15s", "--");

                    json_object_object_get_ex(devobj, "size", &obj);
                    size = json_object_get_int64(obj);
                    nbd_info("%-15llu%s\n", size, objkey);
                }
            }
        }
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (status) {
                nbd_info("%-20s%-15s", (char *)key, "Inuse");
                if (json_object_object_get_ex(globalobj, key, &dobj)) {
                    json_object_object_get_ex(dobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "--");

                    json_object_object_get_ex(dobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-15s", tmp ? tmp : "--");

                    json_object_object_get_ex(dobj, "backstore", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%s\n", tmp ? tmp : "--");
                } else {
                    nbd_info("%-25s%-15s%-15s%s\n", "--", "--", "--", "--");
                }
            } else {
                nbd_info("%-20s%-15s%-25s%-15s%-15s%s\n", (char *)key, "Free",
                        "--", "--", "--", "--");
            }
        }
        break;
    default:
        nbd_err("Invalid list type: %d!\n", ltype);
        goto err;
    }

err:
    if (globalobj)
        json_object_put(globalobj);
    return;
}

static int
nbd_cli_list_device(int sock, int count, char **options, handler_t htype)
{
    list_type ltype = NBD_LIST_ALL;
    struct cli_request req = {0, };
    struct cli_reply *rep = NULL;
    struct nl_sock *netfd = NULL;
    GHashTable *list_hash = NULL;
    struct nl_msg *msg;
    int driver_id;
    int ret = 0;
    int len;
    int ind;

    /* strict check */
    if (count < 0 || count > 3) {
         nbd_err("Invalid argument counts\n");
         ret = -EINVAL;
         goto out;
    }

    req.htype = htype;
    req.cmd = NBD_CLI_LIST;

    ind = 0;
    while (ind < count) {
        if (!strcmp(options[ind], "host")) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto out;
            }

            snprintf(req.rhost, 255, options[ind + 1]);

            if (!nbd_is_valid_host(req.rhost)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", req.rhost);
                goto out;
            }

            ind += 2;
        } else if (!strcmp(options[ind], "inuse")) {
            ltype = NBD_LIST_INUSE;
            ind++;
        } else if (!strcmp(options[ind], "free")) {
            ltype = NBD_LIST_FREE;
            ind++;
        } else if (!strcmp(options[ind], "create")) {
            ltype = NBD_LIST_CREATED;
            ind++;
        } else if (!strcmp(options[ind], "dead")) {
            ltype = NBD_LIST_DEAD;
            ind++;
        } else if (!strcmp(options[ind], "live")) {
            ltype = NBD_LIST_LIVE;
            ind++;
        } else if (!strcmp(options[ind], "all")) {
            ltype = NBD_LIST_ALL;
            ind++;
        } else {
            ret = -EINVAL;
            nbd_err("Invalid argument for list: %s!\n", options[ind]);
            goto out;
        }
    }

    if (!req.rhost[0])
        snprintf(req.rhost, 255, "localhost");

    rep = nbd_request_and_wait(sock, &req);
    if (!rep) {
        ret = -ENOMEM;
        nbd_err("No memory for the reply!\n");
        goto out;
    }

    ret = rep->exit;
    if (ret) {
        nbd_err("fetching backstore info failed: %s!\n",
                rep->len ? (char *)rep->buf : "Unknown error");
        goto out;
    }

    ret = nbd_get_device_list(&list_hash);
    if (ret || !list_hash) {
        nbd_err("failed get device list, ret: %d!\n", ret);
        goto out;
    }

    list_info(rep->buf, list_hash, ltype);
    ret = 0;

out:
    if (ret)
        nbd_err("List Failed!\n");

    if (list_hash)
        g_hash_table_destroy(list_hash);
    free(rep);

    return ret;
}

static void
nbd_cli_print_info(gpointer data, gpointer user_data)
{
    struct cli_cmd *clicmd = data;

    if (clicmd->disable)
        return;

    nbd_info("\t%s\n", clicmd->pattern);
    nbd_info("\t\t%s\n\n", clicmd->desc);
}

static int nbd_cli_help(void)
{
    GHashTableIter iter;
    gpointer key, value;
    int i;

    nbd_info("Usage:\n\n");
    g_ptr_array_foreach(cmds_list, nbd_cli_print_info, NULL);
    nbd_info("\n");

    return 0;
}

static int
nbd_register_cmds(GPtrArray *cmds_list, struct cli_cmd *cmds)
{
    char *key;
    char *sep;
    const char *p;
    int len;
    int i;

    if (!cmds_list || !cmds)
        return -EINVAL;

    for (i = 0; cmds[i].pattern; i++)
        g_ptr_array_add(cmds_list, (gpointer)&cmds[i]);

    return 0;
}

static GPtrArray *nbd_register_backstores(handler_t htype)
{
    GPtrArray *cmds_list;

    cmds_list = g_ptr_array_new_full(16, NULL);
    if (!cmds_list) {
        nbd_err("failed to create cmds arrary table!\n");
        return NULL;
    }

    if (htype == NBD_BACKSTORE_GLUSTER &&
        cli_cmd_gluster_register(cmds_list, nbd_register_cmds)) {
        nbd_err("failed to register gluster cmds!\n");
        goto err;
    }

    if (htype == NBD_BACKSTORE_AZBLK &&
        cli_cmd_azblk_register(cmds_list, nbd_register_cmds)) {
        nbd_err("failed to register azblk cmds!\n");
        goto err;
    }

    return cmds_list;

err:
    g_ptr_array_free(cmds_list, true);
    return NULL;
}

static void nbd_unregister_backstores(GPtrArray *cmds_list)
{
    if (cmds_list)
        g_ptr_array_free(cmds_list, true);
}

static void usage(void)
{
    nbd_info("Usage:\n\n"
             "\tgluster help\n\t\tDisplay help for gluster commands\n\n"
             "\tazblk help\n\t\tDisplay help for azblk commands\n\n"
             "\tceph help [TODO]\n\t\tDisplay help for ceph commands\n\n"
             "\tglobal help [TODO]\n\t\tDisplay help for global commands\n\n"
             "\tversion\n\t\tDisplay the version of nbd-cli\n\n"
            );
}

typedef enum {
    NBD_OPT_HELP,
    NBD_OPT_VERSION,

    NBD_OPT_MAX
} nbd_cli_opt_command;

static const char *const nbd_cli_opt_commands[] = {
    [NBD_OPT_HELP]           = "help",
    [NBD_OPT_VERSION]        = "version",

    [NBD_OPT_MAX]            = NULL,
};

static const char *const nbd_cli_handlers[] = {
	[NBD_BACKSTORE_GLUSTER]  = "gluster",
	[NBD_BACKSTORE_CEPH]     = "ceph",
	[NBD_BACKSTORE_AZBLK]    = "azblk",

	[NBD_BACKSTORE_MAX]      = NULL,
};

static int nbd_cli_get_handler_type(const char *chtype)
{
    handler_t htype;

    if (!chtype)
        return NBD_BACKSTORE_MAX;

    if (!strcmp(chtype, "gluster")) {
	    htype = NBD_BACKSTORE_GLUSTER;
    } else if (!strcmp(chtype, "azblk")) {
	    htype = NBD_BACKSTORE_AZBLK;
    } else if (!strcmp(chtype, "ceph")) {
	    htype = NBD_BACKSTORE_CEPH;
    } else {
        htype = NBD_BACKSTORE_MAX;
    }

    return htype;
}

static int nbd_cli_command_lookup(const char *command)
{
    int i;

    if (!command)
        return NBD_OPT_MAX;

    for (i = 0; i < NBD_OPT_MAX; i++) {
        if (!strcmp(nbd_cli_opt_commands[i], command))
            return i;
    }

    return NBD_OPT_MAX;
}

static gboolean nbd_cli_cmd_find(gconstpointer a, gconstpointer b)
{
    const struct cli_cmd *clicmd = a;

    return !strncmp(b, clicmd->pattern, strlen((char *)b));
}

int main(int argc, char *argv[])
{
    nbd_cli_opt_command cmd;
    int ret = EXIT_FAILURE;
    struct cli_cmd *clicmd;
    handler_t htype;
    char **options;
    int count;
    int sock;
    int ind;

    if (argc == 1) {
        usage();
        ret = EXIT_SUCCESS;
        goto out;
    }

    if (argc >= 2) {
        cmd = nbd_cli_command_lookup(argv[1]);

        ret = EXIT_SUCCESS;
        switch(cmd) {
        case NBD_OPT_HELP:
            usage();
            goto out;
        case NBD_OPT_VERSION:
            nbd_info("nbd-cli (%s)\n\n", VERSION);
            nbd_info("%s\n", NBD_LICENSE_INFO);
            goto out;
        case NBD_OPT_MAX:
        default:
            htype = nbd_cli_get_handler_type(argv[1]);
            if (htype == NBD_BACKSTORE_MAX) {
                nbd_err("Invalid handler type, try 'nbd-cli --help' for more information!\n");
                exit(1);
            }
        }
    }

    if (!nbd_minimal_kernel_version_check())
        goto out;

    cmds_list = nbd_register_backstores(htype);
    if (!cmds_list) {
        nbd_err("No command registered!\n");
        goto out;
    }

    /* List all the handler's help info */
    if (argc == 2) {
        nbd_cli_help();
        ret = EXIT_SUCCESS;
        goto out;
    }

    if (!g_ptr_array_find_with_equal_func(cmds_list, argv[2], nbd_cli_cmd_find,
        &ind)) {
        nbd_err("Invalid cmd %s!\n", argv[2]);
        nbd_cli_help();
        goto out;
    }

    clicmd = g_ptr_array_index(cmds_list, ind);

    if (clicmd->cmd == NBD_CLI_HELP) {
        nbd_cli_help();
        ret = EXIT_SUCCESS;
        goto out;
    }

    count = argc - 3;
    options = argc > 3 ? argv + 3 : NULL;

    sock = nbd_ipc_connect();
    if (sock < 0)
        goto out;

    switch (clicmd->cmd) {
    case NBD_CLI_CREATE:
        nbd_cli_create_backstore(sock, count, options, htype);
        break;
    case NBD_CLI_DELETE:
        nbd_cli_delete_backstore(sock, count, options, htype);
        break;
    case NBD_CLI_MAP:
        nbd_cli_map_device(sock, count, options, htype);
        break;
    case NBD_CLI_UNMAP:
        nbd_cli_unmap_device(sock, count, options, htype);
        break;
    case NBD_CLI_LIST:
        nbd_cli_list_device(sock, count, options, htype);
        break;
    case NBD_CLI_HELP:
    case NBD_CLI_MAX:
    default:
        nbd_cli_help();
    }

    ret = EXIT_SUCCESS;
out:
    nbd_unregister_backstores(cmds_list);
    exit(ret);
}
