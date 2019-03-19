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
#include "nbd-cli-cmd.h"

static GHashTable *list_hash;

static void free_key(gpointer key)
{
    free(key);
}

static void free_value(gpointer value)
{
    free(value);
}

static struct addrinfo *nbd_get_sock_addr(const char *host)
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

int nbd_create_backstore(int count, char **options, int type)
{
    CLIENT *clnt = NULL;
    struct nbd_create *create;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
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

    create = calloc(1, sizeof(struct nbd_create));
    if (!create) {
        nbd_err("No memory for nbd_create!\n");
        return -ENOMEM;
    }

    create->type = type;

    len = snprintf(create->cfgstring, max_len, "key=%s", options[0]);
    if (len < 0) {
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        ret = -errno;
        goto err;
    }
    create->cfgstring[len++] = ';';

    ind = 1;
    while (ind < count) {
        if (!strcmp("host", options[ind])) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto err;
            }

            host = strdup(options[ind + 1]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto err;
            }

            if (!nbd_is_valid_host(host)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", host);
                goto err;
            }

            ind += 2;
        } else if (!strcmp("prealloc", options[ind])) {
            create->prealloc = true;
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

            create->size = size;

            ind += 2;
        } else {
            nbd_err("Invalid option : %s\n", options[ind]);
            ret = -EINVAL;
            goto err;
        }
    }

    if (!host && !(host = strdup("localhost"))) {
        ret = -ENOMEM;
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_create_1(create, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_create_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.buf)
        nbd_err("Create failed: %s\n", rep.buf);
    else
        nbd_info("Create succeeded!\n");

err:
    if (clnt) {
        if (rep.buf && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response,
                                     (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(create);
    return ret;
}

int nbd_delete_backstore(int count, char **options, int type)
{
    CLIENT *clnt = NULL;
    struct nbd_delete *delete;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int ret = 0;
    int len;
    int max_len = 1024;

    /* strict check */
    if (count != 1 && count != 3) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    delete = calloc(1, sizeof(struct nbd_delete));
    if (!delete) {
        nbd_err("No memory for nbd_delete!\n");
        return -ENOMEM;
    }

    delete->type = type;

    len = snprintf(delete->cfgstring, max_len, "key=%s", options[0]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        goto err;
    }

    if (count == 3) {
        if(!strcmp("host", options[1])) {
            host = strdup(options[2]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto err;
            }

            if (!nbd_is_valid_host(host)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", host);
                goto err;
            }
        } else {
                ret = -EINVAL;
                nbd_err("Invalid parameter '%s %s'!\n", options[1], options[2]);
                goto err;
        }
    }

    if (!host && !(host = strdup("localhost"))) {
        ret = -ENOMEM;
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_delete_1(delete, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_delete_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.buf)
        nbd_err("Delete failed: %s\n", rep.buf);
    else
        nbd_info("Delete succeeded!\n");

err:
    if (clnt) {
        if (rep.buf && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response,
                                     (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(delete);
    return ret;
}

typedef enum {
    /* These are for the NBD device stats */
    NBD_LIST_MAPPED,
    NBD_LIST_UNMAPPED,

    /* The followings are for the backstore state */
    NBD_LIST_CREATED,
    NBD_LIST_DEAD,
    NBD_LIST_LIVE,

    /* Will list all the states above */
    NBD_LIST_ALL,
} list_type;

static struct nla_policy nbd_device_policy[NBD_DEVICE_ATTR_MAX + 1] = {
    [NBD_DEVICE_INDEX]              =       { .type = NLA_U32 },
    [NBD_DEVICE_CONNECTED]          =       { .type = NLA_U8 },
};

struct map_args {
    int type;
    char *cfg;
    CLIENT *clnt;
};

static int map_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    struct nbd_postmap map;
    struct nbd_response rep = {0,};
    struct map_args *args = arg;
    uint32_t index;

    if (nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        nbd_err("Invalid response from the kernel\n");
        return NL_STOP;
    }

    if (!msg_attr[NBD_ATTR_INDEX]) {
        nbd_err("Did not receive index from the kernel\n");
        return NL_STOP;
    }

    index = nla_get_u32(msg_attr[NBD_ATTR_INDEX]);
    nbd_info("Connected /dev/nbd%d\n", (int)index);

    map.type = args->type;
    snprintf(map.nbd, NBD_DLEN_MAX, "/dev/nbd%d", index);
    time_string_now(map.time);
    strcpy(map.cfgstring, args->cfg);
    if (nbd_postmap_1(&map, &rep, args->clnt) != RPC_SUCCESS) {
        if (rep.exit && rep.buf) {
            nbd_err("nbd_postmap_1 failed: %s!\n", rep.buf);
            return NL_STOP;
        }
    }

    return NL_OK;
}

static int list_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    uint32_t index;
    struct nlattr *attr;
    int rem;
    char *key;
    int *value;
    int status;
    int ret = NL_OK;

    if (!list_hash)
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

        g_hash_table_insert(list_hash, key, value);
    }

err:
    return ret;
}

static struct nl_sock *nbd_setup_netlink(int *driver_id, int cmd, int type,
                                         char *cfg, CLIENT *clnt)
{
    struct map_args *args;
    int (*nl_callback_fn)(struct nl_msg *, void *);
    struct nl_sock *netfd;

    if (!driver_id)
        return NULL;

    args = malloc(sizeof(struct map_args));
    if (!args) {
        nbd_err("Couldn't alloc args, %s!\n", strerror(errno));
        return NULL;
    }

    args->type = type;
    args->cfg = cfg;
    args->clnt = clnt;
    netfd = nl_socket_alloc();
    if (!netfd) {
        nbd_err("Couldn't alloc socket, %s!\n", strerror(errno));
        goto err;
    }

    switch (cmd) {
    case NBD_CLI_MAP:
        nl_callback_fn = map_nl_callback;
        break;
    case NBD_CLI_LIST:
        nl_callback_fn = list_nl_callback;
        break;
    case NBD_CLI_UNMAP:
    default:
        nl_callback_fn = genl_handle_msg;
    }

    nl_socket_modify_cb(netfd, NL_CB_VALID, NL_CB_CUSTOM, nl_callback_fn, args);

    if (genl_connect(netfd)) {
        nbd_err("Couldn't connect to the nbd netlink socket, %s!\n",
                strerror(errno));
        goto err;
    }

    *driver_id = genl_ctrl_resolve(netfd, "nbd");
    if (*driver_id < 0) {
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

static int nbd_device_connect(char *cfg, struct nl_sock *netfd, int sockfd,
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

static int nbd_connect_to_server(char *host, int port)
{
    struct sockaddr_in addr;
    int sock;

    if (!host || port < 0) {
        nbd_err("Invalid host or port param!\n");
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        nbd_err("connect error: %s\n", strerror(errno));
        goto err;
    }

    return sock;

err:
    close(sock);
    return -1;
}

static int _nbd_map_device(char *cfg, struct nbd_response *rep, int dev_index,
                           int timeout, bool readonly, int type, CLIENT *clnt)
{
    struct nl_sock *netfd;
    int driver_id;
    int sockfd;
    int ret;

    /* Connect to server for IOs */
    sockfd = nbd_connect_to_server(rep->host, atoi(rep->port));
    if (sockfd < 0)
        return -1;

    /* Setup netlink to configure the nbd device */
    netfd = nbd_setup_netlink(&driver_id, NBD_CLI_MAP, type, cfg, clnt);
    if (!netfd)
        goto err;


    /* Setup the IOs sock fd to nbd device to start IOs */
    ret = nbd_device_connect(cfg, netfd, sockfd, driver_id, rep->size,
                             rep->blksize, timeout, dev_index, readonly);

    if (!ret)
        return 0;

err:
    close(sockfd);
    nl_socket_free(netfd);
    return -1;
}

int nbd_map_device(int count, char **options, int type)
{
    CLIENT *clnt = NULL;
    struct nbd_premap *map;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int dev_index = -1;
    int timeout = 0;
    bool readonly = false;
    int ret = 0;
    int len;
    int ind;
    int max_len = 1024;

    /* strict check */
    if (count < 1 || count > 7 ) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    map = calloc(1, sizeof(struct nbd_premap));
    if (!map) {
        nbd_err("No memory for nbd_map!\n");
        return -ENOMEM;
    }

    map->type = type;

    len = snprintf(map->cfgstring, max_len, "key=%s", options[0]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        goto err;
    }

    map->cfgstring[len++] = ';';

    ind = 1;
    while (ind < count) {
        if (!strncmp("/dev/nbd", options[ind], strlen("/dev/nbd"))) {
            if (sscanf(options[ind], "/dev/nbd%d", &dev_index) != 1) {
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

            host = strdup(options[ind + 1]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto err;
            }

            if (!nbd_is_valid_host(host)) {
                nbd_err("Invalid host '%s'!\n", host);
                goto err;
            }

            ind += 2;
        } else if (!strcmp("readonly", options[ind])) {
            map->readonly = true;
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

            ind += 2;
        } else {
            ret = -EINVAL;
            nbd_err("Invalid argument '%s'!\n", options[ind]);
            goto err;
        }
    }

    if (!host && !(host = strdup("localhost"))) {
        ret = -ENOMEM;
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_premap_1(map, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_premap_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.buf) {
        nbd_err("Map failed: %s\n", rep.buf);
        goto err;
    }

    /* create the /dev/nbdX device */
    ret = _nbd_map_device(map->cfgstring, &rep, dev_index, timeout, readonly,
                          type, clnt);
    if (ret < 0) {
        nbd_err("failed to init the /dev/nbd device!\n");
        goto err;
    }

    nbd_info("Map succeeded!\n");

err:
    if (clnt) {
        if (rep.buf && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response,
                                     (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(map);
    return ret;
}

static int unmap_device(struct nl_sock *netfd, int driver_id, int index)
{
    struct nl_msg *msg;
    int ret = 0;

    msg = nlmsg_alloc();
    if (!msg) {
        nbd_err("Couldn't allocate netlink message!\n");
        ret = -1;
        goto nla_put_failure;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
            NBD_CMD_DISCONNECT, 0);
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, index);
    if (nl_send_sync(netfd, msg) < 0) {
        nbd_err("Failed to disconnect device, check dmsg\n");
        ret = -1;
    }

    nbd_info("Unmap succeeded!\n");

nla_put_failure:
    return ret;
}

int nbd_unmap_device(int count, char **options, int type)
{
    CLIENT *clnt = NULL;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    struct nbd_unmap unmap = {.type = type};
    struct nl_sock *netfd;
    int driver_id;
    int dev_index;
    int ind;
    int ret;;

    /* strict check */
    if (count != 1 && count != 3) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    dev_index = -1;
    ind = 0;
    while (ind < count) {
        if (!strncmp("/dev/nbd", options[ind], strlen("/dev/nbd"))) {
            if (sscanf(options[ind], "/dev/nbd%d", &dev_index) != 1) {
                ret = -errno;
                nbd_err("Invalid nbd-device!\n");
                goto err;
            }

            strcpy(unmap.nbd, options[ind]);
            ind += 1;
        } else if (!strcmp("host", options[ind])) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto err;
            }

            host = strdup(options[ind + 1]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto err;
            }

            if (!nbd_is_valid_host(host)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", host);
                goto err;
            }

            ind += 2;
        } else {
            ret = -EINVAL;
            nbd_err("Invalid argument '%s'!\n", options[ind]);
            goto err;
        }
    }

    if (!host && !(host = strdup("localhost"))) {
        ret = -ENOMEM;
        nbd_err("No memory for host!\n");
        goto err;
    }

    if (dev_index < 0) {
        ret = -EINVAL;
        nbd_err("Invalid nbd device target!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_unmap_1(&unmap, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_premap_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.buf) {
        nbd_err("Unmap failed: %s\n", rep.buf);
        goto err;
    }

    netfd = nbd_setup_netlink(&driver_id, NBD_CLI_UNMAP, type, NULL, NULL);
    if (!netfd) {
        ret = -ENOMEM;
        goto err;
    }

    ret = unmap_device(netfd, driver_id, dev_index);

err:
    free(host);
    return ret;
}

static void list_info(const char *info, list_type ltype)
{
    json_object *globalobj = NULL;
    json_object *dobj = NULL;
    json_object *obj = NULL;
    GHashTableIter iter;
    gpointer key, value;
    const char *tmp, *tmp1;
    int status;

    if (!info) {
        nbd_err("Invalid argument and info is NULL!\n");
        return;
    }

    nbd_info("%-20s%-15s%-25s%-15s%s\n", "DEVICES", "NBD-STAT", "TIME", "BS-STAT", "BACKSTORE");
    nbd_info("%-20s%-15s%-25s%-15s%s\n", "-------", "--------", "----", "-------", "---------");

    globalobj = json_tokener_parse(info);

    switch (ltype) {
    case NBD_LIST_MAPPED:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "nbd", &obj);
                tmp = json_object_get_string(obj);
                if (tmp && tmp[0]) {
                    g_hash_table_remove(list_hash, tmp);

                    nbd_info("%-20s%-15s", tmp, "Mapped");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "NA");

                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    if (!strcmp(tmp, "dead"))
                        nbd_info("%-15s%s\n", "Dead", objkey);
                    else if (!strcmp(tmp, "mapped"))
                        nbd_info("%-15s%s\n", "Live", objkey);
                    else
                        nbd_info("%-15s", "NA");
                }
            }
        }
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (status) {
                nbd_info("%-20s%-15s", (char *)key, "Mapped");
                if (json_object_object_get_ex(globalobj, key, &dobj)) {
                    json_object_object_get_ex(dobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "NA");

                    json_object_object_get_ex(dobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-15s", tmp ? tmp : "NA");

                    json_object_object_get_ex(dobj, "backstore", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%s\n", tmp ? tmp : "NA");
                } else {
                    nbd_info("%-25s%-15s%s\n", "NA", "NA", "NA");
                }
            }
        }
        break;
    case NBD_LIST_UNMAPPED:
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (!status)
                nbd_info("%-20s%-15s%-25s%-15s%s\n", (char *)key, "Unmapped",
                        "NA", "NA", "NA");
        }
        break;
    case NBD_LIST_CREATED:
        if (globalobj) {
            json_object_object_foreach(globalobj, objkey, devobj) {
                json_object_object_get_ex(devobj, "status", &obj);
                tmp = json_object_get_string(obj);
                if (!strcmp(tmp, "created"))
                    nbd_info("%-20s%-15s%-25s%-15s%s\n", "NA", "NA", "NA",
                            "Created", objkey);
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
                    nbd_info("%-20s%-15s", tmp ? tmp : "NA", "Mapped");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s%-15s%s\n", tmp ? tmp : "NA", "Dead", objkey);
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
                        break;

                    nbd_info("%-20s%-15s", tmp, "Mapped");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "NA");

                    nbd_info("%-15s%s\n", "Live", objkey);
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
                    g_hash_table_remove(list_hash, tmp);

                    nbd_info("%-20s%-15s", tmp, "Mapped");

                    json_object_object_get_ex(devobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "NA");

                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    if (!strcmp(tmp, "dead"))
                        nbd_info("%-15s%s\n", "Dead", objkey);
                    else if (!strcmp(tmp, "mapped"))
                        nbd_info("%-15s%s\n", "Live", objkey);
                    else
                        nbd_info("%-15s", "NA");
                } else {
                    nbd_info("%-20s%-15s%-25s", "NA", "NA", "NA");
                    json_object_object_get_ex(devobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    if (!strcmp(tmp, "created"))
                        nbd_info("%-15s", "Created");
                    else
                        nbd_info("%-15s", "NA");
                    nbd_info("%s\n", objkey);
                }
            }
        }
        g_hash_table_iter_init(&iter, list_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            status = *(int *)value;
            if (status) {
                nbd_info("%-20s%-15s", (char *)key, "Mapped");
                if (json_object_object_get_ex(globalobj, key, &dobj)) {
                    json_object_object_get_ex(dobj, "maptime", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-25s", tmp ? tmp : "NA");

                    json_object_object_get_ex(dobj, "status", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%-15s", tmp ? tmp : "NA");

                    json_object_object_get_ex(dobj, "backstore", &obj);
                    tmp = json_object_get_string(obj);
                    nbd_info("%s\n", tmp ? tmp : "NA");
                } else {
                    nbd_info("%-25s%-15s%s\n", "NA", "NA", "NA");
                }
            } else {
                nbd_info("%-20s%-15s%-25s%-15s%s\n", (char *)key, "Unmapped",
                        "NA", "NA", "NA");
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

int nbd_list_devices(int count, char **options, int type)
{
    CLIENT *clnt = NULL;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    struct nbd_list list = {.type = type};
    struct nl_sock *netfd = NULL;
    struct nl_msg *msg;
    int driver_id;
    int ind;
    int ret = -1;
    list_type ltype = NBD_LIST_ALL;

    /* strict check */
    if (count < 0 || count > 3) {
         nbd_err("Invalid argument counts\n");
         return -EINVAL;
    }

    ind = 0;
    while (ind < count) {
        if (!strcmp(options[ind], "host")) {
            if (ind + 1 >= count) {
                ret = -EINVAL;
                nbd_err("Invalid argument '<host RUNNER_HOST>'!\n\n");
                goto nla_put_failure;
            }

            host = strdup(options[ind + 1]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto nla_put_failure;
            }

            if (!nbd_is_valid_host(host)) {
                ret = -EINVAL;
                nbd_err("Invalid host '%s'!\n", host);
                goto nla_put_failure;
            }

            ind += 2;
        } else if (!strcmp(options[ind], "map")) {
            ltype = NBD_LIST_MAPPED;
            ind++;
        } else if (!strcmp(options[ind], "unmap")) {
            ltype = NBD_LIST_UNMAPPED;
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
            goto nla_put_failure;
        }
    }

    if (!host && !(host = strdup("localhost"))) {
        ret = -ENOMEM;
        nbd_err("No memory for host!\n");
        goto nla_put_failure;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto nla_put_failure;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
            RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto nla_put_failure;
    }

    if (nbd_list_1(&list, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_list_1 failed!\n");
        goto nla_put_failure;
    }

    ret = rep.exit;
    if (ret && rep.buf) {
        nbd_err("List failed: %s\n", rep.buf);
        goto nla_put_failure;
    }

    list_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key, free_value);
    if (!list_hash) {
        ret = -errno;
        nbd_err("failed to create list_hash table!\n");
        goto nla_put_failure;
    }

    netfd = nbd_setup_netlink(&driver_id, NBD_CLI_LIST, type, NULL, NULL);
    if (!netfd) {
        ret = -ENOMEM;
        goto nla_put_failure;
    }

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

    if (nl_send_sync(netfd, msg) < 0) {
        ret = -errno;
        nbd_err("Failed to setup device, check dmesg\n");
    }

    list_info(rep.buf, ltype);
    ret = 0;

nla_put_failure:
    nl_socket_free(netfd);
    if (clnt) {
        if (rep.buf && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response,
                    (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    if (list_hash)
        g_hash_table_destroy(list_hash);
    free(host);
    return ret;
}

int nbd_register_cmds(GHashTable *cmds_hash, struct cli_cmd *cmds)
{
    char *key;
    char *sep, *q;
    const char *p;
    int len;
    int i;

    if (!cmds)
        return -1;

    for (i = 0; cmds[i].pattern; i++) {
        key = calloc(1, 1024);
        if (!key) {
            nbd_err("No memory for cmds_hash key!\n");
            return -1;
        }

        /* Skip the white spaces fist */
        p = cmds[i].pattern;
        while (*p == ' ')
            p++;

        /* Parse the backstore type, like "gluster" and "ceph" */
        sep = strchr(p, ' ');
        if (!sep) {
            strcpy(key, p);
            goto insert;
        }
        len = sep - p;
        strncpy(key, p, len);
        p += len;

        /* The hash key will be like "backstore_type cmd" */
        key[len++] = ' ';
        q = key + len;

        while (*p == ' ')
            p++;

        /* Parse the cmd, like "create", "delete", "map" */
        sep = strchr(p, ' ');
        if (!sep) {
            strcpy(q, p);
        } else {
            len = sep - p;
            strncpy(q, p, len);
            q[len] = '\0';
        }
insert:
        g_hash_table_insert(cmds_hash, key, &cmds[i]);
    }

    return 0;
}

GHashTable *nbd_register_backstores(void)
{
    GHashTable *cmds_hash;

    cmds_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key, NULL);
    if (!cmds_hash) {
        nbd_err("failed to create cmds_hash table!\n");
        return NULL;
    }

    if (cli_cmd_gluster_register(cmds_hash)) {
        nbd_err("failed to register gluster cmds!\n");
        goto err;
    }

    return cmds_hash;

err:
    g_hash_table_destroy(cmds_hash);
    return NULL;
}

void nbd_unregister_backstores(GHashTable *cmds_hash)
{
    if (cmds_hash)
        g_hash_table_destroy(cmds_hash);
}
