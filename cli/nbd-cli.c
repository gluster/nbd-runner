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
#include <pthread.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <linux/nbd.h>
#include <fcntl.h>
#include <libkmod.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "rpc_nbd.h"
#include "utils/utils.h"
#include "nbd-log.h"
#include "nbd-netlink.h"

struct timeval TIMEOUT = {.tv_sec = 5};

static void usage(void)
{
    _nbd_out("Usage:\n"
             "\tnbd <command> [<args>]\n\n"
             "Commands:\n"
             "\thelp\n"
             "\t\tdisplay help for nbd commands\n\n"
             "\tcreate <volname@host:/path> [prealloc <yes|no>] <size SIZE> <host HOST>\n"
             "\t\tcreate path file on the volname volume, prealloc is no as default,\n"
             "\t\tand the SIZE is valid with B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB)\n\n"
             "\tdelete <volname@host:/path> <host HOST>\n"
             "\t\tdelete path file on the volname volume\n\n"
             "\tmap <volname@host:/path> [nbd-device] [threads NUM] [timeout TIME] <host HOST>\n"
             "\t\tmap path file to the nbd device, as default the threads 4, timeout 0 and daemon on\n\n"
             "\tumap <nbd-device>\n"
             "\t\tumap the nbd device\n\n"
             "\tlist <map|umap|all>\n"
             "\t\tlist the mapped|umapped|all nbd devices, all as default\n\n"
             "\tversion\n"
             "\t\tshow version info and exit.\n\n"
             "\t<host HOST> means the RPC server IP.\n"
            );
}

typedef enum {
    NBD_OPT_HELP,
    NBD_OPT_CREATE,
    NBD_OPT_DELETE,
    NBD_OPT_MAP,
    NBD_OPT_UNMAP,
    NBD_OPT_LIST,
    NBD_OPT_VERSION,

    NBD_OPT_MAX
} nbd_opt_command;

static const char *const nbd_opt_commands[] = {
    [NBD_OPT_HELP]           = "help",
    [NBD_OPT_DELETE]         = "delete",
    [NBD_OPT_CREATE]         = "create",
    [NBD_OPT_MAP]            = "map",
    [NBD_OPT_UNMAP]          = "umap",
    [NBD_OPT_LIST]           = "list",
    [NBD_OPT_VERSION]        = "version",

    [NBD_OPT_MAX]            = NULL,
};

static int nbd_command_lookup(const char *command)
{
    int i;

    if (!command)
        return -1;

    for (i = 0; i < NBD_OPT_MAX; i++) {
        if (!strcmp(nbd_opt_commands[i], command))
            return i;
    }

    return -1;
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

static int nbd_create_file(int count, char **options)
{
    CLIENT *clnt = NULL;
    struct nbd_create *create;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int ret = 0;
    int ind;
    int len;
    int max_len = 1024;

    create = calloc(1, sizeof(struct nbd_create));
    if (!create) {
        nbd_err("No memory for nbd_create!\n");
        return -ENOMEM;
    }

    create->type = NBD_HANDLER_GLUSTER;

    len = snprintf(create->cfgstring, max_len, "%s", options[2]);
    if (len < 0) {
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        ret = -errno;
        goto err;
    }
    create->cfgstring[len++] = ';';

    ind = 3;
    while (ind < count) {
        if (!strcmp("host", options[ind])) {
            host = strdup(options[ind + 1]);
            if (!host) {
                nbd_err("No memory for host!\n");
                goto err;
            }

            ind += 2;
        } else if (!strcmp("prealloc", options[ind])) {
            /* prealloc yes --> prealloc=yes */
            if (strcmp(options[ind + 1], "yes") && strcmp(options[ind + 1], "no")) {
                nbd_err("Invalid value for prealloc!\n");
                ret = -EINVAL;
                goto err;
            }

            len += snprintf(create->cfgstring + len, max_len - len, "%s", options[ind]);
            if (len < 0) {
                nbd_err("strcpy error for prealloc, %s!\n", strerror(errno));
                ret = -errno;
                goto err;
            }

            create->cfgstring[len++] = '=';

            len += snprintf(create->cfgstring + len, max_len - len, "%s", options[ind + 1]);
            if (len < 0) {
                nbd_err("strcpy error for prealloc value, %s!\n", strerror(errno));
                ret = -errno;
                goto err;
            }

            create->cfgstring[len++] = ';';
            ind += 2;
        } else if (!strcmp("size", options[ind])) {
            if (!nbd_valid_size(options[ind + 1])) {
                nbd_err("Invalid size!\n");
                ret = -EINVAL;
                goto err;
            }

            len += snprintf(create->cfgstring + len, max_len - len, "%s", options[ind]);
            if (len < 0) {
                nbd_err("strcpy error for prealloc, %s!\n", strerror(errno));
                ret = -errno;
                goto err;
            }

            create->cfgstring[len++] = '=';

            len += snprintf(create->cfgstring + len, max_len - len, "%s", options[ind + 1]);
            if (len < 0) {
                nbd_err("strcpy error for prealloc value, %s!\n", strerror(errno));
                ret = -errno;
                goto err;
            }

            create->cfgstring[len++] = ';';
            ind += 2;
        } else {
            nbd_err("Invalid option : %s\n", options[ind]);
            ret = -EINVAL;
            goto err;
        }
    }

    if (!host) {
        nbd_err("<host HOST> param is a must here!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD, RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_create_1(create, &rep, clnt) != RPC_SUCCESS) {
        nbd_err("nbd_create_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.out)
        nbd_err("Create failed: %s\n", rep.out);
    else
        nbd_out("Create succeeded!\n");

err:
    if (clnt) {
        if (rep.out && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(create);
    return ret;
}

static int nbd_delete_file(int count, char **options)
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

    delete = calloc(1, sizeof(struct nbd_delete));
    if (!delete) {
        nbd_err("No memory for nbd_delete!\n");
        return -ENOMEM;
    }

    delete->type = NBD_HANDLER_GLUSTER;

    len = snprintf(delete->cfgstring, max_len, "%s", options[2]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        goto err;
    }

    if (!strcmp("host", options[3])) {
        host = strdup(options[4]);
        if (!host) {
            ret = -ENOMEM;
            nbd_err("No memory for host!\n");
            goto err;
        }
    }

    if (!host) {
        nbd_err("<host HOST> param is a must here!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD, RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_delete_1(delete, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_create_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.out)
        nbd_err("Delete failed: %s\n", rep.out);
    else
        nbd_out("Delete succeeded!\n");

err:
    if (clnt) {
        if (rep.out && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(delete);
    return ret;
}

typedef enum {
    NBD_LIST_MAPPED,
    NBD_LIST_UNMAPPED,
    NBD_LIST_ALL,
} list_type;

static int nbd_list_type = NBD_LIST_ALL;

static struct nla_policy nbd_device_policy[NBD_DEVICE_ATTR_MAX + 1] = {
    [NBD_DEVICE_INDEX]              =       { .type = NLA_U32 },
    [NBD_DEVICE_CONNECTED]          =       { .type = NLA_U8 },
};

static int map_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    uint32_t index;
    int ret;

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
    nbd_out("Connected /dev/nbd%d\n", (int)index);

    return NL_OK;
}

static int list_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    uint32_t index;
    struct nlattr *attr;
    int rem;
    int status;

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
            return NL_STOP;
        }

        if (nla_parse_nested(devices, NBD_DEVICE_ATTR_MAX, attr,
                             nbd_device_policy) < 0) {
            nbd_err("nbd: error processing device list\n");
            return NL_STOP;
        }

        index = (int)nla_get_u32(devices[NBD_DEVICE_INDEX]);
        status = (int)nla_get_u8(devices[NBD_DEVICE_CONNECTED]);

        switch (nbd_list_type) {
        case NBD_LIST_MAPPED:
            if (status)
                nbd_out("/dev/nbd%d \t%s\n", index, "Mapped");
            break;
        case NBD_LIST_UNMAPPED:
            if (!status)
                nbd_out("/dev/nbd%d \t%s\n", index, "Unmapped");
            break;
        case NBD_LIST_ALL:
            nbd_out("/dev/nbd%d \t%s\n", index,
                    status ? "Mapped" : "Unmapped");
            break;
        default:
            nbd_err("Invalid list type: %d!\n", nbd_list_type);
            return NL_STOP;
        }
    }

    return NL_OK;
}

static struct nl_sock *nbd_setup_netlink(int *driver_id, int cmd)
{
    int (*nl_callback_fn)(struct nl_msg *, void *);
    struct nl_sock *netfd;

    if (!driver_id)
        return NULL;

    netfd = nl_socket_alloc();
    if (!netfd) {
        nbd_err("Couldn't alloc socket, %s!\n", strerror(errno));
        return NULL;
    }

    switch (cmd) {
    case NBD_OPT_MAP:
        nl_callback_fn = map_nl_callback;
        break;
    case NBD_OPT_LIST:
        nl_callback_fn = list_nl_callback;
        break;
    case NBD_OPT_UNMAP:
    default:
        nl_callback_fn = genl_handle_msg;
    }

    nl_socket_modify_cb(netfd, NL_CB_VALID, NL_CB_CUSTOM, nl_callback_fn, NULL);

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
    nl_socket_free(netfd);
    return NULL;
}

static int nbd_device_connect(char *cfg, struct nl_sock *netfd, int sockfd,
                              int driver_id, ssize_t size, ssize_t blk_size,
                              int timeout, int dev_index)
{
    struct nlattr *sock_attr;
    struct nlattr *sock_opt;
    struct nl_msg *msg;
    int flags = 0;
    struct nego_header hdr;

    hdr.len = strlen(cfg);
    nbd_socket_write(sockfd, &hdr, sizeof(struct nego_header));
    nbd_socket_write(sockfd, cfg, hdr.len);

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
    int ret;

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

static int _nbd_map_device(char *cfg, struct nbd_response *rep, int dev_index, int timeout)
{
    int ret = -1;
    int sockfd;
    struct nl_sock *netfd;
    int driver_id;

    printf("lxb : host: %s, port: %s, size: %llu, blksize: %llu\n", rep->host, rep->port, rep->size, rep->blksize);
    /* Connect to server for IOs */
    sockfd = nbd_connect_to_server(rep->host, atoi(rep->port));
    if (sockfd < 0)
        return -1;

    /* Setup netlink to configure the nbd device */
    netfd = nbd_setup_netlink(&driver_id, NBD_OPT_MAP);
    if (!netfd)
        return -1;

    /* Setup the IOs sock fd to nbd device to start IOs */
    return nbd_device_connect(cfg, netfd, sockfd, driver_id, rep->size, rep->blksize, timeout, dev_index);

err:
    nl_socket_free(netfd);
    return -1;
}

static int nbd_map_device(int count, char **options)
{
    CLIENT *clnt = NULL;
    struct nbd_map *map;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int dev_index = -1;
    int timeout = 0;
    int ret = 0;
    int len;
    int ind;
    int max_len = 1024;

    map = calloc(1, sizeof(struct nbd_map));
    if (!map) {
        nbd_err("No memory for nbd_map!\n");
        return -ENOMEM;
    }

    map->type = NBD_HANDLER_GLUSTER;

    len = snprintf(map->cfgstring, max_len, "%s", options[2]);
    if (len < 0) {
        ret = -errno;
        nbd_err("snprintf error for volinfo, %s!\n", strerror(errno));
        goto err;
    }

    ind = 3;
    while (ind < count) {
        if (!strncmp("/dev/nbd", options[ind], strlen("/dev/nbd"))) {
            if (sscanf(options[ind], "/dev/nbd%d", &dev_index) != 1) {
                ret = -errno;
                nbd_err("Invalid nbd-device!\n");
                goto err;
            }

            ind += 1;
        } else if (!strcmp("host", options[ind])) {
            host = strdup(options[ind + 1]);
            if (!host) {
                ret = -ENOMEM;
                nbd_err("No memory for host!\n");
                goto err;
            }

            ind += 2;
#if 0
        } else if (!strcmp("threads", options[ind])) {
            threads = atoi(options[ind + 1]);
            if (threads <= 0) {
                fprintf(stderr,
                        "Invalid threads, will set it as default %d!\n",
                        NBD_MAX_THREAD_DEF);
                threads = NBD_MAX_THREAD_DEF;
            }

            if (threads > NBD_MAX_THREAD_MAX) {
                fprintf(stderr,
                        "Currently the max threads is %d!\n",
                        NBD_MAX_THREAD_MAX);
                threads = NBD_MAX_THREAD_MAX;
            }

            ind += 2;
#endif
        } else if (!strcmp("timeout", options[ind])) {
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

    if (!host) {
        nbd_err("<host HOST> param is a must here!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        ret = -ENOMEM;
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD, RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        ret = -errno;
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_map_1(map, &rep, clnt) != RPC_SUCCESS) {
        ret = -errno;
        nbd_err("nbd_create_1 failed!\n");
        goto err;
    }

    ret = rep.exit;
    if (ret && rep.out) {
        nbd_err("Map failed: %s\n", rep.out);
        goto err;
    }

    /* create the /dev/nbdX device */
    ret = _nbd_map_device(map->cfgstring, &rep, dev_index, timeout);
    if (ret < 0) {
        nbd_err("failed to init the /dev/nbd device!\n");
        goto err;
    }

    nbd_out("Map succeeded!\n");

err:
    if (clnt) {
        if (rep.out && !clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep))
            nbd_err("clnt_freeres failed!\n");
        clnt_destroy(clnt);
    }

    free(host);
    free(map);
    return ret;
}

static int
umap_device(struct nl_sock *netfd, int driver_id, int index)
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

nla_put_failure:
    return ret;
}

static int
nbd_umap_device(int count, char **options)
{
    struct nl_sock *netfd;
    int driver_id;
    int index = -1;

    if (count != 3) {
        nbd_err("Invalid arguments for umap command!\n");
        return -1;
    }

    if (sscanf(options[2], "/dev/nbd%d", &index) != 1) {
        nbd_err("Invalid nbd device target!\n");
        return -1;
    }

    if (index < 0) {
        nbd_err("Invalid nbd device target!\n");
        return -1;
    }

    netfd = nbd_setup_netlink(&driver_id, NBD_OPT_UNMAP);
    if (!netfd)
        return -1;

    return umap_device(netfd, driver_id, index);
}

static int nbd_devices_query(struct nl_sock *netfd, int driver_id)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (!msg) {
        nbd_err("Couldn't allocate netlink message, %s!\n",
                strerror(errno));
        goto nla_put_failure;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
            NBD_CMD_STATUS, 0);
    /* -1 means list all the devices allocated(mapped and umapped) in kernel space */
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, -1);

    if (nl_send_sync(netfd, msg) < 0)
        nbd_err("Failed to setup device, check dmesg\n");

    return 0;

nla_put_failure:
    nl_socket_free(netfd);
    return -1;
}

static int
nbd_list_devices(int count, char **options)
{
    struct nl_sock *netfd;
    int driver_id;

    if (count != 3) {
        nbd_err("Invalid arguments for list command!\n");
        return -1;
    }

    if (!strcmp(options[2], "map")) {
        nbd_list_type = NBD_LIST_MAPPED;
    } else if (!strcmp(options[2], "umap")) {
        nbd_list_type = NBD_LIST_UNMAPPED;
    } else if (!strcmp(options[2], "all")) {
        nbd_list_type = NBD_LIST_ALL;
    } else {
        nbd_err("Invalid argument for list!\n");
        return -1;
    }

    netfd = nbd_setup_netlink(&driver_id, NBD_OPT_LIST);
    if (!netfd)
        return -1;

    return nbd_devices_query(netfd, driver_id);
}

static int load_our_module(void)
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
                nbd_out("no modules directory '/lib/modules/%s', checking module nbd entry in '/sys/modules/'\n",
                        u.release);
                ret = stat(CFGFS_NBD_MOD, &sb);
                if (ret) {
                    nbd_err("stat() on '%s' failed: %m\n", CFGFS_NBD_MOD);
                } else {
                  //  nbd_out("Module nbd already loaded\n");
                }
            }
        } else {
            nbd_err("kmod_module_new_from_lookup() failed to lookup alias target_core_use %m\n");
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
            nbd_out("Module '%s' is builtin\n", kmod_module_get_name(mod));
            break;

        case KMOD_MODULE_LIVE:
//            nbd_out("Module '%s' is already loaded\n", kmod_module_get_name(mod));
            break;

        default:
            err = kmod_module_probe_insert_module(mod,
                    KMOD_PROBE_APPLY_BLACKLIST,
                    NULL, NULL, NULL, NULL);

            if (err == 0) {
                nbd_out("Inserted module '%s'\n", kmod_module_get_name(mod));
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
        }
        kmod_module_unref(mod);
    }

    kmod_module_unref_list(list);
    kmod_unref(ctx);

    return ret;
}

int main(int argc, char *argv[])
{
    int ex = EXIT_SUCCESS;
    nbd_opt_command cmd;
    int ret;

    nbd_log_init();

    if (!nbd_minimal_kernel_version_check())
        goto out;

    if (argc <= 1) {
        nbd_err("Too few options!\n\n" );
        usage();
        ex = EXIT_FAILURE;
        goto out;
    }

    if (load_our_module() < 0)
        goto out;

    cmd = nbd_command_lookup(argv[1]);
    if (cmd < 0) {
        nbd_err("Invalid command!\n\n" );
        usage();
        ex = EXIT_FAILURE;
        goto out;
    }

    switch(cmd) {
    case NBD_OPT_HELP:
        usage();
        goto out;
    case NBD_OPT_CREATE:
        ret = nbd_create_file(argc, argv);
        if (ret < 0)
                ex = EXIT_FAILURE;
        break;
    case NBD_OPT_DELETE:
        ret = nbd_delete_file(argc, argv);
        if (ret < 0)
                ex = EXIT_FAILURE;
        break;
    case NBD_OPT_MAP:
        ret = nbd_map_device(argc, argv);
        if (ret < 0)
                ex = EXIT_FAILURE;
        break;
    case NBD_OPT_UNMAP:
        ret = nbd_umap_device(argc, argv);
        if (ret < 0)
                ex = EXIT_FAILURE;
        break;
    case NBD_OPT_LIST:
        ret = nbd_list_devices(argc, argv);
        if (ret < 0)
                ex = EXIT_FAILURE;
        break;
    case NBD_OPT_VERSION:
        _nbd_out("%s\n", nbd_version_info);
        break;
    case NBD_OPT_MAX:
    default:
        nbd_err("Invalid command!\n");
        usage();
        ex = EXIT_FAILURE;
        goto out;
    }

out:
    nbd_log_destroy();
    exit(ex);
}
