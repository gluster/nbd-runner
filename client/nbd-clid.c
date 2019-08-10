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
#include "nbd-cli-common.h"
#include "nbd-netlink.h"
#include "ipc.h"

#define NBD_CLID_PID_FILE_DEFAULT "/run/nbd-clid.pid"

static void
nbd_clid_create_backstore(int type, const char *cfg, ssize_t size,
                          bool prealloc, const char *rhost,
                          struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_create *create;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int ind;
    int len;
    int max_len = 1024;

    create = calloc(1, sizeof(struct nbd_create));
    if (!create) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_create!");
        nbd_err("No memory for nbd_create!\n");
        return;
    }

    create->type = type;
    create->size = size;
    create->prealloc = prealloc;

    len = snprintf(create->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        nbd_clid_fill_reply(cli_rep, -errno, "snprintf error for cfgstring, %s!",
                            strerror(errno));
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        goto err;
    }

    if (rhost)
        host = strdup(rhost);
    else
        host = strdup("localhost");
    if (!host) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for host!");
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed, %s!");
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_create_1(create, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_create_1 failed!");
        nbd_err("nbd_create_1 failed, %s!\n", strerror(errno));
        goto err;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "Create failed: %s", rep.buf);
        nbd_err("Create failed: %s\n", rep.buf);
    } else {
        nbd_info("Create succeeded!\n");
    }

err:
    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    free(host);
    free(create);
}

static void
nbd_clid_delete_backstore(int type, const char *cfg, const char *rhost,
                          struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_delete *delete;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int len;
    int max_len = 1024;

    delete = calloc(1, sizeof(struct nbd_delete));
    if (!delete) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_delete!");
        nbd_err("No memory for nbd_delete!\n");
        return;
    }

    delete->type = type;

    len = snprintf(delete->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        nbd_clid_fill_reply(cli_rep, -errno, "snprintf error for cfgstring!");
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        goto err;
    }

    if (rhost)
        host = strdup(rhost);
    else
        host = strdup("localhost");
    if (!host) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for host!");
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed!");
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_delete_1(delete, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_delete_1 failed!");
        nbd_err("nbd_delete_1 failed!\n");
        goto err;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "Delete failed: %s", rep.buf);
        nbd_err("Delete failed: %s\n", rep.buf);
    } else {
        nbd_info("Delete succeeded!\n");
    }

err:
    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    free(host);
    free(delete);
}

static int nbd_device_connect(char *cfg, struct nl_sock *netfd, int sockfd,
                              int driver_id, ssize_t size, ssize_t blk_size,
                              int timeout, int nbd_index, bool readonly)
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
    if (nbd_index < -1)
        nbd_index = -1;
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, nbd_index);
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
        return -EINVAL;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        return sock;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ret = -errno;
        nbd_err("connect error: %s\n", strerror(errno));
        goto err;
    }

    return sock;

err:
    close(sock);
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
        /*
         * There will be 16 nbd device created when the nbd.ko
         * is loading as default, if the dead backstore mapped
         * to have higher number than 15 and after the client
         * node is restart or the module is reloaded, the kernel
         * will return ENOENT
         */
        if (errno != ENOENT) {
            nbd_err("Failed to disconnect device, check dmsg, %d\n", errno);
            ret = -1;
            goto nla_put_failure;
        }
    }

    nbd_info("Unmap '/dev/nbd%d' succeeded!\n", index);

nla_put_failure:
    return ret;
}

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

static void
nbd_clid_map_device(int type, const char *cfg, int nbd_index, bool readonly,
                    const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_premap *map;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    int tmp_index;
    int timeout = 30; //This is the default timeout value in kernel space for each IO request
    int ret = -EINVAL;
    int len;
    int ind;
    int max_len = 1024;
    struct nl_sock *netfd = NULL;
    int driver_id;
    int sockfd = -1;

    if (nbd_index < -1)
        nbd_index = -1;

    map = calloc(1, sizeof(struct nbd_premap));
    if (!map) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_map!");
        nbd_err("No memory for nbd_map!\n");
        return;
    }

    map->type = type;
    map->readonly = readonly;
    map->timeout = timeout;

    len = snprintf(map->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        nbd_clid_fill_reply(cli_rep, -errno, "snprintf error for cfgstring!");
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
        goto err;
    }

    if (rhost)
        host = strdup(rhost);
    else
        host = strdup("localhost");
    if (!host) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for host!");
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed!");
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    /* Setup netlink to configure the nbd device */
    netfd = nbd_setup_netlink(&driver_id, map_nl_callback, type, map->cfgstring,
                              clnt, &ret);
    if (!netfd) {
        nbd_clid_fill_reply(cli_rep, ret, "nbd_setup_netlink failed");
        goto err;
    }

    if (nbd_premap_1(map, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_premap_1 failed!");
        nbd_err("nbd_premap_1 failed!\n");
        goto err;
    }

    if (rep.exit == -EEXIST) {
        if (sscanf(rep.buf, "/dev/nbd%d", &tmp_index) != 1) {
            nbd_clid_fill_reply(cli_rep, -errno, "Invalid nbd-device returned from server side!");
            nbd_err("Invalid nbd-device returned from server side!\n");
            goto err;
        }

        ret = unmap_device(netfd, driver_id, tmp_index);
        if (ret) {
            nbd_clid_fill_reply(cli_rep, ret, "unmap /dev/nbd%d failed!",
                                tmp_index);
            nbd_err("unmap /dev/nbd%d failed!\n", tmp_index);
            goto err;
        }
    } else if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "Map failed: %s", rep.buf);
        nbd_err("Map failed: %s\n", rep.buf);
        goto err;
    }

    nbd_dbg("The listen host is '%s' and the port is '%s'\n", rep.host,
            rep.port);

    /* Connect to server for IOs */
    sockfd = nbd_connect_to_server(rep.host, atoi(rep.port));
    if (sockfd < 0) {
        nbd_clid_fill_reply(cli_rep, sockfd, "failed to connect to server!");
        goto err;
    }

    /* Setup the IOs sock fd to nbd device to start IOs */
    ret = nbd_device_connect(map->cfgstring, netfd, sockfd, driver_id, rep.size,
                             rep.blksize, timeout, nbd_index, readonly);
    if (ret < 0) {
        nbd_clid_fill_reply(cli_rep, ret, "failed to init the /dev/nbd device!");
        nbd_err("failed to init the /dev/nbd device!\n");
        goto err;
    }

    nbd_info("Map succeeded!\n");

err:
    /* We will keep the sockfd opened if succeeded */
    if (sockfd >= 0)
        close(sockfd);

    nl_socket_free(netfd);

    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    free(host);
    free(map);
}

static void
nbd_clid_unmap_device(int type, const char *cfg, int nbd_index,
                      const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_response rep = {0,};
    struct addrinfo *res;
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    struct nbd_unmap *unmap = NULL;
    struct nl_sock *netfd = NULL;
    int max_len = 1024;
    int driver_id;
    int ind;
    int len;
    int ret;;

    unmap = calloc(1, sizeof(struct nbd_unmap));
    if (!unmap) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_map!");
        nbd_err("No memory for nbd_map!\n");
        return;
    }

    unmap->type = type;

    if (nbd_index < -1)
        nbd_index = -1;

    if (nbd_index >= 0) {
        sprintf(unmap->nbd, "/dev/nbd%d", nbd_index);
    } else {
        len = snprintf(unmap->cfgstring, max_len, "%s", cfg);
        if (len < 0) {
            nbd_clid_fill_reply(cli_rep, -errno, "snprintf error for cfgstring!");
            nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
            goto err;
        }
    }

    if (rhost)
        host = strdup(rhost);
    else
        host = strdup("localhost");
    if (!host) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for host!");
        nbd_err("No memory for host!\n");
        goto err;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed!");
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_unmap_1(unmap, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_premap_1 failed!");
        nbd_err("nbd_premap_1 failed!\n");
        goto err;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "Unmap failed: %s", rep.buf);
        nbd_err("Unmap failed: %s\n", rep.buf);
        goto err;
    }

    /* We will get the nbd device from the server side */
    if (nbd_index < 0 && rep.buf) {
        sscanf(rep.buf, "/dev/nbd%d", &nbd_index);

        /*
         * If it is NULL, that means the backstore is not
         * mapped or already unmapped
         */
        if (nbd_index < 0) {
            nbd_clid_fill_reply(cli_rep, -EINVAL, "%s is not mapped!",
                                unmap->cfgstring);
            nbd_err("%s is not mapped!\n", unmap->cfgstring);
            goto err;
        }
    }

    netfd = nbd_setup_netlink(&driver_id, genl_handle_msg, type, NULL, NULL,
                              &ret);
    if (!netfd) {
        nbd_clid_fill_reply(cli_rep, ret, "setup netlink failed!");
        goto err;
    }

    ret = unmap_device(netfd, driver_id, nbd_index);
    if (ret)
        nbd_clid_fill_reply(cli_rep, ret, "unmap_device failed!");

err:
    nl_socket_free(netfd);
    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    free(host);
    free(unmap);
}

static void
nbd_clid_list_devices(int type, const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct addrinfo *res;
    struct nbd_response rep = {0,};
    char *host = NULL;
    int sock = RPC_ANYSOCK;
    struct nbd_list list = {.type = type};
    int driver_id;
    int ind;
    int ret = -1;

    if (rhost)
        host = strdup(rhost);
    else
        host = strdup("localhost");
    if (!host) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for host!");
        nbd_err("No memory for host!\n");
        goto nla_put_failure;
    }

    res = nbd_get_sock_addr(host);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto nla_put_failure;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed!");
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto nla_put_failure;
    }

    if (nbd_list_1(&list, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_list_1 failed!");
        nbd_err("nbd_list_1 failed!\n");
        goto nla_put_failure;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "List failed: %s", rep.buf);
        nbd_err("List failed: %s\n", rep.buf);
        goto nla_put_failure;
    }

    nbd_clid_fill_reply(cli_rep, 0, "%s", rep.buf);

nla_put_failure:
    if (clnt) {
        if (rep.buf)
            clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    free(host);
}

static struct option const long_options[] = {
	{"debug", required_argument, NULL, 'd'},
	{"uid", required_argument, NULL, 'u'},
	{"gid", required_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static void usage(void)
{
    nbd_info("Usage:\n"
             "\tnbd-clid [<args>]\n\n"
             "Commands:\n"
             "\t-d, --debug debuglevel\n"
             "\t\tprint debugging information\n\n"
             "\t-u, --uid=uid\n"
             "\t\trun as uid, default is current user\n\n"
             "\t-g, --gid=gid\n"
             "\t\trun as gid, default is current user group\n\n"
             "\t-h, --help\n"
             "\t\tdisplay this help and exit\n\n"
             "\t-v, --version\n"
             "\t\tdisplay version and exit\n\n"
            );
}

static int nbd_setup_pid_file(void)
{
    int ret = 0;
    char buf[16];
    int fd;

    fd = open(NBD_CLID_PID_FILE_DEFAULT, O_WRONLY|O_CREAT, 0644);
    if (fd < 0) {
        nbd_err("Failed to create pid file: %s\n", NBD_CLID_PID_FILE_DEFAULT);
        ret = -1;
        goto err;
    }

    if (lockf(fd, F_TLOCK, 0) < 0) {
        nbd_err("Failed to lock pid file: %s, file locked!\n",
                NBD_CLID_PID_FILE_DEFAULT);
        ret = -1;
        goto err;
    }

    if (ftruncate(fd, 0) < 0) {
        nbd_err("Failed to truncate pid file: %s\n", NBD_CLID_PID_FILE_DEFAULT);
        ret = -1;
        goto err;
    }

    sprintf(buf, "%d\n", getpid());
    if (write(fd, buf, strlen(buf)) < 0) {
        nbd_err("Failed to write pid file: %s\n", NBD_CLID_PID_FILE_DEFAULT);
        ret = -1;
        goto err;
    }

err:
    close(fd);
    return ret;
}

static volatile int event_loop_stop;

static void event_loop_exit(void)
{
	event_loop_stop = 1;
}

static int nbd_clid_ipc_handle(int fd)
{
    struct cli_request req;
    struct cli_reply *cli_rep = NULL;
    int sock;
    char *buf;
    int ret = 0;

    sock = accept(fd, NULL, NULL);
    if (sock < 0) {
        nbd_err("Failed to accept!\n");
        return -1;
    }

    bzero(&req, sizeof(struct cli_request));
    ret = nbd_socket_read(sock, &req, sizeof(struct cli_request));
    if (ret != sizeof(struct cli_request)) {
        nbd_err("Nigo failed, ret: %d, sizeof(struct cli_request): %d!\n",
                ret, sizeof(struct cli_request));
        ret = -1;
        goto out;
    }

    switch (req.cmd) {
    case NBD_CLI_CREATE:
        nbd_clid_create_backstore(req.type, req.create.cfgstring,
                                  req.create.size, req.create.prealloc,
                                  req.rhost, &cli_rep);
        break;
    case NBD_CLI_DELETE:
        nbd_clid_delete_backstore(req.type, req.delete.cfgstring, req.rhost,
                                  &cli_rep);
        break;
    case NBD_CLI_MAP:
        nbd_clid_map_device(req.type, req.map.cfgstring,
                            req.map.nbd_index, req.map.readonly,
                            req.rhost, &cli_rep);
        break;
    case NBD_CLI_UNMAP:
        nbd_clid_unmap_device(req.type, req.unmap.cfgstring,
                              req.unmap.nbd_index, req.rhost, &cli_rep);
        break;
    case NBD_CLI_LIST:
        nbd_clid_list_devices(req.type, req.rhost, &cli_rep);
        break;
    default:
        break;
    }

    if (!cli_rep) {
        nbd_clid_fill_reply(&cli_rep, 0, "Success");
    }

    nbd_socket_write(sock, cli_rep, sizeof(struct cli_reply) + cli_rep->len);

    ret = 0;
out:
    close(sock);
    return ret;
}

static void nbd_event_loop(int fd)
{
	struct pollfd pfd;
    struct timespec tmo;
    int ret;

	do {
        memset(&tmo, 0, sizeof(tmo));
        tmo.tv_sec = 5;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

		ret = ppoll(&pfd, 1, &tmo, NULL);
		if (ret == -1) {
			nbd_err("poll returned %d", ret);
            return;
        }

        if (!ret)
            continue;

        if (pfd.revents != POLLIN) {
			nbd_err("ppoll received unexpected revent: 0x%x", pfd.revents);
            return;
        }

        if (nbd_clid_ipc_handle(fd)) {
            return;
        }
	} while (!event_loop_stop);
}

static void sig_handler(int signo)
{
    switch (signo) {
    case SIGINT:
    case SIGTERM:
        event_loop_exit();
        break;
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
	int ch, longindex;
	struct sigaction sa_old;
	struct sigaction sa_new;
    int clid_ipc_fd = -1;
    static struct nbd_config *nbd_cfg;
	uid_t uid = 0;
    gid_t gid = 0;
	pid_t pid;
    char buf[32];
    int ret = -1;
    int log_level;

	while ((ch = getopt_long(argc, argv, "d:u:g:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'v':
            nbd_info("nbd-clid (%s)\n\n", VERSION);
            nbd_info("%s\n", NBD_LICENSE_INFO);
			exit(0);
		case 'h':
			usage();
			exit(0);
		default:
		    nbd_err("Try 'nbd-clid -h/--help' for more information.\n");
			exit(1);
        }
    }

    if (!nbd_minimal_kernel_version_check())
        goto out;

    if (load_our_module() < 0)
        goto out;

    nbd_cfg = nbd_load_config(false);
    if (!nbd_cfg) {
        nbd_err("Failed to load config file!\n");
        goto out;
    }

	sa_new.sa_handler = sig_handler;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	umask(0177);

	if ((clid_ipc_fd = nbd_ipc_listen()) < 0) {
        nbd_err("Failed to setup the ipc listen socket!\n");
        goto out;
	}

    if (nbd_setup_pid_file())
        goto out;

    if (gid && setgid(gid) < 0) {
        nbd_err("Failed to setgid to %d\n", gid);
        goto out;
    }

    if ((geteuid() == 0) && (getgroups(0, NULL))) {
        if (setgroups(0, NULL) != 0) {
            nbd_err("Failed to drop supplementary group ids\n");
            goto out;
        }
    }

    if (uid && setuid(uid) < 0) {
        nbd_err("Failed to setuid to %d\n", uid);
        goto out;
    }
#if 0
	/* Try to restore the stale connections */
	ret = nbd_sync_from_server();
	if (ret < 0) {
        nbd_err("Failed to setuid to %d\n", uid);
        goto out;
    } else if (ret > 0) {
		/*
		 * Restore stale connetions in the background
		 */

		pid = fork();
		if (pid < 0) {
			nbd_err("Failed to fork %m\n");
            goto out;
        } else if (pid == 0) {
			nbd_restore_stale_connections();
			exit(0);
        }
	}
#endif
	nbd_event_loop(clid_ipc_fd);

    ret = 0;
out:
	nbd_ipc_close(clid_ipc_fd);
    nbd_free_config(nbd_cfg);
    exit(ret);
}
