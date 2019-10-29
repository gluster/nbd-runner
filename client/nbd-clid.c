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
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#include <linux/nbd.h>
#include <linux/nbd-netlink.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <json-c/json.h>
#include <pthread.h>
#include <signal.h>

#include "rpc_nbd.h"
#include "utils.h"
#include "nbd-log.h"
#include "nbd-cli-common.h"
#include "ipc.h"

#define NBD_CLID_PID_FILE_DEFAULT "/run/nbd-clid.pid"

static pthread_cond_t nbd_live_cond;
static pthread_mutex_t nbd_live_lock;
static pthread_mutex_t nbd_lock;

static void
nbd_clid_create_backstore(handler_t htype, const char *cfg, ssize_t size,
                          bool prealloc, const char *rhost,
                          struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_create *create;
    struct nbd_response rep = {0,};
    struct addrinfo *res = NULL;
    int sock = RPC_ANYSOCK;
    int len;
    int max_len = 1024;
    int eno;

    nbd_info("Create request htype: %d, cfg: %s, prealloc: %d, size: %zu, rhost: %s\n",
             htype, cfg, !!prealloc, size, rhost);

    create = calloc(1, sizeof(struct nbd_create));
    if (!create) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_create!");
        nbd_err("No memory for nbd_create!\n");
        return;
    }

    create->htype = htype;
    create->size = size;
    create->prealloc = prealloc;

    len = snprintf(create->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "snprintf error for cfgstring, %s!",
                            strerror(eno));
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(eno));
        goto err;
    }

    res = nbd_get_sock_addr(rhost, NBD_RPC_SVC_PORT);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "clnttcp_create failed, %s!",
                            strerror(eno));
        nbd_err("clnttcp_create failed, %s!\n", strerror(eno));
        goto err;
    }

    if (nbd_create_1(create, &rep, clnt) != RPC_SUCCESS) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "nbd_create_1 failed, %s!",
                            strerror(eno));
        nbd_err("nbd_create_1 failed, %s!\n", strerror(eno));
        goto err;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "%s", rep.buf);
        nbd_err("Create failed: %d, %s\n", rep.exit, rep.buf);
    } else {
        nbd_info("Create succeeded!\n");
    }

err:
    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    freeaddrinfo(res);
    free(create);
}

static void
nbd_clid_delete_backstore(handler_t htype, const char *cfg, const char *rhost,
                          struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_delete *delete;
    struct nbd_response rep = {0,};
    struct addrinfo *res = NULL;
    int sock = RPC_ANYSOCK;
    int len;
    int max_len = 1024;
    int eno;

    nbd_info("Delete request htype: %d, cfg: %s, rhost: %s\n",
             htype, cfg, rhost);

    delete = calloc(1, sizeof(struct nbd_delete));
    if (!delete) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_delete!");
        nbd_err("No memory for nbd_delete!\n");
        return;
    }

    delete->htype = htype;

    len = snprintf(delete->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "snprintf error for cfgstring, %s!",
                            strerror(eno));
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(eno));
        goto err;
    }

    res = nbd_get_sock_addr(rhost, NBD_RPC_SVC_PORT);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "clnttcp_create failed, %s!",
                            strerror(eno));
        nbd_err("clnttcp_create failed, %s!\n", strerror(eno));
        goto err;
    }

    if (nbd_delete_1(delete, &rep, clnt) != RPC_SUCCESS) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "nbd_delete_1 failed, %s!",
                            strerror(eno));
        nbd_err("nbd_delete_1 failed, %s!\n", strerror(eno));
        goto err;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "%s", rep.buf);
        nbd_err("Delete failed: %d, %s\n", rep.exit, rep.buf);
    } else {
        nbd_info("Delete succeeded!\n");
    }

err:
    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    freeaddrinfo(res);
    free(delete);
}

/*
 * Return values:
 * 1,   means inused
 * 0,   means nbd device does not exist or already in free state
 * < 0, means something is wrong when checking the status
 */
static int nbd_check_device_status(struct cli_reply **cli_rep, int nbd_index)
{
    GHashTable *list_hash = NULL;
    char nbd[64] = {0};
    gpointer status;
    int ret = 1;

    ret = nbd_get_device_list(&list_hash);
    if (ret) {
        nbd_clid_fill_reply(cli_rep, ret, "nbd_get_device_list failed!");
        nbd_err("nbd_get_device_list failed!\n");
        goto out;
    }

    /* Check whether the /dev/nbdX is already unmapped or not */
    sprintf(nbd, "/dev/nbd%d", nbd_index);
    status = g_hash_table_lookup(list_hash, nbd);
    if (!status) {
        nbd_clid_fill_reply(cli_rep, 0, "/dev/nbd%d does not exist in nbd.ko!",
                            nbd_index);
        nbd_info("/dev/nbd%d does not exist in nbd.ko!\n", nbd_index);
        ret = 0;
        goto out;
    }
    if (*(int *)status == 0) {
        nbd_clid_fill_reply(cli_rep, 0, "/dev/nbd%d is not mapped or already unmapped!",
                            nbd_index);
        nbd_info("/dev/nbd%d is not mapped or already unmapped!\n", nbd_index);
        ret = 0;
        goto out;
    }

    ret = 1;
out:
    if (list_hash)
        g_hash_table_destroy(list_hash);

    return ret;
}

static int nbd_device_connect(char *cfg, struct nl_sock *netfd, int sockfd,
                              int driver_id, ssize_t size, ssize_t blk_size,
                              int timeout, int nbd_index, bool readonly,
                              bool reconnect)
{
    struct nlattr *sock_attr;
    struct nlattr *sock_opt;
    struct nl_msg *msg;
    int flags = readonly ? NBD_FLAG_READ_ONLY : 0;
    struct nego_request nhdr;
    struct nego_reply nrep;
    int count = 0;
    char *buf;
    int ret = 0;

    nbd_info("cfg: %s, nbd_index: %d, readonly: %d, size: %zu, blk_size: %zu, timeout: %d\n",
             cfg, nbd_index, readonly, size, blk_size, timeout);

    if (reconnect && nbd_index < 0) {
        nbd_err("Trying to reconfigure but get an invalid nbd_index: %d\n",
                nbd_index);
        return -EINVAL;
    }

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
        ret = nrep.exit;
        goto nla_put_failure;
    }

retry:
    msg = nlmsg_alloc();
    if (!msg) {
        ret = -errno;
        nbd_err("Couldn't allocate netlink message, %s!\n",
                strerror(ret));
        goto nla_put_failure;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
                reconnect ? NBD_CMD_RECONFIGURE : NBD_CMD_CONNECT, 0);

    /* -1 means alloc the device dynamically */
    if (nbd_index < -1)
        nbd_index = -1;
    NLA_PUT_U32(msg, NBD_ATTR_INDEX, nbd_index);
    NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, size);
    NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES,
                blk_size ? blk_size : NBD_DEFAULT_SECTOR_SIZE);
    NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, flags);

    /* Release/remove the nbd device when disconnected */
    NLA_PUT_U64(msg, NBD_ATTR_CLIENT_FLAGS, NBD_CFLAG_DESTROY_ON_DISCONNECT);

    if (timeout)
        NLA_PUT_U64(msg, NBD_ATTR_TIMEOUT, timeout);

    /*
     * Sometimes we like to upgrade our server(nbd-runner) or for some reason
     * the server has been rebooted without making all of our clients freak
     * out and reconnect.
     *
     * We need to specify a dead connection timeout to allow us to pause all
     * requests and wait for new connections to be opened. With this in place
     * I can take down the nbd server for less than the dead connection timeout
     * time and bring it back up and everything resumes gracefully.
     */
    NLA_PUT_U64(msg, NBD_ATTR_DEAD_CONN_TIMEOUT, 30);

    sock_attr = nla_nest_start(msg, NBD_ATTR_SOCKETS);
    if (!sock_attr) {
        ret = -errno;
        nbd_err("Couldn't nest the socket, %s!\n", strerror(ret));
        goto nla_put_failure;
    }
    sock_opt = nla_nest_start(msg, NBD_SOCK_ITEM);
    if (!sock_opt) {
        nbd_err("Couldn't nest the socket item, %s!\n", strerror(errno));
        goto nla_put_failure;
    }

    NLA_PUT_U32(msg, NBD_SOCK_FD, sockfd);
    nla_nest_end(msg, sock_opt);
    nla_nest_end(msg, sock_attr);

    if ((ret = nl_send_sync(netfd, msg)) < 0) {
        if (nbd_index == -1 || count++ >= 500) {
            nbd_err("Failed to setup device, check dmesg, %d!\n", ret);
            goto nla_put_failure;
        }

        /*
         * There is one problem that when trying to check the nbd device
         * NBD_CMD_STATUS and at the same time insert the nbd.ko module,
         * we can randomly get some of the 16 /dev/nbd{0~15} are connected,
         * but they are not. This is because that the udev service in user
         * space will try to open /dev/nbd{0~15} devices to do some sanity
         * check when they are added in "__init nbd_init()" and then close
         * it asynchronousely.
         *
         * And the NBD_CMD_DISCONNECT still has the similiar problem, so
         * we need to wait for a while.
         *
         * TBD: This should be fixed in kernel space. And here as one work
         * around we just hard code it and wait at most 5 seconds.
         */
        g_usleep(10000);
        goto retry;
    }

    return 0;

nla_put_failure:
    return ret;
}

static int nbd_connect_to_server(char *host, int port)
{
    struct addrinfo *res = NULL;
    int sock;
    int ret;

    if (!host || port < 0) {
        nbd_err("Invalid host or port param!\n");
        return -EINVAL;
    }

    nbd_dbg("host: %s, port %d\n", host, port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        return sock;
    }

    res = nbd_get_sock_addr(host, port);
    if (!res) {
        nbd_err("failed to get sock addr for '%s:%d'!\n", host, port);
        ret = -EINVAL;
        goto err;
    }

    if (connect(sock, (struct sockaddr_in *)res->ai_addr, sizeof(struct sockaddr_in)) < 0) {
        ret = -errno;
        nbd_err("connect error: %s\n", strerror(errno));
        goto err;
    }

    freeaddrinfo(res);
    return sock;

err:
    if (res)
        freeaddrinfo(res);
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
    if ((ret = nl_send_sync(netfd, msg)) < 0) {
        nbd_err("Failed to disconnect device, check dmsg, %d\n", ret);
        ret = -1;
        goto nla_put_failure;
    }

nla_put_failure:
    if (ret)
        nbd_err("Unmap '/dev/nbd%d' failed!\n", index);
    else
        nbd_info("Unmap '/dev/nbd%d' succeeded!\n", index);

    return ret;
}

static int map_nl_callback(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
    struct nbd_postmap postmap;
    struct nbd_response rep = {0,};
    struct nl_cbk_args *args = arg;
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

    postmap.htype = args->htype;
    snprintf(postmap.nbd, NBD_DLEN_MAX, "/dev/nbd%d", index);
    time_string_now(postmap.time);
    strcpy(postmap.cfgstring, args->cfg);
    if (nbd_postmap_1(&postmap, &rep, args->clnt) != RPC_SUCCESS) {
        if (rep.exit && rep.buf) {
            nbd_err("nbd_postmap_1 failed: %s!\n", rep.buf);
            return NL_STOP;
        }
    }

    return NL_OK;
}

static void
nbd_clid_map_device(handler_t htype, const char *cfg, int32_t nbd_index, bool readonly,
                    int timeout, const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_premap *map;
    struct nbd_postmap postmap = {0,};
    struct nbd_response rep = {0,};
    struct addrinfo *res = NULL;
    int sock = RPC_ANYSOCK;
    bool reconnect = false;
    int tmp_index;
    int ret = -EINVAL;
    int len;
    int max_len = 1024;
    struct nl_sock *netfd = NULL;
    int driver_id;
    int sockfd = -1;
    int eno;

    nbd_info("Map request htype: %d, cfg: %s, nbd_index: %d, readonly: %d, timeout: %d, rhost: %s\n",
             htype, cfg, nbd_index, readonly, timeout, rhost);

    if (nbd_index < -1)
        nbd_index = -1;

    map = calloc(1, sizeof(struct nbd_premap));
    if (!map) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_map!");
        nbd_err("No memory for nbd_map!\n");
        return;
    }

    map->htype = htype;
    map->readonly = readonly;
    map->timeout = timeout;

    len = snprintf(map->cfgstring, max_len, "%s", cfg);
    if (len < 0) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "snprintf error for cfgstring, %s!",
                            strerror(eno));
        nbd_err("snprintf error for cfgstring, %s!\n", strerror(eno));
        goto err;
    }

    res = nbd_get_sock_addr(rhost, NBD_RPC_SVC_PORT);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "clnttcp_create failed, %s!",
                            strerror(eno));
        nbd_err("clnttcp_create failed, %s!\n", strerror(eno));
        goto err;
    }

    /* Setup netlink to configure the nbd device */
    netfd = nbd_setup_netlink(&driver_id, map_nl_callback, htype, map->cfgstring,
                              clnt, NULL, &ret);
    if (!netfd) {
        nbd_clid_fill_reply(cli_rep, ret, "nbd_setup_netlink failed");
        goto err;
    }

    if (nbd_premap_1(map, &rep, clnt) != RPC_SUCCESS) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "nbd_premap_1 failed, %s!",
                            strerror(eno));
        nbd_err("nbd_premap_1 failed, %s!\n", strerror(eno));
        goto err;
    }

    if (rep.exit == -EEXIST) {
        if (sscanf(rep.buf, "/dev/nbd%d", &tmp_index) != 1) {
            eno = errno;
            nbd_clid_fill_reply(cli_rep, -eno, "Invalid nbd-device returned from server side, %s!",
                                strerror(eno));
            nbd_err("Invalid nbd-device returned from server side, %s!\n", strerror(eno));
            goto err;
        }

        if (nbd_index != -1 && tmp_index != nbd_index) {
            nbd_clid_fill_reply(cli_rep, -EINVAL, "Invalid nbd index (%d), currently only (%d) is allowed, or you can unmap it and then try it again with the new index (%d)!", nbd_index, tmp_index, nbd_index);
            nbd_err("Invalid nbd index (%d), currently only (%d) is allowed, or you can unmap it and then try it again with the new index (%d)!", nbd_index, tmp_index, nbd_index);
            goto err;
        }

        ret = nbd_check_device_status(cli_rep, nbd_index);
        if (ret == 1) {
            reconnect = true;
        } else if (ret < 0) {
            nbd_err("nbd_check_device_status failed!\n");
            goto err;
        }
    } else if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "%s", rep.buf);
        nbd_err("Map failed: %d, %s\n", rep.exit, rep.buf);
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
                             rep.blksize, timeout, nbd_index, readonly, reconnect);
    if (ret < 0) {
        nbd_clid_fill_reply(cli_rep, ret, "failed to init the /dev/nbd device!");
        nbd_err("failed to init the /dev/nbd device, ret: %d!\n", ret);
        goto err;
    }

    if (reconnect) {
        postmap.htype = htype;
        snprintf(postmap.nbd, NBD_DLEN_MAX, "/dev/nbd%d", nbd_index);
        time_string_now(postmap.time);
        strcpy(postmap.cfgstring, cfg);
        if (nbd_postmap_1(&postmap, &rep, clnt) != RPC_SUCCESS) {
            if (rep.exit && rep.buf) {
                nbd_err("nbd_postmap_1 failed: %s!\n", rep.buf);
                ret = rep.exit;
                goto err;
            }
        }
    }

err:
    if (ret) {
        nbd_err("Map failed, %s!\n", rep.buf);
        if (clnt) {
            if (rep.buf)
                clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);

            postmap.htype = htype;
            strcpy(postmap.cfgstring, cfg);
            if (nbd_postmap_1(&postmap, &rep, clnt) != RPC_SUCCESS) {
                if (rep.exit && rep.buf)
                    nbd_err("nbd_postmap_1 failed: %s!\n", rep.buf);
            }
        }
    } else {
        nbd_info("Map succeeded!\n");
    }

    /* We will keep the sockfd opened if succeeded */
    if (sockfd >= 0)
        close(sockfd);

    nl_socket_free(netfd);

    if (clnt) {
        if (rep.buf)
           clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }

    freeaddrinfo(res);
    free(map);
}

static void
nbd_clid_unmap_device(handler_t htype, const char *cfg, int nbd_index,
                      const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct nbd_response rep = {0,};
    struct addrinfo *res = NULL;
    int sock = RPC_ANYSOCK;
    struct nbd_unmap *unmap = NULL;
    struct nl_sock *netfd = NULL;
    int max_len = 1024;
    int driver_id;
    int len;
    int ret;;

    nbd_info("Unmap request htype: %d, cfg: %s, nbd_index: %d, rhost: %s\n",
             htype, cfg, nbd_index, rhost);

    unmap = calloc(1, sizeof(struct nbd_unmap));
    if (!unmap) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "No memory for nbd_map!");
        nbd_err("No memory for nbd_map!\n");
        return;
    }

    unmap->htype = htype;

    if (nbd_index < -1)
        nbd_index = -1;

    if (nbd_index >= 0) {
        sprintf(unmap->nbd, "/dev/nbd%d", nbd_index);
    } else {
        len = snprintf(unmap->cfgstring, max_len, "%s", cfg);
        if (len < 0) {
            nbd_clid_fill_reply(cli_rep, -errno, "snprintf error for cfgstring, %s!",
                                strerror(errno));
            nbd_err("snprintf error for cfgstring, %s!\n", strerror(errno));
            goto err;
        }
    }

    res = nbd_get_sock_addr(rhost, NBD_RPC_SVC_PORT);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto err;
    }

    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        nbd_clid_fill_reply(cli_rep, -errno, "clnttcp_create failed, %s!",
                            strerror(errno));
        nbd_err("clnttcp_create failed, %s!\n", strerror(errno));
        goto err;
    }

    if (nbd_unmap_1(unmap, &rep, clnt) != RPC_SUCCESS) {
        nbd_clid_fill_reply(cli_rep, -errno, "nbd_premap_1 failed!");
        nbd_err("nbd_premap_1 failed!\n");
        goto err;
    }

    if (rep.exit == -EEXIST) {
        nbd_info("%s\n", rep.buf ? rep.buf : "No map exists");
    } else if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "%s", rep.buf);
        nbd_err("Unmap failed: %d, %s\n", rep.exit, rep.buf);
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

    if (nbd_check_device_status(cli_rep, nbd_index) <= 0)
        goto err;

    netfd = nbd_setup_netlink(&driver_id, genl_handle_msg, htype, NULL, NULL,
                              NULL, &ret);
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

    freeaddrinfo(res);
    free(unmap);
}

static void
nbd_clid_list_devices(handler_t htype, const char *rhost, struct cli_reply **cli_rep)
{
    CLIENT *clnt = NULL;
    struct addrinfo *res;
    struct nbd_response rep = {0,};
    struct nbd_list list = {.htype = htype};
    int count = 0;
    int sock;
    int eno;

    nbd_info("List request htype: %d, rhost: %s\n", htype, rhost);

    res = nbd_get_sock_addr(rhost, NBD_RPC_SVC_PORT);
    if (!res) {
        nbd_clid_fill_reply(cli_rep, -ENOMEM, "failed to get sock addr!");
        nbd_err("failed to get sock addr!\n");
        goto nla_put_failure;
    }

retry:
    sock = RPC_ANYSOCK;
    clnt = clnttcp_create((struct sockaddr_in *)res->ai_addr, RPC_NBD,
                          RPC_NBD_VERS, &sock, 0, 0);
    if (!clnt) {
        eno = errno;
        if (eno == ECONNREFUSED && count++ < 50) {
            g_usleep(100000);
            goto retry;
        }

        nbd_clid_fill_reply(cli_rep, -eno, "clnttcp_create failed, %s!",
                            strerror(eno));
        nbd_err("clnttcp_create failed, %s!\n", strerror(eno));
        goto nla_put_failure;
    }

    if (nbd_list_1(&list, &rep, clnt) != RPC_SUCCESS) {
        eno = errno;
        nbd_clid_fill_reply(cli_rep, -eno, "nbd_list_1 failed, %s!",
                            strerror(eno));
        nbd_err("nbd_list_1 failed, %s!\n", strerror(eno));
        goto nla_put_failure;
    }

    if (rep.exit && rep.buf) {
        nbd_clid_fill_reply(cli_rep, rep.exit, "%s", rep.buf);
        nbd_err("List failed: %d, %s\n", rep.exit, rep.buf);
        goto nla_put_failure;
    }

    nbd_info("List successed!\n");
    nbd_clid_fill_reply(cli_rep, 0, "%s", rep.buf);

nla_put_failure:
    if (clnt) {
        if (rep.buf)
            clnt_freeres(clnt, (xdrproc_t)xdr_nbd_response, (char *)&rep);
        clnt_destroy(clnt);
    }
    freeaddrinfo(res);
}

static bool need_to_restore_again = false;

static void *nbd_ping_liveness_start(void *arg)
{
    struct nbd_config *nbd_cfg = arg;
    char timestamp[1024] = {0};
    char buf[1024];
    int sock;

    nbd_info("rhost: %s, ping_interval is %d\n", nbd_cfg->rhost, nbd_cfg->ping_interval);

    while (1) {
        sleep(nbd_cfg->ping_interval);

        sock = nbd_connect_to_server(nbd_cfg->rhost, NBD_PING_SVC_PORT);
        if (sock < 0) {
            nbd_err("The nbd-runner daemon is down, sock: %d!\n", sock);
        }

        if (sock) {
            nbd_socket_read(sock, buf, 1024);
            if(strcmp(timestamp, buf) || need_to_restore_again) {
                if (!need_to_restore_again)
                    memcpy(timestamp, buf, 1024);

                pthread_mutex_lock(&nbd_live_lock);
                pthread_cond_signal(&nbd_live_cond);
                pthread_mutex_unlock(&nbd_live_lock);
                need_to_restore_again = false;
            }
            close(sock);
        }
    }

    nbd_info("nbd ping liveness thread exits!\n");
    return NULL;
}

static void *nbd_clid_connections_restore(void *arg)
{
    struct cli_reply *cli_rep = NULL;
    struct nbd_config *nbd_cfg = arg;
    json_object *globalobj = NULL;
    json_object *obj = NULL;
    handler_t htype;
    bool readonly;
    const char *tmp, *cfg;
    int nbd_index;
    int timeout;

    nbd_info("clid restore thread starting!\n");

    while (1) {
        /*
         * Retry and wait 5 seconds
         *
         * Currently if we restart the nbd-runner and nbd-clid at the same
         * time or at the node's boot time, the nbd-runner may need to take
         * a while to get ready.
         */
        nbd_clid_list_devices(NBD_BACKSTORE_MAX, nbd_cfg->rhost, &cli_rep);
        if (!cli_rep) {
            nbd_err("nbd_clid_list_devices failed, no memory!\n");
            return NULL;
        }

        if (cli_rep->exit) {
            nbd_err("nbd_clid_list_devices failed, %s!\n", cli_rep->buf);
            goto out;
        }

        pthread_mutex_lock(&nbd_lock);
        globalobj = json_tokener_parse((char *)cli_rep->buf);
        if (!globalobj) {
            nbd_info("There is no any stale devices or connections!\n");
            goto unlock;
        }

        json_object_object_foreach(globalobj, objkey, devobj) {
            json_object_object_get_ex(devobj, "status", &obj);
            tmp = json_object_get_string(obj);
            nbd_info("objkey: %s, status: %s\n", objkey, tmp);
            if (!strcmp(tmp, "dead")) {
                json_object_object_get_ex(devobj, "type", &obj);
                htype = json_object_get_int64(obj);

                json_object_object_get_ex(devobj, "nbd", &obj);
                tmp = json_object_get_string(obj);
                if (sscanf(tmp, "/dev/nbd%d", &nbd_index) != 1) {
                    nbd_err("Invalid nbd-device, %s!\n", strerror(errno));
                    continue;
                }

                json_object_object_get_ex(devobj, "readonly", &obj);
                readonly = json_object_get_boolean(obj);

                json_object_object_get_ex(devobj, "timeout", &obj);
                timeout = json_object_get_int64(obj);

                cfg = objkey;

                free(cli_rep);
                cli_rep = NULL;
                nbd_clid_map_device(htype, cfg, nbd_index, readonly, timeout,
                        nbd_cfg->rhost, &cli_rep);
                if (cli_rep && cli_rep->exit) {
                    nbd_err("nbd_clid_map_device failed, %s!\n", cli_rep->buf);
                    /*
                     * There maybe something wrong in the server side,
                     * such as for the gluster the volume may not ready
                     * after the node is rebooted, try it again later.
                     */
                    need_to_restore_again = true;
                    continue;
                }
            }
        }
unlock:
        pthread_mutex_unlock(&nbd_lock);

        pthread_mutex_lock(&nbd_live_lock);
        pthread_cond_wait(&nbd_live_cond, &nbd_live_lock);
        pthread_mutex_unlock(&nbd_live_lock);

        nbd_info("nbd-runner daemon is restarted, restore the connection again!\n");
    }
    nbd_info("nbd restore thread exits!\n");
out:
    if (globalobj)
        json_object_put(globalobj);
    free(cli_rep);
    return NULL;
}

static struct option const long_options[] = {
	{"rhost", required_argument, NULL, 'r'},
	{"uid", required_argument, NULL, 'u'},
	{"gid", required_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static void usage(void)
{
    printf("Usage:\n"
           "\tnbd-clid [<args>]\n\n"
           "Commands:\n"
           "\t-r, --rhost=<RUNNER_HOST>\n"
           "\t\tSpecify the listenning IP for the nbd-runner server who are handling the\n\t\tcommands of create/delete/map/unmap/list, etc from nbd-clid and IO requests\n\t\tfrom nbd.ko, 'localhost' as default\n\n"
           "\t-u, --uid=<UID>\n"
           "\t\tRun as uid, default is current user\n\n"
           "\t-g, --gid=<GID>\n"
           "\t\tRun as gid, default is current user group\n\n"
           "\t-h, --help\n"
           "\t\tDisplay this help and exit\n\n"
           "\t-v, --version\n"
           "\t\tDisplay version and exit\n\n"
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
        return -1;
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

static int nbd_clid_ipc_handle(int fd, const struct nbd_config *nbd_cfg)
{
    struct cli_request req;
    struct cli_reply *cli_rep = NULL;
    const char *rhost = nbd_cfg->rhost;
    int ret = 0;
    int sock;

    sock = accept(fd, NULL, NULL);
    if (sock < 0) {
        nbd_err("Failed to accept, %m!\n");
        return -1;
    }

    bzero(&req, sizeof(struct cli_request));
    ret = nbd_socket_read(sock, &req, sizeof(struct cli_request));
    if (ret != sizeof(struct cli_request)) {
        if (!ret)
            goto out;

        nbd_err("Nego failed, ret: %d, sizeof(struct cli_request): %lu!\n",
                ret, sizeof(struct cli_request));
        ret = -1;
        goto out;
    }

    /* Use the rhost from nbd-cli if exists */
    if (nbd_is_valid_host(req.rhost))
        rhost = req.rhost;

    switch (req.cmd) {
    case NBD_CLI_CREATE:
        pthread_mutex_lock(&nbd_lock);
        nbd_clid_create_backstore(req.htype, req.create.cfgstring,
                                  req.create.size, req.create.prealloc,
                                  rhost, &cli_rep);
        pthread_mutex_unlock(&nbd_lock);
        break;
    case NBD_CLI_DELETE:
        pthread_mutex_lock(&nbd_lock);
        nbd_clid_delete_backstore(req.htype, req.delete.cfgstring, rhost,
                                  &cli_rep);
        pthread_mutex_unlock(&nbd_lock);
        break;
    case NBD_CLI_MAP:
        pthread_mutex_lock(&nbd_lock);
        nbd_clid_map_device(req.htype, req.map.cfgstring, req.map.nbd_index,
                            req.map.readonly, req.map.timeout, rhost, &cli_rep);
        pthread_mutex_unlock(&nbd_lock);
        break;
    case NBD_CLI_UNMAP:
        pthread_mutex_lock(&nbd_lock);
        nbd_clid_unmap_device(req.htype, req.unmap.cfgstring,
                              req.unmap.nbd_index, rhost, &cli_rep);
        pthread_mutex_unlock(&nbd_lock);
        break;
    case NBD_CLI_LIST:
        nbd_clid_list_devices(req.htype, rhost, &cli_rep);
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
    free(cli_rep);
    close(sock);
    return ret;
}

static void nbd_event_loop(int fd, const struct nbd_config *nbd_cfg)
{
	struct pollfd pfd;
    struct timespec tmo;
    int ret;

    nbd_info("Starting the event loop!\n");
	do {
        memset(&tmo, 0, sizeof(tmo));
        tmo.tv_sec = 5;

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

		ret = ppoll(&pfd, 1, &tmo, NULL);

        if (event_loop_stop)
            goto out;

		if (ret == -1) {
			nbd_err("ppoll returned -1, %d\n", errno);
            goto out;
        }

        if (!ret)
            continue;

        if (pfd.revents != POLLIN) {
			nbd_err("ppoll received unexpected revent: 0x%x\n", pfd.revents);
            goto out;
        }

        if (nbd_clid_ipc_handle(fd, nbd_cfg)) {
            goto out;
        }
	} while (!event_loop_stop);

out:
    nbd_info("Stopping the event loop!\n");
}

static void sig_handler(int signo)
{
    nbd_info("Have received signal!\n");

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
    struct nbd_config *nbd_cfg;
    pthread_t restore_threadid;
    pthread_t ping_threadid;
	uid_t uid = 0;
    gid_t gid = 0;
    int ret = -1;

    nbd_cfg = nbd_load_config(false);
    if (!nbd_cfg) {
        nbd_err("Failed to load config file!\n");
        goto out;
    }

    if (nbd_setup_log(nbd_cfg->log_dir, false))
        goto out;

    nbd_info("Starting...\n");

	while ((ch = getopt_long(argc, argv, "r:u:g:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'r':
            snprintf(nbd_cfg->rhost, NBD_HOST_MAX, "%s", optarg);

            if (!nbd_is_valid_host(optarg)) {
                nbd_err("Invalid rhost IP %s!\n", optarg);
                goto out;
            }
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'v':
            printf("nbd-clid (%s)\n\n", VERSION);
            printf("%s\n", NBD_LICENSE_INFO);
			exit(0);
		case 'h':
			usage();
			exit(0);
		default:
		    printf("Try 'nbd-clid -h/--help' for more information.\n");
			exit(1);
        }
    }

    if (!nbd_minimal_kernel_version_check())
        goto out;

    if (load_our_module() < 0) {
        goto out;
    }

	sa_new.sa_handler = sig_handler;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old);
	sigaction(SIGPIPE, &sa_new, &sa_old);
	sigaction(SIGTERM, &sa_new, &sa_old);

	umask(0177);

	if ((clid_ipc_fd = nbd_ipc_listen()) < 0) {
        nbd_err("Failed to setup the ipc listen socket!\n");
        goto out;
	}

    if (nbd_setup_pid_file())
        goto out;

    if (gid && setgid(gid) < 0) {
        nbd_err("Failed to setgid to %d, %m\n", gid);
        goto out;
    }

    if ((geteuid() == 0) && (getgroups(0, NULL))) {
        if (setgroups(0, NULL) != 0) {
            nbd_err("Failed to drop supplementary group ids, %m\n");
            goto out;
        }
    }

    if (uid && setuid(uid) < 0) {
        nbd_err("Failed to setuid to %d, %m\n", uid);
        goto out;
    }

    pthread_mutex_init(&nbd_lock, NULL);
    pthread_mutex_init(&nbd_live_lock, NULL);
    pthread_cond_init(&nbd_live_cond, NULL);

    /*
     * Restore the stale connetions in the background
     *
     * NOTE: the restore thread may take a while to be finished
     * due to the known kernel issue.
     */
    pthread_create(&restore_threadid, NULL, nbd_clid_connections_restore, nbd_cfg);

    pthread_create(&ping_threadid, NULL, nbd_ping_liveness_start, nbd_cfg);

	nbd_event_loop(clid_ipc_fd, nbd_cfg);

    nbd_info("Stopping...\n");

    pthread_cancel(restore_threadid);
    pthread_cancel(ping_threadid);
    pthread_join(restore_threadid, NULL);
    pthread_join(ping_threadid, NULL);

    ret = 0;
out:
    pthread_mutex_destroy(&nbd_lock);
    pthread_mutex_destroy(&nbd_live_lock);
    pthread_cond_destroy(&nbd_live_cond);
	nbd_ipc_close(clid_ipc_fd);
    nbd_free_config(nbd_cfg);
    exit(ret);
}
