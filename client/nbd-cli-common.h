/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of nbd-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
*/

#ifndef __NBD_CLI_COMMON_H
#define __NBD_CLI_COMMON_H

#define _GNU_SOURCE

#include <stdio.h>

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>
#include <ctype.h>
#include <pthread.h>
#include <linux/types.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <gmodule.h>
#include <glib.h>
#include <gmodule.h>
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

#include "config.h"
#include "rpc_nbd.h"

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

    NBD_LIST_MAX
} list_type;

typedef enum {
    NBD_CLI_HELP,
    NBD_CLI_CREATE,
    NBD_CLI_DELETE,
    NBD_CLI_MAP,
    NBD_CLI_UNMAP,
    NBD_CLI_LIST,

    NBD_CLI_MAX
} nbd_cli_cmd_t;

struct cli_cmd {
    const char *pattern;
    nbd_cli_cmd_t cmd;
    const char *desc;
    bool disable;
};

struct cli_request {
    nbd_cli_cmd_t cmd;

    handler_t type;

    union {
        struct {
            u_quad_t size;
            bool_t prealloc;
            char cfgstring[1024];
        } create;

        struct {
            char cfgstring[1024];
        } delete;

        struct {
            bool_t readonly;
            int timeout;
            int nbd_index;
            char cfgstring[1024];
        } map;

        struct {
            int nbd_index;
            char cfgstring[1024];
        } unmap;
    };

	char rhost[255];
};

struct map_args {
    int type;
    char *cfg;
    CLIENT *clnt;
};

/* This is used to register the backstores */
typedef int (*cmd_fn_t)(GPtrArray *, struct cli_cmd *);
int cli_cmd_gluster_register(GPtrArray *cmds, cmd_fn_t fn);
int cli_cmd_azblk_register(GPtrArray *cmds, cmd_fn_t fn);

struct addrinfo *nbd_get_sock_addr(const char *host);

typedef int (*list_nl_cbk_t)(struct nl_msg *, void *);
struct nl_sock *nbd_setup_netlink(int *driver_id, list_nl_cbk_t fn, int type,
                                  char *cfg, CLIENT *clnt, int *ret);
int load_our_module(void);
#endif /* __NBD_CLI_COMMON_H */
