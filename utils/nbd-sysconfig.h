/*
 * Copyright 2016 China Mobile, Inc.
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of nbd-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * This file is partially copied from tcmu-runner project
 */

#ifndef __NBD_CONFIG_H
#define __NBD_CONFIG_H

#include <stdbool.h>
#include <pthread.h>

#include "utils.h"
#include "nbd-log.h"
#include "list.h"
#include "config.h"

#define NBD_CONFIG_DIR_DEFAULT "/etc/sysconfig"
#define NBD_CONFIG_SERV_DEFAULT NBD_CONFIG_DIR_DEFAULT"/nbd-runner"
#define NBD_CONFIG_CLID_DEFAULT NBD_CONFIG_DIR_DEFAULT"/nbd-clid"

#define NBD_HOST_LOCAL_DEFAULT    "localhost"
#define NBD_PING_INTERVAL_DEFAULT 5 /* seconds */

struct nbd_config {
    int log_level;

    char log_dir[PATH_MAX];

    /*
     * The default value will be:
     * INADDR_ANY for nbd-runner.service
     * 'localhost' for nbd-clid.service
     */
    char rhost[NBD_HOST_MAX];

    /*
     * The ihost only for the nbd-runner.service
     *
     * The ihost could be the same with the rhost, and if
     * there only has one nic/ipaddr in the node, they certainly
     * will be the same.
     *
     * And in the case there has more than 1 nic in your node,
     * you can specify 2 different ipaddr in the sysconfig file
     * or the via the command line to improve the perf ?
     */
    char ihost[NBD_HOST_MAX]; /* INADDR_ANY as default */

    /*
     * The ghost only for the gluster handler in nbd-runner.service
     */
    char ghost[NBD_HOST_MAX]; /* 'localhost' as default */

    /*
     * The ping instavel about the liveness of the nbd-runner daemon
     * This is only for nbd-clid.service
     */
    int ping_interval;
};

/*
 * There are 6 logging levels supported in nbd.conf:
 *    0: CRIT
 *    1: ERROR
 *    2: WARNING
 *    3: INFO
 *    4: DEBUG
 *    5: DEBUG NBD IO
 */
enum {
    NBD_CONF_LOG_LEVEL_MIN = 0,
    NBD_CONF_LOG_CRIT = 0,
    NBD_CONF_LOG_ERROR = 1,
    NBD_CONF_LOG_WARN,
    NBD_CONF_LOG_INFO,
    NBD_CONF_LOG_DEBUG,
    NBD_CONF_LOG_DEBUG_IO,
    NBD_CONF_LOG_LEVEL_MAX = NBD_CONF_LOG_DEBUG_IO,
};

static const char *const log_level_lookup[] = {
	[NBD_CONF_LOG_CRIT]             = "CRIT",
	[NBD_CONF_LOG_ERROR]            = "ERROR",
	[NBD_CONF_LOG_WARN]             = "WARNING",
	[NBD_CONF_LOG_INFO]             = "INFO",
	[NBD_CONF_LOG_DEBUG]            = "DEBUG",
	[NBD_CONF_LOG_DEBUG_IO]         = "DEBUG IO",
};

struct nbd_config* nbd_load_config(bool server);
void nbd_free_config(struct nbd_config *cfg);

#endif /* __NBD_CONFIG_H */
