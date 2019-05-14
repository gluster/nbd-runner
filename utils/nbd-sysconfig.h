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
#define NBD_CONFIG_FILE_DEFAULT NBD_CONFIG_DIR_DEFAULT"/nbd-runner"

#define NBD_HOST_LOCAL_DEFAULT "localhost"

struct nbd_config {
    int log_level;

    char log_dir[PATH_MAX];

    char ihost[NBD_HOST_MAX];
    char rhost[NBD_HOST_MAX];
    char ghost[NBD_HOST_MAX];
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

struct nbd_config* nbd_load_config(void);
void nbd_free_config(struct nbd_config *cfg);

#endif /* __NBD_CONFIG_H */
