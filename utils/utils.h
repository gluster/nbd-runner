/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of nbd-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
*/

#ifndef __UTILS_H
#define __UTILS_H

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
#include "config.h"
#include "strlcpy.h"

#define NBD_LICENSE_INFO                                            \
"Repository rev: https://github.com/gluster/nbd-runner.git\n"       \
"Copyright (c) 2019 Red Hat, Inc. <https://redhat.com/>\n"          \
"gluster-nbd comes with ABSOLUTELY NO WARRANTY.\n"                  \
"It is licensed to you under your choice of the GNU Lesser\n"       \
"General Public License, version 3 or any later version (LGPLv3\n"  \
"or later), or the GNU General Public License, version 2 (GPLv2),\n"\
"in all cases as published by the Free Software Foundation."

#define NBD_PING_SVC_PORT    24109
#define NBD_RPC_SVC_PORT     24110
#define NBD_MAP_SVC_PORT     24111

#define NBD_DEFAULT_SECTOR_SIZE  512

#define NBD_SAVE_CONFIG_DIR "/etc/nbd-runner"
#define NBD_SAVE_CONFIG_FILE NBD_SAVE_CONFIG_DIR"/saveconfig.json"

#define NBD_HOST_MAX  255
#define NBD_CFGS_MAX  1024
#define NBD_PORT_MAX  32
/*
 * Currently only when the NBD_EXIT_MAX >= PATH_MAX(4096) + NAME_MAX(255)
 * will eliminate the snprintf's truncate warning, and here we set it to
 * 8192.
 */
#define NBD_EXIT_MAX  8192
#define NBD_TLEN_MAX  32    /* "2019-02-13 12:20:45" */
#define NBD_DLEN_MAX  32    /* "/dev/nbdXX" */

#define ALLOWED_BSOFLAGS (O_DIRECT | O_RDWR | O_LARGEFILE)
#define NBD_CMD_MASK_COMMAND 0x0000ffff
#define NBD_NL_VERSION 1

#define CFGFS_NBD_MOD "/sys/module/nbd"

typedef enum {
    NBD_DEV_CONN_ST_MIN = 0,

    NBD_DEV_CONN_ST_CREATED,
    NBD_DEV_CONN_ST_MAPPING,
    NBD_DEV_CONN_ST_MAPPED,
    NBD_DEV_CONN_ST_DEAD,
    NBD_DEV_CONN_ST_UNMAPPING,

    NBD_DEV_CONN_ST_MAX,
} dev_status_t;

#define max(a, b) ({			\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(void) (&_a == &_b);		\
	_a < _b ? _b : _a; })

#define min(a, b) ({			\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(void) (&_a == &_b);		\
	_a < _b ? _a : _b; })

#define round_up(a, b) ({		\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	((_a + (_b - 1)) / _b) * _b; })

#define round_down(a, b) ({		\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(_a - (_a % _b)); })

struct nego_request {
    __u32 len;
    __u8  cfg[0];
};

struct nego_reply {
    __s32 exit;
    __s32 len;
    __u8  error[0];
};

struct cli_reply {
    __s32 exit;
    __s32 len;
    __u8  buf[0];
};

const char *nbd_dev_status_lookup_str(dev_status_t st);
dev_status_t nbd_dev_status_lookup(const char *st);
bool nbd_valid_size(const char *value);
ssize_t nbd_parse_size(const char *value, int sector_size);
int nbd_socket_write(int fd, void *buf, size_t count);
int nbd_socket_read(int fd, void *buf, size_t count);
int nbd_handle_request(int sock, int threads);
bool nbd_minimal_kernel_version_check(void);
bool nbd_is_valid_host(const char *host);

int time_string_now(char* buf);
#endif /* __UTILS_H */
