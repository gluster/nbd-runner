/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
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

#define nbd_version_info ""                                       \
"nbd-runner (0.1)\n\n"                                              \
"Repository rev: https://github.com/gluster/nbd-runner.git\n"       \
"Copyright (c) 2019 Red Hat, Inc. <https://redhat.com/>\n"          \
"gluster-nbd comes with ABSOLUTELY NO WARRANTY.\n"                  \
"It is licensed to you under your choice of the GNU Lesser\n"       \
"General Public License, version 3 or any later version (LGPLv3\n"  \
"or later), or the GNU General Public License, version 2 (GPLv2),\n"\
"in all cases as published by the Free Software Foundation."

#define NBD_RPC_SVC_PORT     24110
#define NBD_IOS_SVC_PORT     24111

#define  NBD_DEFAULT_SECTOR_SIZE  512

#define ALLOWED_BSOFLAGS (O_DIRECT | O_RDWR | O_LARGEFILE)
#define NBD_CMD_MASK_COMMAND 0x0000ffff
#define NBD_NL_VERSION 1

#define CFGFS_NBD_MOD "/sys/module/nbd"

#define round_down(a, b) ({            \
        __typeof__ (a) _a = (a);       \
        __typeof__ (b) _b = (b);       \
        (_a - (_a % _b)); })

struct nego_header {
    __u32 len;
    __u8  cfg[0];
};

bool nbd_valid_size(const char *value);
ssize_t nbd_parse_size(const char *value, int sector_size);
int nbd_socket_write(int fd, void *buf, size_t count);
int nbd_socket_read(int fd, void *buf, size_t count);
int nbd_handle_request(int sock);
bool nbd_minimal_kernel_version_check(void);

#endif /* __UTILS_H */
