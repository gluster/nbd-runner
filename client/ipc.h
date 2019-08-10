/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
 *
 * This file is part of nbd-runner.
 */

#ifndef __NBD_IPC_H
#define __NBD_IPC_H

#include <stdarg.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <syslog.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "nbd-sysconfig.h"
#include "rpc_nbd.h"
#include "config.h"

int nbd_ipc_listen(void);
int nbd_ipc_connect(void);
void nbd_ipc_close(int sock);

#endif /* __NBD_IPC_H */
