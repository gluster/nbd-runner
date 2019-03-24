/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of nbd-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"
#include "nbd-log.h"

int nbd_socket_read(int fd, void *buf, size_t count)
{
    size_t cnt = 0;

    while (cnt < count) {
        ssize_t r = read(fd, buf, count - cnt);
        if (r <= 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            if (r == 0) {
                /* EOF */
                return cnt;
            }
            return -errno;
        }
        cnt += r;
        buf = (char *)buf + r;
    }
    return cnt;
}

int nbd_socket_write(int fd, void *buf, size_t count)
{
    while (count > 0) {
        ssize_t r = write(fd, buf, count);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        count -= r;
        buf = (char *)buf + r;
    }
    return 0;
}
