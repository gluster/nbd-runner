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

#include "ipc.h"
#include "utils.h"
#include "nbd-log.h"

#define NBD_CLID_SOCKET "/run/nbd-clid.sock"

static int nbd_ipc_unix_addr(struct sockaddr_un *sun)
{
    if (!sun)
        return -EINVAL;

    memset(sun, 0, sizeof(*sun));
    sun->sun_family = AF_LOCAL;
    strlcpy(sun->sun_path, NBD_CLID_SOCKET, sizeof(sun->sun_path));

    return 0;
}

int nbd_ipc_listen(void)
{
	struct sockaddr_un sun;
	int fd, ret;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		nbd_err("Failed to create ipc socket, %m!\n");
		return fd;
	}

    unlink(NBD_CLID_SOCKET);
	ret = nbd_ipc_unix_addr(&sun);
    if (ret) {
        nbd_err("Failed to get the unix address!\n");
        goto err;
    }

	if ((ret = bind(fd, (struct sockaddr *)&sun, sizeof(sun))) < 0 ) {
		nbd_err("Failed to bind ipc socket, %m!\n");
        goto err;
	}

	if ((ret = listen(fd, 32)) < 0) {
		nbd_err("Failed to listen ipc socket, %m!\n");
        goto err;
	}

	return fd;
err:
    close(fd);
    return ret;
}

#define NBD_MAX_RETRIES 128
int nbd_ipc_connect(void)
{
    struct sockaddr_un sun;
    int nsec;
    int fd;
    int ret;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        nbd_err("Failed to create ipc socket (%d)!\n", errno);
        return fd;
    }

    ret = nbd_ipc_unix_addr(&sun);
    if (ret) {
        nbd_err("Failed to get the unix address!\n");
        goto err;
    }

	/*
	 * Trying to connect with exponential backoff
	 */
    ret = -ETIMEDOUT;
    for (nsec = 1; nsec <= NBD_MAX_RETRIES; nsec <<= 1) {
        if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0)
            return fd;

        /*
         * If nbd-clid isn't there, there's no sense
         * in retrying.
         */
        if (errno == ECONNREFUSED) {
            ret = -ECONNREFUSED;
            break;
        }

        /*
         * Delay before trying again
         */
        if (nsec <= NBD_MAX_RETRIES / 2)
            sleep(nsec);
    }

err:
    nbd_err("can not connect to nbd-clid daemon (%d)!\n", errno);
    return ret;
}

void nbd_ipc_close(int sock)
{
    if (sock < 0)
        return;

    close(sock);
}
