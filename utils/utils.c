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
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gmodule.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"
#include "nbd-log.h"

bool nbd_valid_size(const char *value)
{
    char *postfix;
    ssize_t sizef;

    if (!value)
        return false;

    sizef = strtod(value, &postfix);
    if (sizef <= 0) {
        return false;
    }

    if (!postfix)
        return true;

    switch (tolower(postfix[1])) {
    case 'y':
    case 'z':
    case 'e':
    case 'p':
    case 't':
    case 'g':
    case 'm':
    case 'k':
    case 'b':
        if (postfix[2] == '\0')
            return true;
        if (tolower(postfix[2]) != 'i')
            return false;
        if (tolower(postfix[3]) != 'b')
            return false;
        return true;
    case '\0':
        return true;
    default:
        return false;
    }

    return false;
}

ssize_t nbd_parse_size(const char *value, int sector_size)
{
    char *postfix;
    ssize_t sizef;

    if (!value)
        return -1;

    sizef = strtod(value, &postfix);
    if (sizef <= 0) {
        nbd_err("The size cannot be negative number or zero!\n");
        return -1;
    }

    if (sector_size <= 0)
        sector_size = NBD_DEFAULT_SECTOR_SIZE;

    switch (tolower(*postfix)) {
    case 'y':
        sizef *= 1024;
    case 'z':
        sizef *= 1024;
    case 'e':
        sizef *= 1024;
    case 'p':
        sizef *= 1024;
    case 't':
        sizef *= 1024;
    case 'g':
        sizef *= 1024;
    case 'm':
        sizef *= 1024;
    case 'k':
        sizef *= 1024;
    case 'b':
    case '\0':
        if (sizef < sector_size) {
            nbd_err("minimum acceptable block size is %d bytes\n",
                    sector_size);
            return -1;
        }

        if (sizef % sector_size) {
            fprintf(stdout, "The size %zd will align to sector size %d bytes\n",
                    sizef, sector_size);
            sizef = round_down(sizef, sector_size);
        }
        break;
    default:
        return -1;
    }

    return sizef;
}

#define VERNUM_BUFLEN  8
#define MIN_KERNEL_VERSION "4.12.0"  /* Minimum recommended kernel version */

bool nbd_minimal_kernel_version_check(void)
{
    struct utsname ver;
    size_t num[VERNUM_BUFLEN] = {0, };
    int i = 0;
    char *rel;

    bzero(&ver, sizeof(struct utsname));
    if (uname(&ver) != 0) {
        nbd_err("uname() failed: %s\n", strerror(errno));
        goto err;
    }

    rel = ver.release;
    while (i < VERNUM_BUFLEN && *rel) {
        if (isdigit(*rel)) {
            num[i] = strtol(rel, &rel, 10);
            i++;
        } else if (isalpha(*rel)) {
            break;
        } else {
            rel++;
        }
    }

    /* The minimal kernel version is MIN_KERNEL_VERSION */
    if (KERNEL_VERSION(num[0], num[1], num[2]) < KERNEL_VERSION(4, 12, 0)) {
        goto err;
    } else if (KERNEL_VERSION(num[0], num[1], num[2]) == KERNEL_VERSION(4, 12, 0)) {
        if (KERNEL_VERSION(num[3], num[4], num[5]) < KERNEL_VERSION(1, 0, 0)) {
            goto err;
        }
    }

    return true;
err:
    nbd_err("Minimum recommended kernel version: '%s' and current kernel version: '%s'.\n",
            MIN_KERNEL_VERSION, ver.release);

    return false;
}

dev_status_t nbd_dev_status_lookup(const char *st)
{
    if (!strcmp(st, "created"))
        return NBD_DEV_CONN_ST_CREATED;
    else if (!strcmp(st, "mapping"))
        return NBD_DEV_CONN_ST_MAPPING;
    else if (!strcmp(st, "mapped"))
        return NBD_DEV_CONN_ST_MAPPED;
    else if (!strcmp(st, "dead"))
        return NBD_DEV_CONN_ST_DEAD;
    else if (!strcmp(st, "unmapping"))
        return NBD_DEV_CONN_ST_UNMAPPING;

    return NBD_DEV_CONN_ST_MAX;
}

static const char *const dev_status_lookup[] = {
    [NBD_DEV_CONN_ST_CREATED]       = "created",
    [NBD_DEV_CONN_ST_MAPPING]       = "mapping",
    [NBD_DEV_CONN_ST_MAPPED]        = "mapped",
    [NBD_DEV_CONN_ST_DEAD]          = "dead",
    [NBD_DEV_CONN_ST_UNMAPPING]     = "unmapping",

    [NBD_DEV_CONN_ST_MAX]           = NULL,
};

const char *nbd_dev_status_lookup_str(dev_status_t st)
{
    if (st >= NBD_DEV_CONN_ST_MAX || st <= NBD_DEV_CONN_ST_MIN)
        return NULL;
    return dev_status_lookup[st];
}

bool nbd_is_valid_host(const char *host)
{
    char *tmp;

    if (!strcmp(host, "localhost"))
        return true;

    tmp = malloc(1024);
    if (!tmp) {
        nbd_err("No memory for tmp buffer!\n");
        return false;
    }

    if (!inet_pton(AF_INET, host, tmp) && !inet_pton(AF_INET6, host, tmp)) {
        free(tmp);
        return false;
    }

    free(tmp);
    return true;
}

int nbd_setup_abstract_addr(struct sockaddr_un *addr, char *unix_sock_name)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_LOCAL;
    strlcpy(addr->sun_path + 1, unix_sock_name, sizeof(addr->sun_path) - 1);
    return offsetof(struct sockaddr_un, sun_path) +
        strlen(addr->sun_path + 1) + 1;
}

