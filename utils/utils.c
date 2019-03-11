/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#define   _GNU_SOURCE

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

#define NBD_DISTRO_CHECK  "grep -P '(^ID=)' /etc/os-release"

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
            fprintf(stdout, "The size %ld will align to sector size %d bytes\n",
                    sizef, sector_size);
            sizef = round_down(sizef, sector_size);
        }
        break;
    default:
        return -1;
    }

    return sizef;
}

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

#define VERNUM_BUFLEN  8
#define MIN_KERNEL_VERSION "4.12.0"  /* Minimum recommended kernel version */

bool nbd_minimal_kernel_version_check(void)
{
    struct utsname ver = {'\0', };
    size_t num[VERNUM_BUFLEN] = {0, };
    int i = 0;
    char *rel;
    size_t len;

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
