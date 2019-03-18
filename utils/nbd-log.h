/*
   Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
   This file is part of nbd-runner.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

#ifndef __NBD_LOG_H
#define __NBD_LOG_H

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

static inline int _nbd_err(const char *fmt, ...)
{
    va_list ap;
    int ret = 0;

    va_start(ap, fmt);

    ret = vfprintf(stderr, fmt, ap);
    va_end(ap);

    return ret;
}

static inline int _nbd_out(const char *fmt, ...)
{
    va_list ap;
    int ret = 0;

    va_start(ap, fmt);

    ret = vprintf(fmt, ap);
    va_end(ap);

    return ret;
}

#define nbd_err(...)                                                \
    do {                                                            \
        _nbd_err(__VA_ARGS__);                                      \
        syslog(LOG_ERR, __VA_ARGS__);                               \
    } while (0)

#define nbd_out(...)                                                \
    do {                                                            \
        _nbd_out(__VA_ARGS__);                                      \
        syslog(LOG_INFO, __VA_ARGS__);                              \
    } while (0)

#define nbd_dbg(...)                                                \
    do {                                                            \
            _nbd_out(__VA_ARGS__);                                  \
            syslog(LOG_DEBUG, __VA_ARGS__);                         \
    } while (0)

static inline int nbd_log_init(void)
{
    openlog(NULL, 0, 0);
    return 0;
}

static inline void nbd_log_destroy(void)
{
    closelog();
}

#endif /* __NBD_LOG_H */
