/*
 * Copyright 2017 China Mobile, Inc.
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * This file is copied from tcmu-runner project and modified as needed.
 */

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "utils.h"

int time_string_now(char* buf)
{
    struct tm *tm;
    struct timeval tv;
    int l = 0;

    if (!buf)
        return -EINVAL;

    if (gettimeofday(&tv, NULL) < 0)
        return -errno;

    /* The value maybe changed in multi-thread*/
    tm = localtime(&tv.tv_sec);
    if (tm == NULL)
        return -errno;

    tm->tm_year += 1900;
    tm->tm_mon += 1;

    l = snprintf(buf, NBD_TLEN_MAX, "%4d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year, tm->tm_mon, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
    assert(l < NBD_TLEN_MAX);

    return 0;
}
