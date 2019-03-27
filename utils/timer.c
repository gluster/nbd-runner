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
#include <uv.h>

#include "utils.h"
#include "list.h"
#include "nbd-log.h"

static pthread_t timer_thread;
static uv_loop_t *nbd_uv_loop;
static bool timer_base_stopped = false;

static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timer_cond = PTHREAD_COND_INITIALIZER;

static void nbd_timer_cbk(uv_timer_t* uv_timer)
{
    nbd_timer_t *timer;

    timer = container_of(uv_timer, nbd_timer_t, uv_timer);

    timer->cbk(timer);
}

/*
 * timeout: all the entries will time out after 'timeout' milliseconds.
 * repeat: repeat the timer for every 'repeat' milliseconds after 'timeout'.
 */
void nbd_init_timer(nbd_timer_t *timer, __u64 timeout, __u64 repeat,
                    nbd_timer_cbk_t cbk)
{
    if (!timer)
        return;

    timer->timeout = timeout;
    timer->repeat = repeat;
    timer->cbk = cbk;

    bzero(&timer->uv_timer, sizeof(uv_timer_t));
}

void nbd_add_timer(nbd_timer_t *timer)
{
    if (!timer)
        return;

    pthread_mutex_lock(&timer_lock);
    if (!nbd_uv_loop) {
        nbd_err("Timer loop is not initialized yet!\n");
        goto unlock;
    }

    /*
     * To avoid segment fault. If the timer is already
     * running, the uv_timer_init will set the cbk to
     * NULL, which will lead sigment fault for the running
     * timer.
     */
    if (uv_is_active((uv_handle_t*)(&timer->uv_timer))) {
        nbd_warn("The timer %p is already running!\n", timer);
        goto unlock;
    }

    uv_timer_init(nbd_uv_loop, &timer->uv_timer);
    uv_timer_start(&timer->uv_timer, nbd_timer_cbk, timer->timeout,
                   timer->repeat);

    pthread_cond_signal(&timer_cond);

unlock:
    pthread_mutex_unlock(&timer_lock);
}

void nbd_del_timer(nbd_timer_t *timer)
{
    uv_timer_stop(&timer->uv_timer);
}

void nbd_reset_timer(nbd_timer_t *timer)
{
    pthread_mutex_lock(&timer_lock);
    uv_update_time(nbd_uv_loop);

    /*
     * The uv_timer_start will stop the timer first if
     * the timer is already active, then start it again
     */
    uv_timer_start(&timer->uv_timer, nbd_timer_cbk, timer->timeout, timer->repeat);
    pthread_cond_signal(&timer_cond);
    pthread_mutex_unlock(&timer_lock);
}

static void *nbd_timer_base_thread_start(void *arg)
{
    pthread_mutex_lock(&timer_lock);
    if (!nbd_uv_loop) {
        nbd_err("Timer loop is not init yet!\n");
        pthread_mutex_unlock(&timer_lock);
        return NULL;
    }
    pthread_mutex_unlock(&timer_lock);

    /*
     * The uv_run will stopped when all the timer
     * handlers has been handled, so we need to
     * start it again when there has new timer is
     * added.
     */
    while (!timer_base_stopped) {
        uv_run(nbd_uv_loop, UV_RUN_DEFAULT);

        /* If the timer base is cancelled, no need to wait */
        if (timer_base_stopped)
            break;

        pthread_mutex_lock(&timer_lock);
        pthread_cond_wait(&timer_cond, &timer_lock);
        pthread_mutex_unlock(&timer_lock);
    }

    return NULL;
}

void nbd_timer_base_init(void)
{
    pthread_mutex_lock(&timer_lock);
    if (nbd_uv_loop) {
        nbd_warn("Timer loop is already start, do nothing!\n");
        goto unlock;
    }

    nbd_uv_loop = uv_default_loop();
    if (!nbd_uv_loop) {
        nbd_err("No memory for nbd_uv_loop!\n");
        goto unlock;
    }

    pthread_create(&timer_thread, NULL, nbd_timer_base_thread_start, NULL);

unlock:
    pthread_mutex_unlock(&timer_lock);
}

void nbd_timer_base_fini(void)
{
    pthread_mutex_lock(&timer_lock);
    if (!nbd_uv_loop) {
        pthread_mutex_unlock(&timer_lock);
        return;
    }
    timer_base_stopped = true;

    /* Stop the pending timers if there has */
    uv_stop(nbd_uv_loop);

    pthread_cond_signal(&timer_cond);

    /*
     * Release the uv loop, this should always after
     * enabling timer_base_stopped, uv_stop and
     * pthread_cond_signal
     */
    uv_loop_close(nbd_uv_loop);
    nbd_uv_loop = NULL;
    pthread_mutex_unlock(&timer_lock);

    pthread_cancel(timer_thread);
    pthread_join(timer_thread, NULL);
}
