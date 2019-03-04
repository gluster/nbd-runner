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
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <rpc/pmap_clnt.h>
#include <signal.h>
#include <errno.h>
#include <event.h>
#include <arpa/inet.h>

#include "utils.h"
#include "nbd-log.h"
#include "rpc_nbd.h"
#include "rpc_nbd_svc.h"

#define NBD_LOCK_FILE "/run/nbd-runner.lock"

static void *worker_thread(void *arg)
{
    int sock = *(int *)arg;

    if (nbd_handle_request(sock))
        return NULL;

    return NULL;
}

static void event_handler(int listenfd, short event, void *arg)
{
    pthread_t thread_id;
    struct sockaddr_storage addr_in;
    socklen_t sin_size = sizeof(addr_in);
    int acceptfd;

    acceptfd = accept(listenfd, (struct sockaddr*)&addr_in, &sin_size);
    if(acceptfd < 0) {
        nbd_err("error occure in accept: %s\n", strerror(errno));
        return;
    }

    if (pthread_create(&thread_id, NULL, worker_thread, &acceptfd) != 0)
        nbd_err("failed to create thread: %s!\n", strerror(errno));

    if (pthread_detach(thread_id) != 0)
        nbd_err("failed to detach thread: %s!\n", strerror(errno));
}

static void *nbd_ios_svc_thread_start(void *arg)
{
    char *host = NULL;
    struct sockaddr_in addr;
    struct event_base *base;
    struct event listen_ev;
    int listenfd;
    int ret = 0;

    if (!arg)
        host = arg;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        return NULL;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    if (host) {
        if (inet_pton(AF_INET, host, (void *)&addr.sin_addr.s_addr) < 0)
        {
            nbd_err("failed to convert %s to binary form!\n", host);
            goto err;
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    addr.sin_port = htons(NBD_IOS_SVC_PORT);

    if (bind(listenfd, (struct sockaddr*)&addr, sizeof(struct sockaddr)) < 0) {
        nbd_err("failed to bind an address to a socket: %s\n", strerror(errno));
        goto err;
    }

    if (listen(listenfd, 10) < 0) {
        nbd_err("failed to start listening on a socket: %s\n", strerror(errno));
        goto err;
    }

    evutil_make_socket_nonblocking(listenfd);

    base = event_base_new();
    if (!base) {
        nbd_err("failed to create event base: %s\n", strerror(errno));
        goto err;
    }

    event_set(&listen_ev, listenfd, EV_READ|EV_PERSIST, event_handler, NULL);
    event_base_set(base, &listen_ev);
    event_add(&listen_ev, NULL);
    event_base_dispatch(base);

    nbd_out("nbd server exits!\n");

    event_del(&listen_ev);
    event_base_free(base);

err:
    close(listenfd);
    return NULL;
}

static void *nbd_rpc_svc_thread_start(void *arg)
{
    register SVCXPRT *transp = NULL;
    struct sockaddr_in sin = {0, };
    int listenfd = RPC_ANYSOCK;
    int opt = 1;
    int ret;

    listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenfd < 0) {
        nbd_err("socket creation failed, %s\n", strerror(errno));
        return NULL;
    }

    ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (ret < 0) {
        nbd_err("setsocket set option to re-use address failed, %s\n",
                strerror(errno));
        goto out;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(NBD_RPC_SVC_PORT);

    ret = bind(listenfd, (struct sockaddr *) &sin, sizeof (sin));
    if (ret < 0) {
        nbd_err("bind on port %d failed, %s\n", NBD_RPC_SVC_PORT, strerror(errno));
        goto out;
    }

    transp = svctcp_create(listenfd, 0, 0);
    if (!transp) {
        nbd_err("svctcp_create failed, %s\n", strerror(errno));
        goto out;
    }

    if (!svc_register(transp, RPC_NBD, RPC_NBD_VERS, rpc_nbd_1, IPPROTO_TCP)) {
        nbd_err("Please check if rpcbind service is running.");
        goto out;
    }

    svc_run();

out:
    if (transp)
        svc_destroy(transp);

    if (listenfd != RPC_ANYSOCK)
        close(listenfd);

    return NULL;
}

int main (int argc, char **argv)
{
    int lockfd = -1;
    pthread_t rpc_svc_threadid;
    pthread_t ios_svc_threadid;
    struct flock lock = {0, };
    int ret;

    ret = nbd_log_init();
    if (ret < 0) {
        nbd_err("nbd_log_init failed!\n");
        goto out;
    }

    /* make sure only one nbd-runner daemon is running */
    lockfd = creat(NBD_LOCK_FILE, S_IRUSR | S_IWUSR);
    if (lockfd == -1) {
        nbd_err("create lock file :%s failed, %s!\n", NBD_LOCK_FILE,
                strerror(errno));
        goto out;
    }

    lock.l_type = F_WRLCK;
    if (fcntl(lockfd, F_SETLK, &lock) == -1) {
        nbd_err("nbd-runner service is already running...\n");
        goto out;
    }

    /* set signal */
    signal(SIGPIPE, SIG_IGN);

    pmap_unset(RPC_NBD, RPC_NBD_VERS);

    pthread_create(&rpc_svc_threadid, NULL, nbd_rpc_svc_thread_start, NULL);
    pthread_create(&ios_svc_threadid, NULL, nbd_ios_svc_thread_start, NULL);
    pthread_join(ios_svc_threadid, NULL);
    pthread_join(rpc_svc_threadid, NULL);

    nbd_err("svc_run returned %s\n", strerror (errno));

    lock.l_type = F_UNLCK;
    if (fcntl(lockfd, F_SETLK, &lock) == -1) {
        nbd_err("fcntl unlock pidfile %s failed, %s\n", NBD_LOCK_FILE,
                strerror(errno));
    }

out:
    if (lockfd != -1)
        close(lockfd);
    nbd_log_destroy();
    exit (EXIT_FAILURE);
}
