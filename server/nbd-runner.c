/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#include <pthread.h>
#include <rpc/pmap_clnt.h>
#include <signal.h>
#include <errno.h>
#include <event.h>
#include <arpa/inet.h>
#include <time.h>

#include "utils.h"
#include "nbd-log.h"
#include "nbd-sysconfig.h"
#include "nbd-common.h"
#include "nbd-svc-routines.h"
#include "config.h"
#include "rpc_nbd.h"
#include "rpc_nbd_svc.h"

#define NBD_LOCK_FILE "/run/nbd-runner.lock"
#define NBD_MIN_THREADS  1
#define NBD_DEF_THREADS  1
#define NBD_MAX_THREADS  16

static struct nbd_config *nbd_cfg;

struct io_thread_data {
    int threads;
    int sockfd;
};

static void usage(void)
{
    printf("Usage:\n"
           "\tnbd-runner [<args>]\n\n"
           "Commands:\n"
           "\t-h, --help\n"
           "\t\tDisplay help for nbd-runner command\n\n"
           "\t-t, --threads=<NUMBER>\n"
           "\t\tSpecify the IO thread number for each mapped backstore, %d as default\n\n"
           "\t-r, --rhost=<RUNNER_HOST>\n"
           "\t\tSpecify the listenning IP for the nbd-runner server to receive/reply the control\n"
           "\t\tcommands(create/delete/map/unmap/list, etc) from nbd-cli, INADDR_ANY as default\n\n"
           "\t-i, --ihost=<IO_HOST>\n"
           "\t\tSpecify the listenning IP for the nbd-runner server to receive/reply the NBD device's\n"
           "\t\tIO operations(WRITE/READ/FLUSH/TRIM, etc), INADDR_ANY as default\n\n"
           "\t-G, --ghost=<IO_HOST>\n"
           "\t\tSpecify the Gluster server IP for the volume to connect to, 'localhost' as default\n\n"
           "\t-u, --uid=<UID>\n"
           "\t\tRun as uid, default is current user\n\n"
           "\t-g, --gid=<GID>\n"
           "\t\tRun as gid, default is current user group\n\n"
           "\t-v, --version\n"
           "\t\tShow version info and exit.\n\n"
           "\tNOTE:\n"
           "\t\tThe RUNNER_HOST and the IO_HOST will be useful if you'd like the control commands\n"
           "\t\troute different from the IOs route via different NICs, or just omit them as default\n",
           NBD_DEF_THREADS);
}

static void *worker_thread(void *arg)
{
    struct io_thread_data *data = arg;

    if (nbd_handle_request(data->sockfd, data->threads))
        return NULL;

    return NULL;
}

static void event_handler(int listenfd, short event, void *arg)
{
    pthread_t thread_id;
    struct sockaddr_storage addr_in;
    socklen_t sin_size = sizeof(addr_in);
    struct io_thread_data data = {0, };
    int acceptfd;

    acceptfd = accept(listenfd, (struct sockaddr*)&addr_in, &sin_size);
    if(acceptfd < 0) {
        nbd_err("error occured in accept: %s\n", strerror(errno));
        return;
    }

    data.threads = *(int *)arg;
    data.sockfd = acceptfd;

    if (pthread_create(&thread_id, NULL, worker_thread, &data) != 0)
        nbd_err("failed to create thread: %s!\n", strerror(errno));

    if (pthread_detach(thread_id) != 0)
        nbd_err("failed to detach thread: %s!\n", strerror(errno));
}

/* If there has any error, will kill the whole process */
static void *nbd_live_svc_thread_start(void *arg)
{
    struct sockaddr_in sin = {0,};
    int listenfd;
    int opt = 1;
    time_t tm;
    char timestamp[1024] = {0};

    time(&tm);
    sprintf(timestamp, "%s", ctime((&tm)));

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        exit(1);
    }

    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        nbd_err("setsocket set option to re-use address failed, %s\n",
                strerror(errno));
        exit(1);
    }

    sin.sin_family = AF_INET;
    if (nbd_cfg->rhost[0]) {
        if (inet_pton(AF_INET, nbd_cfg->rhost, (void *)&sin.sin_addr.s_addr) < 0)
        {
            nbd_err("failed to convert %s to binary form!\n", nbd_cfg->rhost);
            exit(1);
        }
    } else {
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    sin.sin_port = htons(NBD_PING_SVC_PORT);

    if (bind(listenfd, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
        nbd_warn("bind on port %d failed, %s\n", NBD_PING_SVC_PORT, strerror(errno));
        exit(1);
    }

    if (listen(listenfd, 16) < 0) {
        nbd_err("failed to start listening on a socket: %s\n", strerror(errno));
        exit(1);
    }

    while (1) {
        int sock;

        sock = accept(listenfd, NULL, NULL);
        if (sock == -1) {
            if (errno == EINTR)
                goto out;
            nbd_err("Failed to accept!\n");
            exit(1);
        }

        nbd_socket_write(sock, timestamp, 1024);

        close(sock);
    }

    nbd_info("nbd live thread exits!\n");

out:
    close(listenfd);
    return NULL;
}

static void *nbd_map_svc_thread_start(void *arg)
{
    struct sockaddr_in sin = {0,};
    struct event_base *base;
    struct event listen_ev;
    int listenfd;
    int opt = 1;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0){
        nbd_err("failed to create socket: %s\n", strerror(errno));
        return NULL;
    }

    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        nbd_err("setsocket set option to re-use address failed, %s\n",
                strerror(errno));
        goto err;
    }

    sin.sin_family = AF_INET;
    if (nbd_cfg->ihost[0]) {
        if (inet_pton(AF_INET, nbd_cfg->ihost, (void *)&sin.sin_addr.s_addr) < 0)
        {
            nbd_err("failed to convert %s to binary form!\n", nbd_cfg->ihost);
            goto err;
        }
    } else {
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    sin.sin_port = htons(NBD_MAP_SVC_PORT);

    if (bind(listenfd, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
        nbd_warn("bind on port %d failed, %s\n", NBD_MAP_SVC_PORT, strerror(errno));
        goto err;
    }

    if (listen(listenfd, 16) < 0) {
        nbd_err("failed to start listening on a socket: %s\n", strerror(errno));
        goto err;
    }

    evutil_make_socket_nonblocking(listenfd);

    base = event_base_new();
    if (!base) {
        nbd_err("failed to create event base: %s\n", strerror(errno));
        goto err;
    }

    event_set(&listen_ev, listenfd, EV_READ|EV_PERSIST, event_handler, arg);
    event_base_set(base, &listen_ev);
    event_add(&listen_ev, NULL);
    event_base_dispatch(base);

    nbd_info("nbd map thread exits!\n");

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
    if (nbd_cfg->rhost[0]) {
        if (inet_pton(AF_INET, nbd_cfg->rhost, (void *)&sin.sin_addr.s_addr) < 0)
        {
            nbd_err("failed to convert %s to binary form!\n", nbd_cfg->rhost);
            goto out;
        }
    } else {
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    sin.sin_port = htons(NBD_RPC_SVC_PORT);

    ret = bind(listenfd, (struct sockaddr *) &sin, sizeof (sin));
    if (ret < 0) {
        nbd_err("bind on port %d failed, %s\n", NBD_RPC_SVC_PORT,
                strerror(errno));
        goto out;
    }

#if HAVE_TIRPC
    if (listen(listenfd, 16) < 0) {
        nbd_err("failed to start listening on a socket: %s\n",
                strerror(errno));
        goto out;
    }
#endif

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

    nbd_info("nbd rpc thread exits!\n");
out:
    if (transp)
        svc_destroy(transp);

    if (listenfd != RPC_ANYSOCK)
        close(listenfd);

    return NULL;
}

static struct option const long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"threads", required_argument, NULL, 't'},
    {"rhost", required_argument, NULL, 'r'},
    {"ihost", required_argument, NULL, 'i'},
    {"ghost", required_argument, NULL, 'G'},
    {"uid", required_argument, NULL, 'u'},
    {"gid", required_argument, NULL, 'g'},
    {"version", no_argument, NULL, 'v'},
    {NULL, 0, NULL, 0},
};

int main (int argc, char **argv)
{
    int lockfd = -1;
    pthread_t rpc_svc_threadid;
    pthread_t map_svc_threadid;
    pthread_t live_svc_threadid;
    struct flock lock = {0, };
    int threads = NBD_DEF_THREADS;
	int ch, longindex;
    int ret = EXIT_FAILURE;
	uid_t uid = 0;
    gid_t gid = 0;

    nbd_cfg = nbd_load_config(true);
    if (!nbd_cfg) {
        nbd_err("nbd_initialize_config failed!\n");
        goto out;
    }

	while ((ch = getopt_long(argc, argv, "ht:r:i:G:u:g:v", long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'r':
            snprintf(nbd_cfg->rhost, NBD_HOST_MAX, "%s", optarg);

            if (!nbd_is_valid_host(optarg)) {
                nbd_err("Invalid rhost IP %s!\n", optarg);
                goto out;
            }
			break;
        case 'i':
            snprintf(nbd_cfg->ihost, NBD_HOST_MAX, "%s", optarg);

            if (!nbd_is_valid_host(optarg)) {
                nbd_err("Invalid ihost IP %s!\n", optarg);
                goto out;
            }
			break;
        case 'G':
            snprintf(nbd_cfg->ghost, NBD_HOST_MAX, "%s", optarg);

            if (!nbd_is_valid_host(optarg)) {
                nbd_err("Invalid ghost IP %s!\n", optarg);
                goto out;
            }
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
        case 't':
            threads = atoi(optarg);
            if (threads < NBD_MIN_THREADS) {
                nbd_err("Currently the min threads are %d, will set it to %d!\n",
                        NBD_MIN_THREADS, NBD_MIN_THREADS);
                threads = NBD_MIN_THREADS;
            }

            if (threads > NBD_MAX_THREADS) {
                nbd_err("Currently the max threads are %d, will set it to %d!\n",
                        NBD_MAX_THREADS, NBD_MAX_THREADS);
                threads = NBD_MAX_THREADS;
            }
            break;
		case 'v':
            printf("nbd-clid (%s)\n\n", VERSION);
            printf("%s\n", NBD_LICENSE_INFO);
			exit(0);
		case 'h':
			usage();
			exit(0);
		default:
		    nbd_err("Try 'nbd-clid -h/--help' for more information.\n");
			exit(1);
        }
    }

    if (nbd_setup_log(nbd_cfg->log_dir, true))
        goto out;

    nbd_crit("Starting...\n");

    if (gid && setgid(gid) < 0) {
        nbd_err("Failed to setgid to %d\n", gid);
        goto out;
    }

    if ((geteuid() == 0) && (getgroups(0, NULL))) {
        if (setgroups(0, NULL) != 0) {
            nbd_err("Failed to drop supplementary group ids\n");
            goto out;
        }
    }

    if (uid && setuid(uid) < 0) {
        nbd_err("Failed to setuid to %d\n", uid);
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

    nbd_service_init(nbd_cfg);

    /* set signal */
    signal(SIGPIPE, SIG_IGN);

    pmap_unset(RPC_NBD, RPC_NBD_VERS);

    pthread_create(&live_svc_threadid, NULL, nbd_live_svc_thread_start, NULL);
    pthread_create(&map_svc_threadid, NULL, nbd_map_svc_thread_start, &threads);
    pthread_create(&rpc_svc_threadid, NULL, nbd_rpc_svc_thread_start, NULL);

    pthread_join(live_svc_threadid, NULL);
    pthread_join(map_svc_threadid, NULL);
    pthread_join(rpc_svc_threadid, NULL);

    nbd_err("svc_run returned %s\n", strerror (errno));

    lock.l_type = F_UNLCK;
    if (fcntl(lockfd, F_SETLK, &lock) == -1) {
        nbd_err("fcntl unlock pidfile %s failed, %s\n", NBD_LOCK_FILE,
                strerror(errno));
    }

    ret = EXIT_SUCCESS;

out:
    nbd_free_config(nbd_cfg);

    nbd_destroy_log();

    if (lockfd != -1)
        close(lockfd);
    nbd_service_fini();
    exit(ret);
}
