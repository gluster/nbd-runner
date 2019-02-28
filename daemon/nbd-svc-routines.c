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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <linux/nbd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <glusterfs/api/glfs.h>
#include <glib.h>

#include "rpc_nbd.h"
#include "nbd-log.h"
#include "utils.h"

#define NBD_GFAPI_LOG_FILE "/var/log/nbd-runner.log"
#define NBD_GFAPI_LOG_LEVEL 7
#define NBD_NL_VERSION 1

static struct glfs *nbd_volume_init(char *volume, char *host)
{
    struct glfs *glfs;
    int ret;

    glfs = glfs_new(volume);
    if (!glfs) {
        nbd_err("Not able to Initialize volume %s, %s\n",
                volume, strerror(errno));
        return NULL;
    }

    ret = glfs_set_volfile_server(glfs, "tcp", host, 24007);
    if (ret) {
        nbd_err("Not able to add Volfile server for volume %s, %s\n",
                volume, strerror(errno));
        goto out;
    }

    ret = glfs_set_logging(glfs, NBD_GFAPI_LOG_FILE, NBD_GFAPI_LOG_LEVEL);
    if (ret) {
        nbd_err("Not able to add logging for volume %s, %s\n",
                volume, strerror(errno));
        goto out;
    }

    ret = glfs_init(glfs);
    if (ret) {
        if (errno == ENOENT) {
            nbd_err("Volume %s does not exist\n", volume);
        } else if (errno == EIO) {
            nbd_err("Check if volume %s is operational\n",
                    volume);
        } else {
            nbd_err("Not able to initialize volume %s, %s\n",
                    volume, strerror(errno));
        }
        goto out;
    }

    return glfs;

out:
    glfs_fini(glfs);

    return NULL;
}

static bool nbd_check_available_space(struct glfs *glfs, char *volume, size_t size)
{
    struct statvfs buf = {'\0', };

    if (!glfs_statvfs(glfs, "/", &buf)) {
        if ((buf.f_bfree * buf.f_bsize) >= size)
            return true;

        nbd_err("Low space on volume %s\n", volume);
        return false;
    }

    nbd_err("couldn't get file-system statistics on volume %s\n", volume);

    return false;
}

struct gluster_volinfo {
    char volume[255];
    char host[255];
    char path[255];
    bool prealloc;
    ssize_t size;
};

static struct gluster_volinfo *
nbd_parse_cfgstring(const char *cfg, nbd_response *rep)
{
    struct gluster_volinfo *info = NULL;
    char *tmp = NULL;
    char *sem;
    char *sep;
    char *ptr;
    int ret = 0;

    if (!cfg)
        return NULL;

    if (rep)
        rep->exit = 0;

    info = calloc(1, sizeof(struct gluster_volinfo));
    if (!info) {
        if (rep) {
            rep->exit = -ENOMEM;
            snprintf(rep->out, 8192, "No memory for info!");
        }
        nbd_err("No memory for info\n");
        return NULL;
    }

    tmp = strdup(cfg);
    if (!tmp) {
        if (rep) {
            rep->exit = -ENOMEM;
            snprintf(rep->out, 8192, "No memory for tmp!");
        }
        nbd_err("No memory for tmp\n");
        goto err;
    }

    ptr = tmp;

    /*
     * The valid cfgstring is like:
     *    "volname@host:/path;prealloc=yes"
     * or
     *    "volname@host:/path;prealloc=yes;"
     */
    do {
        sem = strchr(ptr, ';');
        if (sem)
            *sem = '\0';

        if (*ptr == '\0') {
            /* in case the last valid char is ';' */
            break;
        } else if (!strncmp("size", ptr, strlen("size"))) {
            /* size=1G */
            sep = ptr + strlen("size");
            if (*sep != '=') {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid size key/pair: %s!", ptr);
                }
                nbd_err("Invalid size key/pair: %s!\n", ptr);
                goto err;
            }

            ptr = sep + 1;
            info->size = nbd_parse_size(ptr, NBD_DEFAULT_SECTOR_SIZE);
            if (info->size < 0) {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid size value: %s!", ptr);
                }
                nbd_err("Invalid size value: %s!\n", ptr);
                goto err;
            }
        } else if (!strncmp("prealloc", ptr, strlen("prealloc"))) {
            /* prealloc=yes|no */
            sep = ptr + strlen("prealloc");
            if (*sep != '=') {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid prealloc key/pair: %s!", ptr);
                }
                nbd_err("Invalid prealloc key/pair: %s!\n", ptr);
                goto err;
            }

            ptr = sep + 1;
            if (!strcmp("yes", ptr)) {
                info->prealloc = true;
            } else if (!strcmp("no", ptr)) {
                info->prealloc = false;
            } else {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid prealloc value: %s!", ptr);
                }
                nbd_err("Invalid prealloc value: %s!\n", ptr);
                goto err;
            }
        } else if (strchr(ptr, '@') && strchr(ptr, ':')) {
            /* volname@host:/path */
            sep = strchr(ptr, '@');
            if (!sep) {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid volinfo value: %s!", ptr);
                }
                nbd_err("Invalid volinfo value: %s!\n", ptr);
                goto err;
            }

            *sep = '\0';

            strncpy(info->volume, ptr, 255);

            ptr = sep + 1;
            sep = strchr(ptr, ':');
            if (!sep) {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid host value: %s!", ptr);
                }
                nbd_err("Invalid host value: %s!\n", ptr);
                goto err;
            }

            *sep = '\0';

            strncpy(info->host, ptr, 255);

            ptr = sep + 1;
            if (*ptr != '/') {
                if (rep) {
                    rep->exit = -EINVAL;
                    snprintf(rep->out, 8192, "Invalid path value: %s!", ptr);
                }
                nbd_err("Invalid path value: %s!\n", ptr);
                goto err;
            }

            ptr++;

            strncpy(info->path, ptr, 255);
        }

        if (sem)
            ptr = sem + 1;
    } while (sem);

    free(tmp);
    return info;

err:
    free(tmp);
    free(info);
    return NULL;
}

bool_t nbd_create_1_svc(nbd_create *create, nbd_response *rep, struct svc_req *req)
{
    struct gluster_volinfo *info = NULL;
    struct glfs *glfs = NULL;
    struct glfs_fd *fd = NULL;

    rep->exit = 0;

    rep->out = malloc(8192);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, 8192, "No memory for rep->out!");
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    info = nbd_parse_cfgstring(create->cfgstring, rep);
    if (!info)
        goto err;

    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, 8192, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (!glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -EEXIST;
        snprintf(rep->out, 8192, "file %s is already exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is already exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!nbd_check_available_space(glfs, info->volume, info->size)) {
        rep->exit = -ENOSPC;
        snprintf(rep->out, 8192, "No enough space in volume %s, require %d!",
                 info->volume, info->size);
        nbd_err("No enough space in volume %s, require %d!\n", info->volume, info->size);
        goto err;
    }

    fd = glfs_creat(glfs, info->path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC,
                    S_IRUSR | S_IWUSR);
    if (!fd) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "Failed to create file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to create file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    if (glfs_ftruncate(fd, info->size, NULL, NULL) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "Failed to truncate file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to truncate file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    if (info->prealloc && glfs_zerofill(fd, 0, info->size) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "Failed to prealloc file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to prealloc file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

err:
    if (fd)
        glfs_close(fd);

    free(info);

    return true;
}

bool_t nbd_delete_1_svc(nbd_delete *delete, nbd_response *rep, struct svc_req *req)
{
    struct gluster_volinfo *info = NULL;
    struct glfs *glfs = NULL;
    struct glfs_fd *fd = NULL;

    rep->exit = 0;

    rep->out = malloc(8192);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, 8192, "No memory for rep->out!");
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    info = nbd_parse_cfgstring(delete->cfgstring, rep);
    if (!info)
        goto err;

    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, 8192, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -ENOENT;
        snprintf(rep->out, 8192, "file %s is not exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (glfs_unlink(glfs, info->path) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "failed to delete file %s in volume %s!",
                 info->path, info->volume);
        nbd_err("failed to delete file %s in volume %s!",
                 info->path, info->volume);
        goto err;
    }

err:
    free(info);
    return true;
}

bool_t nbd_map_1_svc(nbd_map *map, nbd_response *rep, struct svc_req *req)
{
    struct gluster_volinfo *info = NULL;
    struct stat st;
    struct glfs *glfs;
    struct addrinfo hints, *res;

    rep->exit = 0;

    rep->out = malloc(8192);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, 8192, "No memory for rep->out!");
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    info = nbd_parse_cfgstring(map->cfgstring, rep);
    if (!info)
        goto err;

    /* To check whether the file is exist */
    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, 8192, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -ENOENT;
        snprintf(rep->out, 8192, "file %s is not exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (glfs_lstat(glfs, info->path, &st) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "failed to lstat file %s in volume: %s!",
                 info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s!\n",
                 info->path, info->volume);
        goto err;
    }

    rep->size = st.st_size;
    rep->blksize = st.st_blksize;

    nbd_out("blksize: %d\n", rep->blksize);
#if 0
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(NULL, NBD_IOS_SVC_PORT, &hints, &res)) {
        rep->exit = -errno;
        snprintf(rep->out, 8192, "getaddrinfo failed!");
        nbd_err("getaddrinfo failed\n");
        goto err;
    }
#endif
    snprintf(rep->host, 64, "%s", "192.168.195.164");
    snprintf(rep->port, 32, "%d", NBD_IOS_SVC_PORT);

err:
    free(info);
    return true;
}

struct pool_request {
    __u32 magic;
    __u32 cmd;
    __u32 flags;
    __u64 offset;
    __u32 len;
    char handle[8];

    glfs_t *glfs;
    glfs_fd_t *gfd;
    int sock;
    void *data;
};

static pthread_spinlock_t nbd_write_lock;
static void
glfs_async_cbk(glfs_fd_t *gfd, ssize_t ret, struct glfs_stat *prestat,
        struct glfs_stat *poststat, void *data)
{
    struct pool_request *req = data;
    struct nbd_reply reply;

    reply.magic = htonl(NBD_REPLY_MAGIC);
    reply.error = htonl(ret < 0 ? ret : 0);
    memcpy(&(reply.handle), &(req->handle), sizeof(req->handle));

    pthread_spin_lock(&nbd_write_lock);
    nbd_socket_write(req->sock, &reply, sizeof(struct nbd_reply));
    if(req->cmd == NBD_CMD_READ && !reply.error)
        nbd_socket_write(req->sock, req->data, req->len);
    pthread_spin_unlock(&nbd_write_lock);

    free(req->data);
    free(req);
}

static void
_handle_request(gpointer data, gpointer user_data)
{
    struct pool_request *req;

    if (!data)
        return;

    req = (struct pool_request*)data;

    switch (req->cmd) {
    case NBD_CMD_WRITE:
        nbd_dbg("NBD_CMD_WRITE: offset: %llu, len: %u\n", req->offset,
                req->len);
        glfs_pwrite_async(req->gfd, req->data, req->len, req->offset,
                          ALLOWED_BSOFLAGS, glfs_async_cbk, req);
        break;
    case NBD_CMD_READ:
        nbd_dbg("NBD_CMD_READ: offset: %llu, len: %u\n", req->offset, req->len);
        glfs_pread_async(req->gfd, req->data, req->len, req->offset, SEEK_SET,
                         glfs_async_cbk, req);
        break;
    case NBD_CMD_FLUSH:
        nbd_dbg("NBD_CMD_FLUSH");
        glfs_fdatasync_async(req->gfd, glfs_async_cbk, req);
        break;
    case NBD_CMD_TRIM:
        nbd_dbg("NBD_CMD_TRIM: offset: %llu, len: %u\n", req->offset, req->len);
        glfs_discard_async(req->gfd, req->offset, req->len,
                glfs_async_cbk, req);
        break;
    default:
        fprintf(stderr,"Invalid request command\n");
        return;
    }
}

int nbd_handle_request(int sock)
{
    struct gluster_volinfo *info = NULL;
    struct pool_request *req;
    struct nbd_request request;
    GThreadPool *nbd_thread_pool;
    int ret = -1;
    struct sigaction sa;
    glfs_fd_t *gfd = NULL;
    glfs_t *glfs = NULL;
    struct nego_header hdr;
    char *cfg = NULL;
    int threads = 16;

    nbd_thread_pool = g_thread_pool_new(_handle_request, NULL, threads,
            false, NULL);
    if (!nbd_thread_pool) {
        nbd_err("Creating new thread pool failed!\n");
        return -1;
    }

    pthread_spin_init(&nbd_write_lock, 0);

    bzero(&hdr, sizeof(struct nego_header));
    ret = nbd_socket_read(sock, &hdr, sizeof(struct nego_header));
    if (ret != sizeof(struct nego_header)) {
        ret = -1;
        goto err;
    }

    cfg = calloc(1, 1024);
    ret = nbd_socket_read(sock, cfg, hdr.len);
    if (ret != hdr.len) {
        ret = -1;
        goto err;
    }

    info = nbd_parse_cfgstring(cfg, NULL);
    if (!info)
        goto err;

    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        ret = -1;
        goto err;
    }

    gfd = glfs_open(glfs, info->path, ALLOWED_BSOFLAGS);
    if (!gfd) {
        nbd_err("Failed to open file %s, %s\n", info->path, strerror(errno));
        ret = -1;
        goto err;
    }

    while (1) {
        memset(&request, 0, sizeof(struct nbd_request));
        ret = nbd_socket_read(sock, &request,
                sizeof(struct nbd_request));
        if (ret != sizeof(struct nbd_request)) {
            if (!ret)
                continue;
            ret = -1;
            goto err;
        }

        if (request.magic != htonl(NBD_REQUEST_MAGIC))
            nbd_err("invalid nbd request header!\n");

        if(request.type == htonl(NBD_CMD_DISC)) {
            nbd_dbg("Unmap request received!\n");
            ret = 0;
            goto err;
        }

        req = calloc(1, sizeof(struct pool_request));
        if (!req) {
            nbd_err("Failed to alloc memory for pool request!\n");
            ret = -1;
            goto err;
        }

        req->glfs = glfs;
        req->gfd = gfd;
        req->sock = sock;
        req->offset = be64toh(request.from);
        req->cmd = ntohl(request.type) & NBD_CMD_MASK_COMMAND;
        req->flags = ntohl(request.type) & ~NBD_CMD_MASK_COMMAND;
        req->len = ntohl(request.len);
        memcpy(&(req->handle), &(request.handle), sizeof(request.handle));
        req->data = NULL;

        if(req->cmd == NBD_CMD_READ || req->cmd == NBD_CMD_WRITE) {
            req->data = malloc(req->len);
            if (!req->data) {
                nbd_err("Failed to alloc memory for data!\n");
                free(req);
                ret = -1;
                goto err;
            }
        }

        if(req->cmd == NBD_CMD_WRITE)
            nbd_socket_read(sock, req->data, req->len);

        g_thread_pool_push(nbd_thread_pool, req, NULL);
    }

err:
    glfs_close(gfd);
    glfs_fini(glfs);
    g_thread_pool_free(nbd_thread_pool, false, true);
    pthread_spin_destroy(&nbd_write_lock);
    return ret;
}

bool_t nbd_version_1_svc(void *data, nbd_response *rep, struct svc_req *req)
{

    return true;
}

int rpc_nbd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
    xdr_free(xdr_result, result);

    return 1;
}
