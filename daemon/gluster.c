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
#include "strlcpy.h"
#include "nbd-common.h"
#include "nbd-sysconfig.h"

#define NBD_GFAPI_LOG_FILE NBD_LOG_DIR_DEFAULT"/nbd-runner-glfs.log"
#define NBD_GFAPI_LOG_LEVEL 7
#define NBD_NL_VERSION 1

struct glfs_container {
    struct glfs *glfs;
    unsigned long ref_count;
};

struct glfs_info {
    char volume[NAME_MAX];
    char path[PATH_MAX];

    struct glfs_container *container;
    glfs_fd_t *gfd;
};

static char *glfs_host;
static struct nbd_lru *nbd_lru;

static pthread_rwlock_t lru_lock = PTHREAD_RWLOCK_INITIALIZER;

static bool glfs_lru_release(void *value)
{
    struct glfs_container *container = value;
    bool ret = true;

    pthread_rwlock_wrlock(&lru_lock);
    if (container && container->ref_count) {
        ret = false;
        goto unlock;
    }

    if (container->glfs)
        glfs_fini(container->glfs);

    free(container);

unlock:
    pthread_rwlock_unlock(&lru_lock);

    return ret;
}

static struct glfs_container *nbd_volume_init(char *volume)
{
    struct glfs_container *container;
    struct glfs *glfs = NULL;
    char *key;
    int ret;

    if (!volume)
        return NULL;

    key = volume;

    if (!nbd_lru) {
        nbd_lru = nbd_lru_init(32, 36000, glfs_lru_release);
        if (!nbd_lru) {
            nbd_err("Failed to init nbd_lru!\n");
            return NULL;
        }
    }

    container = nbd_lru_get(nbd_lru, key);
    if (container) {
        return container;
    }

    glfs = glfs_new(volume);
    if (!glfs) {
        nbd_err("Not able to Initialize volume %s, %s\n",
                volume, strerror(errno));
        goto out;
    }

    ret = glfs_set_volfile_server(glfs, "tcp", glfs_host, 24007);
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

    container = malloc(sizeof(*container));
    if (!container) {
        nbd_err("No memory for conatiner!\n");
        goto out;
    }

    container->glfs = glfs;
    container->ref_count = 0;

    nbd_lru_update(nbd_lru, key, container);
    return container;

out:
    if (glfs)
        glfs_fini(glfs);
    return NULL;
}

static bool nbd_check_available_space(struct glfs *glfs, char *volume,
                                      size_t size)
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

static bool glfs_cfg_parse(struct nbd_device *dev, const char *cfg,
                           nbd_response *rep)
{
    struct glfs_info *info = NULL;
    char *tmp = NULL;
    char *sem;
    char *sep;
    char *ptr;

    if (!cfg || !dev) {
        nbd_fill_reply(rep, -EINVAL, "The cfg param is NULL, will do nothing!");
        nbd_err("The cfg param is NULL, will do nothing!\n");
        return false;
    }

    info = calloc(1, sizeof(struct glfs_info));
    if (!info) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for info!");
        nbd_err("No memory for info\n");
        goto err;
    }

    /* skip the "key=" */
    tmp = strdup(cfg + 4);
    if (!tmp) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for tmp!");
        nbd_err("No memory for tmp\n");
        goto err;
    }

    ptr = tmp;

    /*
     * The valid cfgstring is like:
     *    "volname/filepath;"
     * or
     *    "volname/filepath"
     */
    do {
        sem = strchr(ptr, ';');
        if (sem)
            *sem = '\0';

        if (*ptr == '\0') {
            /* in case the last valid char is ';' */
            break;
        }

        sep = strchr(ptr, '/');
        if (!sep) {
            nbd_fill_reply(rep, -EINVAL, "Invalid volinfo volume/filepath: %s!", ptr);
            nbd_err("Invalid volinfo value: %s!\n", ptr);
            goto err;
        }

        *sep = '\0';

        strlcpy(info->volume, ptr, NAME_MAX);
        strlcpy(info->path, sep + 1, PATH_MAX);

        if (sem)
            ptr = sem + 1;
    } while (sem);

    dev->priv = info;
    free(tmp);
    return true;

err:
    free(tmp);
    free(info);
    return false;
}

static bool glfs_create(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info =dev->priv;
    struct glfs_container *container = NULL;
    struct glfs_fd *fd = NULL;
    struct stat st;
    bool ret = false;

    if (rep)
        rep->exit = 0;

    pthread_rwlock_wrlock(&lru_lock);
    container = nbd_volume_init(info->volume);
    if (!container) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (!glfs_access(container->glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -EEXIST, "file %s is already exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is already exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!nbd_check_available_space(container->glfs, info->volume, dev->size)) {
        nbd_fill_reply(rep, -ENOSPC, "No enough space in volume %s, require %ld!",
                       info->volume, dev->size);
        nbd_err("No enough space in volume %s, require %ld!\n", info->volume,
                dev->size);
        goto err;
    }

    fd = glfs_creat(container->glfs, info->path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC,
                    S_IRUSR | S_IWUSR);
    if (!fd) {
        nbd_fill_reply(rep, -errno, "Failed to create file %s on volume %s!",
                       info->path, info->volume);
        nbd_err("Failed to create file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

#if GFAPI_VER6
    if (glfs_ftruncate(fd, dev->size, NULL, NULL) < 0) {
#else
    if (glfs_ftruncate(fd, dev->size) < 0) {
#endif
        nbd_fill_reply(rep, -errno, "Failed to truncate file %s on volume %s!",
                       info->path, info->volume);
        nbd_err("Failed to truncate file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    if (glfs_lstat(container->glfs, info->path, &st) < 0) {
        nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s!\n",
                info->path, info->volume);
        goto err;
    }
    dev->blksize = st.st_blksize;

    if (dev->prealloc && glfs_zerofill(fd, 0, dev->size) < 0) {
        nbd_fill_reply(rep, -errno, "Failed to prealloc file %s on volume %s!",
                       info->path, info->volume);
        nbd_err("Failed to prealloc file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    container->ref_count++;
    info->container = container;

    ret = true;

err:
    glfs_close(fd);
    pthread_rwlock_unlock(&lru_lock);

    return ret;
}

static bool glfs_delete(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs_container *container = info->container;

    if (rep)
        rep->exit = 0;

    pthread_rwlock_wrlock(&lru_lock);

    if (!container) {
        container = nbd_volume_init(info->volume);
        if (!container) {
            nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
            nbd_err("Init volume %s failed!\n", info->volume);
            goto err;
        }

        info->container = container;
    }

    if (glfs_access(container->glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -ENOENT, "file %s is not exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (glfs_unlink(container->glfs, info->path) < 0) {
        nbd_fill_reply(rep, -errno, "failed to delete file %s in volume %s!",
                       info->path, info->volume);
        nbd_err("failed to delete file %s in volume %s!",
                 info->path, info->volume);
        goto err;
    }

    container->ref_count--;

    free(info);
    dev->priv = NULL;

    pthread_rwlock_unlock(&lru_lock);

    return true;

err:
    pthread_rwlock_unlock(&lru_lock);
    return false;
}

static bool glfs_map(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs_container *container = info->container;
    glfs_fd_t *gfd = NULL;
    struct stat st;
    bool ret = false;

    if (rep)
        rep->exit = 0;

    pthread_rwlock_wrlock(&lru_lock);

    if (!container) {
        container = nbd_volume_init(info->volume);
        if (!container) {
            nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
            nbd_err("Init volume %s failed!\n", info->volume);
            goto err;
        }

        info->container = container;
    }

    if (glfs_access(container->glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -ENOENT, "file %s is not exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!dev->size || !dev->blksize) {
        if (glfs_lstat(container->glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            goto err;
        }

        dev->size = st.st_size;
        dev->blksize = st.st_blksize;
    }

    gfd = glfs_open(container->glfs, info->path, ALLOWED_BSOFLAGS);
    if (!gfd) {
        nbd_fill_reply(rep, -errno, "failed to open file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("Failed to open file %s, %s\n", info->path, strerror(errno));
        goto err;
    }
    info->gfd = gfd;

    container->ref_count++;

    ret = true;

err:
    pthread_rwlock_unlock(&lru_lock);
    return ret;
}

static bool glfs_unmap(struct nbd_device *dev)
{
    struct glfs_info *info = dev->priv;
    struct glfs_container *container = info->container;

    pthread_rwlock_wrlock(&lru_lock);

    if (!container) {
        container = nbd_volume_init(info->volume);
        if (!container) {
            nbd_err("Init volume %s failed!\n", info->volume);
            pthread_rwlock_unlock(&lru_lock);
            return false;
        }

        info->container = container;
    }

    glfs_close(info->gfd);
    container->ref_count--;

    info->gfd = NULL;

    pthread_rwlock_unlock(&lru_lock);

    return true;
}

static ssize_t glfs_get_size(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs_container *container = info->container;
    struct stat st;
    ssize_t ret = -1;

    if (rep)
        rep->exit = 0;

    pthread_rwlock_rdlock(&lru_lock);
    if (container && container->glfs) {
        if (glfs_lstat(container->glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            return -1;
        }

        return st.st_size;
    }

    container = nbd_volume_init(info->volume);
    if (!container) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        return -1;
    }

    info->container = container;

    if (glfs_lstat(container->glfs, info->path, &st) < 0) {
        nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s!\n",
                info->path, info->volume);
        ret = -1;
        goto err;
    }

    ret = st.st_size;
err:
    pthread_rwlock_unlock(&lru_lock);
    return ret;
}

static ssize_t glfs_get_blksize(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs_container *container = info->container;
    struct stat st;
    ssize_t ret = -1;

    if (rep)
        rep->exit = 0;

    pthread_rwlock_rdlock(&lru_lock);
    if (container && container->glfs) {
        if (glfs_lstat(container->glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            return -1;
        }

        return st.st_blksize;
    }

    container = nbd_volume_init(info->volume);
    if (!container) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        return -1;
    }

    info->container = container;

    if (glfs_lstat(container->glfs, info->path, &st) < 0) {
        nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s, %s!\n",
                info->path, info->volume, strerror(errno));
        ret = -1;
        goto err;
    }

    ret = st.st_blksize;
err:
    pthread_rwlock_unlock(&lru_lock);
    return ret;
}

#if GFAPI_VER6
static void glfs_async_cbk(glfs_fd_t *gfd, ssize_t ret,
                           struct glfs_stat *prestat,
                           struct glfs_stat *poststat,
                           void *data)
#else
static void glfs_async_cbk(glfs_fd_t *gfd, ssize_t ret,
                           void *data)
#endif
{
    struct nbd_handler_request *req = data;

    req->done(req, ret);

    free(req->rwbuf);
    free(req);
}

static void glfs_handle_request(gpointer data, gpointer user_data)
{
    struct nbd_handler_request *req;
    struct glfs_info *info;

    if (!data)
        return;

    req = (struct nbd_handler_request*)data;

    info = req->dev->priv;

    pthread_rwlock_rdlock(&lru_lock);
    if (!info->gfd) {
        nbd_err("%s/%s is unmapped, fails current cmd %d\n",
                info->volume, info->path, req->cmd);
        goto unlock;
    }

    switch (req->cmd) {
    case NBD_CMD_WRITE:
        nbd_dbg_io("NBD_CMD_WRITE: offset: %ld len: %ld\n", req->offset,
                   req->len);
        glfs_pwrite_async(info->gfd, req->rwbuf, req->len, req->offset,
                          ALLOWED_BSOFLAGS, glfs_async_cbk, req);
        break;
    case NBD_CMD_READ:
        nbd_dbg_io("NBD_CMD_READ: offset: %ld, len: %ld\n", req->offset,
                   req->len);
        glfs_pread_async(info->gfd, req->rwbuf, req->len, req->offset, SEEK_SET,
                         glfs_async_cbk, req);
        break;
    case NBD_CMD_FLUSH:
        nbd_dbg_io("NBD_CMD_FLUSH");
        glfs_fdatasync_async(info->gfd, glfs_async_cbk, req);
        break;
    case NBD_CMD_TRIM:
        nbd_dbg_io("NBD_CMD_TRIM: offset: %ld, len: %ld\n", req->offset,
                   req->len);
        glfs_discard_async(info->gfd, req->offset, req->len,
                glfs_async_cbk, req);
        break;
    default:
        nbd_err("Invalid request command: %d\n", req->cmd);
    }

unlock:
    pthread_rwlock_unlock(&lru_lock);
}

struct nbd_handler glfs_handler = {
    .name           = "Gluster gfapi handler",
    .subtype        = NBD_BACKSTORE_GLUSTER,

    .cfg_parse      = glfs_cfg_parse,
    .create         = glfs_create,
    .delete         = glfs_delete,
    .map            = glfs_map,
    .unmap          = glfs_unmap,
    .get_size       = glfs_get_size,
    .get_blksize    = glfs_get_blksize,
    .handle_request = glfs_handle_request,
};

/* Entry point must be named "handler_init". */
int gluster_handler_init(const char *host)
{
    if (!host)
        glfs_host = strdup("localhost");
    else
        glfs_host = strdup(host);

    return nbd_register_handler(&glfs_handler);
}
