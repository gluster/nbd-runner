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

struct glfs_info {
    char volume[NAME_MAX];
    char path[PATH_MAX];
    struct glfs *glfs;
    glfs_fd_t *gfd;
};

static char *glfs_host;

static GHashTable *glfs_volume_hash;

static struct glfs *nbd_volume_init(char *volume)
{
    struct glfs *glfs;
    char *key;
    int ret;

    if (!volume)
        return NULL;

    key = strdup(volume);
    if (!key) {
        nbd_err("No memory for buf!\n");
        return NULL;
    }

    glfs = g_hash_table_lookup(glfs_volume_hash, key);
    if (glfs)
        return glfs;

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

    g_hash_table_insert(glfs_volume_hash, key, glfs);
    return glfs;

out:
    glfs_fini(glfs);
    free(key);
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
    struct glfs *glfs = NULL;
    struct glfs_fd *fd = NULL;
    struct stat st;
    bool ret = false;

    rep->exit = 0;

    glfs = nbd_volume_init(info->volume);
    if (!glfs) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (!glfs_access(glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -EEXIST, "file %s is already exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is already exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!nbd_check_available_space(glfs, info->volume, dev->size)) {
        nbd_fill_reply(rep, -ENOSPC, "No enough space in volume %s, require %ld!",
                       info->volume, dev->size);
        nbd_err("No enough space in volume %s, require %ld!\n", info->volume,
                dev->size);
        goto err;
    }

    fd = glfs_creat(glfs, info->path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC,
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

    if (glfs_lstat(glfs, info->path, &st) < 0) {
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

    ret = true;

err:
    glfs_close(fd);

    return ret;
}

static bool glfs_delete(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    bool ret = false;

    rep->exit = 0;

    glfs = nbd_volume_init(info->volume);
    if (!glfs) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -ENOENT, "file %s is not exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (glfs_unlink(glfs, info->path) < 0) {
        nbd_fill_reply(rep, -errno, "failed to delete file %s in volume %s!",
                       info->path, info->volume);
        nbd_err("failed to delete file %s in volume %s!",
                 info->path, info->volume);
        goto err;
    }

    ret = true;

err:
    free(info);
    dev->priv = NULL;
    return ret;
}

static bool glfs_map(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    glfs_fd_t *gfd = NULL;
    struct stat st;
    bool ret = false;

    rep->exit = 0;

    /* To check whether the file is exist */
    glfs = nbd_volume_init(info->volume);
    if (!glfs) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        nbd_fill_reply(rep, -ENOENT, "file %s is not exist in volume %s!",
                       info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!dev->size || !dev->blksize) {
        if (glfs_lstat(glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            goto err;
        }

        dev->size = st.st_size;
        dev->blksize = st.st_blksize;
    }

    gfd = glfs_open(glfs, info->path, ALLOWED_BSOFLAGS);
    if (!gfd) {
        nbd_fill_reply(rep, -errno, "failed to open file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("Failed to open file %s, %s\n", info->path, strerror(errno));
        goto err;
    }

    info->glfs = glfs;
    info->gfd = gfd;

    ret = true;

err:
    return ret;
}

static bool glfs_unmap(struct nbd_device *dev)
{
    struct glfs_info *info = dev->priv;

    glfs_close(info->gfd);

    info->gfd = NULL;
    info->glfs = NULL;

    return true;
}

static ssize_t glfs_get_size(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    struct stat st;
    ssize_t ret = -1;

    rep->exit = 0;

    if (info->glfs) {
        if (glfs_lstat(glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            return -1;
        }

        return st.st_size;
    }

    glfs = nbd_volume_init(info->volume);
    if (!glfs) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        return -1;
    }

    if (glfs_lstat(glfs, info->path, &st) < 0) {
        nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s!\n",
                info->path, info->volume);
        ret = -1;
        goto err;
    }

    ret = st.st_size;
err:
    return ret;
}

static ssize_t glfs_get_blksize(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    struct stat st;
    ssize_t ret = -1;

    if (rep)
        rep->exit = 0;

    if (info->glfs) {
        if (glfs_lstat(glfs, info->path, &st) < 0) {
            nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                           info->path, info->volume);
            nbd_err("failed to lstat file %s in volume: %s!\n",
                    info->path, info->volume);
            return -1;
        }

        return st.st_blksize;
    }

    glfs = nbd_volume_init(info->volume);
    if (!glfs) {
        nbd_fill_reply(rep, -EINVAL, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        return -1;
    }

    if (glfs_lstat(glfs, info->path, &st) < 0) {
        nbd_fill_reply(rep, -errno, "failed to lstat file %s in volume: %s!",
                       info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s, %s!\n",
                info->path, info->volume, strerror(errno));
        ret = -1;
        goto err;
    }

    ret = st.st_blksize;
err:
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

    switch (req->cmd) {
    case NBD_CMD_WRITE:
        nbd_dbg("NBD_CMD_WRITE: offset: %ld len: %ld\n", req->offset,
                req->len);
        glfs_pwrite_async(info->gfd, req->rwbuf, req->len, req->offset,
                          ALLOWED_BSOFLAGS, glfs_async_cbk, req);
        break;
    case NBD_CMD_READ:
        nbd_dbg("NBD_CMD_READ: offset: %ld, len: %ld\n", req->offset,
                req->len);
        glfs_pread_async(info->gfd, req->rwbuf, req->len, req->offset, SEEK_SET,
                         glfs_async_cbk, req);
        break;
    case NBD_CMD_FLUSH:
        nbd_dbg("NBD_CMD_FLUSH");
        glfs_fdatasync_async(info->gfd, glfs_async_cbk, req);
        break;
    case NBD_CMD_TRIM:
        nbd_dbg("NBD_CMD_TRIM: offset: %ld, len: %ld\n", req->offset,
                req->len);
        glfs_discard_async(info->gfd, req->offset, req->len,
                glfs_async_cbk, req);
        break;
    default:
        fprintf(stderr,"Invalid request command\n");
        return;
    }
}

static void free_key(gpointer key)
{
    free(key);
}

static void free_value(gpointer value)
{
    struct glfs *glfs = value;

    glfs_fini(glfs);
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
    glfs_volume_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
                                             free_value);
    if (!glfs_volume_hash) {
        nbd_err("failed to create glfs_volume_hash hash table!\n");
        return -1;
    }

    if (!host)
        glfs_host = strdup("localhost");
    else
        glfs_host = strdup(host);

    return nbd_register_handler(&glfs_handler);
}
