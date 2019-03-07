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
#include "nbd-common.h"

#define NBD_GFAPI_LOG_FILE "/var/log/nbd-runner.log"
#define NBD_GFAPI_LOG_LEVEL 7
#define NBD_NL_VERSION 1

struct glfs_info {
    char volume[NAME_MAX];
    char host[NBD_HOST_MAX];
    char path[PATH_MAX];
    struct glfs *glfs;
    glfs_fd_t *gfd;
};

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

static struct nbd_device *glfs_cfg_parse(const char *cfg, nbd_response *rep)
{
    struct nbd_device *dev = NULL;
    struct glfs_info *info = NULL;
    char *tmp = NULL;
    char *sem;
    char *sep;
    char *ptr;
    int ret = 0;

    if (!cfg) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "The cfg param is NULL, will do nothing!");
        nbd_err("The cfg param is NULL, will do nothing!\n");
        return NULL;
    }

    dev = calloc(1, sizeof(struct nbd_device));
    if (!dev) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, NBD_EXIT_MAX, "No memory for dev!");
        nbd_err("No memory for dev!\n");
        return NULL;
    }

    info = calloc(1, sizeof(struct glfs_info));
    if (!info) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, NBD_EXIT_MAX, "No memory for info!");
        nbd_err("No memory for info\n");
        goto err;
    }

    /* skip the "key=" */
    tmp = strdup(cfg + 4);
    if (!tmp) {
        rep->exit = -ENOMEM;
        snprintf(rep->out, NBD_EXIT_MAX, "No memory for tmp!");
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
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid size key/pair: %s!", ptr);
                nbd_err("Invalid size key/pair: %s!\n", ptr);
                goto err;
            }

            ptr = sep + 1;
            dev->size = nbd_parse_size(ptr, NBD_DEFAULT_SECTOR_SIZE);
            if (dev->size < 0) {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid size value: %s!", ptr);
                nbd_err("Invalid size value: %s!\n", ptr);
                goto err;
            }
        } else if (!strncmp("readonly", ptr, strlen("readonly"))) {
            /* prealloc=yes|no */
            sep = ptr + strlen("readonly");
            if (*sep != '=') {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid readonly key/pair: %s!", ptr);
                nbd_err("Invalid readonly key/pair: %s!\n", ptr);
                goto err;
            }

            ptr = sep + 1;
            if (!strcmp("yes", ptr)) {
                dev->readonly = true;
            } else if (!strcmp("no", ptr)) {
                dev->readonly = false;
            } else {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid readonly value: %s!", ptr);
                nbd_err("Invalid readonly value: %s!\n", ptr);
                goto err;
            }
        } else if (!strncmp("prealloc", ptr, strlen("prealloc"))) {
            /* prealloc=yes|no */
            sep = ptr + strlen("prealloc");
            if (*sep != '=') {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid prealloc key/pair: %s!", ptr);
                nbd_err("Invalid prealloc key/pair: %s!\n", ptr);
                goto err;
            }

            ptr = sep + 1;
            if (!strcmp("yes", ptr)) {
                dev->prealloc = true;
            } else if (!strcmp("no", ptr)) {
                dev->prealloc = false;
            } else {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid prealloc value: %s!", ptr);
                nbd_err("Invalid prealloc value: %s!\n", ptr);
                goto err;
            }
        } else if (strchr(ptr, '@') && strchr(ptr, ':')) {
            /* volname@host:/path */
            sep = strchr(ptr, '@');
            if (!sep) {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid volinfo key/pair: %s!", ptr);
                nbd_err("Invalid volinfo value: %s!\n", ptr);
                goto err;
            }

            *sep = '\0';

            strncpy(info->volume, ptr, NAME_MAX);

            ptr = sep + 1;
            sep = strchr(ptr, ':');
            if (!sep) {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid volinfo host value: %s!", ptr);
                nbd_err("Invalid volinfo host value: %s!\n", ptr);
                goto err;
            }

            *sep = '\0';

            strncpy(info->host, ptr, NBD_HOST_MAX);

            ptr = sep + 1;
            if (*ptr != '/') {
                rep->exit = -EINVAL;
                snprintf(rep->out, NBD_EXIT_MAX, "Invalid volinfo path value: %s!", ptr);
                nbd_err("Invalid path path value: %s!\n", ptr);
                goto err;
            }

            ptr++;

            strncpy(info->path, ptr, PATH_MAX);
        }

        if (sem)
            ptr = sem + 1;
    } while (sem);

    dev->priv = info;
    free(tmp);
    return dev;

err:
    free(dev);
    free(tmp);
    free(info);
    return NULL;
}

static bool glfs_create(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info =dev->priv;
    struct glfs *glfs = NULL;
    struct glfs_fd *fd = NULL;
    struct stat st;
    bool ret = false;

    rep->exit = 0;

    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (!glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -EEXIST;
        snprintf(rep->out, NBD_EXIT_MAX, "file %s is already exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is already exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!nbd_check_available_space(glfs, info->volume, dev->size)) {
        rep->exit = -ENOSPC;
        snprintf(rep->out, NBD_EXIT_MAX, "No enough space in volume %s, require %d!",
                 info->volume, dev->size);
        nbd_err("No enough space in volume %s, require %d!\n", info->volume,
                dev->size);
        goto err;
    }

    fd = glfs_creat(glfs, info->path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC,
                    S_IRUSR | S_IWUSR);
    if (!fd) {
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "Failed to create file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to create file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    if (glfs_ftruncate(fd, dev->size, NULL, NULL) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "Failed to truncate file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to truncate file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    if (glfs_lstat(glfs, info->path, &st) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "failed to lstat file %s in volume: %s!",
                info->path, info->volume);
        nbd_err("failed to lstat file %s in volume: %s!\n",
                info->path, info->volume);
        goto err;
    }
    dev->blksize = st.st_blksize;

    if (dev->prealloc && glfs_zerofill(fd, 0, dev->size) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "Failed to prealloc file %s on volume %s!",
                 info->path, info->volume);
        nbd_err("Failed to prealloc file %s on volume %s!\n",
                info->path, info->volume);
        goto err;
    }

    ret = true;

err:
    glfs_close(fd);
    glfs_fini(glfs);

    return ret;
}

static bool glfs_delete(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    struct glfs_fd *fd = NULL;
    bool ret = false;

    rep->exit = 0;

    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -ENOENT;
        snprintf(rep->out, NBD_EXIT_MAX, "file %s is not exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (glfs_unlink(glfs, info->path) < 0) {
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "failed to delete file %s in volume %s!",
                 info->path, info->volume);
        nbd_err("failed to delete file %s in volume %s!",
                 info->path, info->volume);
        goto err;
    }

    ret = true;

err:
    glfs_fini(glfs);
    free(info);
    dev->priv = NULL;
    free(dev);
    return ret;
}

static bool glfs_map(struct nbd_device *dev, nbd_response *rep)
{
    struct glfs_info *info = dev->priv;
    struct glfs *glfs = NULL;
    glfs_fd_t *gfd = NULL;
    struct stat st;
    struct nbd_ip *ips = NULL, *p, *q;
    bool ret = false;

    rep->exit = 0;

    /* To check whether the file is exist */
    glfs = nbd_volume_init(info->volume, info->host);
    if (!glfs) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Init volume %s failed!", info->volume);
        nbd_err("Init volume %s failed!\n", info->volume);
        goto err;
    }

    if (glfs_access(glfs, info->path, F_OK)) {
        rep->exit = -ENOENT;
        snprintf(rep->out, NBD_EXIT_MAX, "file %s is not exist in volume %s!",
                 info->path, info->volume);
        nbd_err("file %s is not exist in volume %s!\n",
                 info->path, info->volume);
        goto err;
    }

    if (!dev->size || !dev->blksize) {
        if (glfs_lstat(glfs, info->path, &st) < 0) {
            rep->exit = -errno;
            snprintf(rep->out, NBD_EXIT_MAX, "failed to lstat file %s in volume: %s!",
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
        rep->exit = -errno;
        snprintf(rep->out, NBD_EXIT_MAX, "failed to open file %s in volume: %s!",
                 info->path, info->volume);
        nbd_err("Failed to open file %s, %s\n", info->path, strerror(errno));
        goto err;
    }

    info->glfs = glfs;
    info->gfd = gfd;

    ret = true;

err:
    if (!ret)
        glfs_fini(glfs);
    return ret;
}

static bool glfs_unmap(struct nbd_device *dev)
{
    struct glfs_info *info = dev->priv;

    glfs_close(info->gfd);
    glfs_fini(info->glfs);

    return true;
}

static void glfs_async_cbk(glfs_fd_t *gfd, ssize_t ret,
                           struct glfs_stat *prestat,
                           struct glfs_stat *poststat,
                           void *data)
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
        nbd_dbg("NBD_CMD_WRITE: offset: %llu, len: %u\n", req->offset,
                req->len);
        glfs_pwrite_async(info->gfd, req->rwbuf, req->len, req->offset,
                          ALLOWED_BSOFLAGS, glfs_async_cbk, req);
        break;
    case NBD_CMD_READ:
        nbd_dbg("NBD_CMD_READ: offset: %llu, len: %u\n", req->offset,
                req->len);
        glfs_pread_async(info->gfd, req->rwbuf, req->len, req->offset, SEEK_SET,
                         glfs_async_cbk, req);
        break;
    case NBD_CMD_FLUSH:
        nbd_dbg("NBD_CMD_FLUSH");
        glfs_fdatasync_async(info->gfd, glfs_async_cbk, req);
        break;
    case NBD_CMD_TRIM:
        nbd_dbg("NBD_CMD_TRIM: offset: %llu, len: %u\n", req->offset,
                req->len);
        glfs_discard_async(info->gfd, req->offset, req->len,
                glfs_async_cbk, req);
        break;
    default:
        fprintf(stderr,"Invalid request command\n");
        return;
    }
}

struct nbd_handler glfs_handler = {
    .name           = "Gluster gfapi handler",
    .subtype        = NBD_BACKSTORE_GLUSTER,

    .lock           = PTHREAD_MUTEX_INITIALIZER,

    .cfg_parse      = glfs_cfg_parse,
    .create         = glfs_create,
    .delete         = glfs_delete,
    .map            = glfs_map,
    .unmap          = glfs_unmap,
    .handle_request = glfs_handle_request,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return nbd_register_handler(&glfs_handler);
}
