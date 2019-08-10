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
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/nbd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <glib.h>
#include <gmodule.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <json-c/json.h>

#include "rpc_nbd.h"
#include "nbd-common.h"
#include "nbd-log.h"
#include "utils.h"
#include "strlcpy.h"
#include "nbd-sysconfig.h"

static GHashTable *nbd_handler_hash;
static GHashTable *nbd_devices_hash;
static GHashTable *nbd_nbds_hash;

static char *ihost;
int iport = NBD_MAP_SVC_PORT;

#define NBD_NL_VERSION 1
#define NBD_RETRY_THREAD_THRESH 60000

static void nbd_gfree_data(gpointer data)
{
    free(data);
}

static GPtrArray *nbd_init_iohost(unsigned int family)
{
    GPtrArray *iohost;
    gpointer ip;
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa;
    int s;
    char tmp[NI_MAXHOST];

    if (family != AF_INET && family != AF_INET6) {
        nbd_err("invalid family type and only AF_INET/AF_INET6 are allowed!\n");
        return NULL;
    }

    iohost = g_ptr_array_new_full(16, nbd_gfree_data);
    if (!iohost) {
        nbd_err("failed to init g_ptr array for iohost, %s!\n", strerror(errno));
        return NULL;
    }

    if (getifaddrs(&ifaddr) == -1) {
        nbd_err("getifaddrs failed, %s!\n", strerror(errno));
        goto err;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (family == ifa->ifa_addr->sa_family) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    tmp, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s) {
                nbd_err("getnameinfo() failed, %s\n", gai_strerror(s));
                goto err;
            }

            if (!strcmp(tmp, "127.0.0.1"))
                continue;

            ip = strdup(tmp);
            if (!ip) {
                nbd_err("no memory for ip!\n");
                goto err;
            }
            g_ptr_array_add(iohost, ip);
        }
    }

    freeifaddrs(ifaddr);
    return iohost;

err:
    g_ptr_array_free(iohost, true);
    freeifaddrs(ifaddr);
    return NULL;
}

static void nbd_fini_iohost(GPtrArray *iohost)
{
    if (!iohost)
        return;

    g_ptr_array_free(iohost, true);
}

/*
 * Delete the device config from the config json file
 */
static int nbd_config_delete_backstore(struct nbd_device *dev, const char *key)
{
    json_object *globalobj = NULL;
    json_object *devobj = NULL;

    if (!key) {
        nbd_err("Invalid dev or key parameter!\n");
        return -EINVAL;
    }

    if (dev->status == NBD_DEV_CONN_ST_MAPPED) {
        nbd_err("The device is still mapped, please unmap it first!\n");
        return -EINVAL;
    }

    globalobj = json_object_from_file(NBD_SAVE_CONFIG_FILE);
    if (!globalobj)
        return 0;

    if (!json_object_object_get_ex(globalobj, key, &devobj)) {
        nbd_err("%s is no exist in conig file!\n", key);
        json_object_put(globalobj);
        return -EINVAL;
    }

    json_object_object_del(globalobj, key);
    json_object_to_file_ext(NBD_SAVE_CONFIG_FILE, globalobj, JSON_C_TO_STRING_PRETTY);
    json_object_put(globalobj);
    return 0;
}

/*
 * Update the device config to the config json file
 */
static int nbd_update_json_config_file(struct nbd_device *dev, bool replace)
{
    json_object *globalobj = NULL;
    json_object *devobj = NULL;
    const char *st;
    char *key;
    int ret = 0;

    if (!dev) {
        nbd_err("Invalid dev parameter!\n");
        return -EINVAL;
    }

    key = dev->bstore;

    globalobj = json_object_from_file(NBD_SAVE_CONFIG_FILE);
    if (globalobj) {
        if (json_object_object_get_ex(globalobj, key, &devobj)) {
            if (replace) {
                json_object_object_del(globalobj, key);
            } else {
                json_object_put(globalobj);
                nbd_info("%s is already in the json conig file!\n", key);
                return 0;
            }
        }
    } else {
        /* The config file is empty */
        globalobj = json_object_new_object();
        if (!globalobj) {
            nbd_err("No memory for globalobj!\n");
            return -ENOMEM;
        }
    }

    devobj = json_object_new_object();
    if (!devobj) {
        nbd_err("No memory for devobj!\n");
        ret = -ENOMEM;
        goto err;
    }

    /*
     * It will be like:
     *
     * "myvolume\/myfilepath":{
     *   "type":0,
     *   "nbd":"/dev/nbd3",
     *   "maptime":"2019-04-01 15:53:13",
     *   "size":104857600,
     *   "blksize":0,
     *   "readonly":false,
     *   "prealloc":false,
     *   "dummy1":"value"
     *   "dummy2":true
     *   "dummy3":0
     *   "status":"mapped"
     * },
     *
     * NOTE: the dummy options are private extra ones
     */
    json_object_object_add(devobj, "type", json_object_new_int64(dev->htype));
    json_object_object_add(devobj, "nbd", json_object_new_string(dev->nbd));
    json_object_object_add(devobj, "maptime", json_object_new_string(dev->time));
    json_object_object_add(devobj, "size", json_object_new_int64(dev->size));
    json_object_object_add(devobj, "blksize", json_object_new_int64(dev->blksize));
    json_object_object_add(devobj, "readonly", json_object_new_boolean(dev->readonly));
    json_object_object_add(devobj, "prealloc", json_object_new_boolean(dev->prealloc));

    if (dev->handler && dev->handler->update_json)
	    dev->handler->update_json(dev, devobj);

    st = nbd_dev_status_lookup_str(dev->status);
    json_object_object_add(devobj, "status", json_object_new_string(st));


    json_object_object_add(globalobj, key, devobj);
    json_object_to_file_ext(NBD_SAVE_CONFIG_FILE, globalobj, JSON_C_TO_STRING_PRETTY);

    ret = 0;
err:
    json_object_put(globalobj);
    return ret;
}

/*
 * Prase the saved config from the json file
 */
static int nbd_parse_from_json_config_file(void)
{
    json_object *globalobj = NULL;
    json_object *obj = NULL;
    struct nbd_handler *handler;
    struct nbd_device *dev;
    const char *tmp;
    char *ktmp;

    globalobj = json_object_from_file(NBD_SAVE_CONFIG_FILE);
    if (!globalobj)
        return 0;

    {
        json_object_object_foreach(globalobj, key, devobj) {
            dev = calloc(1, sizeof(struct nbd_device));
            if (!dev) {
                nbd_err("No memory for nbd device!\n");
                free(key);
                json_object_put(globalobj);
                return -1;
            }

            json_object_object_get_ex(devobj, "type", &obj);
            dev->htype = json_object_get_int64(obj);

            json_object_object_get_ex(devobj, "nbd", &obj);
            tmp = json_object_get_string(obj);
            if (tmp)
                strlcpy(dev->nbd, tmp, NBD_DLEN_MAX);

            json_object_object_get_ex(devobj, "maptime", &obj);
            tmp = json_object_get_string(obj);
            if (tmp)
                strlcpy(dev->time, tmp, NBD_TLEN_MAX);

            json_object_object_get_ex(devobj, "size", &obj);
            dev->size = json_object_get_int64(obj);

            json_object_object_get_ex(devobj, "blksize", &obj);
            dev->blksize = json_object_get_int64(obj);

            json_object_object_get_ex(devobj, "prealloc", &obj);
            dev->prealloc = json_object_get_boolean(obj);

            json_object_object_get_ex(devobj, "readonly", &obj);
            dev->readonly = json_object_get_boolean(obj);

            /* The connection is dead, needed to remap from the client */
            if (dev->nbd[0])
                dev->status = NBD_DEV_CONN_ST_DEAD;
            else
                dev->status = NBD_DEV_CONN_ST_CREATED;

            strcpy(dev->bstore, key);

            nbd_dbg("key: %s, type: %d, nbd: %s, maptime: %s, size: %zd, blksize: %zd, prealloc: %d, readonly: %d\n",
                    key, dev->htype, dev->nbd, dev->time, dev->size, dev->blksize, dev->prealloc, dev->readonly);
            handler = g_hash_table_lookup(nbd_handler_hash, &dev->htype);
            if (!handler) {
                nbd_err("handler type %d is not registered!\n", dev->htype);
                free(dev);
            } else {
                dev->handler = handler;

                if (handler->load_json) {
                    ktmp = malloc(NBD_CFGS_MAX);
                    snprintf(ktmp, NBD_CFGS_MAX, "%s", key);
                    handler->load_json(dev, devobj, ktmp);
                    free(ktmp);
                }

                ktmp = strdup(key);
                g_hash_table_insert(nbd_devices_hash, ktmp, dev);
                if (dev->nbd[0]) {
                    ktmp = strdup(dev->nbd);
                    g_hash_table_insert(nbd_nbds_hash, ktmp, dev);
                }
            }
        }
    }

    json_object_put(globalobj);
    return 0;
}

bool_t nbd_create_1_svc(nbd_create *create, nbd_response *rep,
                        struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;

    nbd_info("Create request type: %d, cfg: %s, size: %zu, prealloc: %d\n",
             create->htype, create->cfgstring, create->size, create->prealloc);

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &create->htype);
    if (!handler) {
        nbd_fill_reply(rep, -EINVAL, "Invalid handler or the handler is not loaded: %d!",
                       create->htype);
        nbd_err("Invalid handler or the handler is not loaded: %d!\n",
                create->htype);
        return true;
    }

    key = strdup(create->cfgstring);
    if (!key) {
        nbd_fill_reply(rep, -ENOMEM, "No memory to dup %s!", create->cfgstring);
        nbd_err("No memory to dup %s!\n", create->cfgstring);
        return true;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (dev) {
        nbd_fill_reply(rep, -EEXIST, "%s is already exist!", create->cfgstring);
        nbd_err("%s is already exist!\n", create->cfgstring);
        free(key);
        return true;
    }

    dev = calloc(1, sizeof(struct nbd_device));
    if (!dev) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for nbd_device for %s!",
                       create->cfgstring);
        nbd_err("No memory for nbd_device for %s!\n", create->cfgstring);
        goto err_key;
    }

    if (!handler->cfg_parse(dev, create->cfgstring, rep)) {
        nbd_err("failed to parse cfgstring: %s\n", create->cfgstring);
        goto err_dev;
    }

    pthread_mutex_init(&dev->sock_lock, NULL);
    pthread_mutex_init(&dev->lock, NULL);
    pthread_mutex_init(&dev->retry_lock, NULL);
    dev->htype = create->htype;
    dev->handler = handler;
    dev->size = create->size;
    dev->prealloc = create->prealloc;
    dev->status = NBD_DEV_CONN_ST_CREATED;

    /*
     * Since we allow to create the backstore directly
     * by using the backstore cli instead of the nbd-cli.
     * If so the device won't be insert to the hash table,
     * then we need to insert it here anyway.
     */
    if (!handler->create(dev, rep) && rep->exit != -EEXIST) {
        nbd_err("failed to create backstore: %s\n", create->cfgstring);
        goto err_create;
    }

    dev->blksize = handler->get_blksize(dev, NULL);
    if (dev->blksize < 0)
        dev->blksize = 0;

    strcpy(dev->bstore, key);

    nbd_update_json_config_file(dev, false);
    g_hash_table_insert(nbd_devices_hash, key, dev);

    return true;

err_create:
    pthread_mutex_destroy(&dev->sock_lock);
    pthread_mutex_destroy(&dev->lock);
    pthread_mutex_destroy(&dev->retry_lock);
err_dev:
    if (dev && dev->priv)
        free(dev->priv);
    free(dev);
err_key:
    free(key);
    return true;
}

bool_t nbd_delete_1_svc(nbd_delete *delete, nbd_response *rep,
                        struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;
    int retry;

    nbd_info("Delete request type %d, cfg: %s\n", delete->htype,
             delete->cfgstring);

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!\n");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &delete->htype);
    if (!handler) {
        nbd_fill_reply(rep, -EINVAL, "Invalid handler or the handler is not loaded: %d!",
                       delete->htype);
        nbd_err("Invalid handler or the handler is not loaded: %d!\n",
                delete->htype);
        goto err;
    }

    key = strdup(delete->cfgstring);
    if (!key) {
        nbd_fill_reply(rep, -EINVAL, "Invalid cfgstring %s!", delete->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", delete->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (!dev) {
        /*
         * Since we allow to create the backstore directly
         * by using the backstore cli instead of the nbd-cli.
         * If so the device won't be insert to the hash table,
         * then we need to delete the backstore to alloc one
         * tmp new dev.
         */
        nbd_info("%s is not in the hash table, will try to delete enforce!\n",
                 delete->cfgstring);
        dev = calloc(1, sizeof(struct nbd_device));
        if (!dev) {
            nbd_fill_reply(rep, -ENOMEM, "No memory for nbd_device!");
            nbd_err("No memory for nbd_device!\n");
            goto err;
        }

        if (!handler->cfg_parse(dev, delete->cfgstring, rep)) {
            nbd_fill_reply(rep, -EAGAIN, "failed to delete %s!", delete->cfgstring);
            nbd_err("failed to delete %s\n", delete->cfgstring);
            goto err;
        }

        dev->handler = handler;
        dev->status = NBD_DEV_CONN_ST_CREATED;
        handler->delete(dev, rep);
        goto err;
    }

    /*
     * Wait for about "NBD_RETRY_THREAD_THRESH * 50" microseconds to
     * wait the dev->retry_thread to be totally stopped to avoid crash.
     */
    retry = 0;
    while (dev->status == NBD_DEV_CONN_ST_UNMAPPING && retry < 50) {
        g_usleep(NBD_RETRY_THREAD_THRESH);
        retry++;
    }
    nbd_info("Retry %d times for waiting the device to be unmapped!");

    pthread_mutex_lock(&dev->lock);
    if (dev->status == NBD_DEV_CONN_ST_MAPPED) {
        nbd_fill_reply(rep, -EPERM, "Device %s is still mapped, please unmap it first!", key);
        nbd_err("Device %s is still mapped, please unmap it first!\n", key);
        pthread_mutex_unlock(&dev->lock);
        goto err;
    } else if (dev->status == NBD_DEV_CONN_ST_MAPPING) {
        nbd_fill_reply(rep, -EAGAIN, "Device %s is still unmapping, please try it again later!", key);
        nbd_err("Device %s is still unmapping, please try it again first!\n", key);
        pthread_mutex_unlock(&dev->lock);
        goto err;
    }

    /*
     * If the handler return -ENOENT, that means there is no need
     * to do the deletion in the hanler backend, then we will delete
     * the device from the hash table by default.
     */
    if (!handler->delete(dev, rep)) {
        if (rep->exit != -ENOENT) {
            nbd_err("Failed to delete device %s!\n", key);
            pthread_mutex_unlock(&dev->lock);
            goto err;
        }

        rep->exit = 0;
    }

    nbd_config_delete_backstore(dev, key);
    pthread_mutex_unlock(&dev->lock);
    if (dev->nbd[0])
        g_hash_table_remove(nbd_devices_hash, dev->nbd);
    g_hash_table_remove(nbd_devices_hash, key);

err:
    free(key);
    return true;
}

bool_t nbd_premap_1_svc(nbd_premap *map, nbd_response *rep, struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;
    bool inserted = false;
    int save_ret;

    nbd_info("Premap request type: %d, cfg: %s, readonly: %d, timeout: %d\n",
             map->htype, map->cfgstring, map->readonly, map->timeout);

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!\n");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &map->htype);
    if (!handler) {
        nbd_fill_reply(rep, -EINVAL, "Invalid handler or the handler is not loaded: %d!",
                       map->htype);
        nbd_err("Invalid handler or the handler is not loaded: %d!",
                map->htype);
        goto err;
    }

    key = strdup(map->cfgstring);
    if (!key) {
        nbd_fill_reply(rep, -EINVAL, "Invalid cfgstring %s!", map->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", map->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (dev) {
        if (dev->status == NBD_DEV_CONN_ST_MAPPED) {
            nbd_fill_reply(rep, -EBUSY, "%s already mapped to %s!", key, dev->nbd);
            nbd_err("%s already map to %s!\n", key, dev->nbd);
            goto err;
        } else if (dev->status == NBD_DEV_CONN_ST_MAPPING) {
            nbd_fill_reply(rep, -EBUSY, "%s already in mapping state!", key);
            nbd_err("%s already in mapping state!\n", key);
            goto err;
        } else if (dev->status == NBD_DEV_CONN_ST_UNMAPPING) {
            nbd_fill_reply(rep, -EBUSY, "%s is still in unmapping state!", key);
            nbd_err("%s is still in in unmapping state!\n", key);
            goto err;
        } else if (dev->status == NBD_DEV_CONN_ST_DEAD) {
            nbd_fill_reply(rep, -EEXIST, "%s", dev->nbd);
            goto map;
        }
    }

    if (!dev) {
        /*
        * Since we allow to create the backstore directly
        * by using the backstore cli instead of the nbd-cli.
        * If so the device won't be insert to the hash table,
        * then we need to insert it here anyway.
        */
        nbd_info("%s is not in the hash table, will try to map enforce!\n",
                map->cfgstring);
        dev = calloc(1, sizeof(struct nbd_device));
        if (!dev) {
            nbd_fill_reply(rep, -ENOMEM, "No memory for nbd_device!");
            nbd_err("No memory for nbd_device!\n");
            goto err;
        }

        if (!handler->cfg_parse(dev, map->cfgstring, rep)) {
            nbd_fill_reply(rep, -EAGAIN, "failed to parse %s!", map->cfgstring);
            nbd_err("failed to parse %s\n", map->cfgstring);
            free(dev);
            goto err;
        }

        dev->status = NBD_DEV_CONN_ST_CREATED;
        dev->htype = map->htype;
        dev->handler = handler;
        dev->readonly = map->readonly;
        dev->size = handler->get_size(dev, rep);
        if (dev->size < 0) {
            free(dev);
            goto err;
        }
        dev->blksize = handler->get_blksize(dev, rep);
        if (dev->blksize < 0) {
            free(dev);
            goto err;
        }

        strcpy(dev->bstore, key);

        pthread_mutex_init(&dev->sock_lock, NULL);
        pthread_mutex_init(&dev->lock, NULL);
        pthread_mutex_init(&dev->retry_lock, NULL);
        nbd_update_json_config_file(dev, false);
        g_hash_table_insert(nbd_devices_hash, key, dev);
        inserted = true;
    }

map:
    save_ret = rep->exit;
    dev->timeout = map->timeout;
    pthread_mutex_lock(&dev->lock);
    dev->status = NBD_DEV_CONN_ST_MAPPING;
    if (!handler->map(dev, rep)) {
        pthread_mutex_unlock(&dev->lock);
        goto err;
    }

    rep->size = dev->size;
    rep->blksize = dev->blksize;
    INIT_LIST_HEAD(&dev->retry_io_queue);
    pthread_mutex_unlock(&dev->lock);

    if (!rep->exit)
        rep->exit = save_ret;

    /* Currently we will use the first host */
    snprintf(rep->host, NBD_HOST_MAX, "%s", ihost);
    snprintf(rep->port, NBD_PORT_MAX, "%d", iport);

err:
    if (!inserted)
        free(key);
    return true;
}

bool_t nbd_postmap_1_svc(nbd_postmap *map, nbd_response *rep, struct svc_req *req)
{
    struct nbd_device *dev;
    char *cfg = map->cfgstring;
    char *key;
    char *nbd;

    nbd_info("Postmap request type: %d, cfg: %s, nbd: %s, time: %s\n",
             map->htype, map->cfgstring, map->nbd, map->time);

    rep->exit = 0;

    rep->buf = calloc(1, NBD_EXIT_MAX);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!\n");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    key = strdup(cfg);
    if (!key) {
        nbd_fill_reply(rep, -EINVAL, "Invalid cfgstring %s!", cfg);
        nbd_err("Invalid cfgstring %s!\n", cfg);
        return true;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (!dev) {
        nbd_fill_reply(rep, -ENOENT, "Device is none exist!");
        nbd_err("Device is none exist!\n");
        return true;
    }

    pthread_mutex_lock(&dev->lock);
    dev->status = NBD_DEV_CONN_ST_MAPPED;
    strcpy(dev->time, map->time);
    strcpy(dev->nbd, map->nbd);
    nbd = strdup(dev->nbd);
    g_hash_table_insert(nbd_nbds_hash, nbd, dev);
    nbd_update_json_config_file(dev, true);
    pthread_mutex_unlock(&dev->lock);

    return true;
}

bool_t nbd_unmap_1_svc(nbd_unmap *unmap, nbd_response *rep, struct svc_req *req)
{
    struct nbd_device *dev;
    char *key = NULL;

    nbd_info("Unmap request type: %d, cfg: %s, nbd: %s\n", unmap->htype,
             unmap->cfgstring, unmap->nbd);

    rep->exit = 0;

    rep->buf = calloc(1, NBD_EXIT_MAX);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!\n");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    if (!unmap->nbd[0] && !unmap->cfgstring[0]) {
        nbd_fill_reply(rep, -EINVAL,
                       "Invalid nbd device and cfgstring, they shouldn't be null at the same time!");
        nbd_err("Invalid nbd device and cfgstring, they shouldn't be null at the same time!\n");
        goto out;
    }

    if (unmap->nbd[0]) {
        dev = g_hash_table_lookup(nbd_nbds_hash, unmap->nbd);
        if (!dev) {
            nbd_fill_reply(rep, -EEXIST, "there is no maping for '%s'!",
                           unmap->nbd);
            nbd_warn("There is no maping for '%s'!\n", unmap->nbd);
            goto out;
        }
    } else {
        key = strdup(unmap->cfgstring);
        if (!key) {
            nbd_fill_reply(rep, -EINVAL, "Invalid cfgstring %s!", unmap->cfgstring);
            nbd_err("Invalid cfgstring %s!\n", unmap->cfgstring);
            goto out;
        }

        dev = g_hash_table_lookup(nbd_devices_hash, key);
        if (!dev) {
            nbd_fill_reply(rep, -ENODEV, "There is no maping for '%s'!", key);
            nbd_warn("There is no maping for '%s'!\n", key);
            goto out;
        }

        nbd_fill_reply(rep, 0, "%s", dev->nbd);
    }

    pthread_mutex_lock(&dev->lock);
    dev->status = NBD_DEV_CONN_ST_UNMAPPING;
    dev->nbd[0] = '\0';
    dev->time[0] = '\0';
    nbd_update_json_config_file(dev, true);
    g_hash_table_remove(nbd_nbds_hash, unmap->nbd);
    pthread_mutex_unlock(&dev->lock);

out:
    free(key);
    return true;
}

bool_t nbd_list_1_svc(nbd_list *list, nbd_response *rep, struct svc_req *req)
{
    json_object *globalobj = NULL;
    json_object *devobj = NULL;
    struct nbd_device *dev;
    GHashTableIter iter;
    gpointer key, value;
    char *out;
    int len = NBD_EXIT_MAX;
    int l = 0;
    char *tmp = NULL;
    const char *st;
    int max = max(4096, max(NBD_DLEN_MAX, NBD_TLEN_MAX));

    nbd_info("List request type: %d\n", list->htype);

    rep->exit = 0;

    rep->buf = calloc(1, len);
    if (!rep->buf) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for rep->buf!\n");
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    globalobj = json_object_new_object();
    if (!globalobj) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for the gloablobj!");
        nbd_err("No memory for globalobj!\n");
        return true;
    }

    tmp = malloc(max);
    if (!tmp) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for the tmp buf!");
        nbd_err("No memory for tmp buf!\n");
        goto err;
    }

    g_hash_table_iter_init(&iter, nbd_devices_hash);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        dev = value;
        pthread_mutex_lock(&dev->lock);
        /* NBD_BACKSTORE_MAX for the mapping restore in nbd-clid */
        if (list->htype != NBD_BACKSTORE_MAX && list->htype != dev->htype) {
            pthread_mutex_unlock(&dev->lock);
            continue;
        }

        /*
         * The length equals to
         *   "dht@192.168.195.164:\/file313":{                --> >=5 extra chars
         *     "type":0,                                      --> 8 extra chars
         *     "nbd":"\/dev\/nbd121",                         --> 11 extra chars
         *     "maptime":"2019-03-12 13:03:10",               --> 13 extra chars
         *     "size":1073741824,                             --> 8 extra chars
         *     "blksize":4096,                                --> 11 extra chars
         *     "readonly":false,                              --> 17 chars
         *     "prealloc":false,                              --> 17 chars
         *     "status":"mapped"                              --> 11 extra chars
         *   },                                               --> 2 extar chars
         */
        l += strlen(dev->nbd) + 5;
        l += strlen(key) + 11;
        l += snprintf(tmp, max, "%d", dev->htype) + 8;
        l += strlen(dev->time) + 13;
        l += snprintf(tmp, max, "%zd", dev->size) + 8;
        l += snprintf(tmp, max, "%zd", dev->blksize) + 11;
        l += 17;
        l += 17;
        st = nbd_dev_status_lookup_str(dev->status);
        l += strlen(st) + 11;
        l += 2;
        l += 128;  /* Add 128 extra more space */

        devobj = json_object_new_object();
        if (!devobj) {
            nbd_fill_reply(rep, -ENOMEM, "No memory for the devobj!");
            nbd_err("No memory for devobj!\n");
            pthread_mutex_unlock(&dev->lock);
            goto err;
        }

        json_object_object_add(devobj, "type", json_object_new_int64(dev->htype));
        json_object_object_add(devobj, "nbd", json_object_new_string(dev->nbd));
        json_object_object_add(devobj, "maptime", json_object_new_string(dev->time));
        json_object_object_add(devobj, "size", json_object_new_int64(dev->size));
        json_object_object_add(devobj, "blksize", json_object_new_int64(dev->blksize));
        json_object_object_add(devobj, "readonly", json_object_new_boolean(dev->readonly));
        json_object_object_add(devobj, "prealloc", json_object_new_boolean(dev->prealloc));
        json_object_object_add(devobj, "status", json_object_new_string(st));
        pthread_mutex_unlock(&dev->lock);
        json_object_object_add(globalobj, key, devobj);
    }

    if (l > len) {
        out = realloc(rep->buf, l);
        if (!out) {
            nbd_fill_reply(rep, -ENOMEM, "No memory for the list buffer!");
            nbd_err("No memory for the list buffer!\n");
            goto err;
        }
        rep->buf = out;
    }

    snprintf(rep->buf, l, "%s", json_object_to_json_string_ext(globalobj, JSON_C_TO_STRING_PRETTY));

err:
    json_object_put(globalobj);
    free(tmp);
    return true;
}

static gpointer nbd_request_retry(gpointer data)
{
    struct nbd_device *dev = data;
    struct nbd_handler_request *req, *tmp;
    gint64 current_time;

    while (!dev->stop_retry_thread) {
        g_usleep(NBD_RETRY_THREAD_THRESH);
        pthread_mutex_lock(&dev->retry_lock);
        list_for_each_entry_safe(req, tmp, &dev->retry_io_queue, entry) {
            current_time = g_get_monotonic_time();
            if (current_time >= req->timer_expires) {
                list_del(&req->entry);
                dev->handler->handle_request(req, NULL);
            }
        }
        pthread_mutex_unlock(&dev->retry_lock);
    }

    pthread_mutex_lock(&dev->retry_lock);
    list_for_each_entry_safe(req, tmp, &dev->retry_io_queue, entry) {
        list_del(&req->entry);
        req->done(req, -EIO);
    }
    pthread_mutex_unlock(&dev->retry_lock);

    return NULL;
}

void nbd_handle_request_done(struct nbd_handler_request *req, int ret)
{
    struct nbd_reply reply;
    struct nbd_device *dev = req->dev;

    if (ret == -EAGAIN && dev->timeout) {
        gint64 current_time;
        gint64 expire_interval = 2 * G_USEC_PER_SEC;

        if (!req->retry_end_time)
            req->retry_end_time = req->io_start_time + (dev->timeout * G_USEC_PER_SEC);

        current_time = g_get_monotonic_time();
        if (current_time + expire_interval >= req->retry_end_time) {
            ret = -EIO;
            goto done;
        }

        req->timer_expires = current_time + expire_interval;
        INIT_LIST_HEAD(&req->entry);

        pthread_mutex_lock(&dev->retry_lock);
        list_add_tail(&req->entry, &dev->retry_io_queue);
        pthread_mutex_unlock(&dev->retry_lock);
        return;
    }

done:
    reply.magic = htonl(NBD_REPLY_MAGIC);
    reply.error = htonl(ret < 0 ? ret : 0);
    memcpy(&(reply.handle), &(req->handle), sizeof(req->handle));

    pthread_mutex_lock(&dev->sock_lock);
    nbd_socket_write(dev->sockfd, &reply, sizeof(struct nbd_reply));
    if(req->cmd == NBD_CMD_READ && !reply.error)
        nbd_socket_write(dev->sockfd, req->rwbuf, req->len);
    pthread_mutex_unlock(&dev->sock_lock);
    free(req->rwbuf);
    free(req);
}

int nbd_handle_request(int sock, int threads)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler_request *req;
    struct nbd_request request;
    struct nbd_reply reply;
    GThreadPool *thread_pool = NULL;
    struct nego_request nhdr;
    struct nego_reply nrep = {0, };
    char *cfg = NULL;
    char *buf = NULL;
    char *key = NULL;
    int cmd;
    int ret = -1;

    /* nego start */
    bzero(&nhdr, sizeof(struct nego_request));
    ret = nbd_socket_read(sock, &nhdr, sizeof(struct nego_request));
    if (ret != sizeof(struct nego_request)) {
        ret = -1;
        goto err;
    }

    cfg = calloc(1, nhdr.len + 1);
    ret = nbd_socket_read(sock, cfg, nhdr.len);
    if (ret != nhdr.len) {
        ret = -1;
        goto err;
    }

    key = strdup(cfg);
    if (!key) {
        nrep.exit = -EINVAL;
        buf = calloc(1, 4096);
        nrep.len = snprintf(buf, 4096, "Invalid cfg %s for nego!", cfg);
        nbd_err("Invalid cfg %s for nego!\n", cfg);
    }
    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (!dev) {
        nrep.exit = -EINVAL;
        buf = calloc(1, 4096);
        ret = snprintf(buf, 4096, "No such device found: %s", cfg);
        if (ret < 0)
            nrep.len = 0;
        else
            nrep.len = ret;
    }
    free(cfg);
    free(buf);

    pthread_mutex_lock(&dev->sock_lock);
    nbd_socket_write(sock, &nrep, sizeof(struct nego_reply));
    if (nrep.len && buf)
        nbd_socket_write(sock, buf, nrep.len);
    pthread_mutex_unlock(&dev->sock_lock);
    /* nego end */

    if (nrep.exit)
        goto err;

    dev->sockfd = sock;

    thread_pool = g_thread_pool_new(dev->handler->handle_request, NULL, threads,
                                    false, NULL);

    if (!thread_pool) {
        nbd_err("Creating new thread pool failed!\n");
        return -1;
    }

    dev->retry_thread = g_thread_try_new("retry thread", nbd_request_retry, (gpointer)dev, NULL);

    if (!dev->retry_thread) {
        nbd_err("Creating device retry thread failed!\n");
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
            nbd_dbg("Unmap request received for dev: %s!\n", key);
            pthread_mutex_lock(&dev->lock);
            dev->handler->unmap(dev);
            pthread_mutex_unlock(&dev->lock);
            ret = 0;
            goto err;
        }

        cmd = ntohl(request.type) & NBD_CMD_MASK_COMMAND;
        if (dev->readonly && cmd != NBD_CMD_READ && cmd != NBD_CMD_FLUSH) {
            reply.magic = htonl(NBD_REPLY_MAGIC);
            reply.error = htonl(EROFS);
            memcpy(&(reply.handle), &(request.handle), sizeof(request.handle));

            pthread_mutex_lock(&dev->sock_lock);
            nbd_socket_write(sock, &reply, sizeof(struct nbd_reply));
            pthread_mutex_unlock(&dev->sock_lock);

            continue;
        }

        req = calloc(1, sizeof(struct nbd_handler_request));
        if (!req) {
            nbd_err("Failed to alloc memory for pool request!\n");
            ret = -1;
            goto err;
        }

        req->dev = dev;
        req->cmd = cmd;
        req->done = nbd_handle_request_done;
        req->offset = be64toh(request.from);
        req->flags = ntohl(request.type) & ~NBD_CMD_MASK_COMMAND;
        req->len = ntohl(request.len);
        memcpy(&(req->handle), &(request.handle), sizeof(request.handle));
        req->rwbuf = NULL;

        if(req->cmd == NBD_CMD_READ || req->cmd == NBD_CMD_WRITE) {
            req->rwbuf = malloc(req->len);
            if (!req->rwbuf) {
                nbd_err("Failed to alloc memory for data!\n");
                free(req);
                ret = -1;
                goto err;
            }
        }

        if(req->cmd == NBD_CMD_WRITE)
            nbd_socket_read(sock, req->rwbuf, req->len);

        req->io_start_time = g_get_monotonic_time();

        g_thread_pool_push(thread_pool, req, NULL);
    }

err:
    free(key);
    g_thread_pool_free(thread_pool, false, true);

    if (dev->retry_thread) {
        dev->stop_retry_thread = 1;
        g_thread_join(dev->retry_thread);
        dev->retry_thread = 0;
        dev->stop_retry_thread = 0;
    }

    /* After unmap, the status will be back to created */
    pthread_mutex_lock(&dev->lock);
    dev->status = NBD_DEV_CONN_ST_CREATED;
    pthread_mutex_unlock(&dev->lock);

    close(sock);
    return ret;
}

int rpc_nbd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
    xdr_free(xdr_result, result);

    return 1;
}

static void free_key(gpointer key)
{
    free(key);
}

static void free_value(gpointer value)
{
    struct nbd_device *dev = value;

    pthread_mutex_destroy(&dev->sock_lock);
    pthread_mutex_destroy(&dev->lock);
    pthread_mutex_destroy(&dev->retry_lock);
    free(dev);
}

static int nbd_register_handler(struct nbd_handler *handler)
{
    if (!handler) {
        nbd_err("handler is NULL!\n");
        return -1;
    }

    if (g_hash_table_lookup(nbd_handler_hash, &handler->subtype)) {
        nbd_err("handler %s is already registered!\n", handler->name);
        return -1;
    }

    g_hash_table_insert(nbd_handler_hash, &handler->subtype, handler);

    return 0;
}

static int is_handler(const struct dirent *dirent)
{
    char *p;

    p = strstr(dirent->d_name, "_handler.so");
    if (!p)
        return 0;

    if (strlen(p) == strlen("_handler.so")) {
        nbd_dbg("Find handler %s...\n", dirent->d_name);
        return 1;
    }

    return 0;
}

static int nbd_open_handlers(const struct nbd_config *cfg)
{
    struct nbd_handler *handler;
    struct dirent **dirent_list;
    int num_handlers;
    int num_good = 0;
    char *error;
    int i;

    nbd_dbg("Handler paths is %s\n", NBD_RUNNER_LIBDIR);
    num_handlers = scandir(NBD_RUNNER_LIBDIR, &dirent_list, is_handler, alphasort);

    nbd_info("num_handlers: %d\n", num_handlers);
    if (num_handlers == -1)
        return -1;

    for (i = 0; i < num_handlers; i++) {
        char *path;
        void *handle;
        handler_init_fn_t handler_init;
        int ret;

        ret = asprintf(&path, "%s/%s", NBD_RUNNER_LIBDIR, dirent_list[i]->d_name);
        if (ret == -1) {
            nbd_err("ENOMEM\n");
            continue;
        }

        handle = dlopen(path, RTLD_NOW|RTLD_LOCAL);
        if (!handle) {
            nbd_err("Could not open handler at %s: %s\n", path, dlerror());
            free(path);
            continue;
        }

        dlerror();
        handler_init = dlsym(handle, "handler_init");
        if ((error = dlerror())) {
            nbd_err("dlsym failure on %s: (%s)\n", path, error);
            free(path);
            continue;
        }

        handler = handler_init(cfg);
        if (!handler) {
            nbd_err("handler init failed on path %s\n", path);
            free(path);
            continue;
        }
        nbd_register_handler(handler);

        free(path);

        if (ret == 0)
            num_good++;
    }

    for (i = 0; i < num_handlers; i++)
        free(dirent_list[i]);
    free(dirent_list);

    return num_good;
}

static void free_handler(gpointer value)
{
    struct nbd_handler *handler = value;

    if (!handler && handler->destroy)
        handler->destroy();
}

bool nbd_service_init(struct nbd_config *cfg)
{
    GPtrArray *iohost = NULL;

    mkdir(NBD_SAVE_CONFIG_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    open(NBD_SAVE_CONFIG_FILE, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    nbd_handler_hash = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, free_handler);
    if (!nbd_handler_hash) {
        nbd_err("failed to create nbd_handler_hash hash table!\n");
        return false;
    }

    if (!cfg || !cfg->ihost[0]) {
        iohost = nbd_init_iohost(AF_INET);
        if (!iohost) {
            nbd_err("failed to parse the listen IP addr!\n");
            goto err;
        }

        ihost = strdup(g_ptr_array_index(iohost, 0));
        if (!ihost) {
            nbd_err("no memory for ihost!\n");
            goto err;
        }
        nbd_fini_iohost(iohost);
    } else {
        ihost = strdup(cfg->ihost);
        if (!ihost) {
            nbd_err("no memory for ihost!\n");
            goto err;
        }
    }

    nbd_open_handlers(cfg);

    nbd_devices_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
                                             free_value);
    if (!nbd_devices_hash) {
        nbd_err("failed to create nbd_devices_hash hash table!\n");
        goto err;
    }

    nbd_nbds_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
                                          NULL);
    if (!nbd_nbds_hash) {
        nbd_err("failed to create nbd_nbds_hash hash table!\n");
        goto err;
    }

    return !!nbd_parse_from_json_config_file();

err:
    nbd_fini_iohost(iohost);
    g_hash_table_destroy(nbd_handler_hash);
    g_hash_table_destroy(nbd_devices_hash);
    g_hash_table_destroy(nbd_nbds_hash);
    return false;
}

void nbd_service_fini(void)
{
    if (nbd_handler_hash)
        g_hash_table_destroy(nbd_handler_hash);

    if (nbd_devices_hash)
        g_hash_table_destroy(nbd_devices_hash);

    if (nbd_nbds_hash)
        g_hash_table_destroy(nbd_nbds_hash);
}
