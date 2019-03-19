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
#include "nbd-log.h"
#include "utils.h"
#include "nbd-common.h"
#include "nbd-sysconfig.h"

static GHashTable *nbd_handler_hash;
static GHashTable *nbd_devices_hash;
static GHashTable *nbd_nbds_hash;

static char *ihost;
int iport = NBD_MAP_SVC_PORT;

#define NBD_NL_VERSION 1

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

static char *nbd_get_hash_key(const char *cfgstring)
{
    char *sep;
    int len;

    if (strncmp(cfgstring, "key=", 4))
        return NULL;

    sep = strchr(cfgstring, ';');
    if (!sep)
        return strdup(cfgstring + 4);

    len = sep - cfgstring - 4;

    return strndup(cfgstring + 4, len);
}

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
                nbd_out("%s is already in the json conig file!\n", key);
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

    json_object_object_add(devobj, "type", json_object_new_int(dev->type));
    json_object_object_add(devobj, "nbd", json_object_new_string(dev->nbd));
    json_object_object_add(devobj, "maptime", json_object_new_string(dev->time));
    json_object_object_add(devobj, "size", json_object_new_int(dev->size));
    json_object_object_add(devobj, "blksize", json_object_new_int(dev->blksize));
    json_object_object_add(devobj, "readonly", json_object_new_boolean(dev->readonly));
    json_object_object_add(devobj, "prealloc", json_object_new_boolean(dev->prealloc));
    st = nbd_dev_status_lookup_str(dev->status);
    json_object_object_add(devobj, "status", json_object_new_string(st));

    json_object_object_add(globalobj, key, devobj);
    json_object_to_file_ext(NBD_SAVE_CONFIG_FILE, globalobj, JSON_C_TO_STRING_PRETTY);

    ret = 0;
err:
    json_object_put(globalobj);
    return ret;
}

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
            dev->type = json_object_get_int(obj);

            json_object_object_get_ex(devobj, "nbd", &obj);
            tmp = json_object_get_string(obj);
            if (tmp)
                strncpy(dev->nbd, tmp, NBD_DLEN_MAX);

            json_object_object_get_ex(devobj, "maptime", &obj);
            tmp = json_object_get_string(obj);
            if (tmp)
                strncpy(dev->time, tmp, NBD_TLEN_MAX);

            json_object_object_get_ex(devobj, "size", &obj);
            dev->size = json_object_get_int(obj);

            json_object_object_get_ex(devobj, "blksize", &obj);
            dev->blksize = json_object_get_int(obj);

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

            nbd_out("key: %s, type: %d, nbd: %s, maptime: %s, size: %ld, blksize: %ld, prealloc: %d, readonly: %d\n",
                    key, dev->type, dev->nbd, dev->time, dev->size, dev->blksize, dev->prealloc, dev->readonly);
            handler = g_hash_table_lookup(nbd_handler_hash, &dev->type);
            if (!handler) {
                nbd_err("handler type %d is not registered!\n", dev->type);
                free(dev);
            } else {
                dev->handler = handler;
                ktmp = malloc(NBD_CFGS_MAX);
                snprintf(ktmp, NBD_CFGS_MAX, "key=%s", key);
                handler->cfg_parse(dev, ktmp, NULL);
                free(ktmp);
                nbd_update_json_config_file(dev, true);
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

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &create->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %d!",
                 create->type);
        nbd_err("Invalid handler or the handler is not loaded: %d!",
                create->type);
        goto err;
    }

    key = nbd_get_hash_key(create->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "Invalid cfgstring %s!", create->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", create->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (dev) {
        rep->exit = -EEXIST;
        snprintf(rep->buf, NBD_EXIT_MAX, "%s is already exist!", create->cfgstring);
        nbd_err("%s is already exist!\n", create->cfgstring);
        free(key);
        goto err;
    }

    dev = calloc(1, sizeof(struct nbd_device));
    if (!dev) {
        rep->exit = -ENOMEM;
        snprintf(rep->buf, NBD_EXIT_MAX, "No memory for nbd_device!");
        nbd_err("No memory for nbd_device!\n");
        goto err;
    }

    if (!handler->cfg_parse(dev, create->cfgstring, rep)) {
        nbd_err("failed to parse cfgstring: %s\n", create->cfgstring);
        goto err;
    }

    pthread_mutex_init(&dev->sock_lock, NULL);
    pthread_mutex_init(&dev->lock, NULL);
    dev->type = create->type;
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
        goto err;
    }

    dev->blksize = handler->get_blksize(dev, NULL);
    if (dev->blksize < 0)
        goto err;

    strcpy(dev->bstore, key);

    nbd_update_json_config_file(dev, false);
    g_hash_table_insert(nbd_devices_hash, key, dev);

err:
    if (rep->exit && rep->exit != -EEXIST) {
        free(key);
        handler->delete(dev, rep);
        pthread_mutex_destroy(&dev->sock_lock);
        pthread_mutex_destroy(&dev->lock);
        free(dev);
    }
    return true;
}

bool_t nbd_delete_1_svc(nbd_delete *delete, nbd_response *rep,
                        struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &delete->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %d!",
                 delete->type);
        nbd_err("Invalid handler or the handler is not loaded: %d!",
                delete->type);
        goto err;
    }

    key = nbd_get_hash_key(delete->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "Invalid cfgstring %s!", delete->cfgstring);
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
        nbd_out("%s is not in the hash table, will try to delete enforce!\n",
                delete->cfgstring);
        dev = calloc(1, sizeof(struct nbd_device));
        if (!dev) {
            rep->exit = -ENOMEM;
            snprintf(rep->buf, NBD_EXIT_MAX, "No memory for nbd_device!");
            nbd_err("No memory for nbd_device!\n");
            goto err;
        }

        if (!handler->cfg_parse(dev, delete->cfgstring, rep)) {
            rep->exit = -EAGAIN;
            snprintf(rep->buf, NBD_EXIT_MAX, "failed to delete %s!", delete->cfgstring);
            nbd_err("failed to delete %s\n", delete->cfgstring);
            goto err;
        }

        dev->handler = handler;
        dev->status = NBD_DEV_CONN_ST_CREATED;
        handler->delete(dev, rep);
        goto err;
    }

    pthread_mutex_lock(&dev->lock);
    if (dev->status == NBD_DEV_CONN_ST_MAPPED) {
        rep->exit = -EPERM;
        snprintf(rep->buf, NBD_EXIT_MAX,
                 "Device %s is still mapped, please unmap it first!", key);
        nbd_err("Device %s is still mapped, please unmap it first!\n", key);
        pthread_mutex_unlock(&dev->lock);
        goto err;
    }

    handler->delete(dev, rep);

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

    rep->exit = 0;

    rep->buf = malloc(NBD_EXIT_MAX);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &map->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %d!",
                 map->type);
        nbd_err("Invalid handler or the handler is not loaded: %d!",
                map->type);
        goto err;
    }

    key = nbd_get_hash_key(map->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "Invalid cfgstring %s!", map->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", map->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (dev && dev->status == NBD_DEV_CONN_ST_MAPPED) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "%s already map to %s!", key, dev->nbd);
        nbd_err("%s already map to %s!\n", key, dev->nbd);
        goto err;
    }

    if (!dev) {
        /*
        * Since we allow to create the backstore directly
        * by using the backstore cli instead of the nbd-cli.
        * If so the device won't be insert to the hash table,
        * then we need to insert it here anyway.
        */
        nbd_out("%s is not in the hash table, will try to map enforce!\n",
                map->cfgstring);
        dev = calloc(1, sizeof(struct nbd_device));
        if (!dev) {
            rep->exit = -ENOMEM;
            snprintf(rep->buf, NBD_EXIT_MAX, "No memory for nbd_device!");
            nbd_err("No memory for nbd_device!\n");
            goto err;
        }

        if (!handler->cfg_parse(dev, map->cfgstring, rep)) {
            rep->exit = -EAGAIN;
            snprintf(rep->buf, NBD_EXIT_MAX, "failed to parse %s!", map->cfgstring);
            nbd_err("failed to parse %s\n", map->cfgstring);
            free(dev);
            goto err;
        }

        dev->status = NBD_DEV_CONN_ST_CREATED;
        dev->type = map->type;
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
        nbd_update_json_config_file(dev, false);
        g_hash_table_insert(nbd_devices_hash, key, dev);
        inserted = true;
    }

    pthread_mutex_lock(&dev->lock);
    if (!handler->map(dev, rep)) {
        pthread_mutex_unlock(&dev->lock);
        goto err;
    }

    rep->size = dev->size;
    rep->blksize = dev->blksize;
    pthread_mutex_unlock(&dev->lock);

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

    rep->exit = 0;

    rep->buf = calloc(1, NBD_EXIT_MAX);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    key = nbd_get_hash_key(cfg);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "Invalid cfgstring %s!", cfg);
        nbd_err("Invalid cfgstring %s!\n", cfg);
        return true;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (!dev) {
        rep->exit = -ENOENT;
        snprintf(rep->buf, NBD_EXIT_MAX, "Device is none exist!");
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

    rep->exit = 0;

    rep->buf = calloc(1, NBD_EXIT_MAX);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    if (!unmap->nbd[0]) {
        rep->exit = -EINVAL;
        snprintf(rep->buf, NBD_EXIT_MAX, "Invalid nbd device, it shouldn't be null!");
        nbd_err("Invalid nbd device, it shouldn't be null!\n");
        return true;
    }

    dev = g_hash_table_lookup(nbd_nbds_hash, unmap->nbd);
    if (!dev)
        return true;

    pthread_mutex_lock(&dev->lock);
    dev->status = NBD_DEV_CONN_ST_CREATED;
    dev->nbd[0] = '\0';
    dev->time[0] = '\0';
    nbd_update_json_config_file(dev, true);
    pthread_mutex_unlock(&dev->lock);

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

    rep->exit = 0;

    rep->buf = calloc(1, len);
    if (!rep->buf) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->buf!\n");
        return true;
    }

    globalobj = json_object_new_object();
    if (!globalobj) {
        rep->exit = -ENOMEM;
        snprintf(rep->buf, NBD_EXIT_MAX, "No memory for the gloablobj!");
        nbd_err("No memory for globalobj!\n");
        return true;
    }

    tmp = malloc(max);
    if (!tmp) {
        rep->exit = -ENOMEM;
        snprintf(rep->buf, NBD_EXIT_MAX, "No memory for the tmp buf!");
        nbd_err("No memory for tmp buf!\n");
        goto err;
    }

    g_hash_table_iter_init(&iter, nbd_devices_hash);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        dev = value;
        pthread_mutex_lock(&dev->lock);
        if (list->type != dev->type) {
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
        l += snprintf(tmp, max, "%d", dev->type) + 8;
        l += strlen(dev->time) + 13;
        l += snprintf(tmp, max, "%ld", dev->size) + 8;
        l += snprintf(tmp, max, "%ld", dev->blksize) + 11;
        l += 17;
        l += 17;
        st = nbd_dev_status_lookup_str(dev->status);
        l += strlen(st) + 11;
        l += 2;
        l += 128;  /* Add 128 extra more space */

        devobj = json_object_new_object();
        if (!devobj) {
            rep->exit = -ENOMEM;
            snprintf(rep->buf, NBD_EXIT_MAX, "No memory for the devobj!");
            nbd_err("No memory for devobj!\n");
            pthread_mutex_unlock(&dev->lock);
            goto err;
        }

        json_object_object_add(devobj, "type", json_object_new_int(dev->type));
        json_object_object_add(devobj, "nbd", json_object_new_string(dev->nbd));
        json_object_object_add(devobj, "maptime", json_object_new_string(dev->time));
        json_object_object_add(devobj, "size", json_object_new_int(dev->size));
        json_object_object_add(devobj, "blksize", json_object_new_int(dev->blksize));
        json_object_object_add(devobj, "readonly", json_object_new_boolean(dev->readonly));
        json_object_object_add(devobj, "prealloc", json_object_new_boolean(dev->prealloc));
        json_object_object_add(devobj, "status", json_object_new_string(st));
        pthread_mutex_unlock(&dev->lock);
        json_object_object_add(globalobj, key, devobj);
    }

    if (l > len) {
        out = realloc(rep->buf, l);
        if (!out) {
            rep->exit = -ENOMEM;
            snprintf(rep->buf, NBD_EXIT_MAX, "No memory for the list buffer!");
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

void nbd_handle_request_done(struct nbd_handler_request *req, int ret)
{
    struct nbd_reply reply;
    struct nbd_device *dev = req->dev;

    reply.magic = htonl(NBD_REPLY_MAGIC);
    reply.error = htonl(ret < 0 ? ret : 0);
    memcpy(&(reply.handle), &(req->handle), sizeof(req->handle));

    pthread_mutex_lock(&dev->sock_lock);
    nbd_socket_write(dev->sockfd, &reply, sizeof(struct nbd_reply));
    if(req->cmd == NBD_CMD_READ && !reply.error)
        nbd_socket_write(dev->sockfd, req->rwbuf, req->len);
    pthread_mutex_unlock(&dev->sock_lock);
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

    cfg = calloc(1, 4096);
    ret = nbd_socket_read(sock, cfg, nhdr.len);
    if (ret != nhdr.len) {
        ret = -1;
        goto err;
    }

    key = nbd_get_hash_key(cfg);
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

            printf("cmd : %d\n", cmd);
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

        g_thread_pool_push(thread_pool, req, NULL);
    }

err:
    free(key);
    g_thread_pool_free(thread_pool, false, true);
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
    free(dev);
}

bool nbd_service_init(struct nbd_config *cfg)
{
    GPtrArray *iohost = NULL;

    mkdir(NBD_SAVE_CONFIG_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    open(NBD_SAVE_CONFIG_FILE, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    nbd_handler_hash = g_hash_table_new(g_int_hash, g_int_equal);
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

    gluster_handler_init(cfg->ghost);

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

int nbd_register_handler(struct nbd_handler *handler)
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
