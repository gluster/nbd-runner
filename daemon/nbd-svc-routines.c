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
#include <glib.h>
#include <gmodule.h>

#include "rpc_nbd.h"
#include "nbd-log.h"
#include "utils.h"
#include "nbd-common.h"

extern char *listen_host;
GHashTable *nbd_handler_hash;
GHashTable *nbd_devices_hash;

#define NBD_NL_VERSION 1

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

bool_t nbd_create_1_svc(nbd_create *create, nbd_response *rep,
                        struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;

    rep->exit = 0;

    rep->out = malloc(NBD_EXIT_MAX);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &create->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %s!",
                 create->type);
        nbd_err("Invalid handler or the handler is not loaded: %s!", create->type);
        goto err;
    }

    key = nbd_get_hash_key(create->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Invalid cfgstring %s!", create->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", create->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (dev) {
        rep->exit = -EEXIST;
        snprintf(rep->out, NBD_EXIT_MAX, "%s is already exist!", create->cfgstring);
        nbd_err("%s is already exist!\n", create->cfgstring);
        free(key);
        goto err;
    }

    dev = handler->cfg_parse(create->cfgstring, rep);
    if (!dev) {
        nbd_err("failed to parse cfgstring: %s\n", create->cfgstring);
        free(key);
        goto err;
    }

    dev->handler = handler;

    /*
     * Since we allow to create the backstore directly
     * by using the backstore cli instead of the nbd-cli.
     * If so the device won't be insert to the hash table,
     * then we need to insert it here anyway.
     */
    if (!handler->create(dev, rep) && rep->exit != -EEXIST) {
        nbd_err("failed to create backstore: %s\n", create->cfgstring);
        handler->delete(dev, rep);
        free(key);
        goto err;
    }

    g_hash_table_insert(nbd_devices_hash, key, dev);

err:
    return true;
}

bool_t nbd_delete_1_svc(nbd_delete *delete, nbd_response *rep,
                        struct svc_req *req)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;

    rep->exit = 0;

    rep->out = malloc(NBD_EXIT_MAX);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &delete->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %s!",
                 delete->type);
        nbd_err("Invalid handler or the handler is not loaded: %s!", delete->type);
        goto err;
    }

    key = nbd_get_hash_key(delete->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Invalid cfgstring %s!", delete->cfgstring);
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
        dev = handler->cfg_parse(delete->cfgstring, rep);
        if (!dev) {
            rep->exit = -EAGAIN;
            snprintf(rep->out, NBD_EXIT_MAX, "failed to delete %s!", delete->cfgstring);
            nbd_err("failed to delete %s\n", delete->cfgstring);
            goto err;
        }
        dev->handler = handler;
    } else {
        g_hash_table_remove(nbd_devices_hash, key);
    }

    handler->delete(dev, rep);

err:
    free(key);
    return true;
}

bool_t nbd_map_1_svc(nbd_map *map, nbd_response *rep, struct svc_req *req)
{
    struct nbd_ip *ips = NULL, *p, *q;
    struct nbd_device *dev = NULL;
    struct nbd_handler *handler;
    char *key = NULL;
    bool need_to_insert = false;

    rep->exit = 0;

    rep->out = malloc(NBD_EXIT_MAX);
    if (!rep->out) {
        rep->exit = -ENOMEM;
        nbd_err("No memory for rep->out!\n");
        return false;
    }

    handler = g_hash_table_lookup(nbd_handler_hash, &map->type);
    if (!handler) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX,
                 "Invalid handler or the handler is not loaded: %s!",
                 map->type);
        nbd_err("Invalid handler or the handler is not loaded: %s!", map->type);
        goto err;
    }

    key = nbd_get_hash_key(map->cfgstring);
    if (!key) {
        rep->exit = -EINVAL;
        snprintf(rep->out, NBD_EXIT_MAX, "Invalid cfgstring %s!", map->cfgstring);
        nbd_err("Invalid cfgstring %s!\n", map->cfgstring);
        goto err;
    }

    dev = g_hash_table_lookup(nbd_devices_hash, key);
    if (!dev) {
        /*
        * Since we allow to create the backstore directly
        * by using the backstore cli instead of the nbd-cli.
        * If so the device won't be insert to the hash table,
        * then we need to insert it here anyway.
        */
        need_to_insert = true;
        nbd_out("%s is not in the hash table, will try to map enforce!\n",
                map->cfgstring);
        dev = handler->cfg_parse(map->cfgstring, rep);
        if (!dev) {
            rep->exit = -EAGAIN;
            snprintf(rep->out, NBD_EXIT_MAX, "failed to map %s!", map->cfgstring);
            nbd_err("failed to map %s\n", map->cfgstring);
            free(key);
            goto err;
        }
        dev->handler = handler;
    }

    if (!handler->map(dev, rep)) {
        free(key);
        goto err;
    }

    rep->size = dev->size;
    rep->blksize = dev->blksize;
    if (need_to_insert)
        g_hash_table_insert(nbd_devices_hash, key, dev);

    if (listen_host) {
        snprintf(rep->host, NBD_HOST_MAX, "%s", listen_host);
    } else {
        ips = nbd_get_local_ips();
        if (!ips) {
            rep->exit = -EINVAL;
            snprintf(rep->out, NBD_EXIT_MAX, "failed to parse the listen IP addr!");
            nbd_err("failed to parse the listen IP addr!\n");
            goto err;
        }

        p = ips;
        while (p) {
            if (strcmp(p->ip, "127.0.0.1"))
                break;

            p = p->next;
        }

        if (!p) {
            rep->exit = -EINVAL;
            snprintf(rep->out, NBD_EXIT_MAX, "failed to check the listen IP addr!");
            nbd_err("failed to check the listen IP addr!\n");
            goto err;
        }
        snprintf(rep->host, NBD_HOST_MAX, "%s", p);
    }
    snprintf(rep->port, NBD_PORT_MAX, "%d", NBD_IOS_SVC_PORT);

err:
    for (q = ips; q; q = p) {
        p = q->next;
        free(q);
    }
    return true;
}

void nbd_handle_request_done(struct nbd_handler_request *req, int ret)
{
    struct nbd_reply reply;
    struct nbd_device *dev = req->dev;

    reply.magic = htonl(NBD_REPLY_MAGIC);
    reply.error = htonl(ret < 0 ? ret : 0);
    memcpy(&(reply.handle), &(req->handle), sizeof(req->handle));

    pthread_mutex_lock(&dev->handler->lock);
    nbd_socket_write(dev->sockfd, &reply, sizeof(struct nbd_reply));
    if(req->cmd == NBD_CMD_READ && !reply.error)
        nbd_socket_write(dev->sockfd, req->rwbuf, req->len);
    pthread_mutex_unlock(&dev->handler->lock);
}

int nbd_handle_request(int sock, int threads)
{
    struct nbd_device *dev = NULL;
    struct nbd_handler_request *req;
    struct nbd_request request;
    struct nbd_reply reply;
    GThreadPool *thread_pool;
    int ret = -1;
    struct sigaction sa;
    struct nego_request nhdr;
    struct nego_reply nrep = {0, };
    bool readonly = false;
    char *cfg = NULL;
    char *buf = NULL;
    char *key = NULL;
    int cmd;

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
        nrep.len = snprintf(buf, 4096, "No such device found: %s", cfg);
        if (nrep.len < 0)
            nrep.len = 0;
    }
    free(cfg);
    free(buf);
    free(key);

    pthread_mutex_lock(&dev->handler->lock);
    nbd_socket_write(sock, &nrep, sizeof(struct nego_reply));
    if (nrep.len && buf)
        nbd_socket_write(sock, buf, nrep.len);
    pthread_mutex_unlock(&dev->handler->lock);
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
            nbd_dbg("Unmap request received!\n");
            dev->handler->unmap(dev);
            ret = 0;
            goto err;
        }

        cmd = ntohl(request.type) & NBD_CMD_MASK_COMMAND;
        if (dev->readonly && cmd != NBD_CMD_READ && cmd != NBD_CMD_FLUSH) {
            reply.magic = htonl(NBD_REPLY_MAGIC);
            reply.error = htonl(EROFS);
            memcpy(&(reply.handle), &(request.handle), sizeof(request.handle));

            pthread_mutex_lock(&dev->handler->lock);
            nbd_socket_write(sock, &reply, sizeof(struct nbd_reply));
            pthread_mutex_unlock(&dev->handler->lock);

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
    g_thread_pool_free(thread_pool, false, true);
    close(sock);
    return ret;
}

int rpc_nbd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
    xdr_free(xdr_result, result);

    return 1;
}

void free_key(gpointer key)
{
    free(key);
}

bool nbd_service_init(void)
{
    nbd_handler_hash = g_hash_table_new(g_int_hash, g_int_equal);
    if (!nbd_handler_hash) {
        nbd_err("failed to create nbd_handler_hash hash table!\n");
        return false;
    }

    nbd_devices_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
                                             NULL);
    if (!nbd_devices_hash) {
        nbd_err("failed to create nbd_devices_hash hash table!\n");
        return false;
    }
}

void nbd_service_fini(void)
{
    g_hash_table_destroy(nbd_handler_hash);
    g_hash_table_destroy(nbd_devices_hash);
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
