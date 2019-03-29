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

#include "utils.h"
#include "nbd-log.h"
#include "list.h"

static pthread_mutex_t lru_lock = PTHREAD_MUTEX_INITIALIZER;

#define NBD_LRU_MIN 8

struct nbd_lru_priv {
    char *key;
    void *data;
    struct nbd_lru *lru;
    nbd_timer_t timer;

    struct list_head list;
};

static void free_key(gpointer key)
{
    free(key);
}

static void free_value(gpointer value)
{
    struct nbd_lru_priv *priv = value;
    struct nbd_lru *lru = priv->lru;

    if (lru->timeout)
        nbd_del_timer(&priv->timer);

    if (lru->release && lru->release(priv->data)) {
        list_del(&priv->list);
        free(priv);
        lru->lru_cnt--;
    }
}

static void nbd_timer_cbk(nbd_timer_t *timer)
{
    struct nbd_lru_priv *priv = container_of(timer, struct nbd_lru_priv, timer);

    pthread_mutex_lock(&lru_lock);
    priv->lru->lru_cnt--;
    list_del(&priv->list);
    g_hash_table_remove(priv->lru->hash, priv->key);
    pthread_mutex_unlock(&lru_lock);
}

/*
 * lru_max: the max count of entries will be hosted in LRU cache
 * timeout: all the entries will time out after 'timeout' seconds.
 * fn: call back to release the user specified LRU entries
 */
struct nbd_lru *nbd_lru_init(int lru_max, int timeout, lru_release_t fn)
{
    struct nbd_lru *lru;

    lru = calloc(1, sizeof(struct nbd_lru));
    if (!lru) {
        nbd_err("failed to calloc for lru!\n");
        return NULL;
    }

    lru->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free_key,
                                      free_value);
    if (!lru->hash) {
        nbd_err("failed to create lru hash table!\n");
        goto err;
    }

	INIT_LIST_HEAD(&lru->head);

    if (lru_max < NBD_LRU_MIN) {
        nbd_warn("lru_max is %d and will set it to NBD_LRU_MIN %d\n", lru_max,
                 NBD_LRU_MIN);
        lru_max = NBD_LRU_MIN;
    }

    lru->release = fn;
    lru->lru_max = lru_max;
    lru->timeout = timeout;

    return lru;
err:
    free(lru);
    return NULL;
}

void nbd_lru_fini(struct nbd_lru *lru)
{
    if (!lru)
        return;

    g_hash_table_destroy(lru->hash);

    free(lru);
}

void *nbd_lru_get(struct nbd_lru *lru, char *key)
{
    struct nbd_lru_priv *priv;

    if (!lru || !key) {
        nbd_err("Invalid lru or data!\n");
        return NULL;
    }

    pthread_mutex_lock(&lru_lock);
    priv = g_hash_table_lookup(lru->hash, key);
    if (!priv) {
        pthread_mutex_unlock(&lru_lock);
        return NULL;
    }

    if (lru->timeout)
        nbd_reset_timer(&priv->timer);

    list_move_tail(&priv->list, &priv->lru->head);
    pthread_mutex_unlock(&lru_lock);

    return priv->data;
}

/*
 * key: please release the 'key' memory manually after update done
 * data: we will host this and will release via lru_release_t call back
 *
 */
int nbd_lru_update(struct nbd_lru *lru, char *key, void *data)
{
    struct nbd_lru_priv *priv;
    int ret;

    if (!lru || !key || !data) {
        nbd_err("Invalid lru, key or data!\n");
        return -EINVAL;
    }

    pthread_mutex_lock(&lru_lock);
    if (g_hash_table_lookup(lru->hash, key)) {
        nbd_warn("%s is already in the lru, do nothing!\n", key);
        ret = 0;
        goto unlock;
    }

    priv = calloc(1, sizeof(struct nbd_lru_priv));
    if (!priv) {
        nbd_err("No memory for nbd_lru_priv!\n");
        ret = -ENOMEM;
        goto unlock;
    }

    priv->key = strdup(key);
    priv->data = data;
    priv->lru = lru;
    INIT_LIST_HEAD(&priv->list);

    if (lru->timeout)
        nbd_init_timer(&priv->timer, lru->timeout * 1000, 0, nbd_timer_cbk);

    g_hash_table_insert(lru->hash, priv->key, priv);

    list_add_tail(&priv->list, &lru->head);

    if (lru->timeout)
        nbd_add_timer(&priv->timer);

    lru->lru_cnt++;

    if (lru->lru_cnt + 1 > lru->lru_max) {
        priv = list_first_entry(&lru->head, struct nbd_lru_priv, list);

        if (lru->release && lru->release(priv->data))
            g_hash_table_remove(lru->hash, priv->key);
        else
            nbd_warn("release private data failed and the lru entries(%d) will exceed the lru_max(%d)!",
                     lru->lru_cnt, lru->lru_max);
    }

    ret = 0;

unlock:
    pthread_mutex_unlock(&lru_lock);

    return ret;
}
