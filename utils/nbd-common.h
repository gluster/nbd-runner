/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.

  Part of this file copied from open-iscsi/tcmu-runner project.
*/

#ifndef __NBD_COMMON_H
#define __NBD_COMMON_H

#define _GNU_SOURCE

#include <stdint.h>
#include <glib.h>
#include <linux/limits.h>
#include <json-c/json.h>

#include "utils.h"
#include "nbd-sysconfig.h"

struct nbd_device {
    handler_t type;
    struct nbd_handler *handler;

    int sockfd;

    bool readonly;
    bool prealloc;
    ssize_t size;
    ssize_t blksize;

    /* To protect the nbd_device members */
    pthread_mutex_t lock;

    /* To make sure the socket is writen sequentially */
    pthread_mutex_t sock_lock;

    dev_status_t status;

    /*
     * The uniqe key string for each backstore
     *
     * For example for Gluster backstores, it will be
     * "volume/filepath"
     */
    char bstore[NBD_CFGS_MAX];

    /* e.g. "/dev/nbd14" */
    char nbd[NBD_DLEN_MAX];

    /* The mapped time, e.g. "2019-02-12 12:00:37" */
    char time[NBD_TLEN_MAX];

    /*
     * Private data pointer for each device
     *
     * This will also host the options parsed from
     * handler->cfg_parse() if there has.
     * */
    void *priv;
};

struct nbd_handler {
    const char *name;	/* Human-friendly name */
    handler_t subtype;     /* Type for matching */
    const char *cfgstring;	/* Handler specified cfgstring to setup the backstore */

    void *data;		/* Handler private data. */

    /*
     * Parse the device's private extra options and save it
     * into dev->priv, the cfgstring format will be like;
     *
     * "key=volume/filepath;dummy1=value1;dummy2;dummy3=value3;".
     *
     * Please fill the nbd_response if there has any errors
     */
    bool (*cfg_parse)(struct nbd_device *, const char *, nbd_response *);

    /*
     * Create the backstores.
     *
     * You can create the backstores by using the nbd-cli
     * tool, if you want to support the nbd-cli create option,
     * then you need add this support.
     *
     * NOTE:
     * Or you must use the utils privided by the backstore, and
     * when mapping the backstores, the map core code will add
     * the backstore info into the cache and backup json file.
     *
     * Please fill the nbd_response if there has any errors
     */
    bool (*create)(struct nbd_device *, nbd_response *);

    /*
     * Delete the backstores.
     *
     * You can delete the backstores by using the nbd-cli
     * tool, then you need add this support.
     *
     * NOTE:
     * Or you must use the utils privided by the backstore, and
     * the delete option in the core code will only delete the
     * backstore info from the cache and backup json file.
     *
     * Please fill the nbd_response if there has any errors
     */
    bool (*delete)(struct nbd_device *, nbd_response *);

    /*
     * Map the backstore storage to the NBD device.
     *
     * NOTE:
     * If the backstore is not created by using the 'nbd-cli create'
     * then the map core code will add the backstore info into
     * the cache and backup json file.
     *
     * Please fill the nbd_response if there has any errors
     */
    bool (*map)(struct nbd_device *, nbd_response *);

    /* Unmap the backstore storage from the NBD device. */
    bool (*unmap)(struct nbd_device *);

    /*
     * Get the backstore size
     *
     * Please fill the nbd_response if there has any errors
     */
    ssize_t (*get_size)(struct nbd_device *, nbd_response *);

    /*
     * Get the optiomal block size from the handler,
     * if no please return 0.
     *
     * Please fill the nbd_response if there has any errors
     */
    ssize_t (*get_blksize)(struct nbd_device *, nbd_response *);

    /*
     * Handle the IO requests from the NBD device socket.
     *
     * Curently we will only use the first parameter
     */
    void (*handle_request)(gpointer, gpointer);

    /*
     * Update the private extra options to the json file.
     *
     * For string type options please do it like:
     * json_object_object_add(devobj, "dummy1", json_object_new_string(dev->priv->dummy1));
     *
     * For int type options please do it like:
     * json_object_object_add(devobj, "dummy2", json_object_new_int64(dev->priv->dummy2));
     *
     * For boolean type options please do it like:
     * json_object_object_add(devobj, "dummy3", json_object_new_boolean(dev->priv->dummy3));
     */
    bool (*update_json)(struct nbd_device *dev, json_object *devobj);

    /*
     * Load the cfgstring and private extra options from the json file
     *
     * For string type options please do it like:
     * json_object *obj;
     * char *tmp;
     * priv = malloc();
     * dev->priv = priv;
     *
     * json_object_object_get_ex(devobj, "dummy1", &obj);
     * tmp = json_object_get_string(obj);
     * if (tmp)
     *    strlcpy(dev->priv->dummy1, tmp, NBD_DLEN_MAX);
     *
     * For int type options please do it like:
     * json_object_object_get_ex(devobj, "dummy2", &obj);
     * dev->priv->dummy2 = json_object_get_int64(obj);
     *
     * For boolean type options please do it like:
     * json_object_object_get_ex(devobj, "dummy3", &obj);
     * dev->priv->dummy3 = json_object_get_boolean(obj);
     *
     * NOTE: the third parameter is the hash key parsed from the cfgsting
     * when creating or mapping the backstore, for example for Gluster
     * handler, it will be:
     *   "key=myvolume/myfilepath"
     *
     * If needed please parse the key to the priv too.
     */
    bool (*load_json)(struct nbd_device *dev, json_object *devobj, char *key);

    void (*destroy)(void);
};

struct nbd_handler_request;

typedef void (*nbd_callback_fn)(struct nbd_handler_request *, int);

struct nbd_handler_request {
    unsigned int cmd;
    ssize_t offset;
    ssize_t len;
    int flags;
    char handle[8];

    struct nbd_device *dev;

    nbd_callback_fn done;

    void *rwbuf;
};

/*
 * For each handler library's entry point must be named "handler_init".
 *
 * And the handler library name must be "libXXX_handler.so"
 */
typedef struct nbd_handler *(*handler_init_fn_t)(const struct nbd_config *);

#endif /* __NBD_COMMON_H */
