/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.

  Part of this file copied from open-iscsi/tcmu-runner project.
*/

#ifndef __NBD_HANDLER_H
#define __NBD_HANDLER_H

#define _GNU_SOURCE

#include <stdint.h>
#include <glib.h>
#include <linux/limits.h>

#include "rpc_nbd.h"
#include "utils/utils.h"

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

    char bstore[NBD_CFGS_MAX];
    char nbd[NBD_DLEN_MAX]; /* e.g. "/dev/nbd14" */
    char time[NBD_TLEN_MAX]; /* e.g. "2019-02-12 12:00:37" */

    void *priv; /* private ptr for handler module */
};

struct nbd_handler {
    const char *name;	/* Human-friendly name */
    handler_t subtype;     /* Type for matching */
    const char *cfgstring;	/* Handler specified cfgstring to setup the backstore */

    void *data;		/* Handler private data. */

    bool (*cfg_parse)(struct nbd_device *, const char *, nbd_response *);
    bool (*create)(struct nbd_device *, nbd_response *);
    bool (*delete)(struct nbd_device *, nbd_response *);
    bool (*map)(struct nbd_device *, nbd_response *);
    bool (*unmap)(struct nbd_device *);
    ssize_t (*get_size)(struct nbd_device *, nbd_response *);
    ssize_t (*get_blksize)(struct nbd_device *, nbd_response *);
    void (*handle_request)(gpointer, gpointer);
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

int nbd_register_handler(struct nbd_handler *handler);
int gluster_handler_init(const char *host);
bool nbd_service_init(struct nbd_config *cfg);
void nbd_service_fini(void);

#endif /* __NBD_HANDLER_H */
