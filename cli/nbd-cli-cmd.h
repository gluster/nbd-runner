/*
   Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
   This file is part of nbd-runner.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __NBD_CLI_CMD_H__
#define __NBD_CLI_CMD_H__

#include <glib.h>
#include <gmodule.h>

enum {
    NBD_CLI_HELP,
    NBD_CLI_CREATE,
    NBD_CLI_DELETE,
    NBD_CLI_MAP,
    NBD_CLI_UNMAP,
    NBD_CLI_LIST,

    NBD_CLI_MAX
};

typedef int (*cli_cmd_call_t)(int, char **);

struct cli_cmd {
    const char *pattern;
    cli_cmd_call_t call;
    const char *desc;
    bool disable;
};

/* Register the cli cmds */
int nbd_register_cmds(GHashTable *cmds_hash, struct cli_cmd *cmds);

/* Register/unregister all the backstores */
GHashTable *nbd_register_backstores(void);
void nbd_unregister_backstores(GHashTable *cmds_hash);

/* This is used to register the gluster backstore */
int cli_cmd_gluster_register(GHashTable *cmds_hash);

int nbd_create_backstore(int count, char **options, int type);
int nbd_delete_backstore(int count, char **options, int type);
int nbd_map_device(int count, char **options, int type);
int nbd_unmap_device(int count, char **options, int type);
int nbd_list_devices(int count, char **options, int type);
#endif /* __CLI_CMD_H__ */
