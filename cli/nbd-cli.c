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
#include <errno.h>
#include <libkmod.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "rpc_nbd.h"
#include "utils.h"
#include "nbd-log.h"
#include "nbd-cli-cmd.h"
#include "config.h"

static void usage(void)
{
    nbd_info("Usage:\n\n"
             "\tgluster help\n\t\tDisplay help for gluster commands\n\n"
             "\tceph help [TODO]\n\t\tDisplay help for ceph commands\n\n"
             "\tglobal help [TODO]\n\t\tDisplay help for global commands\n\n"
             "\tversion\n\t\tDisplay the version of nbd-cli\n\n"
            );
}

typedef enum {
    NBD_OPT_HELP,
    NBD_OPT_VERSION,

    NBD_OPT_MAX
} nbd_opt_command;

static const char *const nbd_opt_commands[] = {
    [NBD_OPT_HELP]           = "help",
    [NBD_OPT_VERSION]        = "version",

    [NBD_OPT_MAX]            = NULL,
};

static int nbd_command_lookup(const char *command)
{
    int i;

    if (!command)
        return NBD_OPT_MAX;

    for (i = 0; i < NBD_OPT_MAX; i++) {
        if (!strcmp(nbd_opt_commands[i], command))
            return i;
    }

    return NBD_OPT_MAX;
}

static int load_our_module(void)
{
    struct kmod_list *list = NULL, *itr;
    struct kmod_ctx *ctx;
    struct stat sb;
    struct utsname u;
    int ret;

    ctx = kmod_new(NULL, NULL);
    if (!ctx) {
        nbd_err("kmod_new() failed: %m\n");
        return -1;
    }

    ret = kmod_module_new_from_lookup(ctx, "nbd", &list);
    if (ret < 0) {
        /* In some environments like containers, /lib/modules/`uname -r`
         * will not exist, in such cases the load module job be taken
         * care by admin, either by manual load or makesure it's builtin
         */
        if (ENOENT == errno) {
            if (uname(&u) < 0) {
                nbd_err("uname() failed: %m\n");
            } else {
                nbd_info("no modules dir '/lib/modules/%s', checking in '/sys/modules/'\n",
                        u.release);
                ret = stat(CFGFS_NBD_MOD, &sb);
                if (ret) {
                    nbd_err("stat() on '%s' failed: %m\n", CFGFS_NBD_MOD);
                } else {
                    nbd_info("Module nbd already loaded\n");
                }
            }
        } else {
            nbd_err("kmod_module_new_from_lookup() failed to lookup alias nbd %m\n");
        }

        kmod_unref(ctx);
        return ret;
    }

    if (!list) {
        nbd_err("kmod_module_new_from_lookup() failed to find module nbd\n");
        kmod_unref(ctx);
        return -1;
    }

    kmod_list_foreach(itr, list) {
        int state, err;
        struct kmod_module *mod = kmod_module_get_module(itr);

        state = kmod_module_get_initstate(mod);
        switch (state) {
        case KMOD_MODULE_BUILTIN:
            nbd_dbg("Module '%s' is builtin\n", kmod_module_get_name(mod));
            break;

        case KMOD_MODULE_LIVE:
            nbd_dbg("Module '%s' is already loaded\n", kmod_module_get_name(mod));
            break;

        default:
            err = kmod_module_probe_insert_module(mod,
                    KMOD_PROBE_APPLY_BLACKLIST,
                    NULL, NULL, NULL, NULL);

            if (err == 0) {
                nbd_info("Inserted module '%s'\n", kmod_module_get_name(mod));
            } else if (err < 0) {
                nbd_err("Failed to insert '%s': %s\n",
                        kmod_module_get_name(mod), strerror(-err));
                ret = -1;
            } else {
                switch (err) {
                    case KMOD_PROBE_APPLY_BLACKLIST:
                        nbd_err("Module '%s' is blacklisted\n",
                                kmod_module_get_name(mod));
                        break;
                    default:
                        nbd_err("Module '%s' is stopped by a reason: 0x%x\n",
                                kmod_module_get_name(mod), err);
                        break;
                }
                ret = -1;
            }
        }
        kmod_module_unref(mod);
    }

    kmod_module_unref_list(list);
    kmod_unref(ctx);

    return ret;
}

int main(int argc, char *argv[])
{
    GHashTable *cmds_hash = NULL;
    nbd_opt_command cmd;
    struct cli_cmd *clicmd;
    int ret = EXIT_FAILURE;
    char *key = NULL;
    int len;

    if (argc == 1) {
        usage();
        ret = EXIT_SUCCESS;
        goto out;
    }

    if (argc == 2) {
        cmd = nbd_command_lookup(argv[1]);

        ret = EXIT_SUCCESS;
        switch(cmd) {
        case NBD_OPT_HELP:
            usage();
            goto out;
        case NBD_OPT_VERSION:
            nbd_info("nbd-cli (%s)\n\n", VERSION);
            nbd_info("%s\n", NBD_LICENSE_INFO);
            goto out;
        case NBD_OPT_MAX:
        default:
            break;
        }
    }

    if (!nbd_minimal_kernel_version_check())
        goto out;

    if (load_our_module() < 0)
        goto out;

    cmds_hash = nbd_register_backstores();
    if (!cmds_hash) {
        nbd_err("No command registered!\n");
        goto out;
    }

    key = calloc(1, 1024);
    if (!key) {
        nbd_err("No memory for key!\n");
        goto out;
    }

    /* The hash key will be "backstore_type cmd" */
    len = snprintf(key, 1024, "%s", argv[1]);
    if (argc > 2)
        snprintf(key + len, 1024 - len, " %s", argv[2]);

    clicmd = g_hash_table_lookup(cmds_hash, key);
    if (!clicmd) {
        nbd_err("Invalid command: %s\n", key);
        goto out;
    }

    if (clicmd->call(argc - 3, argc > 3 ? argv + 3 : NULL) < 0)
        goto out;

    ret = EXIT_SUCCESS;
out:
    free(key);
    nbd_unregister_backstores(cmds_hash);
    exit(ret);
}
