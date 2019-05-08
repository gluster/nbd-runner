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
#include <stdint.h>
#include <stdlib.h>

#include "rpc_nbd.h"
#include "utils/utils.h"
#include "nbd-log.h"
#include "nbd-cli-cmd.h"

struct cli_cmd azblk_cmds[];

static int azblk_help_routine(int count, char **options)
{
    int i;

    nbd_info("Usage: \n\n");
    for (i = 0; azblk_cmds[i].pattern; i++) {
        if (azblk_cmds[i].disable)
            continue;

        nbd_info("\t%s\n", azblk_cmds[i].pattern);
        nbd_info("\t\t%s\n\n", azblk_cmds[i].desc);
    }
    nbd_info("\n");

    return 0;
}

static int azblk_create_routine(int count, char **options)
{
    return nbd_create_backstore(count, options, NBD_BACKSTORE_AZBLK);
}

static int azblk_delete_routine(int count, char **options)
{
    return nbd_delete_backstore(count, options, NBD_BACKSTORE_AZBLK);
}

static int azblk_map_routine(int count, char **options)
{
    return nbd_map_device(count, options, NBD_BACKSTORE_AZBLK);
}

static int azblk_unmap_routine(int count, char **options)
{
    return nbd_unmap_device(count, options, NBD_BACKSTORE_AZBLK);
}

static int azblk_list_routine(int count, char **options)
{
    return nbd_list_devices(count, options, NBD_BACKSTORE_AZBLK);
}


struct cli_cmd azblk_cmds[] = {
    {.pattern = "azblk",
     .call    = azblk_help_routine,
     .desc    = "Display help for azblk commands",
     .disable = true,
    },
    {.pattern = "azblk help",
     .call    = azblk_help_routine,
     .desc    = "Display help for azblk commands",
    },
    {.pattern = "azblk create <'account.blob.core.windows.net/container/vhd[;option1][;option2']> [prealloc] <size SIZE> [host RUNNER_HOST]",
     .call    = azblk_create_routine,
     .desc    = "Create the vhd file in your storage account container, prealloc is false as default, and the SIZE is valid\n\t\twith B, K(iB), M(iB), G(iB), T(iB), RUNNER_HOST will be 'localhost' as default\n\n\t\tValid options:\n\t\tsas=SAS_STRING\n\t\tlease=LEASE_ID\n\t\thttp https is the default",
    },
    {.pattern = "azblk delete <account.blob.core.windows.net/container/vhd> [host RUNNER_HOST]",
     .call    = azblk_delete_routine,
     .desc    = "Delete the vhd file from your storage account container, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "azblk map <account.blob.core.windows.net/container/vhd> [nbd-device] [timeout TIME] [readonly] [host RUNNER_HOST]",
     .call    = azblk_map_routine,
     .desc    = "Map the vhd to the nbd device, as default the timeout 0, none readonly, RUNNER_HOST\n\t\twill be 'localhost' as default",
    },
    {.pattern = "azblk unmap <nbd-device|<account.blob.core.windows.net/container/vhd> [host RUNNER_HOST]",
     .call    = azblk_unmap_routine,
     .desc    = "Unmap the nbd device or VOLUME/FILEPATH, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "azblk list [map|unmap|create|dead|live|all] [host RUNNER_HOST]",
     .call    = azblk_list_routine,
     .desc    = "List the mapped|unmapped NBD devices or the created|dead|live backstores, all as\n\t\tdefault. 'create' means the backstores are just created or unmapped. 'dead' means\n\t\tthe IO connection is lost, this is mainly due to the nbd-runner service is restart\n\t\twithout unmapping. 'live' means everything is okay for both mapped and IO connection,\n\t\tRUNNER_HOST will be 'localhost' as default"
    },
    {.pattern = NULL,
     .call    = NULL,
     .desc    = NULL,
    },
};

int cli_cmd_azblk_register(GHashTable *cmds_hash)
{
    return nbd_register_cmds(cmds_hash, azblk_cmds);
}
