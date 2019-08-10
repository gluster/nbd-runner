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
#include "nbd-cli-common.h"

struct cli_cmd azblk_cmds[] = {
    {.pattern = "help",
     .cmd     = NBD_CLI_HELP,
     .desc    = "Display help for azblk commands",
    },
    {.pattern = "create <'account.blob.core.windows.net/container/vhd[;option1][;option2']> [prealloc] <size SIZE> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_CREATE,
     .desc    = "Create the vhd file in your storage account container, prealloc is false as default, and the SIZE is valid\n\t\twith B, K(iB), M(iB), G(iB), T(iB), RUNNER_HOST will be 'localhost' as default\n\n\t\tValid options:\n\t\tsas=SAS_STRING\n\t\tlease=LEASE_ID\n\t\thttp https is the default",
    },
    {.pattern = "delete <account.blob.core.windows.net/container/vhd> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_DELETE,
     .desc    = "Delete the vhd file from your storage account container, RUNNER_HOST will be 'localhost' as default.\n\t\tWARNING: Deleting the vhd file will also remove all of it's snapshots.",
    },
    {.pattern = "map <account.blob.core.windows.net/container/vhd> [nbd-device] [timeout TIME] [readonly] [host RUNNER_HOST]",
     .cmd     = NBD_CLI_MAP,
     .desc    = "Map the vhd to the nbd device, as default the socket connection timeout is 30 seconds,\n\t\t none readonly, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "unmap <nbd-device|<account.blob.core.windows.net/container/vhd> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_UNMAP,
     .desc    = "Unmap the nbd device or account/container/vhd, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "list [map|unmap|create|dead|live|all] [host RUNNER_HOST]",
     .cmd     = NBD_CLI_LIST,
     .desc    = "List the mapped|unmapped NBD devices or the created|dead|live backstores, all as\n\t\tdefault. 'create' means the backstores are just created or unmapped. 'dead' means\n\t\tthe IO connection is lost, this is mainly due to the nbd-runner service is restart\n\t\twithout unmapping. 'live' means everything is okay for both mapped and IO connection,\n\t\tRUNNER_HOST will be 'localhost' as default"
    },
    {.pattern = NULL,
     .cmd     = NBD_CLI_MAX,
     .desc    = NULL,
    },
};

int cli_cmd_azblk_register(GPtrArray *cmds_list, cmd_fn_t fn)
{
    return fn(cmds_list, azblk_cmds);
}
