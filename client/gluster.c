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

struct cli_cmd gluster_cmds[] = {
    {.pattern = "help",
     .cmd     = NBD_CLI_HELP,
     .desc    = "Display help for gluster commands",
    },
    {.pattern = "create <VOLUME/FILEPATH> [prealloc] <size SIZE> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_CREATE,
     .desc    = "Create FILEPATH in the VOLUME, prealloc is false as default, and the SIZE is valid\n\t\twith B, K(iB), M(iB), G(iB), T(iB), P(iB), E(iB), Z(iB), Y(iB), RUNNER_HOST will\n\t\tbe 'localhost' as default",
    },
    {.pattern = "delete <VOLUME/FILEPATH> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_DELETE,
     .desc    = "Delete FILEPATH from the VOLUME, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "map <VOLUME/FILEPATH> [nbd-device] [timeout TIME] [readonly] [host RUNNER_HOST]",
     .cmd     = NBD_CLI_MAP,
     .desc    = "Map FILEPATH to the nbd device, as default the socket connection timeout is 30 seconds,\n\t\tnone readonly, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "unmap <nbd-device|VOLUME/FILEPATH> [host RUNNER_HOST]",
     .cmd     = NBD_CLI_UNMAP,
     .desc    = "Unmap the nbd device or VOLUME/FILEPATH, RUNNER_HOST will be 'localhost' as default",
    },
    {.pattern = "list [inuse|free|create|dead|live|all] [host RUNNER_HOST]",
     .cmd     = NBD_CLI_LIST,
     .desc    = "List the inused|free NBD devices or the created|dead|live backstores, all as\n\t\tdefault. 'create' means the backstores are just created or unmapped. 'dead' means\n\t\tthe IO connection is lost, this is mainly due to the nbd-runner service is restart\n\t\twithout unmapping. 'live' means everything is okay for both mapped and IO connection,\n\t\tRUNNER_HOST will be 'localhost' as default"
    },
    {.pattern = NULL,
     .cmd     = NBD_CLI_MAX,
     .desc    = NULL,
    },
};

int cli_cmd_gluster_register(GPtrArray *cmds_list, cmd_fn_t fn)
{
    return fn(cmds_list, gluster_cmds);
}
