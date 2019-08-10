/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.

  Part of this file copied from open-iscsi/tcmu-runner project.
*/

#ifndef __NBD_SVC_ROUTINES_H
#define __NBD_SVC_ROUTINES_H

#define _GNU_SOURCE

#include <stdint.h>
#include <glib.h>

#include "nbd-sysconfig.h"

bool nbd_service_init(struct nbd_config *cfg);
void nbd_service_fini(void);

#endif /* __NBD_SVC_ROUTINES_H */
