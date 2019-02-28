/*
  Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
  This file is part of nbd-runner.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

# ifndef __NBD_SVC_H
# define __NBD_SVC_H

void
rpc_nbd_1(struct svc_req *rqstp, register SVCXPRT *transp);

# endif /* __NBD_SVC_H */
