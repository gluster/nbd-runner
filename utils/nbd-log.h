/*
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 3 or any later version (LGPLv3 or
 * later), or the GNU General Public License, version 2 (GPLv2), in all
 * cases as published by the Free Software Foundation.
 *
 * This file is part of nbd-runner.
 */

#ifndef __NBD_LOG_H
#define __NBD_LOG_H

#include <stdarg.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <syslog.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "nbd-sysconfig.h"
#include "rpc_nbd.h"
#include "config.h"

#define NBD_LOG_CRIT        LOG_CRIT	/* critical conditions */
#define NBD_LOG_ERROR       LOG_ERR		/* error conditions */
#define NBD_LOG_WARN        LOG_WARNING	/* warning conditions */
#define NBD_LOG_INFO        LOG_INFO	/* informational */
#define NBD_LOG_DEBUG       LOG_DEBUG	/* debug-level messages */
#define NBD_LOG_DEBUG_IO    (LOG_DEBUG + 1)	/* nbd io messages */

struct nbd_device;

int nbd_setup_log(char *log_dir, bool server);
void nbd_destroy_log(void);
void nbd_set_log_level(int level);

__attribute__ ((format (printf, 4, 5)))
void _nbd_crit_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void _nbd_err_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void _nbd_warn_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void _nbd_info_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void _nbd_dbg_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void _nbd_dbg_io_message(struct nbd_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 3, 4)))
void _nbd_fill_reply_message(struct nbd_response *rep, int exit, const char *fmt, ...);
void _nbd_clid_fill_reply_message(struct cli_reply **rep, int exit, const char *fmt, ...);

#define nbd_dev_crit(dev, ...)  do { _nbd_crit_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dev_err(dev, ...)  do { _nbd_err_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dev_warn(dev, ...) do { _nbd_warn_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dev_info(dev, ...) do { _nbd_info_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dev_dbg(dev, ...)  do { _nbd_dbg_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dev_dbg_io(dev, ...)  do { _nbd_dbg_io_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)

#define nbd_crit(...) do { _nbd_crit_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_err(...)  do { _nbd_err_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_warn(...) do { _nbd_warn_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_info(...) do { _nbd_info_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dbg(...)  do { _nbd_dbg_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define nbd_dbg_io(...)  do { _nbd_dbg_io_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)

#define nbd_fill_reply(rep, exit, ...)  do { _nbd_fill_reply_message(rep, exit, __VA_ARGS__);} while (0)
#define nbd_clid_fill_reply(rep, exit, ...)  do { _nbd_clid_fill_reply_message(rep, exit, __VA_ARGS__);} while (0)

#endif /* __NBD_LOG_H */
