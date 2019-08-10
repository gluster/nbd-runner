/*
 * Copyright 2016-2017 China Mobile, Inc.
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 * This file is part of nbd-runner.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * This file is partially copied from nbd-runner project
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>

#include "nbd-sysconfig.h"
#include "nbd-log.h"

typedef enum {
    NBD_OPT_NONE = 0,
    NBD_OPT_INT, /* type int */
    NBD_OPT_STR, /* type string */
    NBD_OPT_BOOL, /* type boolean */
    NBD_OPT_MAX,
} nbd_option_type;

struct nbd_conf_option {
    struct list_head list;

    char *key;
    nbd_option_type type;
    union {
        int opt_int;
        bool opt_bool;
        char *opt_str;
    };
};

/*
 * System config for NBD, for now there are only 3 option types supported:
 * 1, The "int type" option, for example:
 *	log_level = 2
 *
 * 2, The "string type" option, for example:
 *	nbd_str = "Tom"  --> Tom
 *    or
 *	nbd_str = 'Tom'  --> Tom
 *    or
 *	nbd_str = 'Tom is a "boy"' ---> Tom is a "boy"
 *    or
 *	nbd_str = "'T' is short for Tom" --> 'T' is short for Tom
 *
 * 3, The "boolean type" option, for example:
 *	nbd_bool
 *
 * ========================
 * How to add new options ?
 *
 * Using "log_level" as an example:
 *
 * 1, Add log_level member in:
 *	struct nbd_config {
 *		int log_level;
 *	};
 *    in file libnbd_config.h.
 *
 * 2, Add the following option in "nbd.conf" file as default:
 *	log_level = 2
 *    or
 *	# log_level = 2
 *
 *    Note: the option name in config file must be the same as in
 *    nbd_config.
 *
 * 3, You should add your own set method in:
 *	static void nbd_conf_set_options(struct nbd_config *cfg)
 *	{
 *		NBD_PARSE_CFG_INT(cfg, log_level);
 *		NBD_CONF_CHECK_LOG_LEVEL(log_level);
 *	}
 *
 * Note: For now, if the options have been changed in config file, the
 * system config reload thread daemon will try to update them for all the
 * nbd-runner, consumer and nbd-synthesizer daemons.
 */

static LIST_HEAD(nbd_options);

static struct nbd_conf_option * nbd_get_option(const char *key)
{
    struct nbd_conf_option *option;

    list_for_each_entry(option, &nbd_options, list) {
        if (!strcmp(option->key, key))
            return option;
    }

    return NULL;
}

    static struct nbd_conf_option *
nbd_register_option(char *key, nbd_option_type type)
{
    struct nbd_conf_option *option;

    option = calloc(1, sizeof(*option));
    if (!option)
        return NULL;

    option->key = strdup(key);
    if (!option->key)
        goto free_option;
    option->type = type;
    INIT_LIST_HEAD(&option->list);

    list_add_tail(&option->list, &nbd_options);
    return option;

free_option:
    free(option);
    return NULL;
}

/* The default value should be specified here,
 * so the next time when users comment out an
 * option in config file, here it will set the
 * default value back.
 */
#define NBD_PARSE_CFG_INT(cfg, key) \
do { \
    struct nbd_conf_option *option; \
    option = nbd_get_option(#key); \
    if (option) { \
        cfg->key = option->opt_int; \
    } \
} while (0)

#define NBD_PARSE_CFG_BOOL(cfg, key) \
do { \
    struct nbd_conf_option *option; \
    option = nbd_get_option(#key); \
    if (option) { \
        cfg->key = option->opt_bool; \
    } \
} while (0)

#define NBD_PARSE_CFG_STR(cfg, key) \
do { \
    struct nbd_conf_option *option; \
    option = nbd_get_option(#key); \
    if (option) { \
        snprintf(cfg->key, sizeof(cfg->key), "%s", option->opt_str); \
    } \
} while (0);

static void nbd_conf_set_options(struct nbd_config *cfg)
{
    /* set log_level option */
    NBD_PARSE_CFG_INT(cfg, log_level);
    nbd_set_log_level(cfg->log_level);

    /* set log_dir path option */
    NBD_PARSE_CFG_STR(cfg, log_dir);

    NBD_PARSE_CFG_STR(cfg, ihost);
    NBD_PARSE_CFG_STR(cfg, rhost);
    NBD_PARSE_CFG_STR(cfg, ghost);
    /* add your new config options */
}

#define NBD_MAX_CFG_FILE_SIZE (2 * 1024 * 1024)
static int nbd_read_config(int fd, char *buf, int count)
{
    ssize_t len;
    int save = errno;

    do {
        len = read(fd, buf, count);
    } while (errno == EAGAIN);

    errno = save;
    return len;
}

/* end of line */
#define __EOL(c) (((c) == '\n') || ((c) == '\r'))

#define NBD_TO_LINE_END(x, y) \
do { while ((x) < (y) && !__EOL(*(x))) { \
    (x)++; } \
} while (0);

/* skip blank lines */
#define NBD_SKIP_BLANK_LINES(x, y) \
do { while ((x) < (y) && (isblank(*(x)) || __EOL(*(x)))) { \
    (x)++; } \
} while (0);

/* skip comment line with '#' */
#define NBD_SKIP_COMMENT_LINE(x, y) \
do { while ((x) < (y) && !__EOL(*x)) { \
    (x)++; } \
    (x)++; \
} while (0);

/* skip comment lines with '#' */
#define NBD_SKIP_COMMENT_LINES(x, y) \
do { while ((x) < (y) && *(x) == '#') { \
    NBD_SKIP_COMMENT_LINE((x), (y)); } \
} while (0);

static void nbd_parse_option(char **cur, const char *end)
{
    struct nbd_conf_option *option;
    nbd_option_type type;
    char *p = *cur, *q = *cur, *r, *s;

    while (isblank(*p))
        p++;

    NBD_TO_LINE_END(q, end);
    *q = '\0';
    *cur = q + 1;

    /* parse the boolean type option */
    s = r = strchr(p, '=');
    if (!r) {
        /* boolean type option at file end or line end */
        r = p;
        while (!isblank(*r) && r < q)
            r++;
        *r = '\0';
        option = nbd_get_option(p);
        if (!option)
            option = nbd_register_option(p, NBD_OPT_BOOL);

        if (option)
            option->opt_bool = true;

        return;
    }
    /* skip character '='  */
    s++;
    r--;
    while (isblank(*r))
        r--;
    r++;
    *r = '\0';

    option = nbd_get_option(p);
    if (!option) {
        r = s;
        while (isblank(*r))
            r++;

        if (isdigit(*r))
            type = NBD_OPT_INT;
        else
            type = NBD_OPT_STR;

        option = nbd_register_option(p, type);
        if (!option)
            return;
    }

    /* parse the int/string type options */
    switch (option->type) {
    case NBD_OPT_INT:
        while (!isdigit(*s))
            s++;
        r = s;
        while (isdigit(*r))
            r++;
        *r= '\0';

        option->opt_int = atoi(s);
        break;
    case NBD_OPT_STR:
        while (isblank(*s))
            s++;
        /* skip first " or ' if exist */
        if (*s == '"' || *s == '\'')
            s++;
        r = q - 1;
        while (isblank(*r))
            r--;
        /* skip last " or ' if exist */
        if (*r == '"' || *r == '\'')
            *r = '\0';

        if (option->opt_str)
            /* free if this is reconfig */
            free(option->opt_str);
        option->opt_str = strdup(s);
        break;
    default:
        nbd_err("option type %d not supported!\n", option->type);
        break;
    }
}

static void nbd_parse_options(struct nbd_config *cfg, char *buf, int len)
{
    char *cur = buf, *end = buf + len;

    while (cur < end) {
        /* skip blanks lines */
        NBD_SKIP_BLANK_LINES(cur, end);

        /* skip comments with '#' */
        NBD_SKIP_COMMENT_LINES(cur, end);

        if (cur >= end)
            break;

        if (!isalpha(*cur))
            continue;

        /* parse the options from config file to nbd_options[] */
        nbd_parse_option(&cur, end);
    }

    /* parse the options from nbd_options[] to struct nbd_config */
    nbd_conf_set_options(cfg);
}

static int _nbd_load_config(struct nbd_config *cfg, bool server)
{
    int ret = -1;
    int fd, len;
    char *buf, *file;
    int i;

    buf = calloc(1, NBD_MAX_CFG_FILE_SIZE);
    if (!buf)
        return -ENOMEM;

    if (server)
        file = strdup(NBD_CONFIG_SERV_DEFAULT);
    else
        file = strdup(NBD_CONFIG_CLID_DEFAULT);

    if (!file)
        goto out;

    for (i = 0; i < 5; i++) {
        if ((fd = open(file, O_RDONLY)) == -1) {
            /* give a moment for editor to restore
             * the conf-file after edit and save */
            sleep(1);
            continue;
        }
        break;
    }
    if (fd == -1) {
        nbd_err("Failed to open file '%s', %m\n", file);
        goto out;
    }

    len = nbd_read_config(fd, buf, NBD_MAX_CFG_FILE_SIZE);
    close(fd);
    if (len < 0) {
        nbd_err("Failed to read file '%s'\n", file);
        goto out;
    }

    buf[len] = '\0';

    nbd_parse_options(cfg, buf, len);

    ret = 0;
out:
    free(buf);
    free(file);
    return ret;
}

struct nbd_config* nbd_load_config(bool server)
{
    struct nbd_config *cfg;

    cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        nbd_err("allocating NBD config failed: %m\n");
        errno = ENOMEM;
        return NULL;
    }

    cfg->log_level = NBD_CONF_LOG_INFO;
    snprintf(cfg->log_dir, PATH_MAX, "%s", NBD_LOG_DIR_DEFAULT);
    snprintf(cfg->ghost, NBD_HOST_MAX, "%s", NBD_HOST_LOCAL_DEFAULT);

    if (_nbd_load_config(cfg, server))
        nbd_err("Failed to load config, will use the default settings!\n");

    return cfg;
}

void nbd_free_config(struct nbd_config *cfg)
{
    struct nbd_conf_option *option, *next;

    if (!cfg)
        return;

    list_for_each_entry_safe(option, next, &nbd_options, list) {
        list_del(&option->list);

        if (option->type == NBD_OPT_STR)
            free(option->opt_str);
        free(option->key);
        free(option);
    }

    free(cfg);
}
