/*
 * Copyright 2016-2019 China Mobile, Inc.
 * Copyright (c) 2019 Red Hat, Inc. <http://www.redhat.com>
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * This file is partially copied from tcmu-runner project
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "nbd-log.h"
#include "nbd-sysconfig.h"
#include "nbd-common.h"
#include "utils.h"
#include "strlcpy.h"

/* nbd ring buffer for log */
#define LOG_ENTRY_LEN 8192 /* rb[0] is reserved for pri */
#define LOG_MSG_LEN (LOG_ENTRY_LEN - 1) /* the length of the log message */
#define LOG_ENTRYS (1024 * 32)

#define NBD_LOG_FILENAME_MAX    32
#define NBD_LOG_RUNNER_FILENAME    "nbd-runner.log"
#define NBD_LOG_CLID_FILENAME      "nbd-clid.log"

typedef int (*log_output_fn_t)(int priority, const char *timestamp,
                               const char *str, void *data);
typedef void (*log_close_fn_t)(void *data);

static int nbd_make_absolute_logfile(char *path, const char *filename);

struct log_output {
    log_output_fn_t output_fn;
    log_close_fn_t close_fn;
    int priority;
    void *data;
};

struct log_buf {
    pthread_cond_t cond;
    pthread_mutex_t lock;

    bool thread_active;

    unsigned int head;
    unsigned int tail;
    char buf[LOG_ENTRYS][LOG_ENTRY_LEN];
    struct log_output *syslog_out;
    struct log_output *file_out;
    pthread_mutex_t file_out_lock;
    pthread_t thread_id;
};

static int nbd_log_level = NBD_LOG_INFO;
static struct log_buf *nbd_logbuf;

static char *nbd_log_dir;
static pthread_mutex_t nbd_log_dir_lock = PTHREAD_MUTEX_INITIALIZER;

/* covert log level from nbd config to syslog */
static inline int to_syslog_level(int level)
{
    switch (level) {
    case NBD_CONF_LOG_CRIT:
        return NBD_LOG_CRIT;
    case NBD_CONF_LOG_ERROR:
        return NBD_LOG_ERROR;
    case NBD_CONF_LOG_WARN:
        return NBD_LOG_WARN;
    case NBD_CONF_LOG_INFO:
        return NBD_LOG_INFO;
    case NBD_CONF_LOG_DEBUG:
        return NBD_LOG_DEBUG;
    case NBD_CONF_LOG_DEBUG_IO:
        return NBD_LOG_DEBUG_IO;
    default:
        return NBD_LOG_INFO;
    }
}

void nbd_set_log_level(int level)
{
    if (nbd_log_level == to_syslog_level(level)) {
        nbd_dbg("No changes to current log_level: %s, skipping it.\n",
                log_level_lookup[level]);
        return;
    }

    if (level > NBD_CONF_LOG_LEVEL_MAX)
        level = NBD_CONF_LOG_LEVEL_MAX;
    else if (level < NBD_CONF_LOG_LEVEL_MIN)
        level = NBD_CONF_LOG_LEVEL_MIN;

    nbd_crit("log level now is %s\n", log_level_lookup[level]);
    nbd_log_level = to_syslog_level(level);
}

static inline uint8_t rb_get_pri(struct log_buf *logbuf, unsigned int cur)
{
    return logbuf->buf[cur][0];
}

static inline void rb_set_pri(struct log_buf *logbuf, unsigned int cur,
                              uint8_t pri)
{
    logbuf->buf[cur][0] = (char)pri;
}

static inline char *rb_get_msg(struct log_buf *logbuf, unsigned int cur)
{
    return logbuf->buf[cur] + 1;
}

static inline bool rb_is_empty(struct log_buf *logbuf)
{
    return logbuf->tail == logbuf->head;
}

static inline bool rb_is_full(struct log_buf *logbuf)
{
    return logbuf->tail == (logbuf->head + 1) % LOG_ENTRYS;
}

static inline void rb_update_tail(struct log_buf *logbuf)
{
    logbuf->tail = (logbuf->tail + 1) % LOG_ENTRYS;
}

static inline void rb_update_head(struct log_buf *logbuf)
{
    /* when the ring buffer is full, the oldest log will be dropped */
    if (rb_is_full(logbuf))
        rb_update_tail(logbuf);

    logbuf->head = (logbuf->head + 1) % LOG_ENTRYS;
}

static void log_cleanup_output(struct log_output *output)
{
    if (output->close_fn != NULL)
        output->close_fn(output->data);
    free(output);
}

static void nbd_log_dir_free(void)
{
    if (nbd_log_dir) {
        free(nbd_log_dir);
        nbd_log_dir = NULL;
    }
}

static void log_cleanup(void *arg)
{
    struct log_buf *logbuf = arg;

    pthread_cond_destroy(&logbuf->cond);
    pthread_mutex_destroy(&logbuf->lock);
    pthread_mutex_destroy(&logbuf->file_out_lock);

    if (logbuf->syslog_out)
        log_cleanup_output(logbuf->syslog_out);
    if (logbuf->file_out)
        log_cleanup_output(logbuf->file_out);

    free(logbuf);
    nbd_log_dir_free();
}

static void log_output(struct log_buf *logbuf, int pri, const char *msg,
                       struct log_output *output)
{
    char timestamp[NBD_TLEN_MAX] = {0, };

    if (time_string_now(timestamp) < 0)
        return;

    if (output && output->output_fn)
        output->output_fn(pri, timestamp, msg, output->data);
}

static void log_queue_msg(struct log_buf *logbuf, int pri, char *buf)
{
    unsigned int head;
    char *msg;

    pthread_mutex_lock(&logbuf->lock);

    head = logbuf->head;
    rb_set_pri(logbuf, head, pri);
    msg = rb_get_msg(logbuf, head);
    memcpy(msg, buf, LOG_MSG_LEN);
    rb_update_head(logbuf);

    if (logbuf->thread_active == false)
        pthread_cond_signal(&logbuf->cond);

    pthread_mutex_unlock(&logbuf->lock);
}

static void cleanup_file_out_lock(void *arg)
{
    struct log_buf *logbuf = arg;

    pthread_mutex_unlock(&logbuf->file_out_lock);
}

static void
log_internal(int pri, struct nbd_device *dev, const char *funcname,
             int linenr, const char *fmt, va_list args)
{
    char buf[LOG_MSG_LEN];
    int n;
    struct nbd_handler *handler;

    if (pri > nbd_log_level)
        return;

    if (!fmt)
        return;

    if (!nbd_logbuf) {
        /* handle early log calls by config and deamon setup */
        vfprintf(stderr, fmt, args);
        return;
    }

    /* Format the log msg */
    if (dev) {
        // TODO: add nbd_dev_get_handler()
        handler = dev->handler;
        n = sprintf(buf, "%s:%d %s/%s: ", funcname, linenr,
                handler ? handler->name: "",
                dev->nbd);
    } else {
        n = sprintf(buf, "%s:%d: ", funcname, linenr);
    }

    vsnprintf(buf + n, LOG_MSG_LEN - n, fmt, args);

    /*
     * Avoid overflowing the log buf with NBD.
     */
    if (pri < NBD_LOG_DEBUG_IO)
        log_queue_msg(nbd_logbuf, pri, buf);

    pthread_cleanup_push(cleanup_file_out_lock, nbd_logbuf);
    pthread_mutex_lock(&nbd_logbuf->file_out_lock);

    log_output(nbd_logbuf, pri, buf, nbd_logbuf->file_out);

    pthread_mutex_unlock(&nbd_logbuf->file_out_lock);
    pthread_cleanup_pop(0);
}

void _nbd_crit_message(struct nbd_device *dev, const char *funcname,
                       int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_CRIT, dev, funcname, linenr, fmt, args);
    va_end(args);
}

void _nbd_err_message(struct nbd_device *dev, const char *funcname,
                      int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_ERROR, dev, funcname, linenr, fmt, args);
    va_end(args);
}

void _nbd_warn_message(struct nbd_device *dev, const char *funcname,
                       int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_WARN, dev, funcname, linenr, fmt, args);
    va_end(args);
}

void _nbd_info_message(struct nbd_device *dev, const char *funcname,
                       int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_INFO, dev, funcname, linenr, fmt, args);
    va_end(args);
}

void _nbd_dbg_message(struct nbd_device *dev, const char *funcname,
                      int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_DEBUG, dev, funcname, linenr, fmt, args);
    va_end(args);
}

void _nbd_dbg_io_message(struct nbd_device *dev, const char *funcname,
                          int linenr, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_internal(NBD_LOG_DEBUG_IO, dev, funcname, linenr, fmt,
            args);
    va_end(args);
}


static void __nbd_fill_reply_message(struct nbd_response *rep, int exit,
                                     const char *fmt, va_list args)
{
    if (!rep)
        return;

    rep->exit = exit;

    if (!rep->buf)
        return;

    vsnprintf(rep->buf, NBD_EXIT_MAX, fmt, args);
}

void _nbd_fill_reply_message(struct nbd_response *rep, int exit,
                             const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    __nbd_fill_reply_message(rep, exit, fmt, args);
    va_end(args);
}

static void __nbd_clid_fill_reply_message(struct cli_reply **rep, int exit,
                                          const char *fmt, va_list args)
{
    char *buf = NULL;
    struct cli_reply *p;
    int n;

    if (!rep)
        return;

    n = vasprintf(&buf, fmt, args);

    p = *rep = calloc(1, sizeof(struct cli_reply) + n + 1);
    if (!(p))
        goto out;

    p->exit = exit;
    p->len = n + 1;

    memcpy(p->buf, buf, n);
out:
    free(buf);
}

void _nbd_clid_fill_reply_message(struct cli_reply **rep, int exit,
                                  const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    __nbd_clid_fill_reply_message(rep, exit, fmt, args);
    va_end(args);
}

static struct log_output *
create_output(log_output_fn_t output_fn, log_close_fn_t close_fn, void *data,
              int pri)
{
    struct log_output *output;

    output = calloc(1, sizeof(*output));
    if (!output)
        return NULL;

    output->output_fn = output_fn;
    output->close_fn = close_fn;
    output->data = data;
    output->priority = pri;

    return output;
}

static int output_to_syslog(int pri, const char *timestamp,
                            const char *str, void *data)
{
    /* convert nbd-runner private level to system level */
    if (pri > NBD_LOG_DEBUG)
        pri = NBD_LOG_DEBUG;
    syslog(pri, "%s", str);
    return strlen(str);
}

static void close_syslog(void *data)
{
    closelog();
}

static void close_fd(void *data)
{
    int fd = (intptr_t) data;
    close(fd);
}

static int create_syslog_output(struct log_buf *logbuf, int pri,
                                const char *ident)
{
    openlog(ident, 0 ,0);
    logbuf->syslog_out = create_output(output_to_syslog, close_syslog, NULL,
            pri);
    if (!logbuf->syslog_out) {
        closelog();
        return -1;
    }
    return 0;
}

static const char *loglevel_string(int priority)
{
    switch (priority) {
    case NBD_LOG_CRIT:
        return "CRIT";
    case NBD_LOG_ERROR:
        return "ERROR";
    case NBD_LOG_WARN:
        return "WARN";
    case NBD_LOG_INFO:
        return "INFO";
    case NBD_LOG_DEBUG:
        return "DEBUG";
    case NBD_LOG_DEBUG_IO:
        return "DEBUG_IO";
    }
    return "UNKONWN";
}

static int output_to_fd(int pri, const char *timestamp,
                        const char *str,void *data)
{
    int fd = (intptr_t) data;
    char *buf, *msg;
    int count, ret, written = 0, r, pid = 0;

    if (fd == -1)
        return -1;

    pid = getpid();
    if (pid <= 0)
        return -1;

    /*
     * format: timestamp pid [loglevel] msg
     */
    ret = asprintf(&msg, "%s %d [%s] %s", timestamp, pid, loglevel_string(pri),
                   str);
    if (ret < 0)
        return -1;

    buf = msg;

    /* safe write */
    count = strlen(buf);
    while (count > 0) {
        r = write(fd, buf, count);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            written = r;
            goto out;
        }
        if (r == 0)
            break;
        buf = (char *) buf + r;
        count -= r;
        written += r;
    }
out:
    free(msg);
    return written;
}

static int create_file_output(struct log_buf *logbuf, int pri,
                              const char *filename)
{
    char log_file_path[PATH_MAX];
    struct log_output *output;
    int fd, ret;

    ret = nbd_make_absolute_logfile(log_file_path, filename);
    if (ret < 0) {
        nbd_err("nbd_make_absolute_logfile failed\n");
        return ret;
    }

    nbd_dbg("Attempting to use '%s' as the log file path\n", log_file_path);

    fd = open(log_file_path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        nbd_err("Failed to open %s:%m\n", log_file_path);
        return fd;
    }

    output = create_output(output_to_fd, close_fd, (void *)(intptr_t) fd,
            pri);
    if (!output) {
        close(fd);
        nbd_err("Failed to create output file: %s\n", log_file_path);
        return -ENOMEM;
    }

    pthread_cleanup_push(cleanup_file_out_lock, logbuf);
    pthread_mutex_lock(&logbuf->file_out_lock);

    if (logbuf->file_out) {
        log_cleanup_output(logbuf->file_out);
    }
    logbuf->file_out = output;

    pthread_mutex_unlock(&logbuf->file_out_lock);
    pthread_cleanup_pop(0);

    nbd_crit("log file path now is '%s'\n", log_file_path);
    return 0;
}

static bool log_dequeue_msg(struct log_buf *logbuf)
{
    unsigned int tail;
    uint8_t pri;
    char *msg, buf[LOG_MSG_LEN];

    pthread_mutex_lock(&logbuf->lock);
    if (rb_is_empty(logbuf)) {
        logbuf->thread_active = false;
        pthread_mutex_unlock(&logbuf->lock);
        return false;
    }

    tail = logbuf->tail;
    pri = rb_get_pri(logbuf, tail);
    msg = rb_get_msg(logbuf, tail);
    memcpy(buf, msg, LOG_MSG_LEN);
    rb_update_tail(logbuf);
    pthread_mutex_unlock(&logbuf->lock);

    /*
     * This may block due to rsyslog and syslog-ng, etc.
     * And the log productors could still insert their log
     * messages into the ring buffer without blocking. But
     * the ring buffer may lose some old log rbs if the
     * ring buffer is full.
     */
    log_output(logbuf, pri, buf, logbuf->syslog_out);

    return true;
}

static void *log_thread_start(void *arg)
{
    pthread_cleanup_push(log_cleanup, nbd_logbuf);

    while (1) {
        pthread_mutex_lock(&nbd_logbuf->lock);
        pthread_cond_wait(&nbd_logbuf->cond, &nbd_logbuf->lock);
        nbd_logbuf->thread_active = true;
        pthread_mutex_unlock(&nbd_logbuf->lock);

        while (log_dequeue_msg(nbd_logbuf));
    }

    pthread_cleanup_pop(1);
    return NULL;
}

static bool nbd_log_dir_check(const char *path)
{
    if (strlen(path) >= PATH_MAX - NBD_LOG_FILENAME_MAX) {
        nbd_err("--nbd-log-dir='%s' cannot exceed %d characters\n",
                path, PATH_MAX - NBD_LOG_FILENAME_MAX - 1);
        return false;
    }

    return true;
}

static int nbd_log_dir_set(const char *log_dir)
{
    char *new_dir;

    new_dir = strdup(log_dir);
    if (!new_dir) {
        nbd_err("Failed to copy log dir: %s\n", log_dir);
        return -ENOMEM;
    }

    nbd_log_dir_free();
    nbd_log_dir = new_dir;
    return 0;
}

static int nbd_mkdir(const char *path)
{
    DIR *dir;

    dir = opendir(path);
    if (dir) {
        closedir(dir);
    } else if (errno == ENOENT) {
        if (mkdir(path, 0755) == -1) {
            nbd_err("mkdir(%s) failed: %m\n", path);
            return -errno;
        }
    } else {
        nbd_err("opendir(%s) failed: %m\n", path);
        return -errno;
    }

    return 0;
}

static int nbd_mkdirs(const char *pathname)
{
    char path[PATH_MAX], *ch;
    int ind = 0, ret;

    strlcpy(path, pathname, PATH_MAX);

    if (path[0] == '/')
        ind++;

    do {
        ch = strchr(path + ind, '/');
        if (!ch)
            break;

        *ch = '\0';

        ret = nbd_mkdir(path);
        if (ret)
            return ret;

        *ch = '/';
        ind = ch - path + 1;
    } while (1);

    return nbd_mkdir(path);
}

static void cleanup_log_dir_lock(void *arg)
{
    pthread_mutex_unlock(&nbd_log_dir_lock);
}

static int nbd_log_dir_create(const char *path)
{
    int ret = 0;

    if (!nbd_log_dir_check(path))
        return -EINVAL;

    pthread_cleanup_push(cleanup_log_dir_lock, NULL);
    pthread_mutex_lock(&nbd_log_dir_lock);
    if (nbd_log_dir && !strcmp(path, nbd_log_dir))
        goto unlock;

    ret = nbd_mkdirs(path);
    if (ret)
        goto unlock;

    ret = nbd_log_dir_set(path);
unlock:
    pthread_mutex_unlock(&nbd_log_dir_lock);
    pthread_cleanup_pop(0);
    return ret;
}

static int nbd_make_absolute_logfile(char *path, const char *filename)
{
    int ret = 0;

    pthread_mutex_lock(&nbd_log_dir_lock);
    if (!nbd_log_dir) {
        ret = -EINVAL;
        goto unlock;
    }

    if (snprintf(path, PATH_MAX, "%s/%s", nbd_log_dir, filename) < 0)
        ret = -EINVAL;
unlock:
    pthread_mutex_unlock(&nbd_log_dir_lock);
    return ret;
}

int nbd_setup_log(char *log_dir, bool server)
{
    int ret;

    ret = nbd_log_dir_create(log_dir);
    if (ret) {
        nbd_err("Could not setup log dir %s. Error %d.\n", log_dir,
                ret);
        return ret;
    }

    nbd_logbuf = calloc(1, sizeof(struct log_buf));
    if (!nbd_logbuf)
        goto free_log_dir;

    nbd_logbuf->thread_active = false;
    nbd_logbuf->head = 0;
    nbd_logbuf->tail = 0;
    pthread_cond_init(&nbd_logbuf->cond, NULL);
    pthread_mutex_init(&nbd_logbuf->lock, NULL);
    pthread_mutex_init(&nbd_logbuf->file_out_lock, NULL);

    ret = create_syslog_output(nbd_logbuf, NBD_LOG_INFO, NULL);
    if (ret < 0)
        nbd_err("create syslog output error \n");

    ret = create_file_output(nbd_logbuf, NBD_LOG_DEBUG_IO,
                             server ? NBD_LOG_RUNNER_FILENAME: NBD_LOG_CLID_FILENAME);
    if (ret < 0)
        nbd_err("create file output error \n");

    ret = pthread_create(&nbd_logbuf->thread_id, NULL, log_thread_start,
                         NULL);
    if (ret) {
        log_cleanup(nbd_logbuf);
        return ret;
    }

    return 0;

free_log_dir:
    nbd_log_dir_free();
    return -ENOMEM;
}

void nbd_destroy_log()
{
    pthread_t thread;
    void *join_retval;

    if (!nbd_logbuf)
        return;

    thread = nbd_logbuf->thread_id;
    if (pthread_cancel(thread))
        return;

    pthread_join(thread, &join_retval);
}
