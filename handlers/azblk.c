/*
 * Copyright (c) 2019 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 */

/*
 * This file includes code covered by the following copyright
 * and license notice:
 *
 * MIT License
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

/*
 * Author: Cathy Avery <cavery@redhat.com>
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uv.h>
#include <errno.h>
#include <time.h>
#include <curl/curl.h>
#include <unistd.h>
#include <glib.h>
#include <linux/nbd.h>
#include <json-c/json.h>
#include <signal.h>

#include "nbd-common.h"
#include "nbd-log.h"
#include "utils.h"
#include "strlcpy.h"
#include "nbd-sysconfig.h"
#include "list.h"

// Http Response processing
#define AZ_RESPONSE_PARTIAL       206   // As returned from GET
#define AZ_RESPONSE_CREATED       201   // As returned from PUT
#define AZ_RESPONSE_OK            200   // As returned from HEAD
#define AZ_RESPONSE_ACCEPTED      202   // As returned from DELETE
#define AZ_RESPONSE_ERR_ACCESS    403   // Access denied
#define AZ_RESPONSE_ERR_LEASE     412   // Lease broke
#define AZ_RESPONSE_ERR_NOT_FOUND 404   // Page blob deleted
#define AZ_RESPONSE_ERR_THROTTLE  503   // We are being throttling
#define AZ_RESPONSE_ERR_TIME_OUT  500   // Throttle but the server
                    // side is misbehaving
#define AZ_RESPONSE_CONFLICT      429   // Conflict. Must be reqing
                    // during transnient states
#define AZ_RESPONSE_BAD_RANGE     416   // Bad range (disk resized?)

#define az_is_catastrophe(azstatuscode) \
    ((azstatuscode == AZ_RESPONSE_ERR_ACCESS  || \
    azstatuscode == AZ_RESPONSE_ERR_LEASE     || \
    azstatuscode == AZ_RESPONSE_ERR_NOT_FOUND || \
    azstatuscode == AZ_RESPONSE_BAD_RANGE) ? 1 : 0)

#define az_is_throttle(azstatuscode) \
    ((azstatuscode == AZ_RESPONSE_ERR_THROTTLE || \
    azstatuscode == AZ_RESPONSE_ERR_TIME_OUT   || \
    azstatuscode == AZ_RESPONSE_CONFLICT) ? 1 : 0)

#define az_is_done(azstatuscode)\
    ((azstatuscode == AZ_RESPONSE_PARTIAL || \
    azstatuscode == AZ_RESPONSE_CREATED) ? 1 : 0)

#define az_not_found(azstatuscode)\
    ((azstatuscode == AZ_RESPONSE_ERR_NOT_FOUND) ? 1 : 0)

#define az_is_ok(azstatuscode)\
    ((azstatuscode == AZ_RESPONSE_OK || \
    azstatuscode == AZ_RESPONSE_ACCEPTED) ? 1 : 0)

// Http headers
#define AZ_ACCOUNT_NAME_LEN 256
#define AZ_SAS_LEN          200
#define AZ_BLOB_URL_LEN     (512 + 63 + 1024)  // host + container + blob
#define AZ_LEASE_ID_LEN     64
#define AZ_FILE_LEN         256

struct curl_callback {
    char *buffer;
    size_t pos;
};

struct azblk_dev_config {
    char *key;
    char *sas;
    /* https://myaccount.blob.core.windows.net/mycontainer/myblob */
    char *blob_url;
    char *lease_id;
    int http;
    ssize_t size;
};

#define ERR_STR_SZ 80

struct az_ret_header {
    ssize_t max_size;
    int lease_state;
    int lease_infinite;
    char err_str[ERR_STR_SZ];
};

struct azblk_dev {
    struct nbd_device *dev;
    struct azblk_dev_config cfg;
    char *read_request_url;
    char *write_request_url;
    CURLM *curl_multi;
    uv_loop_t loop;
    uv_async_t stop_loop;
    uv_timer_t timeout;
    int io_timeout;
    uv_async_t start_io_async;
    struct list_head start_io_queue;
    uv_mutex_t start_io_mutex;
    uv_thread_t thread;
    int unmapping;
};

struct azblk_io_cb {
    struct azblk_dev *azdev;
    struct nbd_handler_request *nbd_req;
    struct list_head entry;
    struct curl_callback ctx;
    struct curl_slist *headers;
    char errmsg[CURL_ERROR_SIZE];
    CURL *curl_ezh;
};

struct azblk_socket_context {
    uv_poll_t poll_handle;
    curl_socket_t sockfd;
    struct azblk_dev *azdev;
};

static void azdev_free(struct azblk_dev *azdev)
{
    free(azdev->cfg.key);
    free(azdev->cfg.blob_url);
    free(azdev->cfg.sas);
    free(azdev->cfg.lease_id);
    free(azdev->read_request_url);
    free(azdev->write_request_url);
    free(azdev);
}

static void azblk_loop_cleanup(uv_handle_t *handle, void *data)
{
    uv_close(handle, NULL);
}

static void azblk_stop_loop(uv_async_t *async_req)
{
    struct azblk_dev *azdev = (struct azblk_dev *)async_req->data;
    struct azblk_io_cb *io_cb, *tmp;

    uv_stop(&azdev->loop);

    uv_mutex_lock(&azdev->start_io_mutex);

    list_for_each_entry_safe(io_cb, tmp, &azdev->start_io_queue, entry) {
        list_del(&io_cb->entry);
        curl_multi_remove_handle(azdev->curl_multi, io_cb->curl_ezh);
        curl_slist_free_all(io_cb->headers);
        curl_easy_cleanup(io_cb->curl_ezh);
        io_cb->nbd_req->done(io_cb->nbd_req, -EIO);
        free(io_cb);
    }

    uv_mutex_unlock(&azdev->start_io_mutex);
}

static void azblk_kick_start(struct azblk_dev *azdev,
     struct azblk_io_cb *io_cb)
{
    uv_mutex_lock(&azdev->start_io_mutex);
    list_add_tail(&io_cb->entry, &azdev->start_io_queue);
    uv_mutex_unlock(&azdev->start_io_mutex);
    uv_async_send(&azdev->start_io_async);
}

static void azblk_start_io(uv_async_t *async_req)
{
    struct azblk_dev *azdev = (struct azblk_dev *)async_req->data;
    struct list_head active_queue;
    int running_handles;
    struct azblk_io_cb *io_cb, *tmp;

    INIT_LIST_HEAD(&active_queue);

    uv_mutex_lock(&azdev->start_io_mutex);

    list_splice_init(&azdev->start_io_queue, &active_queue);

    uv_mutex_unlock(&azdev->start_io_mutex);

    list_for_each_entry_safe(io_cb, tmp, &active_queue, entry) {
        list_del(&io_cb->entry);

        curl_multi_add_handle(azdev->curl_multi, io_cb->curl_ezh);

        curl_multi_socket_action(azdev->curl_multi,
                                 CURL_SOCKET_TIMEOUT, 0,
                                 &running_handles);
    }
}

static void azblk_multi_done(CURLM *curl_multi, CURLMsg *message)
{
    struct azblk_io_cb *io_cb;
    struct nbd_device *dev;
    CURL *curl_ezh;
    long resp_code = 0;
    int ret = 0;

    curl_ezh = message->easy_handle;
    curl_easy_getinfo(curl_ezh, CURLINFO_PRIVATE, (char **)&io_cb);
    dev = io_cb->azdev->dev;

    if (message->data.result != CURLE_OK) {

        curl_easy_getinfo(curl_ezh, CURLINFO_RESPONSE_CODE, &resp_code);

        if (az_is_throttle(resp_code)) {
            nbd_dev_dbg(dev, "Curl HTTP error %ld. Azure is throttling the IO at offset %zd.\n",
                        resp_code, io_cb->nbd_req->offset);
            ret = -EAGAIN;
        } else {
            ret = -EIO;

            if ((message->data.result == CURLE_SEND_ERROR ||
                message->data.result == CURLE_RECV_ERROR ) &&
                resp_code == 0)
                    ret = -EAGAIN;

            if (io_cb->nbd_req->cmd == NBD_CMD_READ) {
                if ( ret == -EAGAIN )
                    nbd_dev_dbg(dev, "Curl IO GET %s '%s' at offset %zd.\n",
                            io_cb->errmsg, curl_easy_strerror(message->data.result),
                            io_cb->nbd_req->offset);
                else
                    nbd_dev_err(dev, "Curl IO GET %s '%s' at offset %zd.\n",
                            io_cb->errmsg, curl_easy_strerror(message->data.result),
                            io_cb->nbd_req->offset);
            } else {
                if ( ret == -EAGAIN )
                    nbd_dev_dbg(dev, "Curl IO PUT %s '%s' at offset %zd.\n",
                            io_cb->errmsg, curl_easy_strerror(message->data.result),
                            io_cb->nbd_req->offset);
                else
                    nbd_dev_err(dev, "Curl IO PUT %s '%s' at offset %zd.\n",
                            io_cb->errmsg, curl_easy_strerror(message->data.result),
                            io_cb->nbd_req->offset);
            }
        }
    }

    curl_multi_remove_handle(curl_multi, curl_ezh);
    curl_slist_free_all(io_cb->headers);
    curl_easy_cleanup(curl_ezh);

    io_cb->nbd_req->done(io_cb->nbd_req, ret);

    free(io_cb);
}

static void azblk_multi_check_completion(CURLM *curl_multi)
{
    int pending;
    CURLMsg *message;

    /* Do not use message data after calling curl_multi_remove_handle() and
     * curl_easy_cleanup(). As per curl_multi_info_read() docs:
     * "WARNING: The data the returned pointer points to will not survive
     * calling curl_multi_cleanup, curl_multi_remove_handle or
     * curl_easy_cleanup."
     */

    while ((message = curl_multi_info_read(curl_multi, &pending))) {
        switch (message->msg) {
        case CURLMSG_DONE:
            azblk_multi_done(curl_multi, message);
            break;
        default:
            break;
        }
    }
}

static void azblk_timeout(uv_timer_t *req)
{
    struct azblk_dev *azdev = (CURLM *)req->data;
    int running_handles;

    curl_multi_socket_action(azdev->curl_multi, CURL_SOCKET_TIMEOUT, 0,
                 &running_handles);
    azblk_multi_check_completion(azdev->curl_multi);
}

static int azblk_start_timeout(CURLM *curl_multi, long timeout_ms, void *userp)
{
    struct azblk_dev *azdev = (struct azblk_dev *)userp;

    if (timeout_ms < 0) {
        uv_timer_stop(&azdev->timeout);
    } else {
        if (timeout_ms == 0)
            timeout_ms = 1; // 0 means directly call socket_action
                            // but we'll do it in a bit
        azdev->timeout.data = azdev;
        uv_timer_start(&azdev->timeout, azblk_timeout, timeout_ms, 0);
    }
    return 0;
}

static struct azblk_socket_context *
azblk_create_socket_context(curl_socket_t sockfd, struct azblk_dev *azdev)
{
    struct azblk_socket_context *context;

    context = (struct azblk_socket_context *)calloc(1, sizeof(*context));
    if (!context)
        return NULL;

    context->sockfd = sockfd;
    context->azdev = azdev;

    uv_poll_init_socket(&azdev->loop, &context->poll_handle, sockfd);
    context->poll_handle.data = context;

    return context;
}
static void azblk_close_socket(uv_handle_t *handle)
{
    // (struct azblk_socket_context *) handle->data;
    free(handle->data);
}

static void azblk_destroy_socket_context(struct azblk_socket_context *context)
{
    uv_close((uv_handle_t *) &context->poll_handle, azblk_close_socket);
}

static void azblk_curl_perform(uv_poll_t *req, int status, int events)
{
    struct azblk_socket_context *context;
    int running_handles;
    int flags = 0;

    context = (struct azblk_socket_context *)req->data;

    if (status < 0) {
        flags = CURL_CSELECT_ERR;
        nbd_dev_dbg(context->azdev->dev, "CURL_CSELECT_ERR %s.\n",
                    uv_err_name(status));
    }
    if (!status && events & UV_READABLE)
        flags |= CURL_CSELECT_IN;
    if (!status && events & UV_WRITABLE)
        flags |= CURL_CSELECT_OUT;

    curl_multi_socket_action(context->azdev->curl_multi, context->sockfd,
                             flags, &running_handles);

    azblk_multi_check_completion(context->azdev->curl_multi);
}

static int azblk_handle_socket(CURL *curl_ezh, curl_socket_t s, int action,
                               void *userp, void *socketp)
{
    struct azblk_socket_context *context = NULL;
    struct azblk_dev *azdev = (struct azblk_dev *)userp;

    if (action == CURL_POLL_IN
        || action == CURL_POLL_OUT
        || action == CURL_POLL_INOUT) {
        if (socketp)
            context = (struct azblk_socket_context *)socketp;
        else {
            context = azblk_create_socket_context(s, azdev);
            curl_multi_assign(azdev->curl_multi, s, (void *)context);
        }
    }

    switch (action) {
    case CURL_POLL_IN:
        uv_poll_start(&context->poll_handle, UV_READABLE, azblk_curl_perform);
        break;
    case CURL_POLL_OUT:
        uv_poll_start(&context->poll_handle, UV_WRITABLE, azblk_curl_perform);
        break;
    case CURL_POLL_INOUT:
        uv_poll_start(&context->poll_handle, UV_READABLE | UV_WRITABLE,
                      azblk_curl_perform);
        break;
    case CURL_POLL_REMOVE:
        if (socketp) {
            context = (struct azblk_socket_context *)socketp;

            uv_poll_stop(&context->poll_handle);
            azblk_destroy_socket_context(context);
            curl_multi_assign(azdev->curl_multi, s, NULL);
        }
        break;
    }

    return 0;
}

static void azblk_dev_loop(void *arg)
{
    struct azblk_dev *azdev = (struct azblk_dev *)arg;
    int ret;

    ret = uv_run(&azdev->loop, UV_RUN_DEFAULT);

    uv_walk(&azdev->loop, azblk_loop_cleanup, NULL);

    uv_run(&azdev->loop, UV_RUN_DEFAULT);

    ret = uv_loop_close(&azdev->loop);
    if (ret == UV_EBUSY)
        nbd_dev_warn(azdev->dev, "Not all libuv handles are closed.\n");
}

static char *azblk_parse_lease(char *str, struct azblk_dev *azdev,
                               char *err_msg)
{
    char *str_end;
    int len;

    str_end = memchr(str, ';', AZ_LEASE_ID_LEN + 1);
    if (!str_end)
        str_end = memchr(str, '\0', AZ_LEASE_ID_LEN + 1);
    if (!str_end) {
        sprintf(err_msg, "Invalid lease argument");
        return NULL;
    }

    len = str_end - str;
    if (len == 0 || (len > AZ_LEASE_ID_LEN - 1)) {
        sprintf(err_msg, "Invalid lease length");
        return NULL;
    }

    azdev->cfg.lease_id = calloc(1, len + 1);
    strlcpy(azdev->cfg.lease_id, str, len + 1);
    return str + len;
}

static char *azblk_parse_sas(char *str, struct azblk_dev *azdev,
                             char *err_msg)
{
    char *str_end;
    int len;

    /* For create you must have an account level sas */

    str_end = memchr(str, ';', AZ_SAS_LEN + 1);
    if (!str_end)
        str_end = memchr(str, '\0', AZ_SAS_LEN + 1);
    if (!str_end) {
        sprintf(err_msg, "Invalid sas argument");
        return NULL;
    }

    len = str_end - str;
    if (len == 0 || (len > AZ_SAS_LEN - 1)) {
        sprintf(err_msg, "Invalid sas length");
        return NULL;
    }

    azdev->cfg.sas = calloc(1, len + 1);
    strlcpy(azdev->cfg.sas, str, len + 1);
    return str + len;
}

static char *azblk_parse_http(char *str, struct azblk_dev *azdev,
                              char *err_msg)
{
    azdev->cfg.http = 1;

    return str;
}

#define AZBLK_PARAMS      3

struct azblk_dev_config_param {
    char    *name;
    char    *(*parse)(char *, struct azblk_dev *, char *err_msg);
} azblk_params[AZBLK_PARAMS] = {
    { "sas=",      azblk_parse_sas },
    { "lease=",    azblk_parse_lease },
    { "http",      azblk_parse_http },
};

static bool azblk_parse_config(struct nbd_device *dev, const char *cfgstring,
                               nbd_response *rep)
{
    struct azblk_dev *azdev;
    char *str, *str_end;
    char *url;
    int i = 0;
    int url_len;
    char err_msg[80];

    if (!cfgstring || !dev) {
        nbd_fill_reply(rep, -EINVAL, "The cfgstring param is NULL.");
        nbd_err("The cfgstring param is NULL.\n");
        return false;
    }

    azdev = calloc(1, sizeof(*azdev));
    if (!azdev) {
        nbd_fill_reply(rep, -ENOMEM, "No memory for device.");
        nbd_err("No memory for device.\n");
        return false;
    }

    azdev->dev = dev;

    str = (char *)cfgstring;

    /* First locate the url */

    str_end = memchr(str, ';', AZ_BLOB_URL_LEN);
    if (str_end == NULL) {
        nbd_fill_reply(rep, -ENOMEM, "Invalid url argument.");
        nbd_err("Invalid url argument.\n");
        azdev_free(azdev);
        return false;
    }

    url_len = str_end - str;

    if (url_len >= AZ_BLOB_URL_LEN) {
        nbd_fill_reply(rep, -EINVAL, "Url too long.");
        nbd_err("Url too long.\n");
        azdev_free(azdev);
        return false;
    }

    url = str;

    /* skip over the url */

    str = str_end;

    /* Parse parameters */
    while (*str == ';' && *(++str) !=  '\0') {
        for (i = 0; i < AZBLK_PARAMS; i++) {
            if (strncmp(str, azblk_params[i].name,
                        strlen(azblk_params[i].name)) == 0)
                break;
        }

        if (i == AZBLK_PARAMS) {
            sprintf(err_msg, "Invalid argument");
            goto error;
        }

        /* skip over parameter name */
        str += strlen(azblk_params[i].name);
        str = (azblk_params[i].parse)(str, azdev, err_msg);
        if (!str)
            goto error;
    }


    azdev->cfg.key = calloc(1, url_len + 1);
    strlcpy(azdev->cfg.key, url, url_len + 1);

    url_len = azdev->cfg.http ? (url_len + 8) : (url_len + 9);

    azdev->cfg.blob_url = calloc(1, url_len);
    snprintf(azdev->cfg.blob_url, url_len,
             azdev->cfg.http ? "http://%s" : "https://%s",
             url);

    dev->priv = azdev;

    return true;

error:

    nbd_fill_reply(rep, -EINVAL, "%s", err_msg);
    nbd_err("%s \n", err_msg);
    azdev_free(azdev);

    return false;
}

static int get_UTC(char *buf, int size)
{
    time_t c_time;
    struct tm gm_time;

    c_time = time(NULL);
    gmtime_r(&c_time, &gm_time);
    strftime(buf, size, "%a, %d %b %Y %X GMT", &gm_time);

    return 0;
}

static bool azblk_sync_io(char *command,
                          CURL *input_curl_ezh,
                          char *request_url,
                          struct curl_slist *input_headers,
                          long *resp_code)
{
    CURL *curl_ezh = input_curl_ezh;
    struct curl_slist *headers = input_headers;
    char buf[128];
    CURLcode res;
    int len;
    int ret = false;

    if (!curl_ezh) {
        curl_ezh = curl_easy_init();
        if (!curl_ezh) {
            nbd_err("Could not init easy handle.\n");
            goto done;
        }
    }

    curl_easy_setopt(curl_ezh, CURLOPT_URL, request_url);
    curl_easy_setopt(curl_ezh, CURLOPT_CUSTOMREQUEST, command);
    curl_easy_setopt(curl_ezh, CURLOPT_USERAGENT,
                "nbd-runner-azblk/1.0");

    headers = curl_slist_append(headers,
                       "x-ms-version: 2018-03-28");

    len = sprintf(buf, "x-ms-date: ");
    get_UTC(buf + len, sizeof(buf) - len);
    headers = curl_slist_append(headers, buf);

    curl_easy_setopt(curl_ezh, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl_ezh);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl_ezh,
                    CURLINFO_RESPONSE_CODE, resp_code);
        ret = true;
    } else {
        nbd_err("Curl sync %s error %x.\n", command, res);
    }

done:

    if (headers)
        curl_slist_free_all(headers);
    if (curl_ezh)
        curl_easy_cleanup(curl_ezh);
    free(request_url);

    return ret;
}

static size_t get_az_ret_headers(void *data, size_t size, size_t nitems, void *userp)
{
    struct az_ret_header *header = (struct az_ret_header *)userp;
    size_t data_size = size * nitems;
    ssize_t length;
    int ret;

    if (strncmp("Content-Length:", data, 15) == 0) {
        ret = sscanf(data, "Content-Length: %zd", &length);
        if (ret)
            header->max_size = length;
    }

    if (strncmp("x-ms-lease-status: locked", data, 25) == 0) {
        header->lease_state = 1;
    }

    if (strncmp("x-ms-lease-duration: infinite", data, 29) == 0) {
        header->lease_infinite = 1;
    }

    if (strncmp("x-ms-error-code: ", data, 17) == 0) {
        void *end = strchr(data, '\r');
        int len = end - (data + 17);

        strlcpy(header->err_str, data + 17,
                len >= ERR_STR_SZ ? ERR_STR_SZ : len + 1);
    }

    return data_size;
}

static int azblk_set_lease(struct azblk_dev *azdev)
{
    struct curl_slist *headers = NULL;
    struct az_ret_header az_ret_header = {0};
    CURL *curl_ezh;
    char *request_url;
    long http_response = 0;
    char buf[128];
    int ret;

    curl_ezh = curl_easy_init();
    if (!curl_ezh) {
        nbd_err("Could not init easy handle.\n");
        return -EINVAL;
    }

    ret = asprintf(&request_url,
                   azdev->cfg.sas ? "%s?comp=lease&%s" : "%s?comp=lease",
                   azdev->cfg.blob_url, azdev->cfg.sas);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        return -ENOMEM;
    }

    curl_easy_setopt(curl_ezh, CURLOPT_HEADERFUNCTION, get_az_ret_headers);
    curl_easy_setopt(curl_ezh, CURLOPT_HEADERDATA, &az_ret_header);
    curl_easy_setopt(curl_ezh, CURLOPT_NOBODY, 1L);

    sprintf(buf, "x-ms-proposed-lease-id: %s", azdev->cfg.lease_id);
    headers = curl_slist_append(headers, buf);
    headers = curl_slist_append(headers, "x-ms-lease-action: acquire");
    headers = curl_slist_append(headers, "x-ms-lease-duration: -1");

    headers = curl_slist_append(headers, "Content-Length: 0");

    /* azblk_sync_io will cleanup the headers, curl handle, and url */

    if (!azblk_sync_io("PUT", curl_ezh, request_url, headers, &http_response))
        return -EINVAL;

    if (!az_is_done(http_response)) {
        nbd_err("Azure sync HEAD error %ld - %s.\n", http_response, az_ret_header.err_str);
        return -EINVAL;
    }

    return 0;
}

static int azblk_get_blob_properties(struct azblk_dev *azdev,
                                     struct az_ret_header *az_ret_header)
{
    struct curl_slist *headers = NULL;
    char *request_url;
    CURL *curl_ezh;
    long http_response = 0;
    int ret;

    curl_ezh = curl_easy_init();
    if (!curl_ezh) {
        nbd_err("Could not init easy handle.\n");
        return -EINVAL;
    }

    ret = asprintf(&request_url,
                   azdev->cfg.sas ? "%s?%s" : "%s",
                   azdev->cfg.blob_url, azdev->cfg.sas);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        curl_easy_cleanup(curl_ezh);
        return -ENOMEM;
    }

    curl_easy_setopt(curl_ezh, CURLOPT_HEADERFUNCTION, get_az_ret_headers);
    curl_easy_setopt(curl_ezh, CURLOPT_HEADERDATA, az_ret_header);
    curl_easy_setopt(curl_ezh, CURLOPT_NOBODY, 1L);
    headers = curl_slist_append(headers, "Content-Length: 0");

    /* azblk_sync_io will cleanup the headers, curl handle, and url */

    if (!azblk_sync_io("HEAD", curl_ezh, request_url, headers, &http_response))
        return -EINVAL;

    if (!az_is_ok(http_response)) {
        if (az_not_found(http_response))
            return -ENODEV;
        nbd_err("Azure sync HEAD error %ld - %s.\n",
                http_response, az_ret_header->err_str);
        return -EINVAL;
    }

    return 0;
}

static bool azblk_create(struct nbd_device *dev, nbd_response *rep)
{
    struct azblk_dev *azdev = dev->priv;
    struct curl_slist *headers = NULL;
    struct az_ret_header az_ret_header = {0};
    CURL *curl_ezh;
    char *request_url;
    long http_response = 0;
    char buf[128];
    int ret;

    curl_ezh = curl_easy_init();
    if (!curl_ezh) {
        nbd_err("Could not init easy handle.\n");
        return -EINVAL;
    }

    ret = asprintf(&request_url,
                   azdev->cfg.sas ? "%s?%s" : "%s",
                   azdev->cfg.blob_url, azdev->cfg.sas);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        nbd_fill_reply(rep, -ENOMEM, "Could not allocate query buf.");
        return false;
    }

    curl_easy_setopt(curl_ezh, CURLOPT_HEADERFUNCTION, get_az_ret_headers);
    curl_easy_setopt(curl_ezh, CURLOPT_HEADERDATA, &az_ret_header);
    curl_easy_setopt(curl_ezh, CURLOPT_NOBODY, 1L);

    headers = curl_slist_append(headers, "x-ms-blob-type: PageBlob");

    headers = curl_slist_append(headers,
                                "Content-Type: application/octet-stream");

    sprintf(buf, "x-ms-blob-content-length: %zd", dev->size);
    headers = curl_slist_append(headers, buf);

    headers = curl_slist_append(headers, "x-ms-blob-sequence-number: 0");

    headers = curl_slist_append(headers, "Content-Length: 0");

    /* azblk_sync_io will cleanup the headers, curl handle, and url */

    if (!azblk_sync_io("PUT", curl_ezh, request_url, headers, &http_response)) {
        nbd_err("Azure sync io error.\n");
        nbd_fill_reply(rep, -EINVAL, "Azure sync io.");
        return false;
    }

    if (!az_is_done(http_response)) {
        nbd_err("Azure sync PUT error %ld - %s\n",
                 http_response, az_ret_header.err_str);
        nbd_fill_reply(rep, -EINVAL, "Azure sync PUT error %ld - %s.",
                       http_response, az_ret_header.err_str);
        return false;
    }

    return true;
}

static bool azblk_add(struct nbd_device *dev, nbd_response *rep)
{
    struct azblk_dev *azdev = dev->priv;
    struct az_ret_header az_ret_header = {0};
    int ret;

    if (rep)
        rep->exit = 0;

    if (!azdev) {
        nbd_err("Create: Device is not allocated.\n");
        nbd_fill_reply(rep, -EINVAL, "Create: Device is not allocated.");
        return false;
    }

    ret = azblk_get_blob_properties(azdev, &az_ret_header);

    if (ret == -EINVAL || ret == -ENOMEM) {
        nbd_err("Error getting blob properties.\n");
        nbd_fill_reply(rep, ret, "Error getting blob properties.");
        goto error;
    }

    if (ret == 0) {
        if (dev->size != az_ret_header.max_size) {
            nbd_err("Blob %s exists but sizes do not match.\n",
                    azdev->cfg.key);
            nbd_fill_reply(rep, -EINVAL,
                           "Blob %s exists but sizes do not match.",
                           azdev->cfg.key);
            goto error;
        }
        if (az_ret_header.lease_state) {
            if (!azdev->cfg.lease_id) {
                nbd_err("Blob %s exists but a lease id is required.\n",
                        azdev->cfg.key);
                nbd_fill_reply(rep, -EINVAL,
                               "Blob %s exists but a lease id is required.\n",
                               azdev->cfg.key);
                goto error;
            }
            if (!az_ret_header.lease_infinite) {
                nbd_err("Blob %s exists but an infinite lease id is required.\n",
                        azdev->cfg.key);
                nbd_fill_reply(rep, -EINVAL,
                               "Blob %s exists but an infinite lease id is required.\n",
                               azdev->cfg.key);
                goto error;
            }
        } else {
            if (azdev->cfg.lease_id) {
                ret = azblk_set_lease(azdev);
                if (ret != 0) {
                    nbd_err("Could not add lease to existing Blob %s.\n",
                             azdev->cfg.key);
                    nbd_fill_reply(rep, -EINVAL,
                                   "Could not add lease to existing Blob %s.\n",
                                   azdev->cfg.key);
                    goto error;
                }
            }
        }

        nbd_warn("Blob %s already exists in Azure. Adding to the backstore.\n", azdev->cfg.key);
        goto done;
    }

    if (!azblk_create(dev, rep))
        goto error;

    if (azdev->cfg.lease_id) {
        ret = azblk_set_lease(azdev);
        if (ret != 0) {
            nbd_err("Blob %s was created in Azure but not the backstore as the lease could not be added.\n",
                     azdev->cfg.key);
            nbd_fill_reply(rep, -EINVAL,
                           "Blob %s was created in Azure but not the backstore as the lease could not be added. Try creating with no lease or a valid lease to add it to the backstore.\n",
                           azdev->cfg.key);
            goto error;
        }
    }

done:

    azdev->cfg.size = dev->size;
    return true;

error:

    azdev_free(azdev);
    dev->priv = NULL;
    return false;
}

/* Delete the blob and delete its config info */
static bool azblk_delete(struct nbd_device *dev, nbd_response *rep)
{
    struct azblk_dev *azdev = dev->priv;
    struct curl_slist *headers = NULL;
    char *request_url;
    long http_response = 0;
    char buf[128];
    int ret;

    if (rep)
        rep->exit = 0;

    if (!azdev) {
        nbd_err("Delete: Device is not allocated\n");
        return true;
    }

    ret = asprintf(&request_url,
                   azdev->cfg.sas ? "%s?%s" : "%s",
                   azdev->cfg.blob_url, azdev->cfg.sas);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        return false;
    }

    headers = curl_slist_append(headers, "Content-Length: 0");

    headers = curl_slist_append(headers,"x-ms-delete-snapshots: include");

    if (azdev->cfg.lease_id) {
        sprintf(buf, "x-ms-lease-id: %s", azdev->cfg.lease_id);
        headers = curl_slist_append(headers, buf);
    }

    /* azblk_sync_io will cleanup the headers, curl handle, and url */

    if (!azblk_sync_io("DELETE", NULL, request_url, headers, &http_response)) {
        nbd_err("Azure sync io error.\n");
        nbd_fill_reply(rep, -EINVAL, "Azure sync io error.");
        return false;
    }

    if (!az_is_ok(http_response) && !az_not_found(http_response)) {
        nbd_err("Azure sync DELETE error %ld.\n", http_response);
        nbd_fill_reply(rep, -EINVAL, "Azure sync DELETE error %ld.", http_response);
        return false;
    }

    azdev_free(azdev);

    dev->priv = NULL;

    return true;
}

static bool azblk_map(struct nbd_device *dev, nbd_response *rep)
{
    struct azblk_dev *azdev = dev->priv;
    int ret = false;

    if (rep)
        rep->exit = 0;

    if (!azdev) {
        nbd_err("Map: Device is not allocated.\n");
        nbd_fill_reply(rep, -EINVAL, "Map: Device is not allocated.");
        return false;
    }

    azdev->io_timeout = dev->timeout;

    azdev->unmapping = 0;

    azdev->curl_multi = curl_multi_init();

    curl_multi_setopt(azdev->curl_multi, CURLMOPT_SOCKETFUNCTION,
              azblk_handle_socket);
    curl_multi_setopt(azdev->curl_multi, CURLMOPT_TIMERFUNCTION,
              azblk_start_timeout);
    curl_multi_setopt(azdev->curl_multi, CURLMOPT_TIMERDATA, azdev);
    curl_multi_setopt(azdev->curl_multi, CURLMOPT_SOCKETDATA, azdev);

    // blob calls

    // Get Page
    if (azdev->cfg.sas)
        ret = asprintf(&azdev->read_request_url, "%s?%s&timeout=%d",
                   azdev->cfg.blob_url, azdev->cfg.sas, azdev->io_timeout);
    else
        ret = asprintf(&azdev->read_request_url, "%s?timeout=%d",
                   azdev->cfg.blob_url, azdev->io_timeout);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        nbd_fill_reply(rep, -ENOMEM, "Could not allocate query buf.");
        goto error;
    }

    // Put Page
    if (azdev->cfg.sas)
        ret = asprintf(&azdev->write_request_url, "%s?comp=page&%s&timeout=%d",
                   azdev->cfg.blob_url, azdev->cfg.sas, azdev->io_timeout);
    else
        ret = asprintf(&azdev->write_request_url, "%s?comp=page&timeout=%d",
                   azdev->cfg.blob_url, azdev->io_timeout);
    if (ret < 0) {
        nbd_err("Could not allocate query buf.\n");
        nbd_fill_reply(rep, -ENOMEM, "Could not global init curl.");
        goto error;
    }

    uv_loop_init(&azdev->loop);

    uv_timer_init(&azdev->loop, &azdev->timeout);

    uv_async_init(&azdev->loop, &azdev->stop_loop, azblk_stop_loop);
    azdev->stop_loop.data = azdev;

    uv_async_init(&azdev->loop, &azdev->start_io_async, azblk_start_io);
    azdev->start_io_async.data = azdev;

    uv_mutex_init(&azdev->start_io_mutex);

    INIT_LIST_HEAD(&azdev->start_io_queue);

    uv_thread_create(&azdev->thread, azblk_dev_loop, azdev);

    return true;

error:

    azdev_free(azdev);

    return false;
}

static bool azblk_unmap(struct nbd_device *dev)
{
    struct azblk_dev *azdev = dev->priv;

    if (!azdev) {
        nbd_err("Unmap: Device is not allocated\n");
        return true;
    }

    // nbd-runner makes sure that the device has been mapped.

    azdev->unmapping = 1;

    uv_timer_stop(&azdev->timeout);

    uv_async_send(&azdev->stop_loop);

    uv_thread_join(&azdev->thread);

    curl_multi_cleanup(azdev->curl_multi);

    uv_mutex_destroy(&azdev->start_io_mutex);

    free(azdev->read_request_url);
    azdev->read_request_url = NULL;

    free(azdev->write_request_url);
    azdev->write_request_url = NULL;

    return true;
}

static size_t get_callback(void *data, size_t size, size_t nmemb, void *userp)
{
    struct curl_callback *ctx = (struct curl_callback *)userp;
    size_t data_size = size * nmemb;

    memcpy(ctx->buffer + ctx->pos, data, data_size);

    ctx->pos += data_size;

    return data_size;
}

static struct azblk_io_cb *alloc_iocb(struct nbd_handler_request *req)
{
    struct azblk_io_cb *io_cb;

    io_cb = calloc(1, sizeof(*io_cb));
    if (!io_cb) {
        nbd_dev_err(req->dev, "Could not allocate io_cb.\n");
        return NULL;
    }
    io_cb->nbd_req = req;
    io_cb->azdev = req->dev->priv;
    INIT_LIST_HEAD(&io_cb->entry);

    return io_cb;
}

static void azblk_read(struct nbd_handler_request *req)
{
    struct azblk_dev *azdev = req->dev->priv;
    struct azblk_io_cb *io_cb = NULL;
    char buf[128];
    int len;
    int ret;

    if (azdev->unmapping) {
        ret = -EIO;
        goto error;
    }

    io_cb = alloc_iocb(req);
    if (!io_cb) {
        ret = -ENOMEM;
        goto error;
    }

    io_cb->curl_ezh = curl_easy_init();
    if (!io_cb->curl_ezh) {
        nbd_dev_err(req->dev, "Failed to allocate easy handle.\n");
        ret = -ENOMEM;
        goto error;
    }

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_ERRORBUFFER, io_cb->errmsg);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TIMEOUT, azdev->io_timeout);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, azdev->read_request_url);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
             "nbd-runner-azblk/1.0");

    io_cb->ctx.buffer = io_cb->nbd_req->rwbuf;
    io_cb->ctx.pos = 0;

    // Writes to the destination are broken into CURL_MAX_WRITE_SIZE chunks

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEFUNCTION,
             get_callback);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEDATA,
             (void *)&io_cb->ctx);

    io_cb->headers = curl_slist_append(io_cb->headers,
                       "x-ms-version: 2018-03-28");

    if (azdev->cfg.lease_id) {
        sprintf(buf, "x-ms-lease-id: %s", azdev->cfg.lease_id);
        io_cb->headers = curl_slist_append(io_cb->headers, buf);
    }

    sprintf(buf, "x-ms-range: bytes=%zd-%zd", req->offset,
        req->offset + (req->len - 1));
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    len = sprintf(buf, "x-ms-date: ");
    get_UTC(buf + len, sizeof(buf) - len);
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

    // Set context associated with this easy handle

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

    azblk_kick_start(azdev, io_cb);

    return;

error:

    if (io_cb && io_cb->curl_ezh) {
        curl_multi_remove_handle(azdev->curl_multi, io_cb->curl_ezh);
        curl_slist_free_all(io_cb->headers);
        curl_easy_cleanup(io_cb->curl_ezh);
    }

    free(io_cb);

    req->done(req, ret);
}

static size_t put_callback(void *data, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

static void azblk_write(struct nbd_handler_request *req)
{
    struct azblk_dev *azdev = req->dev->priv;
    int len;
    int ret;
    struct azblk_io_cb *io_cb = NULL;
    char buf[128];

    if (azdev->unmapping) {
        ret = -EIO;
        goto error;
    }

    io_cb = alloc_iocb(req);
    if (!io_cb) {
        ret = -ENOMEM;
        goto error;
    }

    io_cb->curl_ezh = curl_easy_init();
    if (!io_cb->curl_ezh) {
        nbd_dev_err(req->dev, "Failed to allocate easy handle.\n");
        ret = -ENOMEM;
        goto error;
    }

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_ERRORBUFFER, io_cb->errmsg);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TIMEOUT, azdev->io_timeout);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, azdev->write_request_url);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_POSTFIELDS, req->rwbuf);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_POSTFIELDSIZE, req->len);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
                "nbd-runner-azblk/1.0");

    // Throw away any error return message data so it does not go to stdout
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEFUNCTION,
             put_callback);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEDATA,
             (void *)&io_cb->ctx);

    io_cb->headers = curl_slist_append(io_cb->headers,
                       "x-ms-version: 2018-03-28");

    if (azdev->cfg.lease_id) {
        sprintf(buf, "x-ms-lease-id: %s", azdev->cfg.lease_id);
        io_cb->headers = curl_slist_append(io_cb->headers, buf);
    }

    io_cb->headers = curl_slist_append(io_cb->headers,
                       "x-ms-page-write: update");

    sprintf(buf, "Content-Length: %zd", req->len);
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    io_cb->headers = curl_slist_append(io_cb->headers, "Expect:");

    io_cb->headers = curl_slist_append(io_cb->headers,
                "Content-Type: application/octet-stream");

    sprintf(buf, "x-ms-range: bytes=%zd-%zd", req->offset,
             req->offset + (req->len - 1));
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    len = sprintf(buf, "x-ms-date: ");
    get_UTC(buf + len, sizeof(buf) - len);
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

    azblk_kick_start(azdev, io_cb);

    return;

error:

    if (io_cb && io_cb->curl_ezh) {
        curl_multi_remove_handle(azdev->curl_multi, io_cb->curl_ezh);
        curl_slist_free_all(io_cb->headers);
        curl_easy_cleanup(io_cb->curl_ezh);
    }

    free(io_cb);

    req->done(req, ret);
}

static void azblk_discard(struct nbd_handler_request *req)
{
    struct azblk_dev *azdev = req->dev->priv;
    struct azblk_io_cb *io_cb = NULL;
    char buf[128];
    int len;
    int ret;

    if (azdev->unmapping) {
        ret = -EIO;
        goto error;
    }

    io_cb = alloc_iocb(req);
    if (!io_cb) {
        ret = -ENOMEM;
        goto error;
    }

    io_cb->curl_ezh = curl_easy_init();
    if (!io_cb->curl_ezh) {
        nbd_dev_err(req->dev, "Failed to allocate easy handle.\n");
        ret = -ENOMEM;
        goto error;
    }

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_ERRORBUFFER, io_cb->errmsg);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TIMEOUT, azdev->io_timeout);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_URL, azdev->write_request_url);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_USERAGENT,
             "nbd-runner-azblk/1.0");

    // Throw away any error return message data so it does not go to stdout
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEFUNCTION,
             put_callback);
    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_WRITEDATA,
             (void *)&io_cb->ctx);
    io_cb->headers = curl_slist_append(io_cb->headers,
                       "x-ms-version: 2018-03-28");

    if (azdev->cfg.lease_id) {
        sprintf(buf, "x-ms-lease-id: %s", azdev->cfg.lease_id);
        io_cb->headers = curl_slist_append(io_cb->headers, buf);
    }

    io_cb->headers = curl_slist_append(io_cb->headers, "Content-Length: 0");

    io_cb->headers = curl_slist_append(io_cb->headers,
                       "x-ms-page-write: clear");

    sprintf(buf, "x-ms-range: bytes=%zd-%zd", req->offset,
            req->offset + (req->len - 1));
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    len = sprintf(buf, "x-ms-date: ");
    get_UTC(buf + len, sizeof(buf) - len);
    io_cb->headers = curl_slist_append(io_cb->headers, buf);

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_HTTPHEADER, io_cb->headers);

    // Set context associated with this easy handle

    curl_easy_setopt(io_cb->curl_ezh, CURLOPT_PRIVATE, (void *)io_cb);

    azblk_kick_start(azdev, io_cb);

    return;

error:

    if (io_cb && io_cb->curl_ezh) {
        curl_multi_remove_handle(azdev->curl_multi, io_cb->curl_ezh);
        curl_slist_free_all(io_cb->headers);
        curl_easy_cleanup(io_cb->curl_ezh);
    }

    free(io_cb);

    req->done(req, ret);
}

static void azblk_handle_request(gpointer data, gpointer user_data)
{
    struct nbd_handler_request *req;

    if (!data)
        return;

    req = (struct nbd_handler_request*)data;

    switch (req->cmd) {
    case NBD_CMD_WRITE:
        nbd_dbg_io("NBD_CMD_WRITE: offset: %zd, len: %zd\n", req->offset,
                   req->len);
        azblk_write(req);
        break;
    case NBD_CMD_READ:
        nbd_dbg_io("NBD_CMD_READ: offset: %zd, len: %zd\n", req->offset,
                   req->len);
        azblk_read(req);
        break;
    case NBD_CMD_FLUSH:
        nbd_dbg_io("NBD_CMD_FLUSH: offset: %zd, len: %zd\n", req->offset,
                   req->len);
        req->done(req, 0);
        break;
    case NBD_CMD_TRIM:
        nbd_dbg_io("NBD_CMD_TRIM: offset: %zd, len: %zd\n", req->offset,
                   req->len);
        azblk_discard(req);
        break;
    default:
        nbd_err("Invalid request command: %d.\n", req->cmd);
        return;
    }
}

static ssize_t azblk_get_size(struct nbd_device *dev, nbd_response *rep)
{
    struct azblk_dev *azdev = dev->priv;

    if (rep)
        rep->exit = 0;

    return azdev->cfg.size;
}

static ssize_t azblk_get_blksize(struct nbd_device *dev, nbd_response *rep)
{
    if (rep)
        rep->exit = 0;

    return 0;
}

static bool azblk_load_json(struct nbd_device *dev, json_object *devobj, char *key)
{
    struct azblk_dev *azdev = dev->priv;
    struct az_ret_header az_ret_header;
    json_object *obj;
    char *tmp;
    int ret;

    azdev = calloc(1, sizeof(*azdev));
    if (!azdev) {
        nbd_err("No memory for device.\n");
        return false;
    }

    if (json_object_object_get_ex(devobj, "sas", &obj)) {
        tmp = (char *)json_object_get_string(obj);
        if (tmp) {
            ret = asprintf(&azdev->cfg.sas, "%s", tmp);
            if (ret < 0) {
                nbd_err("No memory for config string.\n");
                goto error;
            }
        }
    }

    if (json_object_object_get_ex(devobj, "blob_url", &obj)) {
        tmp = (char *)json_object_get_string(obj);
        if (tmp) {
            ret = asprintf(&azdev->cfg.blob_url, "%s", tmp);
            if (ret < 0) {
                nbd_err("No memory for config string.\n");
                goto error;
            }
        }
    }

    if (json_object_object_get_ex(devobj, "lease_id", &obj)) {
        tmp = (char *)json_object_get_string(obj);
        if (tmp) {
            ret = asprintf(&azdev->cfg.lease_id, "%s", tmp);
            if (ret < 0) {
                nbd_err("No memory for config string.\n");
                goto error;
            }
        }
    }

    if (json_object_object_get_ex(devobj, "http", &obj)) {
        azdev->cfg.http = json_object_get_int(obj);
    }

    ret = azblk_get_blob_properties(azdev, &az_ret_header);

    if (ret == -EINVAL || ret == -ENOMEM) {
        nbd_err("Error getting Blob %s properties.\n", azdev->cfg.blob_url);
        goto error;
    }

    if (ret == -ENODEV) {
        nbd_err("Blob %s not found.\n", azdev->cfg.blob_url);
        goto error;
    }

    if (ret == 0 && dev->size != az_ret_header.max_size) {
        nbd_err("Blob %s properties do not match.\n", azdev->cfg.blob_url);
        goto error;
    }

    dev->priv = azdev;

    return true;

error:

    azdev_free(azdev);
    dev->priv = NULL;
    return false;
}

static bool azblk_update_json(struct nbd_device *dev, json_object *devobj)
{
    struct azblk_dev *azdev = dev->priv;
    json_object *obj = NULL;

    if (!azdev) {
        nbd_err("Device is not allocated\n");
        return false;
    }

    if (azdev->cfg.sas) {
        if (json_object_object_get_ex(devobj, "sas", &obj)) {
            json_object_set_string(obj, azdev->cfg.sas);
        } else {
            json_object_object_add(devobj, "sas",
                                   json_object_new_string(azdev->cfg.sas));
        }
    }

    if (azdev->cfg.blob_url) {
        if (json_object_object_get_ex(devobj, "blob_url", &obj)) {
            json_object_set_string(obj, azdev->cfg.blob_url);
        } else {
            json_object_object_add(devobj, "blob_url",
                                   json_object_new_string(azdev->cfg.blob_url));
        }
    }

    if (azdev->cfg.lease_id) {
        if (json_object_object_get_ex(devobj, "lease_id", &obj)) {
            json_object_set_string(obj, azdev->cfg.lease_id);
        } else {
            json_object_object_add(devobj, "lease_id",
                                   json_object_new_string(azdev->cfg.lease_id));
        }
    }

    if (json_object_object_get_ex(devobj, "http", &obj)) {
        json_object_set_int(obj, azdev->cfg.http);
    } else {
        json_object_object_add(devobj, "http",
                               json_object_new_int(azdev->cfg.http));
    }

    return true;
}

static void azblk_destroy(void)
{
    curl_global_cleanup();
}

static struct nbd_handler azblk_handler = {
    .name           = "Azure storage handler",
    .subtype        = NBD_BACKSTORE_AZBLK,
    .cfg_parse      = azblk_parse_config,
    .create         = azblk_add,
    .delete         = azblk_delete,
    .map            = azblk_map,
    .unmap          = azblk_unmap,
    .get_size       = azblk_get_size,
    .get_blksize    = azblk_get_blksize,
    .handle_request = azblk_handle_request,
    .destroy        = azblk_destroy,
    .load_json      = azblk_load_json,
    .update_json    = azblk_update_json,
};

struct nbd_handler *handler_init(const struct nbd_config *cfg)
{
    if (curl_global_init(CURL_GLOBAL_ALL)) {
        nbd_err("Could not initialize libcurl.\n");
        return NULL;
    }

    return &azblk_handler;
}
