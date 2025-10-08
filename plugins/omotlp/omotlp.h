/* omotlp.h
 * This is the OpenTelemetry Protocol (OTLP) output module.
 *
 * Copyright 2024 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OMOTLP_H_INCLUDED
#define OMOTLP_H_INCLUDED

#include "syslogd-types.h"

/* Forward declarations */
struct instanceConf_s;

/* Configuration parameters */
typedef struct omotlp_config_s {
    uchar *endpoint;           /* OTLP endpoint URL */
    uchar *path;               /* HTTP path (default: /v1/logs) */
    uchar *protocol;           /* "http/json" or "grpc" */
    uchar *bearer_token;       /* Bearer token for authentication */
    uchar *compression;        /* Compression: none, gzip */
    uchar *proxy;              /* HTTP proxy */
    uchar *ca_file;            /* CA certificate file */
    uchar *cert_file;          /* Client certificate file */
    uchar *key_file;           /* Client private key file */
    int verify_ssl;            /* Verify SSL certificates (0=off, 1=on) */
    int timeout_ms;            /* Request timeout in milliseconds */
    int batch_max_items;       /* Maximum batch size */
    int batch_max_bytes;       /* Maximum batch size in bytes */
    int batch_timeout_ms;      /* Batch timeout in milliseconds */
    int retry_max_retries;     /* Maximum number of retries */
    int retry_initial_ms;      /* Initial retry delay */
    int retry_max_ms;          /* Maximum retry delay */
    double retry_jitter;       /* Retry jitter factor */
    uchar *resource;           /* Resource attributes JSON */
    uchar *attribute_map;      /* Property to attribute mapping JSON */
    uchar *severity_map;       /* Severity mapping JSON */
    uchar *body_template;      /* Template for log body */
    uchar *trace_id_prop;      /* Property name for trace_id */
    uchar *span_id_prop;       /* Property name for span_id */
    uchar *trace_flags_prop;   /* Property name for trace_flags */
} omotlp_config_t;

/* Batch data structure */
typedef struct omotlp_batch_s {
    msg_t **messages;
    size_t count;
    size_t capacity;
    size_t total_bytes;
    time_t first_message_time;
    time_t last_flush_attempt;
    int retry_count;
} omotlp_batch_t;

/* Instance data for per-worker instances */
typedef struct omotlp_instance_s {
    struct instanceConf_s *pConf;
    omotlp_batch_t *current_batch;
    pthread_mutex_t batch_mutex;
} omotlp_instance_t;

/* Global module data */
typedef struct omotlp_data_s {
    omotlp_config_t config;    /* Global configuration */
    pthread_mutex_t mutex;     /* Module mutex */
    statsobj_t *stats;         /* Statistics object */
    /* Add global data here */
} omotlp_data_t;

/* Statistics counters */
STATSCOUNTER_DEF(sent, mutSent)
STATSCOUNTER_DEF(retried, mutRetried)
STATSCOUNTER_DEF(dropped, mutDropped)
STATSCOUNTER_DEF(http_2xx, mutHttp2xx)
STATSCOUNTER_DEF(http_4xx, mutHttp4xx)
STATSCOUNTER_DEF(http_5xx, mutHttp5xx)

/* Module entry points */
rsRetVal omotlp_initCnf(struct cnfobj *o);
rsRetVal omotlp_createInstance(instanceConf_t **pinst);
rsRetVal omotlp_freeInstance(void *pData);
rsRetVal omotlp_freeCnf(void *pData);

/* OTLP JSON builder functions */
rsRetVal omotlp_build_json_payload(struct json_object *logs_array);
rsRetVal omotlp_add_log_record(struct json_object *logs_array, msg_t *pMsg);
rsRetVal omotlp_build_otlp_json(msg_t **messages, size_t msg_count, uchar **payload, size_t *payload_len);

/* HTTP transport functions */
rsRetVal omotlp_http_init(void);
rsRetVal omotlp_http_send(const uchar *payload, size_t payload_len);
rsRetVal omotlp_http_send_with_retry(const uchar *payload, size_t payload_len, int attempt);
rsRetVal omotlp_http_cleanup(void);
rsRetVal omotlp_compress_gzip(const uchar *input, size_t input_len, uchar **output, size_t *output_len);

/* Batching functions */
rsRetVal omotlp_batch_init(omotlp_batch_t **batch);
rsRetVal omotlp_batch_add_message(omotlp_batch_t *batch, msg_t *pMsg);
rsRetVal omotlp_batch_flush(omotlp_batch_t *batch);
rsRetVal omotlp_batch_cleanup(omotlp_batch_t *batch);
int omotlp_batch_should_flush(omotlp_batch_t *batch, omotlp_config_t *config);

/* Utility functions */
rsRetVal omotlp_parse_config(omotlp_config_t *config, struct cnfobj *o);
int omotlp_should_retry(int http_status);
uint64_t omotlp_get_retry_delay(int attempt, int initial_ms, int max_ms, double jitter);

#endif /* OMOTLP_H_INCLUDED */