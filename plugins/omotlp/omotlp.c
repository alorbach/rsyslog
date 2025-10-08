/* omotlp.c
 * This is the OpenTelemetry Protocol (OTLP) output module.
 *
 * Phase 1: HTTP/JSON transport implementation
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
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <strings.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <json.h>
#include <zlib.h>
#if defined(__FreeBSD__)
    #include <unistd.h>
#endif
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "statsobj.h"
#include "cfsysline.h"
#include "unicode-helper.h"
#include "obj-types.h"
#include "ratelimit.h"
#include "ruleset.h"
#include "omotlp.h"

/* Optional gRPC bridge support */
#ifdef ENABLE_OMOTLP_GRPC
#include "grpc_bridge.h"
#endif

#ifndef O_LARGEFILE
    #define O_LARGEFILE 0
#endif

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omotlp")

/* Internal structures */
DEF_OMOD_STATIC_DATA;
DEFobjCurrIf(statsobj)
DEFobjCurrIf(prop)
DEFobjCurrIf(ruleset)

/* Global module data */
static omotlp_data_t *omotlp_data = NULL;

/* Optional gRPC bridge data */
#ifdef ENABLE_OMOTLP_GRPC
static omotlp_grpc_bridge_t *grpc_bridge = NULL;
#endif

/* Statistics counters */
STATSCOUNTER_DEF(sent, mutSent)
STATSCOUNTER_DEF(retried, mutRetried)
STATSCOUNTER_DEF(dropped, mutDropped)
STATSCOUNTER_DEF(http_2xx, mutHttp2xx)
STATSCOUNTER_DEF(http_4xx, mutHttp4xx)
STATSCOUNTER_DEF(http_5xx, mutHttp5xx)

/* Default configuration values */
#define DEFAULT_ENDPOINT "http://127.0.0.1:4318"
#define DEFAULT_PATH "/v1/logs"
#define DEFAULT_PROTOCOL "http/json"
#define DEFAULT_COMPRESSION "none"
#define DEFAULT_TIMEOUT_MS 30000
#define DEFAULT_BATCH_MAX_ITEMS 512
#define DEFAULT_BATCH_MAX_BYTES (1024 * 1024) /* 1MB */
#define DEFAULT_BATCH_TIMEOUT_MS 5000
#define DEFAULT_RETRY_MAX_RETRIES 5
#define DEFAULT_RETRY_INITIAL_MS 1000
#define DEFAULT_RETRY_MAX_MS 30000
#define DEFAULT_RETRY_JITTER 0.1
#define DEFAULT_VERIFY_SSL 1

/* Forward declarations */
static rsRetVal omotlp_tryResume(void);

/* Configuration parameter parsing functions */
static rsRetVal
omotlp_parse_endpoint(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *endpoint = NULL;
    if ((endpoint = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->endpoint = endpoint;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_protocol(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *protocol = NULL;
    if ((protocol = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->protocol = protocol;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_bearer_token(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *token = NULL;
    if ((token = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->bearer_token = token;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_compression(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *compression = NULL;
    if ((compression = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->compression = compression;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_batch_max_items(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->batch_max_items = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_batch_max_bytes(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->batch_max_bytes = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_batch_timeout_ms(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->batch_timeout_ms = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_retry_max_retries(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->retry_max_retries = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_retry_initial_ms(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->retry_initial_ms = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_retry_max_ms(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->retry_max_ms = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_retry_jitter(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->retry_jitter = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_timeout_ms(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->timeout_ms = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_path(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *path = NULL;
    if ((path = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    free(config->path);
    config->path = path;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_proxy(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *proxy = NULL;
    if ((proxy = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->proxy = proxy;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_ca_file(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *ca_file = NULL;
    if ((ca_file = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->ca_file = ca_file;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_cert_file(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *cert_file = NULL;
    if ((cert_file = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->cert_file = cert_file;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_key_file(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *key_file = NULL;
    if ((key_file = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->key_file = key_file;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_verify_ssl(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    config->verify_ssl = pvals->val.d.n;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_resource(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *resource = NULL;
    if ((resource = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->resource = resource;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_attribute_map(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *attribute_map = NULL;
    if ((attribute_map = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->attribute_map = attribute_map;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_severity_map(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *severity_map = NULL;
    if ((severity_map = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->severity_map = severity_map;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_body_template(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *body_template = NULL;
    if ((body_template = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->body_template = body_template;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_trace_id_prop(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *trace_id_prop = NULL;
    if ((trace_id_prop = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->trace_id_prop = trace_id_prop;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_span_id_prop(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *span_id_prop = NULL;
    if ((span_id_prop = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->span_id_prop = span_id_prop;
    return RS_RET_OK;
}

static rsRetVal
omotlp_parse_trace_flags_prop(struct cnfparamvals *pvals, omotlp_config_t *config)
{
    uchar *trace_flags_prop = NULL;
    if ((trace_flags_prop = (uchar*)es_str2cstr(pvals->val.d.estr, NULL)) == NULL)
        return RS_RET_ERR;
    config->trace_flags_prop = trace_flags_prop;
    return RS_RET_OK;
}

/* Initialize configuration with defaults */
static void
omotlp_init_config(omotlp_config_t *config)
{
    memset(config, 0, sizeof(omotlp_config_t));
    config->endpoint = (uchar*)strdup(DEFAULT_ENDPOINT);
    config->path = (uchar*)strdup(DEFAULT_PATH);
    config->protocol = (uchar*)strdup(DEFAULT_PROTOCOL);
    config->compression = (uchar*)strdup(DEFAULT_COMPRESSION);
    config->timeout_ms = DEFAULT_TIMEOUT_MS;
    config->batch_max_items = DEFAULT_BATCH_MAX_ITEMS;
    config->batch_max_bytes = DEFAULT_BATCH_MAX_BYTES;
    config->batch_timeout_ms = DEFAULT_BATCH_TIMEOUT_MS;
    config->retry_max_retries = DEFAULT_RETRY_MAX_RETRIES;
    config->retry_initial_ms = DEFAULT_RETRY_INITIAL_MS;
    config->retry_max_ms = DEFAULT_RETRY_MAX_MS;
    config->retry_jitter = DEFAULT_RETRY_JITTER;
    config->verify_ssl = DEFAULT_VERIFY_SSL;
}

/* Parse configuration parameters */
static rsRetVal
omotlp_parse_config(omotlp_config_t *config, struct cnfobj *o)
{
    struct cnfparamvals *pvals = NULL;
    int i;

    omotlp_init_config(config);

    CHKiRet(cnfParams(o, &pvals));

    for (i = 0; i < cnfParamsGetSize(o); i++) {
        struct cnfparamval *param = pvals + i;

        if (!strcmp(param->name, "endpoint")) {
            CHKiRet(omotlp_parse_endpoint(param, config));
        } else if (!strcmp(param->name, "protocol")) {
            CHKiRet(omotlp_parse_protocol(param, config));
        } else if (!strcmp(param->name, "bearer_token")) {
            CHKiRet(omotlp_parse_bearer_token(param, config));
        } else if (!strcmp(param->name, "compression")) {
            CHKiRet(omotlp_parse_compression(param, config));
        } else if (!strcmp(param->name, "batch.max_items")) {
            CHKiRet(omotlp_parse_batch_max_items(param, config));
        } else if (!strcmp(param->name, "batch.max_bytes")) {
            CHKiRet(omotlp_parse_batch_max_bytes(param, config));
        } else if (!strcmp(param->name, "batch.timeout_ms")) {
            CHKiRet(omotlp_parse_batch_timeout_ms(param, config));
        } else if (!strcmp(param->name, "retry.max_retries")) {
            CHKiRet(omotlp_parse_retry_max_retries(param, config));
        } else if (!strcmp(param->name, "retry.initial_ms")) {
            CHKiRet(omotlp_parse_retry_initial_ms(param, config));
        } else if (!strcmp(param->name, "retry.max_ms")) {
            CHKiRet(omotlp_parse_retry_max_ms(param, config));
        } else if (!strcmp(param->name, "retry.jitter")) {
            CHKiRet(omotlp_parse_retry_jitter(param, config));
        } else if (!strcmp(param->name, "timeout_ms")) {
            CHKiRet(omotlp_parse_timeout_ms(param, config));
        } else if (!strcmp(param->name, "path")) {
            CHKiRet(omotlp_parse_path(param, config));
        } else if (!strcmp(param->name, "proxy")) {
            CHKiRet(omotlp_parse_proxy(param, config));
        } else if (!strcmp(param->name, "ca_file")) {
            CHKiRet(omotlp_parse_ca_file(param, config));
        } else if (!strcmp(param->name, "cert_file")) {
            CHKiRet(omotlp_parse_cert_file(param, config));
        } else if (!strcmp(param->name, "key_file")) {
            CHKiRet(omotlp_parse_key_file(param, config));
        } else if (!strcmp(param->name, "verify_ssl")) {
            CHKiRet(omotlp_parse_verify_ssl(param, config));
        } else if (!strcmp(param->name, "resource")) {
            CHKiRet(omotlp_parse_resource(param, config));
        } else if (!strcmp(param->name, "attribute_map")) {
            CHKiRet(omotlp_parse_attribute_map(param, config));
        } else if (!strcmp(param->name, "severity_map")) {
            CHKiRet(omotlp_parse_severity_map(param, config));
        } else if (!strcmp(param->name, "body_template")) {
            CHKiRet(omotlp_parse_body_template(param, config));
        } else if (!strcmp(param->name, "trace_id_prop")) {
            CHKiRet(omotlp_parse_trace_id_prop(param, config));
        } else if (!strcmp(param->name, "span_id_prop")) {
            CHKiRet(omotlp_parse_span_id_prop(param, config));
        } else if (!strcmp(param->name, "trace_flags_prop")) {
            CHKiRet(omotlp_parse_trace_flags_prop(param, config));
        } else {
            DBGPRINTF("omotlp: unknown parameter '%s'\n", param->name);
        }
    }

finalize_it:
    if (pvals != NULL)
        cnfparamvalsDestruct(pvals, NULL);

    return RS_RET_OK;
}

/* Module initialization */
BEGINmodInit(omotlp)
{
    if ((omotlp_data = calloc(1, sizeof(omotlp_data_t))) == NULL) {
        DBGPRINTF("omotlp: failed to allocate module data\n");
        return RS_RET_OUT_OF_MEMORY;
    }

    /* Initialize mutex */
    pthread_mutex_init(&omotlp_data->mutex, NULL);

    /* Initialize statistics */
    CHKiRet(statsobj.Construct(&omotlp_data->stats));
    CHKiRet(statsobj.SetName(omotlp_data->stats, (uchar*)"omotlp"));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"sent", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(sent)));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"retried", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(retried)));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"dropped", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(dropped)));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"http_2xx", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(http_2xx)));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"http_4xx", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(http_4xx)));
    CHKiRet(statsobj.AddCounter(omotlp_data->stats, (uchar*)"http_5xx", ctrType_IntCtr, CTR_FLAG_RESETTABLE, MUT(http_5xx)));
    STATSCOUNTER_INIT(sent, mutSent);
    STATSCOUNTER_INIT(retried, mutRetried);
    STATSCOUNTER_INIT(dropped, mutDropped);
    STATSCOUNTER_INIT(http_2xx, mutHttp2xx);
    STATSCOUNTER_INIT(http_4xx, mutHttp4xx);
    STATSCOUNTER_INIT(http_5xx, mutHttp5xx);

    CHKiRet(statsobj.ConstructFinalize(omotlp_data->stats));

finalize_it:
    return RS_RET_OK;
}

/* Module deinitialization */
BEGINmodExit(omotlp)
{
    if (omotlp_data != NULL) {
        if (omotlp_data->stats != NULL) {
            statsobj.Destruct(&omotlp_data->stats);
        }
        pthread_mutex_destroy(&omotlp_data->mutex);

        /* Cleanup HTTP transport */
        omotlp_http_cleanup();

        /* Cleanup gRPC bridge if available */
#ifdef ENABLE_OMOTLP_GRPC
        omotlp_grpc_cleanup_bridge();
#endif

        free(omotlp_data);
        omotlp_data = NULL;
    }
}

/* Initialize configuration object */
rsRetVal
omotlp_initCnf(struct cnfobj *o)
{
    omotlp_config_t *config;

    if ((config = calloc(1, sizeof(omotlp_config_t))) == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }

    omotlp_parse_config(config, o);

    o->pModData = config;
    return RS_RET_OK;
}

/* Create action instance */
rsRetVal
omotlp_createInstance(instanceConf_t **pinst)
{
    omotlp_instance_t *instance;
    instanceConf_t *inst;

    if ((inst = calloc(1, sizeof(instanceConf_t))) == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }

    if ((instance = calloc(1, sizeof(omotlp_instance_t))) == NULL) {
        free(inst);
        return RS_RET_OUT_OF_MEMORY;
    }

    /* Initialize batch */
    if (omotlp_batch_init(&instance->current_batch) != RS_RET_OK) {
        free(instance);
        free(inst);
        return RS_RET_OUT_OF_MEMORY;
    }

    /* Initialize batch mutex */
    pthread_mutex_init(&instance->batch_mutex, NULL);

    inst->pModData = instance;
    *pinst = inst;

    return RS_RET_OK;
}

/* Free action instance */
rsRetVal
omotlp_freeInstance(void *pData)
{
    omotlp_instance_t *instance = (omotlp_instance_t*)pData;

    if (instance != NULL) {
        /* Flush any remaining messages in the batch */
        if (instance->current_batch != NULL) {
            omotlp_batch_flush(instance->current_batch);
            omotlp_batch_cleanup(instance->current_batch);
        }

        /* Destroy mutex */
        pthread_mutex_destroy(&instance->batch_mutex);

        free(instance);
    }

    return RS_RET_OK;
}

/* Free configuration */
rsRetVal
omotlp_freeCnf(void *pData)
{
    omotlp_config_t *config = (omotlp_config_t*)pData;

    if (config != NULL) {
        free(config->endpoint);
        free(config->path);
        free(config->protocol);
        free(config->bearer_token);
        free(config->compression);
        free(config->proxy);
        free(config->ca_file);
        free(config->cert_file);
        free(config->key_file);
        free(config->resource);
        free(config->attribute_map);
        free(config->severity_map);
        free(config->body_template);
        free(config->trace_id_prop);
        free(config->span_id_prop);
        free(config->trace_flags_prop);
        free(config);
    }

    return RS_RET_OK;
}

/* OTLP severity mapping */
static int
omotlp_map_severity(int syslog_severity)
{
    /* Map syslog severity to OTLP severity numbers:
     * 0=INVALID, 1=TRACE, 2=TRACE2, 3=TRACE3, 4=TRACE4,
     * 5=DEBUG, 6=DEBUG2, 7=DEBUG3, 8=DEBUG4,
     * 9=INFO, 10=INFO2, 11=INFO3, 12=INFO4,
     * 13=WARN, 14=WARN2, 15=WARN3, 16=WARN4,
     * 17=ERROR, 18=ERROR2, 19=ERROR3, 20=ERROR4,
     * 21=FATAL, 22=FATAL2, 23=FATAL3, 24=FATAL4
     */
    switch (syslog_severity) {
        case 0: return 2;   /* Emergency -> TRACE2 */
        case 1: return 21;  /* Alert -> FATAL */
        case 2: return 20;  /* Critical -> ERROR4 */
        case 3: return 17;  /* Error -> ERROR */
        case 4: return 13;  /* Warning -> WARN */
        case 5: return 9;   /* Notice -> INFO */
        case 6: return 5;   /* Info -> DEBUG */
        case 7: return 1;   /* Debug -> TRACE */
        default: return 9;  /* Default to INFO */
    }
}

/* OTLP severity text mapping */
static const char*
omotlp_map_severity_text(int syslog_severity)
{
    switch (syslog_severity) {
        case 0: return "TRACE2";
        case 1: return "FATAL";
        case 2: return "ERROR4";
        case 3: return "ERROR";
        case 4: return "WARN";
        case 5: return "INFO";
        case 6: return "DEBUG";
        case 7: return "TRACE";
        default: return "INFO";
    }
}

/* Build OTLP log record JSON */
rsRetVal
omotlp_build_json_payload(struct json_object *logs_array)
{
    /* This will be implemented in the next phase */
    return RS_RET_OK;
}

/* Build complete OTLP ExportLogsServiceRequest JSON structure */
rsRetVal
omotlp_build_otlp_json(msg_t **messages, size_t msg_count, uchar **payload, size_t *payload_len)
{
    struct json_object *request = json_object_new_object();
    struct json_object *resource_logs = json_object_new_array();
    struct json_object *resource = json_object_new_object();
    struct json_object *scope_logs = json_object_new_array();
    struct json_object *scope = json_object_new_object();
    struct json_object *log_records = json_object_new_array();
    struct json_object *schema_url = json_object_new_string("https://opentelemetry.io/schemas/1.21.0");
    struct json_object *scope_schema_url = json_object_new_string("https://opentelemetry.io/schemas/1.21.0");
    int i;

    if (request == NULL || resource_logs == NULL || resource == NULL ||
        scope_logs == NULL || scope == NULL || log_records == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: failed to allocate JSON objects");
        if (request) json_object_put(request);
        if (resource_logs) json_object_put(resource_logs);
        if (resource) json_object_put(resource);
        if (scope_logs) json_object_put(scope_logs);
        if (scope) json_object_put(scope);
        if (log_records) json_object_put(log_records);
        return RS_RET_ERR;
    }

    /* Add resource attributes (default service info) */
    json_object_object_add(resource, "service.name", json_object_new_string("rsyslog"));
    json_object_object_add(resource, "service.version", json_object_new_string("8.2510.0"));

    /* Add scope information */
    json_object_object_add(scope, "name", json_object_new_string("io.rsyslog.omotlp"));
    json_object_object_add(scope, "version", json_object_new_string("1.0.0"));
    json_object_object_add(scope, "schema_url", scope_schema_url);

    /* Build log records */
    for (i = 0; i < msg_count; i++) {
        msg_t *pMsg = messages[i];
        struct json_object *record = json_object_new_object();
        struct json_object *timestamp = json_object_new_int64(pMsg->ttGenTime * 1000000000ULL);
        struct json_object *body = json_object_new_string((char*)getMSG(pMsg));
        struct json_object *severity_number = json_object_new_int(omotlp_map_severity(pMsg->iSeverity));
        struct json_object *severity_text = json_object_new_string(omotlp_map_severity_text(pMsg->iSeverity));

        if (record == NULL || timestamp == NULL || body == NULL ||
            severity_number == NULL || severity_text == NULL) {
            LogError(0, RS_RET_ERR, "omotlp: failed to allocate JSON objects for log record");
            if (record) json_object_put(record);
            if (timestamp) json_object_put(timestamp);
            if (body) json_object_put(body);
            if (severity_number) json_object_put(severity_number);
            if (severity_text) json_object_put(severity_text);
            goto cleanup;
        }

        /* Add basic log record fields */
        json_object_object_add(record, "time_unix_nano", timestamp);
        json_object_object_add(record, "body", body);
        json_object_object_add(record, "severity_number", severity_number);
        json_object_object_add(record, "severity_text", severity_text);

        /* Add attributes */
        struct json_object *attributes = json_object_new_object();
        if (attributes != NULL) {
            /* Add syslog-specific attributes */
            json_object_object_add(attributes, "syslog.facility", json_object_new_int(pMsg->iFacility));
            json_object_object_add(attributes, "syslog.severity", json_object_new_int(pMsg->iSeverity));
            json_object_object_add(attributes, "syslog.priority", json_object_new_int(pMsg->iFacility * 8 + pMsg->iSeverity));

            /* Add hostname if available */
            if (pMsg->pszHOSTNAME != NULL && strlen((char*)pMsg->pszHOSTNAME) > 0) {
                json_object_object_add(attributes, "host.name", json_object_new_string((char*)pMsg->pszHOSTNAME));
            }

            /* Add app name if available */
            if (pMsg->pszAPPNAME != NULL && strlen((char*)pMsg->pszAPPNAME) > 0) {
                json_object_object_add(attributes, "syslog.app_name", json_object_new_string((char*)pMsg->pszAPPNAME));
            }

            /* Add process ID if available */
            if (pMsg->pszPROCID != NULL && strlen((char*)pMsg->pszPROCID) > 0) {
                json_object_object_add(attributes, "syslog.procid", json_object_new_string((char*)pMsg->pszPROCID));
            }

            /* Add message ID if available */
            if (pMsg->pszMSGID != NULL && strlen((char*)pMsg->pszMSGID) > 0) {
                json_object_object_add(attributes, "syslog.msgid", json_object_new_string((char*)pMsg->pszMSGID));
            }

            json_object_object_add(record, "attributes", attributes);
        }

        json_object_array_add(log_records, record);
    }

    /* Build the complete structure */
    json_object_object_add(scope, "log_records", log_records);
    json_object_array_add(scope_logs, scope);
    json_object_object_add(resource, "schema_url", schema_url);
    json_object_object_add(resource, "scope_logs", scope_logs);

    struct json_object *resource_log = json_object_new_object();
    json_object_object_add(resource_log, "resource", resource);
    json_object_array_add(resource_logs, resource_log);

    json_object_object_add(request, "resource_logs", resource_logs);

    /* Convert to string */
    const char *json_str = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PRETTY);
    if (json_str == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: failed to convert JSON to string");
        goto cleanup;
    }

    *payload_len = strlen(json_str);
    *payload = (uchar*)strdup(json_str);

    if (*payload == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: failed to allocate payload buffer");
        goto cleanup;
    }

    DBGPRINTF("omotlp: built OTLP JSON payload: %zu bytes, %zu records\n", *payload_len, msg_count);

cleanup:
    json_object_put(request);
    return (*payload != NULL) ? RS_RET_OK : RS_RET_ERR;
}

/* Add a single log record to the batch */
rsRetVal
omotlp_add_log_record(struct json_object *logs_array, msg_t *pMsg)
{
    struct json_object *record = json_object_new_object();
    struct json_object *timestamp = json_object_new_int64(pMsg->ttGenTime * 1000000000ULL);
    struct json_object *body = json_object_new_string((char*)getMSG(pMsg));
    struct json_object *severity_number = json_object_new_int(omotlp_map_severity(pMsg->iSeverity));
    struct json_object *severity_text = json_object_new_string(omotlp_map_severity_text(pMsg->iSeverity));

    json_object_object_add(record, "time_unix_nano", timestamp);
    json_object_object_add(record, "body", body);
    json_object_object_add(record, "severity_number", severity_number);
    json_object_object_add(record, "severity_text", severity_text);

    json_object_array_add(logs_array, record);

    return RS_RET_OK;
}

/* HTTP response callback for libcurl */
static size_t
omotlp_http_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    /* For now, we ignore the response body */
    return size * nmemb;
}

/* HTTP response info callback for getting response code and headers */
static size_t
omotlp_http_header_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    /* For now, we ignore response headers */
    return size * nmemb;
}

/* Initialize HTTP transport */
rsRetVal
omotlp_http_init(void)
{
    /* Initialize libcurl globally if not already done */
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LogError(0, RS_RET_ERR, "omotlp: failed to initialize libcurl");
        return RS_RET_ERR;
    }

    return RS_RET_OK;
}

/* Send HTTP request with retry logic */
rsRetVal
omotlp_http_send(const uchar *payload, size_t payload_len)
{
    return omotlp_http_send_with_retry(payload, payload_len, 0);
}

/* Send HTTP request with retry logic (internal) */
rsRetVal
omotlp_http_send_with_retry(const uchar *payload, size_t payload_len, int attempt)
{
    CURL *curl;
    CURLcode res;
    long response_code;
    struct curl_slist *headers = NULL;
    uchar *compressed_payload = NULL;
    size_t compressed_len = payload_len;
    rsRetVal ret = RS_RET_OK;

    curl = curl_easy_init();
    if (curl == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: failed to create curl handle");
        return RS_RET_ERR;
    }

    /* Set URL */
    char *url = malloc(strlen((char*)omotlp_data->config.endpoint) +
                      strlen((char*)omotlp_data->config.path) + 1);
    sprintf(url, "%s%s", omotlp_data->config.endpoint, omotlp_data->config.path);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Set headers */
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    if (omotlp_data->config.bearer_token != NULL) {
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
                omotlp_data->config.bearer_token);
        headers = curl_slist_append(headers, auth_header);
    }

    /* Handle compression */
    if (strcmp((char*)omotlp_data->config.compression, "gzip") == 0) {
        if (omotlp_compress_gzip(payload, payload_len, &compressed_payload, &compressed_len) == RS_RET_OK) {
            headers = curl_slist_append(headers, "Content-Encoding: gzip");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)compressed_payload);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, compressed_len);
        } else {
            /* Fallback to uncompressed if compression fails */
            headers = curl_slist_append(headers, "Content-Encoding: identity");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)payload);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_len);
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*)payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_len);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set response callbacks */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, omotlp_http_write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, omotlp_http_header_callback);

    /* Set timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, omotlp_data->config.timeout_ms);

    /* Set SSL options */
    if (omotlp_data->config.verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (omotlp_data->config.ca_file != NULL) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, (char*)omotlp_data->config.ca_file);
    }

    if (omotlp_data->config.cert_file != NULL && omotlp_data->config.key_file != NULL) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, (char*)omotlp_data->config.cert_file);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, (char*)omotlp_data->config.key_file);
    }

    /* Set proxy if configured */
    if (omotlp_data->config.proxy != NULL) {
        curl_easy_setopt(curl, CURLOPT_PROXY, (char*)omotlp_data->config.proxy);
    }

    /* Perform the request */
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        LogError(0, RS_RET_ERR, "omotlp: curl_easy_perform() failed: %s",
                curl_easy_strerror(res));

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(url);
        if (compressed_payload) free(compressed_payload);

        /* Check if we should retry */
        if (attempt < omotlp_data->config.retry_max_retries &&
            (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_COULDNT_CONNECT)) {
            uint64_t delay = omotlp_get_retry_delay(attempt, omotlp_data->config.retry_initial_ms,
                                                   omotlp_data->config.retry_max_ms,
                                                   omotlp_data->config.retry_jitter);
            DBGPRINTF("omotlp: retrying request in %llu ms (attempt %d/%d)\n",
                     delay, attempt + 1, omotlp_data->config.retry_max_retries);

            srSleep(delay / 1000, delay % 1000);
            STATSCOUNTER_INC(retried, mutRetried);
            return omotlp_http_send_with_retry(payload, payload_len, attempt + 1);
        }

        return RS_RET_ERR;
    }

    /* Get response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    /* Update statistics */
    if (response_code >= 200 && response_code < 300) {
        STATSCOUNTER_INC(sent, mutSent);
        STATSCOUNTER_INC(http_2xx, mutHttp2xx);
    } else if (response_code >= 400 && response_code < 500) {
        STATSCOUNTER_INC(http_4xx, mutHttp4xx);
        /* For 4xx errors, we typically don't retry unless it's 429 */
        if (response_code == 429 && attempt < omotlp_data->config.retry_max_retries) {
            uint64_t delay = omotlp_get_retry_delay(attempt, omotlp_data->config.retry_initial_ms,
                                                   omotlp_data->config.retry_max_ms,
                                                   omotlp_data->config.retry_jitter);
            DBGPRINTF("omotlp: 429 Too Many Requests, retrying in %llu ms (attempt %d/%d)\n",
                     delay, attempt + 1, omotlp_data->config.retry_max_retries);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(url);
            if (compressed_payload) free(compressed_payload);

            srSleep(delay / 1000, delay % 1000);
            STATSCOUNTER_INC(retried, mutRetried);
            return omotlp_http_send_with_retry(payload, payload_len, attempt + 1);
        }
    } else if (response_code >= 500) {
        STATSCOUNTER_INC(http_5xx, mutHttp5xx);
        /* Retry on 5xx errors */
        if (attempt < omotlp_data->config.retry_max_retries) {
            uint64_t delay = omotlp_get_retry_delay(attempt, omotlp_data->config.retry_initial_ms,
                                                   omotlp_data->config.retry_max_ms,
                                                   omotlp_data->config.retry_jitter);
            DBGPRINTF("omotlp: 5xx error, retrying in %llu ms (attempt %d/%d)\n",
                     delay, attempt + 1, omotlp_data->config.retry_max_retries);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(url);
            if (compressed_payload) free(compressed_payload);

            srSleep(delay / 1000, delay % 1000);
            STATSCOUNTER_INC(retried, mutRetried);
            return omotlp_http_send_with_retry(payload, payload_len, attempt + 1);
        }
    }

    DBGPRINTF("omotlp: HTTP response code: %ld (attempt %d)\n", response_code, attempt);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    if (compressed_payload) free(compressed_payload);

    return ret;
}

/* Compress data using gzip */
rsRetVal
omotlp_compress_gzip(const uchar *input, size_t input_len, uchar **output, size_t *output_len)
{
    z_stream strm;
    int ret;
    size_t compressed_size = compressBound(input_len);

    *output = malloc(compressed_size);
    if (*output == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }

    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + 15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        free(*output);
        *output = NULL;
        return RS_RET_ERR;
    }

    strm.next_in = (Bytef*)input;
    strm.avail_in = input_len;
    strm.next_out = (Bytef*)*output;
    strm.avail_out = compressed_size;

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        free(*output);
        *output = NULL;
        return RS_RET_ERR;
    }

    *output_len = strm.total_out;

    deflateEnd(&strm);
    return RS_RET_OK;
}

/* Cleanup HTTP transport */
rsRetVal
omotlp_http_cleanup(void)
{
    curl_global_cleanup();
    return RS_RET_OK;
}

/* Check if we should retry based on HTTP status code */
int
omotlp_should_retry(int http_status)
{
    /* Retry on 5xx errors and 429 (Too Many Requests) */
    return (http_status >= 500) || (http_status == 429);
}

/* Calculate retry delay with exponential backoff and jitter */
uint64_t
omotlp_get_retry_delay(int attempt, int initial_ms, int max_ms, double jitter)
{
    uint64_t delay = (uint64_t)initial_ms * (1ULL << attempt);
    if (delay > max_ms) {
        delay = max_ms;
    }

    /* Add jitter */
    double jitter_factor = 1.0 + (jitter * (2.0 * rand() / RAND_MAX - 1.0));
    delay = (uint64_t)(delay * jitter_factor);

    return delay;
}

/* Initialize batch */
rsRetVal
omotlp_batch_init(omotlp_batch_t **batch)
{
    omotlp_batch_t *b;

    if ((b = calloc(1, sizeof(omotlp_batch_t))) == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }

    b->capacity = 100; /* Initial capacity */
    if ((b->messages = calloc(b->capacity, sizeof(msg_t*))) == NULL) {
        free(b);
        return RS_RET_OUT_OF_MEMORY;
    }

    b->count = 0;
    b->total_bytes = 0;
    b->first_message_time = 0;
    b->last_flush_attempt = 0;
    b->retry_count = 0;

    *batch = b;
    return RS_RET_OK;
}

/* Add message to batch */
rsRetVal
omotlp_batch_add_message(omotlp_batch_t *batch, msg_t *pMsg)
{
    /* Check if we need to resize */
    if (batch->count >= batch->capacity) {
        size_t new_capacity = batch->capacity * 2;
        msg_t **new_messages = realloc(batch->messages, new_capacity * sizeof(msg_t*));
        if (new_messages == NULL) {
            return RS_RET_OUT_OF_MEMORY;
        }
        batch->messages = new_messages;
        batch->capacity = new_capacity;
    }

    /* Add message */
    batch->messages[batch->count] = pMsg;
    batch->count++;

    /* Update total bytes estimate */
    batch->total_bytes += getMSGLen(pMsg) + 200; /* Rough estimate with JSON overhead */

    /* Set first message time if this is the first message */
    if (batch->count == 1) {
        batch->first_message_time = time(NULL);
    }

    return RS_RET_OK;
}

/* Check if batch should be flushed */
int
omotlp_batch_should_flush(omotlp_batch_t *batch, omotlp_config_t *config)
{
    time_t now = time(NULL);

    /* Flush if we've reached max items */
    if (batch->count >= (size_t)config->batch_max_items) {
        return 1;
    }

    /* Flush if we've reached max bytes */
    if (batch->total_bytes >= (size_t)config->batch_max_bytes) {
        return 1;
    }

    /* Flush if timeout has been reached */
    if (batch->first_message_time > 0 &&
        (now - batch->first_message_time) * 1000 >= config->batch_timeout_ms) {
        return 1;
    }

    return 0;
}

/* Flush batch to OTLP */
rsRetVal
omotlp_batch_flush(omotlp_batch_t *batch)
{
    rsRetVal ret = RS_RET_OK;

    if (batch->count == 0) {
        return RS_RET_OK; /* Nothing to flush */
    }

    DBGPRINTF("omotlp: flushing batch with %zu messages (%zu bytes)\n",
             batch->count, batch->total_bytes);

#ifdef ENABLE_OMOTLP_GRPC
    /* Try gRPC transport if available and configured */
    if (grpc_bridge != NULL && strcmp((char*)omotlp_data->config.protocol, "grpc") == 0) {
        ret = omotlp_grpc_send_batch(batch);
        if (ret == RS_RET_OK) {
            DBGPRINTF("omotlp: successfully sent batch via gRPC of %zu messages\n", batch->count);
            goto reset_batch;
        } else {
            LogError(0, RS_RET_ERR, "omotlp: failed to send via gRPC, falling back to HTTP");
        }
    }
#endif

    /* Fall back to HTTP transport */
    {
        uchar *payload = NULL;
        size_t payload_len = 0;

        /* Build OTLP JSON payload */
        ret = omotlp_build_otlp_json(batch->messages, batch->count, &payload, &payload_len);
        if (ret != RS_RET_OK || payload == NULL) {
            LogError(0, RS_RET_ERR, "omotlp: failed to build JSON payload");
            STATSCOUNTER_INC(dropped, mutDropped);
            goto cleanup;
        }

        /* Send via HTTP */
        ret = omotlp_http_send(payload, payload_len);
        if (ret != RS_RET_OK) {
            LogError(0, RS_RET_ERR, "omotlp: failed to send HTTP request");
            STATSCOUNTER_INC(dropped, mutDropped);
            goto cleanup;
        }

        DBGPRINTF("omotlp: successfully sent batch via HTTP of %zu messages\n", batch->count);

    cleanup:
        if (payload != NULL) {
            free(payload);
        }
    }

reset_batch:
    /* Reset batch */
    batch->count = 0;
    batch->total_bytes = 0;
    batch->first_message_time = 0;
    batch->last_flush_attempt = time(NULL);
    batch->retry_count = 0;

    return ret;
}

/* Cleanup batch */
rsRetVal
omotlp_batch_cleanup(omotlp_batch_t *batch)
{
    if (batch != NULL) {
        if (batch->messages != NULL) {
            free(batch->messages);
        }
        free(batch);
    }
    return RS_RET_OK;
}

/* Action entry point - process a message */
BEGINdoAction(omotlp)
{
    omotlp_instance_t *instance = (omotlp_instance_t*) pData;
    omotlp_config_t *config = &omotlp_data->config;
    rsRetVal ret = RS_RET_OK;

    if (instance == NULL || instance->current_batch == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: instance or batch not initialized");
        return RS_RET_ERR;
    }

    /* Lock batch mutex */
    pthread_mutex_lock(&instance->batch_mutex);

    /* Add message to batch */
    ret = omotlp_batch_add_message(instance->current_batch, ppMsg);
    if (ret != RS_RET_OK) {
        LogError(0, RS_RET_ERR, "omotlp: failed to add message to batch");
        pthread_mutex_unlock(&instance->batch_mutex);
        return ret;
    }

    /* Check if batch should be flushed */
    if (omotlp_batch_should_flush(instance->current_batch, config)) {
        /* Unlock before flushing to avoid deadlock */
        pthread_mutex_unlock(&instance->batch_mutex);

        /* Flush the batch */
        ret = omotlp_batch_flush(instance->current_batch);

        /* Re-lock after flushing */
        pthread_mutex_lock(&instance->batch_mutex);
    }

    pthread_mutex_unlock(&instance->batch_mutex);

    return ret;
}

/* Resume processing (called when action becomes ready again) */
static rsRetVal
omotlp_tryResume(void)
{
    /* This is a placeholder - will be implemented with batching */
    return RS_RET_OK;
}

/* Initialize gRPC bridge */
#ifdef ENABLE_OMOTLP_GRPC
rsRetVal
omotlp_grpc_init_bridge(void)
{
    if (grpc_bridge != NULL) {
        return RS_RET_OK; /* Already initialized */
    }

    omotlp_grpc_config_t grpc_config;

    /* Convert rsyslog config to gRPC bridge config */
    grpc_config.endpoint = (char*)omotlp_data->config.endpoint;
    grpc_config.bearer_token = (char*)omotlp_data->config.bearer_token;
    grpc_config.ca_file = (char*)omotlp_data->config.ca_file;
    grpc_config.cert_file = (char*)omotlp_data->config.cert_file;
    grpc_config.key_file = (char*)omotlp_data->config.key_file;
    grpc_config.verify_ssl = omotlp_data->config.verify_ssl;
    grpc_config.timeout_ms = omotlp_data->config.timeout_ms;
    grpc_config.compression = (strcmp((char*)omotlp_data->config.compression, "gzip") == 0) ? 1 : 0;
    grpc_config.batch_max_items = omotlp_data->config.batch_max_items;
    grpc_config.batch_max_bytes = omotlp_data->config.batch_max_bytes;
    grpc_config.batch_timeout_ms = omotlp_data->config.batch_timeout_ms;

    if (omotlp_grpc_init(&grpc_config, &grpc_bridge) != 0) {
        LogError(0, RS_RET_ERR, "omotlp: failed to initialize gRPC bridge: %s",
                omotlp_grpc_get_error());
        return RS_RET_ERR;
    }

    DBGPRINTF("omotlp: gRPC bridge initialized successfully\n");
    return RS_RET_OK;
}

/* Send batch via gRPC */
int
omotlp_grpc_send_batch(omotlp_batch_t *batch)
{
    if (batch->count == 0) {
        return 0; /* Nothing to send */
    }

    /* Convert batch messages to gRPC log records */
    omotlp_log_record_t *records = (omotlp_log_record_t*)malloc(batch->count * sizeof(omotlp_log_record_t));
    if (records == NULL) {
        LogError(0, RS_RET_ERR, "omotlp: failed to allocate gRPC records");
        return -1;
    }

    for (size_t i = 0; i < batch->count; i++) {
        msg_t *pMsg = batch->messages[i];

        records[i].time_unix_nano = pMsg->ttGenTime * 1000000000ULL;
        records[i].body = (char*)getMSG(pMsg);
        records[i].severity_number = omotlp_map_severity(pMsg->iSeverity);
        records[i].severity_text = omotlp_map_severity_text(pMsg->iSeverity);
        records[i].hostname = (pMsg->pszHOSTNAME != NULL) ? (char*)pMsg->pszHOSTNAME : NULL;
        records[i].app_name = (pMsg->pszAPPNAME != NULL) ? (char*)pMsg->pszAPPNAME : NULL;
        records[i].procid = (pMsg->pszPROCID != NULL) ? (char*)pMsg->pszPROCID : NULL;
        records[i].msgid = (pMsg->pszMSGID != NULL) ? (char*)pMsg->pszMSGID : NULL;
        records[i].facility = pMsg->iFacility;
        records[i].severity = pMsg->iSeverity;
        records[i].priority = pMsg->iFacility * 8 + pMsg->iSeverity;

        /* Set trace correlation if available */
        if (omotlp_data->config.trace_id_prop != NULL) {
            /* Extract trace_id from message properties */
            records[i].trace_id = NULL; /* Would need property extraction logic */
        }
        if (omotlp_data->config.span_id_prop != NULL) {
            records[i].span_id = NULL; /* Would need property extraction logic */
        }
        if (omotlp_data->config.trace_flags_prop != NULL) {
            records[i].trace_flags = NULL; /* Would need property extraction logic */
        }
    }

    /* Send via gRPC */
    int ret = omotlp_grpc_emit(grpc_bridge, records, batch->count);

    free(records);

    if (ret != 0) {
        LogError(0, RS_RET_ERR, "omotlp: gRPC emit failed: %s", omotlp_grpc_get_error());
        return ret;
    }

    return 0;
}

/* Flush gRPC bridge */
rsRetVal
omotlp_grpc_flush_bridge(void)
{
    if (grpc_bridge == NULL) {
        return RS_RET_OK;
    }

    if (omotlp_grpc_flush(grpc_bridge) != 0) {
        LogError(0, RS_RET_ERR, "omotlp: gRPC flush failed: %s", omotlp_grpc_get_error());
        return RS_RET_ERR;
    }

    return RS_RET_OK;
}

/* Cleanup gRPC bridge */
rsRetVal
omotlp_grpc_cleanup_bridge(void)
{
    if (grpc_bridge != NULL) {
        if (omotlp_grpc_shutdown(&grpc_bridge) != 0) {
            LogError(0, RS_RET_ERR, "omotlp: gRPC shutdown failed: %s", omotlp_grpc_get_error());
            return RS_RET_ERR;
        }
        grpc_bridge = NULL;
    }

    return RS_RET_OK;
}
#endif

/* Configuration parameter definitions */
static struct cnfparamdescr cnfparamdescr[] = {
    { "endpoint", eCmdHdlrGetWord, 0 },
    { "protocol", eCmdHdlrGetWord, 0 },
    { "path", eCmdHdlrGetWord, 0 },
    { "bearer_token", eCmdHdlrGetWord, 0 },
    { "compression", eCmdHdlrGetWord, 0 },
    { "proxy", eCmdHdlrGetWord, 0 },
    { "ca_file", eCmdHdlrGetWord, 0 },
    { "cert_file", eCmdHdlrGetWord, 0 },
    { "key_file", eCmdHdlrGetWord, 0 },
    { "verify_ssl", eCmdHdlrBinary, 0 },
    { "timeout_ms", eCmdHdlrInt, 0 },
    { "batch.max_items", eCmdHdlrInt, 0 },
    { "batch.max_bytes", eCmdHdlrInt, 0 },
    { "batch.timeout_ms", eCmdHdlrInt, 0 },
    { "retry.max_retries", eCmdHdlrInt, 0 },
    { "retry.initial_ms", eCmdHdlrInt, 0 },
    { "retry.max_ms", eCmdHdlrInt, 0 },
    { "retry.jitter", eCmdHdlrFloat, 0 },
    { "resource", eCmdHdlrGetWord, 0 },
    { "attribute_map", eCmdHdlrGetWord, 0 },
    { "severity_map", eCmdHdlrGetWord, 0 },
    { "body_template", eCmdHdlrGetWord, 0 },
    { "trace_id_prop", eCmdHdlrGetWord, 0 },
    { "span_id_prop", eCmdHdlrGetWord, 0 },
    { "trace_flags_prop", eCmdHdlrGetWord, 0 }
};

static struct cnfparamblk paramblk = {
    CNFPARAMBLK_VERSION,
    sizeof(cnfparamdescr)/sizeof(struct cnfparamdescr),
    cnfparamdescr
};

BEGINsetModCnf(omotlp)
{
    struct cnfparamvals *pvals = NULL;

    pblk = &paramblk;

    CHKiRet(cnfParams(&pvals));

finalize_it:
    if (pvals != NULL)
        cnfparamvalsDestruct(pvals, NULL);

    return RS_RET_OK;
}

BEGINmodGetCnfName(omotlp)
{
    return (uchar*)"omotlp";
}

BEGINqueryEtryPt(omotlp)
{
    CODESTARTqueryEtryPt(omotlp)
    CODEqueryEtryPt_STD_OMOD_QUERIES
    CODEqueryEtryPt_STD_OMOD8_QUERIES
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
    CODEqueryEtryPt_STD_CONF2_QUERIES
    CODEqueryEtryPt_STD_STATS_QUERIES
}

/* Module version and metadata */
BEGINgetModuleVersion(omotlp)
{
    uchar version[] = "1.0.0";
    return version;
}