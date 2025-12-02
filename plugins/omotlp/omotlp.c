/* omotlp.c -- OpenTelemetry (OTLP) output module scaffolding
 *
 * Concurrency & Locking:
 * - Shared configuration lives in the per-action instanceData structure and is
 *   read-only after instantiation.
 * - Each worker maintains its own HTTP client and batching buffer guarded by a
 *   mutex so no cross-worker locks are required.
 * - A per-worker flush thread wakes periodically to service batch timeouts and
 *   returns control to the rsyslog action queue for retry/backoff decisions.
 */
#include "config.h"
#include "rsyslog.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#include "conf.h"
#include "datetime.h"
#include "msg.h"
#include "srUtils.h"
#include "stringbuf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

#include "otlp_json.h"
#include "omotlp_http.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omotlp")

DEF_OMOD_STATIC_DATA;
DEFobjCurrIf(datetime);

typedef enum omotlp_compression_e {
    OMOTLP_COMPRESSION_UNSET = 0,
    OMOTLP_COMPRESSION_NONE,
    OMOTLP_COMPRESSION_GZIP,
} omotlp_compression_t;

typedef struct header_list_s {
    char **values;
    size_t count;
    size_t capacity;
} header_list_t;

enum {
    OMOTLP_OMSR_IDX_MESSAGE = 0,
    OMOTLP_OMSR_IDX_BODY = 1,
};

typedef struct _instanceData {
    uchar *endpoint;
    uchar *path;
    uchar *protocol;
    uchar *bodyTemplateName;
    uchar *url;
    long requestTimeoutMs;
    size_t batchMaxItems;
    size_t batchMaxBytes;
    long batchTimeoutMs;
    long retryInitialMs;
    long retryMaxMs;
    unsigned int retryMaxRetries;
    unsigned int retryJitterPercent;
    omotlp_compression_t compression_mode;
    int compressionConfigured;
    int headersConfigured;
    int bearerConfigured;
    int timeoutConfigured;
    header_list_t headers;
} instanceData;

typedef struct omotlp_batch_entry_s {
    omotlp_log_record_t record;
    char *body;
    char *hostname;
    char *app_name;
    char *proc_id;
    char *msg_id;
} omotlp_batch_entry_t;

typedef struct omotlp_batch_state_s {
    omotlp_batch_entry_t *entries;
    size_t count;
    size_t capacity;
    size_t estimated_bytes;
    long long first_enqueue_ms;
} omotlp_batch_state_t;

typedef struct wrkrInstanceData {
    instanceData *pData;
    omotlp_http_client_t *http_client;
    omotlp_batch_state_t batch;
    pthread_t flush_thread;
    pthread_mutex_t batch_mutex;
    int flush_thread_running;
    int flush_thread_stop;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;
};

static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

static struct cnfparamdescr actpdescr[] = {{"endpoint", eCmdHdlrString, 0},
                                           {"path", eCmdHdlrString, 0},
                                           {"protocol", eCmdHdlrGetWord, 0},
                                           {"template", eCmdHdlrGetWord, 0},
                                           {"timeout.ms", eCmdHdlrGetWord, 0},
                                           {"compression", eCmdHdlrGetWord, 0},
                                           {"batch.max_items", eCmdHdlrGetWord, 0},
                                           {"batch.max_bytes", eCmdHdlrGetWord, 0},
                                           {"batch.timeout.ms", eCmdHdlrGetWord, 0},
                                           {"retry.initial.ms", eCmdHdlrGetWord, 0},
                                           {"retry.max.ms", eCmdHdlrGetWord, 0},
                                           {"retry.max_retries", eCmdHdlrGetWord, 0},
                                           {"retry.jitter.percent", eCmdHdlrGetWord, 0},
                                           {"headers", eCmdHdlrString, 0},
                                           {"bearer_token", eCmdHdlrString, 0}};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

static rsRetVal parse_headers_env(instanceData *pData, const char *text);
static rsRetVal parse_timeout_string(const char *text, long *out);
static rsRetVal set_compression_mode(instanceData *pData, const char *value);

static void lowercaseInPlace(uchar *value) {
    char *cursor;

    if (value == NULL) {
        return;
    }

    for (cursor = (char *)value; *cursor != '\0'; ++cursor) {
        *cursor = (char)tolower((unsigned char)*cursor);
    }
}

static rsRetVal assignParamFromCStr(uchar **target, const char *value) {
    uchar *tmp;
    DEFiRet;

    if (value == NULL) {
        goto finalize_it;
    }

    tmp = (uchar *)strdup(value);
    if (tmp == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    free(*target);
    *target = tmp;

finalize_it:
    RETiRet;
}

static const char *firstPopulatedEnv(const char *const *names) {
    size_t i;

    if (names == NULL) {
        return NULL;
    }

    for (i = 0; names[i] != NULL; ++i) {
        const char *value = getenv(names[i]);
        if (value != NULL && value[0] != '\0') {
            return value;
        }
    }

    return NULL;
}

static rsRetVal applyEnvDefaults(instanceData *pData) {
    const char *value;
    static const char *const endpointEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT",
                                                  NULL};
    static const char *const protocolEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL",
                                                  NULL};
    static const char *const timeoutEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT", NULL};
    static const char *const compressionEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_COMPRESSION",
                                                     "OTEL_EXPORTER_OTLP_COMPRESSION", NULL};
    static const char *const headersEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS", NULL};

    DEFiRet;

    if (pData->endpoint == NULL) {
        value = firstPopulatedEnv(endpointEnvVars);
        if (value != NULL) {
            CHKiRet(assignParamFromCStr(&pData->endpoint, value));
        }
    }

    if (pData->protocol == NULL) {
        value = firstPopulatedEnv(protocolEnvVars);
        if (value != NULL) {
            CHKiRet(assignParamFromCStr(&pData->protocol, value));
        }
    }

    if (!pData->timeoutConfigured) {
        value = firstPopulatedEnv(timeoutEnvVars);
        if (value != NULL) {
            long timeout_ms;
            CHKiRet(parse_timeout_string(value, &timeout_ms));
            pData->requestTimeoutMs = timeout_ms;
        }
    }

    if (!pData->compressionConfigured && pData->compression_mode == OMOTLP_COMPRESSION_UNSET) {
        value = firstPopulatedEnv(compressionEnvVars);
        if (value != NULL) {
            CHKiRet(set_compression_mode(pData, value));
        }
    }

    if (!pData->headersConfigured) {
        value = firstPopulatedEnv(headersEnvVars);
        if (value != NULL) {
            CHKiRet(parse_headers_env(pData, value));
        }
    }

finalize_it:
    RETiRet;
}

static rsRetVal ensureEndpointPathSplit(instanceData *pData) {
    char *endpoint;
    char *schemeSeparator;
    char *pathStart;
    char *baseDup = NULL;
    char *pathDup = NULL;
    size_t baseLength;

    DEFiRet;

    if (pData->endpoint == NULL || pData->path != NULL) {
        goto finalize_it;
    }

    endpoint = (char *)pData->endpoint;
    schemeSeparator = strstr(endpoint, "://");
    if (schemeSeparator != NULL) {
        pathStart = strchr(schemeSeparator + 3, '/');
    } else {
        pathStart = strchr(endpoint, '/');
    }

    if (pathStart == NULL || *pathStart == '\0' || pathStart == endpoint) {
        goto finalize_it;
    }

    baseLength = (size_t)(pathStart - endpoint);
    baseDup = (char *)malloc(baseLength + 1);
    if (baseDup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    memcpy(baseDup, endpoint, baseLength);
    baseDup[baseLength] = '\0';

    pathDup = strdup(pathStart);
    if (pathDup == NULL) {
        free(baseDup);
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    free(pData->endpoint);
    pData->endpoint = (uchar *)baseDup;
    pData->path = (uchar *)pathDup;

finalize_it:
    RETiRet;
}

static rsRetVal validateProtocol(instanceData *pData) {
    DEFiRet;

    if (pData->protocol == NULL) {
        goto finalize_it;
    }

    if (!strcmp((char *)pData->protocol, "http/json")) {
        goto finalize_it;
    }

    LogError(0, RS_RET_NOT_IMPLEMENTED, "omotlp: protocol '%s' is not supported by the scaffolding build",
             pData->protocol);
    ABORT_FINALIZE(RS_RET_NOT_IMPLEMENTED);

finalize_it:
    RETiRet;
}

static rsRetVal buildEffectiveUrl(instanceData *pData) {
    const char *endpoint = (const char *)pData->endpoint;
    const char *path = (const char *)pData->path;
    size_t endpoint_len;
    size_t path_len;
    size_t total;
    int endpoint_has_slash;
    int path_has_slash;
    char *buffer = NULL;
    size_t cursor = 0;

    DEFiRet;

    if (endpoint == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    endpoint_len = strlen(endpoint);
    path_len = (path != NULL) ? strlen(path) : 0u;
    endpoint_has_slash = (endpoint_len > 0 && endpoint[endpoint_len - 1] == '/');
    path_has_slash = (path_len > 0 && path[0] == '/');

    total = endpoint_len + path_len + 2u;
    buffer = malloc(total);
    if (buffer == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    memcpy(buffer, endpoint, endpoint_len);
    cursor = endpoint_len;

    if (path_len > 0) {
        if (!endpoint_has_slash && !path_has_slash) {
            buffer[cursor++] = '/';
        } else if (endpoint_has_slash && path_has_slash) {
            ++path;
            --path_len;
        }

        memcpy(buffer + cursor, path, path_len);
        cursor += path_len;
    }

    buffer[cursor] = '\0';

    free(pData->url);
    pData->url = (uchar *)buffer;

finalize_it:
    if (iRet != RS_RET_OK && buffer != NULL) {
        free(buffer);
    }
    RETiRet;
}

typedef struct severity_mapping_s {
    uint32_t number;
    const char *text;
} severity_mapping_t;

static const severity_mapping_t severity_lookup[8] = {{24u, "EMERGENCY"}, {23u, "ALERT"},   {22u, "CRITICAL"},
                                                      {17u, "ERROR"},     {13u, "WARNING"}, {11u, "NOTICE"},
                                                      {9u, "INFO"},       {5u, "DEBUG"}};

#define OMOTLP_DEFAULT_BATCH_MAX_ITEMS 512u
#define OMOTLP_DEFAULT_BATCH_MAX_BYTES (512u * 1024u)
#define OMOTLP_DEFAULT_BATCH_TIMEOUT_MS 5000L
#define OMOTLP_DEFAULT_RETRY_INITIAL_MS 1000L
#define OMOTLP_DEFAULT_RETRY_MAX_MS 30000L
#define OMOTLP_DEFAULT_RETRY_MAX_RETRIES 5u
#define OMOTLP_DEFAULT_RETRY_JITTER_PERCENT 20u

#define OMOTLP_BATCH_BASE_OVERHEAD 256u
#define OMOTLP_BATCH_RECORD_OVERHEAD 256u
#define OMOTLP_IDLE_FLUSH_INTERVAL_MS 1000L

static void header_list_init(header_list_t *list) {
    if (list == NULL) {
        return;
    }

    list->values = NULL;
    list->count = 0u;
    list->capacity = 0u;
}

static void header_list_clear(header_list_t *list) {
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; i < list->count; ++i) {
        free(list->values[i]);
        list->values[i] = NULL;
    }

    list->count = 0u;
}

static void header_list_destroy(header_list_t *list) {
    if (list == NULL) {
        return;
    }

    header_list_clear(list);
    free(list->values);
    list->values = NULL;
    list->capacity = 0u;
}

static rsRetVal header_list_add(header_list_t *list, const char *header) {
    char **tmp;
    char *dup = NULL;
    size_t new_capacity;

    DEFiRet;

    if (list == NULL || header == NULL || header[0] == '\0') {
        goto finalize_it;
    }

    if (list->count == list->capacity) {
        new_capacity = (list->capacity == 0u) ? 4u : list->capacity * 2u;
        tmp = (char **)realloc(list->values, new_capacity * sizeof(char *));
        if (tmp == NULL) {
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        list->values = tmp;
        list->capacity = new_capacity;
    }

    dup = strdup(header);
    if (dup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    list->values[list->count++] = dup;
    dup = NULL;

finalize_it:
    if (dup != NULL) {
        free(dup);
    }
    RETiRet;
}

static rsRetVal header_list_add_kv(header_list_t *list, const char *key, const char *value) {
    char *buffer = NULL;
    size_t key_len;
    size_t value_len;
    DEFiRet;

    if (key == NULL || key[0] == '\0') {
        goto finalize_it;
    }

    key_len = strlen(key);
    value_len = (value != NULL) ? strlen(value) : 0u;
    buffer = (char *)malloc(key_len + 2u + value_len + 1u);
    if (buffer == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    memcpy(buffer, key, key_len);
    buffer[key_len] = ':';
    buffer[key_len + 1u] = ' ';
    if (value_len > 0u) {
        memcpy(buffer + key_len + 2u, value, value_len);
    }
    buffer[key_len + 2u + value_len] = '\0';

    CHKiRet(header_list_add(list, buffer));

finalize_it:
    if (buffer != NULL) {
        free(buffer);
    }
    RETiRet;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static void percent_decode(char *value) {
    char *src;
    char *dst;

    if (value == NULL) {
        return;
    }

    src = value;
    dst = value;
    while (*src != '\0') {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            int hi = hex_value(src[1]);
            int lo = hex_value(src[2]);
            if (hi >= 0 && lo >= 0) {
                *dst++ = (char)((hi << 4) | lo);
                src += 3;
                continue;
            }
        }

        *dst++ = *src++;
    }

    *dst = '\0';
}

static char *trim_whitespace(char *value) {
    char *start;
    char *end;

    if (value == NULL) {
        return NULL;
    }

    start = value;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        --end;
    }

    *end = '\0';
    return start;
}

static rsRetVal parse_long_param(const char *name, es_str_t *value, long min, long *out) {
    char *text = NULL;
    char *end = NULL;
    long parsed;

    DEFiRet;

    if (value == NULL || out == NULL) {
        goto finalize_it;
    }

    text = (char *)es_str2cstr(value, NULL);
    if (text == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: invalid numeric value '%s' for parameter %s", text, name);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (parsed < min) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: value %ld for %s is below the minimum %ld", parsed, name, min);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    *out = parsed;

finalize_it:
    if (text != NULL) {
        free(text);
    }
    RETiRet;
}

static rsRetVal parse_size_param(const char *name, es_str_t *value, size_t min, size_t *out) {
    char *text = NULL;
    char *end = NULL;
    unsigned long long parsed;

    DEFiRet;

    if (value == NULL || out == NULL) {
        goto finalize_it;
    }

    text = (char *)es_str2cstr(value, NULL);
    if (text == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: invalid size value '%s' for parameter %s", text, name);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (parsed < (unsigned long long)min) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: value %s for %s is below the minimum %zu", text, name, min);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    *out = (size_t)parsed;

finalize_it:
    if (text != NULL) {
        free(text);
    }
    RETiRet;
}

static rsRetVal parse_uint_param(const char *name, es_str_t *value, unsigned int min, unsigned int *out) {
    char *text = NULL;
    char *end = NULL;
    unsigned long parsed;

    DEFiRet;

    if (value == NULL || out == NULL) {
        goto finalize_it;
    }

    text = (char *)es_str2cstr(value, NULL);
    if (text == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: invalid numeric value '%s' for parameter %s", text, name);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (parsed < (unsigned long)min) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: value %lu for %s is below the minimum %u", parsed, name, min);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    *out = (unsigned int)parsed;

finalize_it:
    if (text != NULL) {
        free(text);
    }
    RETiRet;
}

static rsRetVal parse_headers_json(instanceData *pData, const char *text) {
    struct json_object *root = NULL;
    struct json_object_iterator iter;
    struct json_object_iterator iter_end;

    DEFiRet;

    if (text == NULL || text[0] == '\0') {
        goto finalize_it;
    }

    root = fjson_tokener_parse(text);
    if (root == NULL) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: failed to parse headers JSON '%s'", text);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (!fjson_object_is_type(root, fjson_type_object)) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: headers parameter must be a JSON object");
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    iter = json_object_iter_begin(root);
    iter_end = json_object_iter_end(root);
    while (!json_object_iter_equal(&iter, &iter_end)) {
        const char *key = json_object_iter_peek_name(&iter);
        struct json_object *value_obj = json_object_iter_peek_value(&iter);
        const char *value = NULL;

        if (value_obj != NULL) {
            if (!fjson_object_is_type(value_obj, fjson_type_string)) {
                LogError(0, RS_RET_PARAM_ERROR, "omotlp: header '%s' value must be a string", key);
                ABORT_FINALIZE(RS_RET_PARAM_ERROR);
            }
            value = fjson_object_get_string(value_obj);
        }

        CHKiRet(header_list_add_kv(&pData->headers, key, value));
        json_object_iter_next(&iter);
    }

finalize_it:
    if (root != NULL) {
        fjson_object_put(root);
    }
    RETiRet;
}

static rsRetVal parse_headers_env(instanceData *pData, const char *text) {
    char *dup = NULL;
    char *cursor;

    DEFiRet;

    if (text == NULL || text[0] == '\0') {
        goto finalize_it;
    }

    dup = strdup(text);
    if (dup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    cursor = dup;
    while (cursor != NULL && *cursor != '\0') {
        char *token = cursor;
        char *next = strchr(cursor, ',');
        char *key;
        char *value;

        if (next != NULL) {
            *next = '\0';
            cursor = next + 1;
        } else {
            cursor = NULL;
        }

        token = trim_whitespace(token);
        if (token == NULL || token[0] == '\0') {
            continue;
        }

        value = strchr(token, '=');
        if (value == NULL) {
            LogError(0, RS_RET_PARAM_ERROR, "omotlp: header entry '%s' is missing '='", token);
            ABORT_FINALIZE(RS_RET_PARAM_ERROR);
        }

        *value = '\0';
        ++value;

        key = trim_whitespace(token);
        value = trim_whitespace(value);

        percent_decode(key);
        percent_decode(value);

        CHKiRet(header_list_add_kv(&pData->headers, key, value));
    }

finalize_it:
    if (dup != NULL) {
        free(dup);
    }
    RETiRet;
}

static rsRetVal parse_timeout_string(const char *text, long *out) {
    char *dup = NULL;
    char *number;
    char *end = NULL;
    long multiplier = 1;
    long parsed;
    size_t len;

    DEFiRet;

    if (text == NULL || out == NULL) {
        goto finalize_it;
    }

    dup = strdup(text);
    if (dup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    len = strlen(dup);
    if (len >= 2 && dup[len - 2] == 'm' && dup[len - 1] == 's') {
        dup[len - 2] = '\0';
    } else if (len >= 1 && dup[len - 1] == 's') {
        dup[len - 1] = '\0';
        multiplier = 1000;
    }

    number = trim_whitespace(dup);
    errno = 0;
    parsed = strtol(number, &end, 10);
    if (errno != 0 || end == number || *end != '\0') {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: invalid timeout value '%s'", text);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (parsed < 0) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: timeout must be non-negative, got %ld", parsed);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (multiplier != 1 && parsed > LONG_MAX / multiplier) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: timeout '%s' exceeds range", text);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    *out = parsed * multiplier;

finalize_it:
    if (dup != NULL) {
        free(dup);
    }
    RETiRet;
}

static rsRetVal set_compression_mode(instanceData *pData, const char *value) {
    char buffer[16];
    size_t len;
    size_t i;

    DEFiRet;

    if (pData == NULL || value == NULL || value[0] == '\0') {
        goto finalize_it;
    }

    len = strlen(value);
    if (len >= sizeof(buffer)) {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: unsupported compression value '%s'", value);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    for (i = 0; i < len; ++i) {
        buffer[i] = (char)tolower((unsigned char)value[i]);
    }
    buffer[len] = '\0';

    if (!strcmp(buffer, "gzip")) {
        pData->compression_mode = OMOTLP_COMPRESSION_GZIP;
    } else if (!strcmp(buffer, "none")) {
        pData->compression_mode = OMOTLP_COMPRESSION_NONE;
    } else {
        LogError(0, RS_RET_PARAM_ERROR, "omotlp: compression '%s' is not supported", value);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

finalize_it:
    RETiRet;
}

static rsRetVal duplicate_optional_string(const char *source, char **dest) {
    char *dup = NULL;

    DEFiRet;

    if (dest == NULL) {
        goto finalize_it;
    }

    *dest = NULL;

    if (source == NULL || source[0] == '\0') {
        goto finalize_it;
    }

    dup = strdup(source);
    if (dup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    *dest = dup;
    dup = NULL;

finalize_it:
    if (dup != NULL) {
        free(dup);
    }
    RETiRet;
}

static void mapSeverity(int syslogSeverity, omotlp_log_record_t *record) {
    if (syslogSeverity < 0 || syslogSeverity > 7) {
        record->severity_number = 0u;
        record->severity_text = NULL;
        return;
    }

    record->severity_number = severity_lookup[syslogSeverity].number;
    record->severity_text = severity_lookup[syslogSeverity].text;
}

static uint64_t scaleFractionToNanos(int fraction, int precision) {
    uint64_t value;

    if (precision <= 0 || fraction <= 0) {
        return 0u;
    }

    value = (uint64_t)fraction;
    if (precision > 9) {
        int diff = precision - 9;
        while (diff-- > 0 && value > 0u) {
            value /= 10u;
        }
    } else if (precision < 9) {
        int diff = 9 - precision;
        while (diff-- > 0) {
            value *= 10u;
        }
    }

    return value;
}

static uint64_t syslogTimeToUnixNanos(const struct syslogTime *timestamp) {
    if (timestamp == NULL) {
        return 0u;
    }

    return ((uint64_t)datetime.syslogTime2time_t(timestamp) * 1000000000ull) +
           scaleFractionToNanos(timestamp->secfrac, timestamp->secfracPrecision);
}

static const char *cstrToConst(cstr_t *value) {
    return value == NULL ? NULL : (const char *)rsCStrGetSzStrNoNULL(value);
}

static const char *extractAppName(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSAPPNAME);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    if (msg->iLenPROGNAME > 0 && msg->PROGNAME.ptr != NULL) {
        return (const char *)msg->PROGNAME.ptr;
    }

    return NULL;
}

static const char *extractProcId(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSPROCID);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    return NULL;
}

static const char *extractMsgId(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSMSGID);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    return NULL;
}

static rsRetVal populateLogRecord(smsg_t *msg, const char *body, omotlp_log_record_t *record) {
    int severity;

    DEFiRet;

    memset(record, 0, sizeof(*record));

    record->body = body;

    if (msg != NULL) {
        CHKiRet(MsgGetSeverity(msg, &severity));
        mapSeverity(severity, record);

        record->hostname = (msg->pszHOSTNAME != NULL) ? (const char *)msg->pszHOSTNAME : NULL;
        record->app_name = extractAppName(msg);
        record->proc_id = extractProcId(msg);
        record->msg_id = extractMsgId(msg);
        record->facility = (uint16_t)msg->iFacility;
        record->time_unix_nano = syslogTimeToUnixNanos(&msg->tTIMESTAMP);
        record->observed_time_unix_nano = syslogTimeToUnixNanos(&msg->tRcvdAt);
    } else {
        record->severity_number = 0u;
        record->severity_text = NULL;
        record->hostname = NULL;
        record->app_name = NULL;
        record->proc_id = NULL;
        record->msg_id = NULL;
        record->facility = 0u;
        record->time_unix_nano = 0u;
        record->observed_time_unix_nano = 0u;
    }

    record->trace_id = NULL;
    record->span_id = NULL;
    record->trace_flags = 0u;

finalize_it:
    RETiRet;
}

static void omotlp_batch_entry_clear(omotlp_batch_entry_t *entry) {
    if (entry == NULL) {
        return;
    }

    free(entry->body);
    free(entry->hostname);
    free(entry->app_name);
    free(entry->proc_id);
    free(entry->msg_id);

    memset(entry, 0, sizeof(*entry));
}

static void omotlp_batch_clear(omotlp_batch_state_t *batch) {
    size_t i;

    if (batch == NULL) {
        return;
    }

    for (i = 0; i < batch->count; ++i) {
        omotlp_batch_entry_clear(&batch->entries[i]);
    }

    batch->count = 0u;
    batch->estimated_bytes = 0u;
    batch->first_enqueue_ms = 0;
}

static void omotlp_batch_destroy(omotlp_batch_state_t *batch) {
    if (batch == NULL) {
        return;
    }

    omotlp_batch_clear(batch);
    free(batch->entries);
    batch->entries = NULL;
    batch->capacity = 0u;
}

static rsRetVal omotlp_batch_ensure_capacity(omotlp_batch_state_t *batch, size_t needed) {
    omotlp_batch_entry_t *tmp;
    size_t new_capacity;

    DEFiRet;

    if (batch == NULL) {
        goto finalize_it;
    }

    if (needed <= batch->capacity) {
        goto finalize_it;
    }

    new_capacity = batch->capacity == 0u ? 8u : batch->capacity;
    while (new_capacity < needed) {
        new_capacity *= 2u;
    }

    tmp = (omotlp_batch_entry_t *)realloc(batch->entries, new_capacity * sizeof(omotlp_batch_entry_t));
    if (tmp == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    memset(tmp + batch->capacity, 0, (new_capacity - batch->capacity) * sizeof(omotlp_batch_entry_t));
    batch->entries = tmp;
    batch->capacity = new_capacity;

finalize_it:
    RETiRet;
}

static rsRetVal gzip_compress_buffer(const uint8_t *input, size_t input_len, uint8_t **out, size_t *out_len) {
    z_stream stream;
    uint8_t *buffer = NULL;
    size_t bound;
    int rc;

    DEFiRet;

    if (out == NULL || out_len == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    *out = NULL;
    *out_len = 0u;

    bound = (size_t)compressBound((uLong)input_len);
    buffer = (uint8_t *)malloc(bound);
    if (buffer == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    memset(&stream, 0, sizeof(stream));
    rc = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp: deflateInit2 failed: %d", rc);
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_len;
    stream.next_out = buffer;
    stream.avail_out = (uInt)bound;

    rc = deflate(&stream, Z_FINISH);
    if (rc != Z_STREAM_END) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp: gzip compression failed: %d", rc);
        deflateEnd(&stream);
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    *out = buffer;
    *out_len = stream.total_out;
    buffer = NULL;

    deflateEnd(&stream);

finalize_it:
    if (buffer != NULL) {
        free(buffer);
    }
    RETiRet;
}

static rsRetVal omotlp_flush_batch_locked(wrkrInstanceData_t *pWrkrData, omotlp_batch_state_t *batch) {
    omotlp_log_record_t *records = NULL;
    char *payload = NULL;
    uint8_t *compressed = NULL;
    const uint8_t *to_send;
    size_t send_len = 0u;
    size_t payload_len = 0u;
    size_t i;

    DEFiRet;

    DBGPRINTF("omotlp: omotlp_flush_batch called, batch->count=%zu", batch ? batch->count : 0u);

    if (pWrkrData == NULL || batch == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (batch->count == 0u) {
        DBGPRINTF("omotlp: omotlp_flush_batch: batch is empty, skipping");
        goto finalize_it;
    }

    DBGPRINTF("omotlp: omotlp_flush_batch: flushing %zu records", batch->count);

    records = (omotlp_log_record_t *)malloc(batch->count * sizeof(*records));
    if (records == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    for (i = 0; i < batch->count; ++i) {
        records[i] = batch->entries[i].record;
    }

    DBGPRINTF("omotlp: omotlp_flush_batch: building JSON export for %zu records", batch->count);
    CHKiRet(omotlp_json_build_export(records, batch->count, &payload));

    if (payload != NULL) {
        payload_len = strlen(payload);
        DBGPRINTF("omotlp: omotlp_flush_batch: JSON payload length=%zu", payload_len);
    }

    to_send = (const uint8_t *)payload;
    send_len = payload_len;

    if (pWrkrData->pData->compression_mode == OMOTLP_COMPRESSION_GZIP) {
        DBGPRINTF("omotlp: omotlp_flush_batch: compressing payload");
        CHKiRet(gzip_compress_buffer((const uint8_t *)payload, payload_len, &compressed, &send_len));
        to_send = compressed;
        DBGPRINTF("omotlp: omotlp_flush_batch: compressed size=%zu", send_len);
    }

    DBGPRINTF("omotlp: omotlp_flush_batch: calling omotlp_http_client_post, send_len=%zu", send_len);
    CHKiRet(omotlp_http_client_post(pWrkrData->http_client, to_send, send_len));
    DBGPRINTF("omotlp: omotlp_flush_batch: HTTP POST successful, clearing batch");
    omotlp_batch_clear(batch);

finalize_it:
    free(records);
    free(payload);
    free(compressed);
    RETiRet;
}

static rsRetVal omotlp_flush_batch(wrkrInstanceData_t *pWrkrData) {
    rsRetVal iRet;

    if (pWrkrData == NULL) {
        return RS_RET_PARAM_ERROR;
    }

    pthread_mutex_lock(&pWrkrData->batch_mutex);
    iRet = omotlp_flush_batch_locked(pWrkrData, &pWrkrData->batch);
    pthread_mutex_unlock(&pWrkrData->batch_mutex);

    return iRet;
}

static void *omotlp_batch_flush_thread(void *arg) {
    wrkrInstanceData_t *pWrkrData = (wrkrInstanceData_t *)arg;
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = 100 * 1000 * 1000; /* 100 ms */

    while (!pWrkrData->flush_thread_stop) {
        nanosleep(&req, NULL);

        pthread_mutex_lock(&pWrkrData->batch_mutex);
        if (pWrkrData->flush_thread_stop) {
            pthread_mutex_unlock(&pWrkrData->batch_mutex);
            break;
        }

        if (pWrkrData->batch.count > 0u) {
            long long timeout_ms = pWrkrData->pData->batchTimeoutMs > 0 ? pWrkrData->pData->batchTimeoutMs
                                                                        : OMOTLP_IDLE_FLUSH_INTERVAL_MS;
            if (timeout_ms > 0) {
                long long now = currentTimeMills();
                if (pWrkrData->batch.first_enqueue_ms != 0 &&
                    now - pWrkrData->batch.first_enqueue_ms >= timeout_ms) {
                    (void)omotlp_flush_batch_locked(pWrkrData, &pWrkrData->batch);
                }
            }
        }

        pthread_mutex_unlock(&pWrkrData->batch_mutex);
    }

    pthread_mutex_lock(&pWrkrData->batch_mutex);
    if (pWrkrData->batch.count > 0u) {
        (void)omotlp_flush_batch_locked(pWrkrData, &pWrkrData->batch);
    }
    pthread_mutex_unlock(&pWrkrData->batch_mutex);

    return NULL;
}

static rsRetVal omotlp_batch_add_record(wrkrInstanceData_t *pWrkrData,
                                        const omotlp_log_record_t *record,
                                        const char *body) {
    omotlp_batch_state_t *batch;
    instanceData *cfg;
    omotlp_batch_entry_t *entry = NULL;
    const char *body_text;
    size_t body_len;
    size_t estimated_bytes;

    DEFiRet;

    if (pWrkrData == NULL || record == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    batch = &pWrkrData->batch;
    cfg = pWrkrData->pData;

    pthread_mutex_lock(&pWrkrData->batch_mutex);

    if (cfg->batchMaxItems > 0u && batch->count >= cfg->batchMaxItems) {
        CHKiRet(omotlp_flush_batch_locked(pWrkrData, batch));
    }

    body_text = (body != NULL) ? body : "";
    body_len = strlen(body_text);
    estimated_bytes = OMOTLP_BATCH_RECORD_OVERHEAD + body_len;

    if (cfg->batchMaxBytes > 0u && batch->count > 0u && batch->estimated_bytes + estimated_bytes > cfg->batchMaxBytes) {
        CHKiRet(omotlp_flush_batch_locked(pWrkrData, batch));
    }

    if (cfg->batchMaxBytes > 0u && estimated_bytes > cfg->batchMaxBytes) {
        LogError(0, RS_RET_OK,
                 "omotlp: single record estimated size %zu exceeds batch.max_bytes %zu; sending individually",
                 estimated_bytes, cfg->batchMaxBytes);
    }

    CHKiRet(omotlp_batch_ensure_capacity(batch, batch->count + 1u));
    entry = &batch->entries[batch->count];
    memset(entry, 0, sizeof(*entry));

    entry->body = strdup(body_text);
    if (entry->body == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    CHKiRet(duplicate_optional_string(record->hostname, &entry->hostname));
    CHKiRet(duplicate_optional_string(record->app_name, &entry->app_name));
    CHKiRet(duplicate_optional_string(record->proc_id, &entry->proc_id));
    CHKiRet(duplicate_optional_string(record->msg_id, &entry->msg_id));

    entry->record = *record;
    entry->record.body = entry->body;
    entry->record.hostname = entry->hostname;
    entry->record.app_name = entry->app_name;
    entry->record.proc_id = entry->proc_id;
    entry->record.msg_id = entry->msg_id;

    ++batch->count;
    if (batch->count == 1u) {
        batch->estimated_bytes = OMOTLP_BATCH_BASE_OVERHEAD + estimated_bytes;
        batch->first_enqueue_ms = currentTimeMills();
    } else {
        batch->estimated_bytes += estimated_bytes;
    }

    if (cfg->batchMaxItems > 0u && batch->count >= cfg->batchMaxItems) {
        CHKiRet(omotlp_flush_batch_locked(pWrkrData, batch));
    } else if (cfg->batchMaxBytes > 0u && batch->estimated_bytes >= cfg->batchMaxBytes) {
        CHKiRet(omotlp_flush_batch_locked(pWrkrData, batch));
    }

finalize_it:
    pthread_mutex_unlock(&pWrkrData->batch_mutex);
    if (iRet != RS_RET_OK) {
        if (entry != NULL) {
            omotlp_batch_entry_clear(entry);
        }
        if (batch != NULL && batch->count > 0u) {
            --batch->count;
        }
    }
    RETiRet;
}

static rsRetVal omotlp_batch_flush_if_due(wrkrInstanceData_t *pWrkrData, long long now_ms) {
    omotlp_batch_state_t *batch;
    long long age;

    DEFiRet;

    if (pWrkrData == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    pthread_mutex_lock(&pWrkrData->batch_mutex);
    batch = &pWrkrData->batch;
    if (pWrkrData->pData->batchTimeoutMs <= 0 || batch->count == 0u) {
        goto finalize_it;
    }

    if (now_ms <= batch->first_enqueue_ms) {
        goto finalize_it;
    }

    age = now_ms - batch->first_enqueue_ms;
    if (age >= pWrkrData->pData->batchTimeoutMs) {
        CHKiRet(omotlp_flush_batch_locked(pWrkrData, batch));
    }

finalize_it:
    pthread_mutex_unlock(&pWrkrData->batch_mutex);
    RETiRet;
}

static inline void setInstParamDefaults(instanceData *pData) {
    pData->endpoint = NULL;
    pData->path = NULL;
    pData->protocol = NULL;
    pData->bodyTemplateName = NULL;
    pData->url = NULL;
    pData->requestTimeoutMs = 10000;
    pData->batchMaxItems = OMOTLP_DEFAULT_BATCH_MAX_ITEMS;
    pData->batchMaxBytes = OMOTLP_DEFAULT_BATCH_MAX_BYTES;
    pData->batchTimeoutMs = OMOTLP_DEFAULT_BATCH_TIMEOUT_MS;
    pData->retryInitialMs = OMOTLP_DEFAULT_RETRY_INITIAL_MS;
    pData->retryMaxMs = OMOTLP_DEFAULT_RETRY_MAX_MS;
    pData->retryMaxRetries = OMOTLP_DEFAULT_RETRY_MAX_RETRIES;
    pData->retryJitterPercent = OMOTLP_DEFAULT_RETRY_JITTER_PERCENT;
    pData->compression_mode = OMOTLP_COMPRESSION_UNSET;
    pData->compressionConfigured = 0;
    pData->headersConfigured = 0;
    pData->bearerConfigured = 0;
    pData->timeoutConfigured = 0;
    header_list_init(&pData->headers);
}

BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
    CODESTARTendCnfLoad;
ENDendCnfLoad

BEGINcheckCnf
    CODESTARTcheckCnf;
ENDcheckCnf

BEGINactivateCnf
    CODESTARTactivateCnf;
    runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
    CODESTARTfreeCnf;
ENDfreeCnf

BEGINcreateInstance
    CODESTARTcreateInstance;
    setInstParamDefaults(pData);
ENDcreateInstance

BEGINcreateWrkrInstance
    omotlp_http_client_config_t http_cfg;
    CODESTARTcreateWrkrInstance;
    pWrkrData->pData = pData;
    pWrkrData->http_client = NULL;
    pWrkrData->batch.entries = NULL;
    pWrkrData->batch.count = 0u;
    pWrkrData->batch.capacity = 0u;
    pWrkrData->batch.estimated_bytes = 0u;
    pWrkrData->batch.first_enqueue_ms = 0;
    pWrkrData->flush_thread_running = 0;
    pWrkrData->flush_thread_stop = 0;
    pthread_mutex_init(&pWrkrData->batch_mutex, NULL);

    if (pData == NULL || pData->url == NULL) {
        iRet = RS_RET_INTERNAL_ERROR;
        goto finalize_it;
    }

    http_cfg.url = (const char *)pData->url;
    http_cfg.timeout_ms = pData->requestTimeoutMs;
    http_cfg.user_agent = "rsyslog-omotlp/" VERSION;
    http_cfg.headers = (const char *const *)pData->headers.values;
    http_cfg.header_count = pData->headers.count;
    http_cfg.retry_initial_ms = pData->retryInitialMs;
    http_cfg.retry_max_ms = pData->retryMaxMs;
    http_cfg.retry_max_retries = pData->retryMaxRetries;
    http_cfg.retry_jitter_percent = pData->retryJitterPercent;
    iRet = omotlp_http_client_create(&http_cfg, &pWrkrData->http_client);
    if (iRet != RS_RET_OK) {
        goto finalize_it;
    }

    if (pthread_create(&pWrkrData->flush_thread, NULL, omotlp_batch_flush_thread, pWrkrData) != 0) {
        LogError(errno, RS_RET_SYS_ERR, "omotlp: failed to create flush thread");
        iRet = RS_RET_SYS_ERR;
        goto finalize_it;
    }
    pWrkrData->flush_thread_running = 1;

finalize_it:
    if (iRet != RS_RET_OK) {
        if (pWrkrData != NULL) {
            if (pWrkrData->flush_thread_running) {
                pWrkrData->flush_thread_stop = 1;
                pthread_join(pWrkrData->flush_thread, NULL);
                pWrkrData->flush_thread_running = 0;
            }
            pthread_mutex_destroy(&pWrkrData->batch_mutex);
        }
        omotlp_http_client_destroy(&pWrkrData->http_client);
        free(pWrkrData);
        pWrkrData = NULL;
    }
ENDcreateWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
    if (pData != NULL) {
        free(pData->endpoint);
        free(pData->path);
        free(pData->protocol);
        free(pData->bodyTemplateName);
        free(pData->url);
        header_list_destroy(&pData->headers);
    }
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    if (pWrkrData != NULL) {
        if (pWrkrData->flush_thread_running) {
            pWrkrData->flush_thread_stop = 1;
            pthread_join(pWrkrData->flush_thread, NULL);
            pWrkrData->flush_thread_running = 0;
        }
        (void)omotlp_flush_batch(pWrkrData);
        omotlp_batch_destroy(&pWrkrData->batch);
        pthread_mutex_destroy(&pWrkrData->batch_mutex);
        omotlp_http_client_destroy(&pWrkrData->http_client);
    }
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("omotlp\n");
    dbgprintf("\tendpoint='%s'\n", pData->endpoint ? (char *)pData->endpoint : "(default)");
    dbgprintf("\tpath='%s'\n", pData->path ? (char *)pData->path : "(default)");
    dbgprintf("\tprotocol='%s'\n", pData->protocol ? (char *)pData->protocol : "(default)");
    dbgprintf("\ttemplate='%s'\n", pData->bodyTemplateName ? (char *)pData->bodyTemplateName : "RSYSLOG_FileFormat");
    dbgprintf("\turl='%s'\n", pData->url ? (char *)pData->url : "(unresolved)");
    dbgprintf("\ttimeout.ms=%ld\n", pData->requestTimeoutMs);
    dbgprintf("\tbatch.max_items=%zu\n", pData->batchMaxItems);
    dbgprintf("\tbatch.max_bytes=%zu\n", pData->batchMaxBytes);
    dbgprintf("\tbatch.timeout.ms=%ld\n", pData->batchTimeoutMs);
    dbgprintf("\tretry.initial.ms=%ld\n", pData->retryInitialMs);
    dbgprintf("\tretry.max.ms=%ld\n", pData->retryMaxMs);
    dbgprintf("\tretry.max_retries=%u\n", pData->retryMaxRetries);
    dbgprintf("\tretry.jitter.percent=%u\n", pData->retryJitterPercent);
    dbgprintf("\tcompression=%s\n", pData->compression_mode == OMOTLP_COMPRESSION_GZIP ? "gzip" : "none");
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

static rsRetVal assignParamFromEStr(uchar **target, es_str_t *value) {
    uchar *tmp;
    DEFiRet;

    free(*target);
    *target = NULL;
    tmp = (uchar *)es_str2cstr(value, NULL);
    if (tmp == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    *target = tmp;

finalize_it:
    RETiRet;
}

BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    uchar *tplToUse = NULL;
    CODESTARTnewActInst;

    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "omotlp: error reading config parameters");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CHKiRet(createInstance(&pData));

    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;

        if (!strcmp(actpblk.descr[i].name, "endpoint")) {
            CHKiRet(assignParamFromEStr(&pData->endpoint, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "path")) {
            CHKiRet(assignParamFromEStr(&pData->path, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "protocol")) {
            CHKiRet(assignParamFromEStr(&pData->protocol, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "template")) {
            CHKiRet(assignParamFromEStr(&pData->bodyTemplateName, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "timeout.ms")) {
            long timeout_ms = 0;
            CHKiRet(parse_long_param("timeout.ms", pvals[i].val.d.estr, 0, &timeout_ms));
            pData->requestTimeoutMs = timeout_ms;
            pData->timeoutConfigured = 1;
        } else if (!strcmp(actpblk.descr[i].name, "compression")) {
            char *text = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
            if (text == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            CHKiRet(set_compression_mode(pData, text));
            pData->compressionConfigured = 1;
            free(text);
        } else if (!strcmp(actpblk.descr[i].name, "batch.max_items")) {
            size_t max_items = 0u;
            CHKiRet(parse_size_param("batch.max_items", pvals[i].val.d.estr, 0u, &max_items));
            pData->batchMaxItems = max_items;
        } else if (!strcmp(actpblk.descr[i].name, "batch.max_bytes")) {
            size_t max_bytes = 0u;
            CHKiRet(parse_size_param("batch.max_bytes", pvals[i].val.d.estr, 0u, &max_bytes));
            pData->batchMaxBytes = max_bytes;
        } else if (!strcmp(actpblk.descr[i].name, "batch.timeout.ms")) {
            long timeout_ms = 0;
            CHKiRet(parse_long_param("batch.timeout.ms", pvals[i].val.d.estr, 0, &timeout_ms));
            pData->batchTimeoutMs = timeout_ms;
        } else if (!strcmp(actpblk.descr[i].name, "retry.initial.ms")) {
            long backoff = 0;
            CHKiRet(parse_long_param("retry.initial.ms", pvals[i].val.d.estr, 0, &backoff));
            pData->retryInitialMs = backoff;
        } else if (!strcmp(actpblk.descr[i].name, "retry.max.ms")) {
            long max_backoff = 0;
            CHKiRet(parse_long_param("retry.max.ms", pvals[i].val.d.estr, 0, &max_backoff));
            pData->retryMaxMs = max_backoff;
        } else if (!strcmp(actpblk.descr[i].name, "retry.max_retries")) {
            unsigned int retries = 0u;
            CHKiRet(parse_uint_param("retry.max_retries", pvals[i].val.d.estr, 0u, &retries));
            pData->retryMaxRetries = retries;
        } else if (!strcmp(actpblk.descr[i].name, "retry.jitter.percent")) {
            unsigned int jitter = 0u;
            CHKiRet(parse_uint_param("retry.jitter.percent", pvals[i].val.d.estr, 0u, &jitter));
            if (jitter > 100u) {
                LogError(0, RS_RET_PARAM_ERROR, "omotlp: retry.jitter.percent must be between 0 and 100");
                ABORT_FINALIZE(RS_RET_PARAM_ERROR);
            }
            pData->retryJitterPercent = jitter;
        } else if (!strcmp(actpblk.descr[i].name, "headers")) {
            char *text = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
            if (text == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            CHKiRet(parse_headers_json(pData, text));
            pData->headersConfigured = 1;
            free(text);
        } else if (!strcmp(actpblk.descr[i].name, "bearer_token")) {
            char *token = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
            char *bearer = NULL;
            if (token == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            bearer = (char *)malloc(strlen(token) + strlen("Bearer ") + 1u);
            if (bearer == NULL) {
                free(token);
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            strcpy(bearer, "Bearer ");
            strcat(bearer, token);
            CHKiRet(header_list_add_kv(&pData->headers, "Authorization", bearer));
            pData->bearerConfigured = 1;
            free(bearer);
            free(token);
        } else {
            dbgprintf("omotlp: unhandled parameter '%s'\n", actpblk.descr[i].name);
        }
    }

    CHKiRet(applyEnvDefaults(pData));
    CHKiRet(ensureEndpointPathSplit(pData));

    if (pData->compression_mode == OMOTLP_COMPRESSION_UNSET) {
        pData->compression_mode = OMOTLP_COMPRESSION_NONE;
    }

    if (pData->compression_mode == OMOTLP_COMPRESSION_GZIP) {
        CHKiRet(header_list_add(&pData->headers, "Content-Encoding: gzip"));
    }

    if (pData->protocol == NULL) CHKmalloc(pData->protocol = (uchar *)strdup("http/json"));
    if (pData->endpoint == NULL) CHKmalloc(pData->endpoint = (uchar *)strdup("http://127.0.0.1:4318"));
    if (pData->path == NULL) CHKmalloc(pData->path = (uchar *)strdup("/v1/logs"));
    if (pData->bodyTemplateName == NULL) CHKmalloc(pData->bodyTemplateName = (uchar *)strdup("RSYSLOG_FileFormat"));

    lowercaseInPlace(pData->protocol);
    CHKiRet(validateProtocol(pData));
    CHKiRet(buildEffectiveUrl(pData));

    CODE_STD_STRING_REQUESTnewActInst(2);
    CHKiRet(OMSRsetEntry(*ppOMSR, OMOTLP_OMSR_IDX_MESSAGE, NULL, OMSR_TPL_AS_MSG));

    tplToUse = (uchar *)strdup((char *)pData->bodyTemplateName);
    if (tplToUse == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    CHKiRet(OMSRsetEntry(*ppOMSR, OMOTLP_OMSR_IDX_BODY, tplToUse, OMSR_NO_RQD_TPL_OPTS));

    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdoAction
    char *body = NULL;
    omotlp_log_record_t record;
    long long now_ms;
    smsg_t **ppMsgParam = (smsg_t **)pMsgData;
    smsg_t *msg = (ppMsgParam != NULL) ? ppMsgParam[OMOTLP_OMSR_IDX_MESSAGE] : NULL;
    CODESTARTdoAction;

    if (pWrkrData->pData == NULL) {
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (pWrkrData->http_client == NULL) {
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (ppString != NULL && ppString[OMOTLP_OMSR_IDX_BODY] != NULL) {
        body = (char *)ppString[OMOTLP_OMSR_IDX_BODY];
    }

    if (body == NULL) {
        body = (char *)"";
    }

    now_ms = currentTimeMills();
    CHKiRet(omotlp_batch_flush_if_due(pWrkrData, now_ms));

    CHKiRet(populateLogRecord(msg, body, &record));
    CHKiRet(omotlp_batch_add_record(pWrkrData, &record, body));

    pthread_mutex_lock(&pWrkrData->batch_mutex);
    if (pWrkrData->batch.count == 0u) {
        iRet = RS_RET_OK;
    } else {
        iRet = RS_RET_DEFER_COMMIT;
    }
    pthread_mutex_unlock(&pWrkrData->batch_mutex);

finalize_it:
ENDdoAction

NO_LEGACY_CONF_parseSelectorAct /* clang-format off */
BEGINmodExit
    CODESTARTmodExit;
    omotlp_http_global_cleanup();
    objRelease(datetime, CORE_COMPONENT);
ENDmodExit

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
ENDisCompatibleWithFeature

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt /* clang-format on */

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
    CHKiRet(omotlp_http_global_init());
    CHKiRet(objUse(datetime, CORE_COMPONENT));
ENDmodInit
