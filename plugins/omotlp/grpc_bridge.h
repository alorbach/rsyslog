/* grpc_bridge.h
 * C API facade over OpenTelemetry C++ SDK for OTLP gRPC transport
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
#ifndef GRPC_BRIDGE_H_INCLUDED
#define GRPC_BRIDGE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle for gRPC bridge */
typedef struct omotlp_grpc_bridge_s omotlp_grpc_bridge_t;

/* Configuration for gRPC bridge */
typedef struct omotlp_grpc_config_s {
    const char *endpoint;           /* OTLP gRPC endpoint (host:port) */
    const char *bearer_token;       /* Bearer token for authentication */
    const char *ca_file;            /* CA certificate file path */
    const char *cert_file;          /* Client certificate file path */
    const char *key_file;           /* Client private key file path */
    int verify_ssl;                 /* Verify SSL certificates (0=off, 1=on) */
    int timeout_ms;                 /* Request timeout in milliseconds */
    int compression;                /* Compression: 0=none, 1=gzip */
    int batch_max_items;            /* Maximum batch size */
    int batch_max_bytes;            /* Maximum batch size in bytes */
    int batch_timeout_ms;           /* Batch timeout in milliseconds */
} omotlp_grpc_config_t;

/* Log record structure for gRPC bridge */
typedef struct omotlp_log_record_s {
    uint64_t time_unix_nano;        /* Timestamp in nanoseconds */
    const char *body;               /* Log message body */
    int severity_number;            /* OTLP severity number */
    const char *severity_text;      /* OTLP severity text */
    const char *hostname;           /* Hostname attribute */
    const char *app_name;           /* Application name */
    const char *procid;             /* Process ID */
    const char *msgid;              /* Message ID */
    int facility;                   /* Syslog facility */
    int severity;                   /* Syslog severity */
    int priority;                   /* Syslog priority */
    const char *trace_id;           /* Trace ID (hex string, optional) */
    const char *span_id;            /* Span ID (hex string, optional) */
    const char *trace_flags;        /* Trace flags (hex string, optional) */
} omotlp_log_record_t;

/* Initialize gRPC bridge with configuration */
int omotlp_grpc_init(const omotlp_grpc_config_t *config, omotlp_grpc_bridge_t **bridge);

/* Emit log records via gRPC */
int omotlp_grpc_emit(const omotlp_grpc_bridge_t *bridge, const omotlp_log_record_t *records, size_t count);

/* Flush pending records */
int omotlp_grpc_flush(const omotlp_grpc_bridge_t *bridge);

/* Shutdown gRPC bridge and cleanup resources */
int omotlp_grpc_shutdown(omotlp_grpc_bridge_t **bridge);

/* Get last error message */
const char *omotlp_grpc_get_error(void);

#ifdef __cplusplus
}
#endif

#endif /* GRPC_BRIDGE_H_INCLUDED */