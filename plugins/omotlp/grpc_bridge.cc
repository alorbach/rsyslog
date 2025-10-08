/* grpc_bridge.cc
 * C++ implementation of OTLP gRPC bridge using OpenTelemetry C++ SDK
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

// Compile with: -fvisibility=hidden -std=c++17
// Link with: -lopentelemetry_logs -lopentelemetry_exporter_otlp_grpc_logs -lgrpc++ -lprotobuf -labsl_*

#include "grpc_bridge.h"

#include <opentelemetry/sdk/logs/logger_provider.h>
#include <opentelemetry/sdk/logs/simple_log_record_processor.h>
#include <opentelemetry/sdk/logs/batch_log_record_processor.h>
#include <opentelemetry/exporters/otlp/otlp_grpc_log_record_exporter.h>
#include <opentelemetry/logs/provider.h>
#include <opentelemetry/logs/logger.h>
#include <opentelemetry/sdk/resource/resource.h>
#include <opentelemetry/sdk/resource/semantic_conventions.h>
#include <opentelemetry/exporters/otlp/otlp_grpc_exporter_options.h>
#include <opentelemetry/sdk/common/global_log_handler.h>
#include <opentelemetry/common/attribute_value.h>
#include <opentelemetry/trace/span_id.h>
#include <opentelemetry/trace/trace_id.h>
#include <opentelemetry/trace/trace_flags.h>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <cstring>

namespace nostd = opentelemetry::nostd;
namespace logs_api = opentelemetry::logs;
namespace logs_sdk = opentelemetry::sdk::logs;
namespace resource = opentelemetry::sdk::resource;
namespace otlp = opentelemetry::exporter::otlp;

struct omotlp_grpc_bridge_s {
    std::shared_ptr<logs_sdk::LoggerProvider> logger_provider;
    std::shared_ptr<logs_api::Logger> logger;
    std::shared_ptr<logs_sdk::LogRecordProcessor> processor;
    std::shared_ptr<otlp::OtlpGrpcLogRecordExporter> exporter;
    bool initialized;
};

/* Thread-local error message storage */
static thread_local char error_msg[256] = {0};

/* Set error message for C API */
static void set_error(const char *msg) {
    strncpy(error_msg, msg, sizeof(error_msg) - 1);
    error_msg[sizeof(error_msg) - 1] = '\0';
}

/* Convert syslog severity to OTLP severity */
static logs_api::Severity otlp_severity_from_syslog(int syslog_severity) {
    switch (syslog_severity) {
        case 0: return logs_api::Severity::kTrace2;    // Emergency
        case 1: return logs_api::Severity::kFatal;     // Alert
        case 2: return logs_api::Severity::kError4;    // Critical
        case 3: return logs_api::Severity::kError;     // Error
        case 4: return logs_api::Severity::kWarn;      // Warning
        case 5: return logs_api::Severity::kInfo;      // Notice
        case 6: return logs_api::Severity::kDebug;     // Info
        case 7: return logs_api::Severity::kTrace;     // Debug
        default: return logs_api::Severity::kInfo;
    }
}

/* Convert hex string to trace ID */
static opentelemetry::trace::TraceId trace_id_from_hex(const char *hex_str) {
    if (!hex_str || strlen(hex_str) != 32) {
        return opentelemetry::trace::TraceId{};
    }

    uint8_t bytes[16];
    for (int i = 0; i < 16; i++) {
        sscanf(hex_str + (i * 2), "%2hhx", &bytes[i]);
    }

    return opentelemetry::trace::TraceId(bytes);
}

/* Convert hex string to span ID */
static opentelemetry::trace::SpanId span_id_from_hex(const char *hex_str) {
    if (!hex_str || strlen(hex_str) != 16) {
        return opentelemetry::trace::SpanId{};
    }

    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) {
        sscanf(hex_str + (i * 2), "%2hhx", &bytes[i]);
    }

    return opentelemetry::trace::SpanId(bytes);
}

/* Convert hex string to trace flags */
static opentelemetry::trace::TraceFlags trace_flags_from_hex(const char *hex_str) {
    if (!hex_str || strlen(hex_str) != 2) {
        return opentelemetry::trace::TraceFlags{};
    }

    uint8_t flags;
    sscanf(hex_str, "%2hhx", &flags);
    return opentelemetry::trace::TraceFlags(flags);
}

extern "C" {

int omotlp_grpc_init(const omotlp_grpc_config_t *config, omotlp_grpc_bridge_t **bridge) {
    if (!config || !bridge) {
        set_error("Invalid parameters");
        return -1;
    }

    if (*bridge && (*bridge)->initialized) {
        set_error("Bridge already initialized");
        return -1;
    }

    try {
        /* Note: OpenTelemetry SDK initialization is handled by the logger provider */

        /* Create resource with service information */
        auto resource_attributes = resource::ResourceAttributes{
            {resource::SemanticConventions::kServiceName, "rsyslog"},
            {resource::SemanticConventions::kServiceVersion, "8.2510.0"}
        };

        auto resource = resource::Resource::Create(resource_attributes);

        /* Configure OTLP gRPC exporter */
        otlp::OtlpGrpcExporterOptions exporter_opts;

        if (config->endpoint) {
            exporter_opts.endpoint = std::string(config->endpoint);
        }

        if (config->bearer_token) {
            exporter_opts.headers["authorization"] = std::string("Bearer ") + config->bearer_token;
        }

        if (config->ca_file) {
            exporter_opts.ssl_credentials.cacert_path = config->ca_file;
        }

        if (config->cert_file && config->key_file) {
            exporter_opts.ssl_credentials.cert_path = config->cert_file;
            exporter_opts.ssl_credentials.key_path = config->key_file;
        }

        exporter_opts.use_ssl_credentials = config->verify_ssl;

        if (config->timeout_ms > 0) {
            exporter_opts.timeout = std::chrono::milliseconds(config->timeout_ms);
        }

        if (config->compression) {
            exporter_opts.compression = otlp::Compression::kGzip;
        }

        /* Create exporter */
        auto exporter = std::make_shared<otlp::OtlpGrpcLogRecordExporter>(exporter_opts);

        /* Create batch processor */
        logs_sdk::BatchLogRecordProcessorOptions processor_opts;
        processor_opts.max_export_batch_size = config->batch_max_items;
        processor_opts.export_timeout_millis = config->timeout_ms;
        processor_opts.scheduled_delay_millis = config->batch_timeout_ms;

        auto processor = std::make_shared<logs_sdk::BatchLogRecordProcessor>(
            exporter, processor_opts);

        /* Create logger provider */
        logs_sdk::LoggerProviderOptions provider_opts;
        provider_opts.resource = resource;

        auto logger_provider = std::make_shared<logs_sdk::LoggerProvider>(
            processor, provider_opts);

        /* Create logger */
        auto logger = logger_provider->GetLogger("rsyslog.omotlp");

        /* Create bridge instance */
        auto *bridge_instance = new omotlp_grpc_bridge_t{
            logger_provider,
            logger,
            processor,
            exporter,
            true
        };

        *bridge = bridge_instance;
        return 0;

    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

int omotlp_grpc_emit(const omotlp_grpc_bridge_t *bridge, const omotlp_log_record_t *records, size_t count) {
    if (!bridge || !records) {
        set_error("Invalid parameters");
        return -1;
    }

    try {
        for (size_t i = 0; i < count; ++i) {
            const auto& record = records[i];

            /* Create log record */
            auto log_record = bridge->logger->CreateLogRecord();

            /* Set timestamp */
            log_record.SetTimestamp(std::chrono::system_clock::time_point(
                std::chrono::nanoseconds(record.time_unix_nano)));

            /* Set body */
            if (record.body) {
                log_record.SetBody(record.body);
            }

            /* Set severity */
            log_record.SetSeverity(otlp_severity_from_syslog(record.severity));

            /* Set attributes */
            auto attributes = log_record.GetAttributes();

            if (record.hostname) {
                attributes.SetAttribute("host.name", record.hostname);
            }

            if (record.app_name) {
                attributes.SetAttribute("syslog.app_name", record.app_name);
            }

            if (record.procid) {
                attributes.SetAttribute("syslog.procid", record.procid);
            }

            if (record.msgid) {
                attributes.SetAttribute("syslog.msgid", record.msgid);
            }

            attributes.SetAttribute("syslog.facility", record.facility);
            attributes.SetAttribute("syslog.severity", record.severity);
            attributes.SetAttribute("syslog.priority", record.priority);

            /* Set trace correlation if provided */
            if (record.trace_id && strlen(record.trace_id) == 32) {
                auto trace_id = trace_id_from_hex(record.trace_id);
                log_record.SetTraceId(trace_id);
            }

            if (record.span_id && strlen(record.span_id) == 16) {
                auto span_id = span_id_from_hex(record.span_id);
                log_record.SetSpanId(span_id);
            }

            if (record.trace_flags && strlen(record.trace_flags) == 2) {
                auto trace_flags = trace_flags_from_hex(record.trace_flags);
                log_record.SetTraceFlags(trace_flags);
            }

            /* Emit the record */
            bridge->logger->EmitLogRecord(std::move(log_record));
        }

        return 0;

    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

int omotlp_grpc_flush(const omotlp_grpc_bridge_t *bridge) {
    if (!bridge) {
        set_error("Invalid bridge parameter");
        return -1;
    }

    try {
        /* Force flush the processor */
        if (bridge->processor) {
            bridge->processor->ForceFlush();
        }
        return 0;

    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

int omotlp_grpc_shutdown(omotlp_grpc_bridge_t **bridge) {
    if (!bridge || !*bridge) {
        set_error("Invalid bridge parameter");
        return -1;
    }

    if (!(*bridge)->initialized) {
        set_error("Bridge not initialized");
        return -1;
    }

    try {
        /* Flush any remaining records */
        omotlp_grpc_flush(*bridge);

        /* Shutdown logger provider (this also shuts down the processor and exporter) */
        if ((*bridge)->logger_provider) {
            (*bridge)->logger_provider->Shutdown();
        }

        /* Mark as not initialized */
        (*bridge)->initialized = false;

        /* Clean up */
        delete *bridge;
        *bridge = nullptr;

        return 0;

    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

const char *omotlp_grpc_get_error(void) {
    return error_msg;
}

} /* extern "C" */