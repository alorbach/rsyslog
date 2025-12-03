#ifndef OMOTLP_OTLP_JSON_H
#define OMOTLP_OTLP_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "rsyslog.h"
#include <json.h>

typedef struct omotlp_log_record_s {
    uint64_t time_unix_nano;
    uint64_t observed_time_unix_nano;
    uint32_t severity_number;
    const char *severity_text;
    const char *body;
    const char *hostname;
    const char *app_name;
    const char *proc_id;
    const char *msg_id;
    const char *trace_id;
    const char *span_id;
    uint8_t trace_flags;
    uint16_t facility;
} omotlp_log_record_t;

typedef struct omotlp_resource_attrs_s {
    const char *service_instance_id;
    const char *deployment_environment;
    struct json_object *custom_attributes;  /* Parsed JSON object with custom attributes */
} omotlp_resource_attrs_t;

rsRetVal omotlp_json_build_export(const omotlp_log_record_t *records,
                                  size_t record_count,
                                  const omotlp_resource_attrs_t *resource_attrs,
                                  char **out_payload);

#endif /* OMOTLP_OTLP_JSON_H */
