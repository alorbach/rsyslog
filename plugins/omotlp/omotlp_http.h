#ifndef OMOTLP_HTTP_H
#define OMOTLP_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "rsyslog.h"

typedef struct omotlp_http_client_config_s {
    const char *url;
    long timeout_ms;
    const char *user_agent;
    const char *const *headers;
    size_t header_count;
    long retry_initial_ms;
    long retry_max_ms;
    unsigned int retry_max_retries;
    unsigned int retry_jitter_percent;
} omotlp_http_client_config_t;

typedef struct omotlp_http_client_s omotlp_http_client_t;

rsRetVal omotlp_http_global_init(void);
void omotlp_http_global_cleanup(void);

rsRetVal omotlp_http_client_create(const omotlp_http_client_config_t *config, omotlp_http_client_t **out_client);
void omotlp_http_client_destroy(omotlp_http_client_t **client);

rsRetVal omotlp_http_client_post(omotlp_http_client_t *client, const uint8_t *payload, size_t payload_len,
                                long *out_status_code, long *out_latency_ms);

#endif /* OMOTLP_HTTP_H */
