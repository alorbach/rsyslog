#ifndef OMOTLP_HTTP_H
#define OMOTLP_HTTP_H

#include <stddef.h>

#include "rsyslog.h"

typedef struct omotlp_http_client_config_s {
    const char *url;
    long timeout_ms;
    const char *user_agent;
} omotlp_http_client_config_t;

typedef struct omotlp_http_client_s omotlp_http_client_t;

rsRetVal omotlp_http_global_init(void);
void omotlp_http_global_cleanup(void);

rsRetVal omotlp_http_client_create(const omotlp_http_client_config_t *config, omotlp_http_client_t **out_client);
void omotlp_http_client_destroy(omotlp_http_client_t **client);

rsRetVal omotlp_http_client_post(omotlp_http_client_t *client, const char *payload, size_t payload_len);

#endif /* OMOTLP_HTTP_H */
