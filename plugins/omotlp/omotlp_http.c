#include "config.h"

#include "omotlp_http.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

#include "srUtils.h"

#include "errmsg.h"

struct omotlp_http_client_s {
    CURL *handle;
    struct curl_slist *headers;
    char *url;
    long timeout_ms;
    char error_buffer[CURL_ERROR_SIZE];
    long retry_initial_ms;
    long retry_max_ms;
    unsigned int retry_max_retries;
    unsigned int retry_jitter_percent;
};

static int g_http_global_initialized = 0;

static size_t discard_response(void *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

static rsRetVal set_common_options(omotlp_http_client_t *client, const omotlp_http_client_config_t *config) {
    CURLcode rc;
    DEFiRet;

    if (client->url == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_URL, client->url);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set URL: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_POST, 1L);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to enable POST: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_WRITEFUNCTION, discard_response);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to install response sink: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_NOSIGNAL, 1L);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to disable signals: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (config->timeout_ms > 0) {
        rc = curl_easy_setopt(client->handle, CURLOPT_TIMEOUT_MS, config->timeout_ms);
        if (rc != CURLE_OK) {
            LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set timeout: %s", curl_easy_strerror(rc));
            ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
        }
    }

    if (config->user_agent != NULL) {
        rc = curl_easy_setopt(client->handle, CURLOPT_USERAGENT, config->user_agent);
        if (rc != CURLE_OK) {
            LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set user-agent: %s", curl_easy_strerror(rc));
            ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
        }
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_ERRORBUFFER, client->error_buffer);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to install error buffer: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_HTTPHEADER, client->headers);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to apply headers: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

finalize_it:
    RETiRet;
}

rsRetVal omotlp_http_global_init(void) {
    if (!g_http_global_initialized) {
        CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (rc != CURLE_OK) {
            LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: curl_global_init failed: %s", curl_easy_strerror(rc));
            return RS_RET_INTERNAL_ERROR;
        }
        g_http_global_initialized = 1;
    }

    return RS_RET_OK;
}

void omotlp_http_global_cleanup(void) {
    if (g_http_global_initialized) {
        curl_global_cleanup();
        g_http_global_initialized = 0;
    }
}

rsRetVal omotlp_http_client_create(const omotlp_http_client_config_t *config, omotlp_http_client_t **out_client) {
    omotlp_http_client_t *client = NULL;
    DEFiRet;

    if (config == NULL || out_client == NULL || config->url == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    client = calloc(1, sizeof(*client));
    if (client == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    client->url = strdup(config->url);
    if (client->url == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    client->timeout_ms = config->timeout_ms;

    client->headers = curl_slist_append(client->headers, "Content-Type: application/json");
    if (client->headers == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    client->headers = curl_slist_append(client->headers, "Accept: application/json");
    if (client->headers == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    if (config->headers != NULL && config->header_count > 0) {
        size_t i;
        for (i = 0; i < config->header_count; ++i) {
            client->headers = curl_slist_append(client->headers, config->headers[i]);
            if (client->headers == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
        }
    }

    client->handle = curl_easy_init();
    if (client->handle == NULL) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: curl_easy_init failed");
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    client->error_buffer[0] = '\0';
    client->retry_initial_ms = config->retry_initial_ms;
    client->retry_max_ms = config->retry_max_ms;
    client->retry_max_retries = config->retry_max_retries;
    client->retry_jitter_percent = config->retry_jitter_percent;
    CHKiRet(set_common_options(client, config));

    *out_client = client;
    client = NULL;

finalize_it:
    if (iRet != RS_RET_OK) {
        omotlp_http_client_destroy(&client);
    }

    RETiRet;
}

void omotlp_http_client_destroy(omotlp_http_client_t **client_ptr) {
    omotlp_http_client_t *client;

    if (client_ptr == NULL || *client_ptr == NULL) {
        return;
    }

    client = *client_ptr;
    *client_ptr = NULL;

    if (client->headers != NULL) {
        curl_slist_free_all(client->headers);
    }
    if (client->handle != NULL) {
        curl_easy_cleanup(client->handle);
    }
    free(client->url);
    free(client);
}

static long apply_jitter(long base_delay, unsigned int jitter_percent) {
    long range;
    long offset;

    if (base_delay <= 0 || jitter_percent == 0) {
        return base_delay;
    }

    range = (base_delay * (long)jitter_percent) / 100L;
    if (range <= 0) {
        return base_delay;
    }

    offset = (long)(labs(randomNumber()) % (range * 2L + 1L)) - range;
    base_delay += offset;
    if (base_delay < 0) {
        base_delay = 0;
    }

    return base_delay;
}

static void sleep_with_backoff(long delay_ms) {
    if (delay_ms <= 0) {
        return;
    }

    srSleep((int)(delay_ms / 1000L), (int)((delay_ms % 1000L) * 1000L));
}

static int should_retry_status(long status) {
    if (status == 0) {
        return 1;
    }

    if (status == 408 || status == 429) {
        return 1;
    }

    if (status >= 500) {
        return 1;
    }

    return 0;
}

rsRetVal omotlp_http_client_post(omotlp_http_client_t *client, const uint8_t *payload, size_t payload_len,
                                long *out_status_code, long *out_latency_ms) {
    long status = 0;
    CURLcode rc;
    const uint8_t empty_payload[] = "";
    const uint8_t *payload_bytes;
    unsigned int retries = 0u;
    long delay_ms;
    long long start_ms = 0;
    long long end_ms = 0;
    DEFiRet;

    DBGPRINTF("omotlp/http: omotlp_http_client_post called, payload_len=%zu, url=%s", payload_len,
              client ? (client->url ? client->url : "(null)") : "(null client)");

    if (client == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (out_status_code != NULL) {
        *out_status_code = 0;
    }
    if (out_latency_ms != NULL) {
        *out_latency_ms = 0;
    }

    payload_bytes = payload != NULL ? payload : empty_payload;

    client->error_buffer[0] = '\0';

    rc = curl_easy_setopt(client->handle, CURLOPT_POSTFIELDS, (const char *)payload_bytes);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set payload: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)payload_len);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set payload size: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    delay_ms = client->retry_initial_ms;

    for (;;) {
        client->error_buffer[0] = '\0';
        status = 0;
        start_ms = currentTimeMills();

        DBGPRINTF("omotlp/http: calling curl_easy_perform, attempt %u", retries + 1);
        rc = curl_easy_perform(client->handle);
        end_ms = currentTimeMills();
        DBGPRINTF("omotlp/http: curl_easy_perform returned: %d (%s)", rc, curl_easy_strerror(rc));
        if (rc != CURLE_OK) {
            const char *err = client->error_buffer[0] != '\0' ? client->error_buffer : curl_easy_strerror(rc);
            LogError(0, RS_RET_SUSPENDED, "omotlp/http: HTTP POST failed: %s", err);

            if (retries >= client->retry_max_retries) {
                ABORT_FINALIZE(RS_RET_SUSPENDED);
            }

            if (delay_ms > 0) {
                sleep_with_backoff(apply_jitter(delay_ms, client->retry_jitter_percent));
                delay_ms *= 2;
                if (client->retry_max_ms > 0 && delay_ms > client->retry_max_ms) {
                    delay_ms = client->retry_max_ms;
                }
            }
            ++retries;
            continue;
        }

        rc = curl_easy_getinfo(client->handle, CURLINFO_RESPONSE_CODE, &status);
        if (rc != CURLE_OK) {
            LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to read response code: %s", curl_easy_strerror(rc));
            ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
        }

        DBGPRINTF("omotlp/http: HTTP response status: %ld", status);
        if (status >= 200 && status < 300) {
            DBGPRINTF("omotlp/http: HTTP POST successful (status %ld)", status);
            goto finalize_it;
        }

        if (should_retry_status(status)) {
            LogError(0, RS_RET_SUSPENDED, "omotlp/http: collector returned status %ld; retrying batch", status);
            if (retries >= client->retry_max_retries) {
                ABORT_FINALIZE(RS_RET_SUSPENDED);
            }

            if (delay_ms > 0) {
                sleep_with_backoff(apply_jitter(delay_ms, client->retry_jitter_percent));
                delay_ms *= 2;
                if (client->retry_max_ms > 0 && delay_ms > client->retry_max_ms) {
                    delay_ms = client->retry_max_ms;
                }
            }
            ++retries;
            continue;
        }

        LogError(0, RS_RET_DISCARDMSG, "omotlp/http: collector rejected payload with status %ld", status);
        ABORT_FINALIZE(RS_RET_DISCARDMSG);
    }

finalize_it:
    if (out_status_code != NULL) {
        *out_status_code = status;
    }
    if (out_latency_ms != NULL && start_ms > 0 && end_ms >= start_ms) {
        *out_latency_ms = (long)(end_ms - start_ms);
    }
    DBGPRINTF("omotlp/http: omotlp_http_client_post completed, iRet=%d", iRet);
    RETiRet;
}
