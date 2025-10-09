#include "config.h"

#include "omotlp_http.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

#include "errmsg.h"

struct omotlp_http_client_s {
    CURL *handle;
    struct curl_slist *headers;
    char *url;
    long timeout_ms;
    char error_buffer[CURL_ERROR_SIZE];
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

    rc = curl_easy_setopt(client->handle, CURLOPT_HTTPHEADER, client->headers);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to apply headers: %s", curl_easy_strerror(rc));
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

finalize_it:
    RETiRet;
}

rsRetVal omotlp_http_global_init(void) {
    if (!g_http_global_initialized) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
            LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: curl_global_init failed");
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

    client->handle = curl_easy_init();
    if (client->handle == NULL) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: curl_easy_init failed");
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    client->error_buffer[0] = '\0';
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

rsRetVal omotlp_http_client_post(omotlp_http_client_t *client, const char *payload, size_t payload_len) {
    long status = 0;
    CURLcode rc;
    DEFiRet;

    if (client == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    if (payload == NULL) {
        payload = "";
        payload_len = 0u;
    }

    client->error_buffer[0] = '\0';

    rc = curl_easy_setopt(client->handle, CURLOPT_POSTFIELDS, payload);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set payload: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_setopt(client->handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)payload_len);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to set payload size: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    rc = curl_easy_perform(client->handle);
    if (rc != CURLE_OK) {
        const char *err = client->error_buffer[0] != '\0' ? client->error_buffer : curl_easy_strerror(rc);
        LogError(0, RS_RET_SUSPENDED, "omotlp/http: HTTP POST failed: %s", err);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    rc = curl_easy_getinfo(client->handle, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp/http: failed to read response code: %s", curl_easy_strerror(rc));
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (status >= 200 && status < 300) {
        goto finalize_it;
    }

    if (status == 429 || status >= 500) {
        LogError(0, RS_RET_SUSPENDED, "omotlp/http: collector returned status %ld; message will be retried", status);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    LogError(0, RS_RET_DISCARDMSG, "omotlp/http: collector rejected payload with status %ld", status);
    ABORT_FINALIZE(RS_RET_DISCARDMSG);

finalize_it:
    RETiRet;
}
