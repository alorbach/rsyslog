/* omotlp_http.c - HTTP transport via libcurl for OTLP JSON */
#include "config.h"
#include "rsyslog.h"
#include <curl/curl.h>
#include <curl/easy.h>
#include <string.h>
#include <stdlib.h>
#include "errmsg.h"
#include "omotlp.h"

rsRetVal omotlp_http_setup(omotlp_wrkr_instance_t *wi) {
    DEFiRet;
    wi->curlPostHandle = curl_easy_init();
    if (wi->curlPostHandle == NULL) ABORT_FINALIZE(RS_RET_ERR);
    /* basic defaults */
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_MAXREDIRS, 5L);
finalize_it:
    RETiRet;
}

void omotlp_http_cleanup(omotlp_wrkr_instance_t *wi) {
    if (wi->curlHeader != NULL) {
        curl_slist_free_all(wi->curlHeader);
        wi->curlHeader = NULL;
    }
    if (wi->curlPostHandle != NULL) {
        curl_easy_cleanup(wi->curlPostHandle);
        wi->curlPostHandle = NULL;
    }
}

rsRetVal omotlp_http_post(omotlp_wrkr_instance_t *wi, const uchar *payload, const size_t len, long *httpCode,
                          long timeoutMs, sbool compress, int compressionLevel) {
    DEFiRet;
    (void)compress;
    (void)compressionLevel;
    CURLcode res;
    *httpCode = 0;
    if (wi->curlPostHandle == NULL) ABORT_FINALIZE(RS_RET_INVALID_PARAMS);

    /* headers */
    struct curl_slist *hdr = NULL;
    hdr = curl_slist_append(hdr, "Content-Type: application/json");
    hdr = curl_slist_append(hdr, "Accept: application/json");
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_HTTPHEADER, hdr);
    wi->curlHeader = hdr;

    curl_easy_setopt(wi->curlPostHandle, CURLOPT_URL, (char *)wi->restURL);
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_POST, 1L);
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_POSTFIELDSIZE, (long)len);
    if (timeoutMs > 0) curl_easy_setopt(wi->curlPostHandle, CURLOPT_TIMEOUT_MS, timeoutMs);

    res = curl_easy_perform(wi->curlPostHandle);
    if (res != CURLE_OK) {
        LogError(0, RS_RET_ERR, "omotlp: curl_easy_perform failed: %s", curl_easy_strerror(res));
        ABORT_FINALIZE(RS_RET_ERR);
    }
    curl_easy_getinfo(wi->curlPostHandle, CURLINFO_RESPONSE_CODE, httpCode);
finalize_it:
    RETiRet;
}

