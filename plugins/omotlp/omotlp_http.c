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
    /* TLS options */
    if (wi->pData != NULL) {
        if (wi->pData->allowUnsignedCerts) curl_easy_setopt(wi->curlPostHandle, CURLOPT_SSL_VERIFYPEER, 0L);
        if (wi->pData->skipVerifyHost) curl_easy_setopt(wi->curlPostHandle, CURLOPT_SSL_VERIFYHOST, 0L);
        if (wi->pData->caCertFile) curl_easy_setopt(wi->curlPostHandle, CURLOPT_CAINFO, wi->pData->caCertFile);
        if (wi->pData->myCertFile) curl_easy_setopt(wi->curlPostHandle, CURLOPT_SSLCERT, wi->pData->myCertFile);
        if (wi->pData->myPrivKeyFile) curl_easy_setopt(wi->curlPostHandle, CURLOPT_SSLKEY, wi->pData->myPrivKeyFile);
    }
    /* headers baseline */
    struct curl_slist *hdr = NULL;
    hdr = curl_slist_append(hdr, "Content-Type: application/json");
    hdr = curl_slist_append(hdr, "Accept: application/json");
    if (wi->pData != NULL && wi->pData->bearerToken != NULL) {
        es_str_t *auth = es_newStr(64);
        es_addBuf(&auth, "Authorization: Bearer ", 22);
        es_addBuf(&auth, (const char *)wi->pData->bearerToken, strlen((const char *)wi->pData->bearerToken));
        hdr = curl_slist_append(hdr, (const char *)es_str2cstr(auth, NULL));
        es_deleteStr(auth);
    }
    if (wi->pData != NULL && wi->pData->nHttpHeaders > 0) {
        for (int i = 0; i < wi->pData->nHttpHeaders; ++i) hdr = curl_slist_append(hdr, (const char *)wi->pData->httpHeaders[i]);
    }
    wi->curlHeader = hdr;
    curl_easy_setopt(wi->curlPostHandle, CURLOPT_HTTPHEADER, hdr);
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

