/* omotlp.h - OpenTelemetry Logs output module (HTTP/JSON v1)
 */
#ifndef RSYSLOG_OMOTLP_H
#define RSYSLOG_OMOTLP_H

#include "rsyslog.h"
#include "obj-types.h"
#include "syslogd-types.h"
#include <curl/curl.h>
#include <json.h>
#include <stdint.h>
#include "srUtils.h"

typedef struct omotlp_instance_s omotlp_instance_t;
typedef struct omotlp_wrkr_instance_s omotlp_wrkr_instance_t;
/* adapt names to module-template expected aliases */
typedef struct omotlp_instance_s instanceData;
typedef struct omotlp_wrkr_instance_s wrkrInstanceData_t;

struct omotlp_instance_s {
    int defaultPort;
    uchar **serverBaseUrls;
    int numServers;
    uchar *path; /* e.g. /v1/logs */
    long timeoutMs;
    uchar *bearerToken;
    uchar **httpHeaders;
    int nHttpHeaders;
    sbool useHttps;
    sbool allowUnsignedCerts;
    sbool skipVerifyHost;
    uchar *caCertFile;
    uchar *myCertFile;
    uchar *myPrivKeyFile;
    sbool compress;
    int compressionLevel; /* zlib */
    size_t maxBatchItems;
    size_t maxBatchBytes;
    long batchTimeoutMs;
    sbool retryFailures;
    int nhttpRetryCodes;
    unsigned int *httpRetryCodes;
    int nIgnorableCodes;
    unsigned int *ignorableCodes;
    uchar *resourceJson; /* static resource attributes JSON */
    uchar *tplName;      /* body template name */
};

struct omotlp_wrkr_instance_s {
    omotlp_instance_t *pData;
    int serverIndex;
    long httpStatusCode;
    CURL *curlPostHandle;
    struct curl_slist *curlHeader;
    uchar *restURL;
    struct {
        es_str_t *buf;
        struct fjson_object *records; /* array of logRecords */
        size_t items;
        size_t bytes;
        int64_t firstItemNsec;
    } batch;
};

/* JSON builder */
rsRetVal omotlp_json_begin(es_str_t **pBuf, const uchar *resourceJson);
rsRetVal omotlp_json_add_record(es_str_t *buf, smsg_t *const pMsg, const uchar *body, const uchar *severityText,
                                const int severityNumber, const uchar *traceId, const uchar *spanId,
                                const int traceFlags);
rsRetVal omotlp_json_end(es_str_t *buf);

/* Build a single LogRecord as a libfastjson object */
struct fjson_object *omotlp_json_build_record_obj(smsg_t *const pMsg, const uchar *body, const uchar *severityText,
                                                  const int severityNumber, const uchar *traceId, const uchar *spanId,
                                                  const int traceFlags);

/* HTTP transport */
rsRetVal omotlp_http_setup(omotlp_wrkr_instance_t *wi);
void omotlp_http_cleanup(omotlp_wrkr_instance_t *wi);
rsRetVal omotlp_http_post(omotlp_wrkr_instance_t *wi, const uchar *payload, const size_t len, long *httpCode,
                          long timeoutMs, sbool compress, int compressionLevel);

#endif /* RSYSLOG_OMOTLP_H */

