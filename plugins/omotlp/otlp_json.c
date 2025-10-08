/* otlp_json.c - Build OTLP ExportLogsServiceRequest JSON using libfastjson */
#include "config.h"
#include "rsyslog.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <json.h>
#include "srUtils.h"
#include "msg.h"
#include "template.h"
#include "omotlp.h"

static inline void json_append(es_str_t *dest, const char *s) {
    es_addBuf(dest, (const uchar *)s, strlen(s));
}

rsRetVal omotlp_json_begin(es_str_t **pBuf, const uchar *resourceJson) {
    DEFiRet;
    es_str_t *buf = es_newStr(2048);
    if (buf == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    json_append(buf, "{\"resourceLogs\":[{");
    json_append(buf, "\"resource\":{\"attributes\":[");
    if (resourceJson != NULL && resourceJson[0] != '\0') {
        /* assume resourceJson is a JSON object; map to attributes if needed later */
        es_addBuf(buf, resourceJson, strlen((const char *)resourceJson));
    }
    json_append(buf, "]},\"scopeLogs\":[{\"logRecords\":[");
    *pBuf = buf;
finalize_it:
    RETiRet;
}

/* minimal mapping: body as string, severity number/text, timestamp */
rsRetVal omotlp_json_add_record(es_str_t *buf, smsg_t *const pMsg, const uchar *body, const uchar *severityText,
                                const int severityNumber, const uchar *traceId, const uchar *spanId,
                                const int traceFlags) {
    DEFiRet;
    unsigned long long tsNsec;
    nvlst_t *lst = NULL;
    (void)lst;

    /* if not first log record, add comma */
    if (es_strlen(buf) > 0) {
        const char *cbuf = es_str2cstr(buf, NULL);
        if (cbuf != NULL && cbuf[strlen(cbuf) - 1] != '[') json_append(buf, ",");
    }

    /* timestamp in ns since epoch */
    tsNsec = (unsigned long long)msgGetTSUSec(pMsg) * 1000ULL; /* us to ns */

    es_addBuf(buf, (const uchar *)"{\"timeUnixNano\":", 18);
    es_addNumAsStr(buf, tsNsec);
    json_append(buf, ",\"body\":{\"stringValue\":");
    es_addChar(buf, '"');
    es_addStr(buf, body == NULL ? (uchar *)"" : body);
    es_addChar(buf, '"');
    json_append(buf, ",\"severityText\":");
    es_addChar(buf, '"');
    es_addStr(buf, severityText == NULL ? (uchar *)"" : severityText);
    es_addChar(buf, '"');
    json_append(buf, ",\"severityNumber\":");
    es_addInt(buf, severityNumber);
    if (traceId != NULL && spanId != NULL) {
        json_append(buf, ",\"traceId\":");
        es_addQuotedStr(buf, traceId);
        json_append(buf, ",\"spanId\":");
        es_addQuotedStr(buf, spanId);
        json_append(buf, ",\"flags\":");
        es_addInt(buf, traceFlags);
    }
    json_append(buf, "}");

finalize_it:
    RETiRet;
}

rsRetVal omotlp_json_end(es_str_t *buf) {
    DEFiRet;
    json_append(buf, "]}]}]}");
    RETiRet;
}

