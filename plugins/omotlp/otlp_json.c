/* otlp_json.c - Build OTLP ExportLogsServiceRequest JSON using libfastjson */
#include "config.h"
#include "rsyslog.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <json.h>
#include "datetime.h"
struct fjson_object *omotlp_json_build_record_obj(smsg_t *const pMsg, const uchar *body, const uchar *severityText,
                                                  const int severityNumber, const uchar *traceId, const uchar *spanId,
                                                  const int traceFlags) {
    int64_t tsNsec;
    {
        time_t secs = (time_t)datetime.syslogTime2time_t(&pMsg->tTIMESTAMP);
        unsigned long usec = (unsigned long)pMsg->tTIMESTAMP.secfrac;
        tsNsec = ((int64_t)secs * 1000000000LL) + ((int64_t)usec * 1000LL);
    }
    struct fjson_object *rec = fjson_object_new_object();
    fjson_object_object_add(rec, "timeUnixNano", fjson_object_new_int64(tsNsec));
    struct fjson_object *bodyObj = fjson_object_new_object();
    fjson_object_object_add(bodyObj, "stringValue", fjson_object_new_string((const char *)(body ? body : (uchar *)"")));
    fjson_object_object_add(rec, "body", bodyObj);
    fjson_object_object_add(rec, "severityText",
                            fjson_object_new_string((const char *)(severityText ? severityText : (uchar *)"")));
    fjson_object_object_add(rec, "severityNumber", fjson_object_new_int(severityNumber));
    if (traceId != NULL && spanId != NULL) {
        fjson_object_object_add(rec, "traceId", fjson_object_new_string((const char *)traceId));
        fjson_object_object_add(rec, "spanId", fjson_object_new_string((const char *)spanId));
        fjson_object_object_add(rec, "flags", fjson_object_new_int(traceFlags));
    }
    return rec;
}
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

/* minimal mapping: body as string, severity number/text, timestamp
 * Build each LogRecord as JSON with libfastjson (see mmsnareparse, omhttp patterns).
 */
rsRetVal omotlp_json_add_record(es_str_t *buf, smsg_t *const pMsg, const uchar *body, const uchar *severityText,
                                const int severityNumber, const uchar *traceId, const uchar *spanId,
                                const int traceFlags) {
    DEFiRet;
    int64_t tsNsec;
    
    /* timestamp in ns since epoch from message timestamp */
    {
        time_t secs = (time_t)datetime.syslogTime2time_t(&pMsg->tTIMESTAMP);
        unsigned long usec = (unsigned long)pMsg->tTIMESTAMP.secfrac; /* microseconds */
        tsNsec = ((int64_t)secs * 1000000000LL) + ((int64_t)usec * 1000LL);
    }

    /* Build LogRecord as fjson object */
    struct fjson_object *rec = omotlp_json_build_record_obj(pMsg, body, severityText, severityNumber, traceId, spanId, traceFlags);
    const char *recStr = fjson_object_to_json_string_ext(rec, FJSON_TO_STRING_PLAIN);
    if (recStr == NULL) {
        fjson_object_put(rec);
        ABORT_FINALIZE(RS_RET_ERR);
    }

    if (es_strlen(buf) > 0) es_addChar(buf, ',');
    es_addBuf(&buf, recStr, strlen(recStr));

    fjson_object_put(rec);
finalize_it:
    RETiRet;
}

rsRetVal omotlp_json_end(es_str_t *buf) {
    DEFiRet;
    json_append(buf, "]}]}]}");
    RETiRet;
}

