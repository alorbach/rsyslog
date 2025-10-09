/* omotlp.c -- OpenTelemetry (OTLP) output module scaffolding
 *
 * Concurrency & Locking:
 * - Shared configuration lives in the per-action instanceData structure.
 * - Worker instances only hold a pointer back to the owning instance and do not
 *   introduce additional shared mutable state.
 * - No transport resources are created yet; future work must guard any shared
 *   handles with a mutex in instanceData.
 */
#include "config.h"
#include "rsyslog.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "datetime.h"
#include "msg.h"
#include "srUtils.h"
#include "stringbuf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

#include "otlp_json.h"
#include "omotlp_http.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omotlp")

DEF_OMOD_STATIC_DATA;
DEFobjCurrIf(datetime);

typedef struct _instanceData {
    uchar *endpoint;
    uchar *path;
    uchar *protocol;
    uchar *bodyTemplateName;
    uchar *url;
    long requestTimeoutMs;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
    omotlp_http_client_t *http_client;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;
};

static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

static struct cnfparamdescr actpdescr[] = {{"endpoint", eCmdHdlrString, 0},
                                           {"path", eCmdHdlrString, 0},
                                           {"protocol", eCmdHdlrGetWord, 0},
                                           {"template", eCmdHdlrGetWord, 0}};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

static void lowercaseInPlace(uchar *value) {
    char *cursor;

    if (value == NULL) {
        return;
    }

    for (cursor = (char *)value; *cursor != '\0'; ++cursor) {
        *cursor = (char)tolower((unsigned char)*cursor);
    }
}

static rsRetVal assignParamFromCStr(uchar **target, const char *value) {
    uchar *tmp;
    DEFiRet;

    if (value == NULL) {
        goto finalize_it;
    }

    tmp = (uchar *)strdup(value);
    if (tmp == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    free(*target);
    *target = tmp;

finalize_it:
    RETiRet;
}

static const char *firstPopulatedEnv(const char *const *names) {
    size_t i;

    if (names == NULL) {
        return NULL;
    }

    for (i = 0; names[i] != NULL; ++i) {
        const char *value = getenv(names[i]);
        if (value != NULL && value[0] != '\0') {
            return value;
        }
    }

    return NULL;
}

static rsRetVal applyEnvDefaults(instanceData *pData) {
    const char *value;
    static const char *const endpointEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT",
                                                  NULL};
    static const char *const protocolEnvVars[] = {"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL",
                                                  NULL};

    DEFiRet;

    if (pData->endpoint == NULL) {
        value = firstPopulatedEnv(endpointEnvVars);
        if (value != NULL) {
            CHKiRet(assignParamFromCStr(&pData->endpoint, value));
        }
    }

    if (pData->protocol == NULL) {
        value = firstPopulatedEnv(protocolEnvVars);
        if (value != NULL) {
            CHKiRet(assignParamFromCStr(&pData->protocol, value));
        }
    }

finalize_it:
    RETiRet;
}

static rsRetVal ensureEndpointPathSplit(instanceData *pData) {
    char *endpoint;
    char *schemeSeparator;
    char *pathStart;
    char *baseDup = NULL;
    char *pathDup = NULL;
    size_t baseLength;

    DEFiRet;

    if (pData->endpoint == NULL || pData->path != NULL) {
        goto finalize_it;
    }

    endpoint = (char *)pData->endpoint;
    schemeSeparator = strstr(endpoint, "://");
    if (schemeSeparator != NULL) {
        pathStart = strchr(schemeSeparator + 3, '/');
    } else {
        pathStart = strchr(endpoint, '/');
    }

    if (pathStart == NULL || *pathStart == '\0' || pathStart == endpoint) {
        goto finalize_it;
    }

    baseLength = (size_t)(pathStart - endpoint);
    baseDup = (char *)malloc(baseLength + 1);
    if (baseDup == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    memcpy(baseDup, endpoint, baseLength);
    baseDup[baseLength] = '\0';

    pathDup = strdup(pathStart);
    if (pathDup == NULL) {
        free(baseDup);
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    free(pData->endpoint);
    pData->endpoint = (uchar *)baseDup;
    pData->path = (uchar *)pathDup;

finalize_it:
    RETiRet;
}

static rsRetVal validateProtocol(instanceData *pData) {
    DEFiRet;

    if (pData->protocol == NULL) {
        goto finalize_it;
    }

    if (!strcmp((char *)pData->protocol, "http/json")) {
        goto finalize_it;
    }

    LogError(0, RS_RET_NOT_IMPLEMENTED, "omotlp: protocol '%s' is not supported by the scaffolding build",
             pData->protocol);
    ABORT_FINALIZE(RS_RET_NOT_IMPLEMENTED);

finalize_it:
    RETiRet;
}

static rsRetVal buildEffectiveUrl(instanceData *pData) {
    const char *endpoint = (const char *)pData->endpoint;
    const char *path = (const char *)pData->path;
    size_t endpoint_len;
    size_t path_len;
    size_t total;
    int endpoint_has_slash;
    int path_has_slash;
    char *buffer = NULL;
    size_t cursor = 0;

    DEFiRet;

    if (endpoint == NULL) {
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }

    endpoint_len = strlen(endpoint);
    path_len = (path != NULL) ? strlen(path) : 0u;
    endpoint_has_slash = (endpoint_len > 0 && endpoint[endpoint_len - 1] == '/');
    path_has_slash = (path_len > 0 && path[0] == '/');

    total = endpoint_len + path_len + 2u;
    buffer = malloc(total);
    if (buffer == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    memcpy(buffer, endpoint, endpoint_len);
    cursor = endpoint_len;

    if (path_len > 0) {
        if (!endpoint_has_slash && !path_has_slash) {
            buffer[cursor++] = '/';
        } else if (endpoint_has_slash && path_has_slash) {
            ++path;
            --path_len;
        }

        memcpy(buffer + cursor, path, path_len);
        cursor += path_len;
    }

    buffer[cursor] = '\0';

    free(pData->url);
    pData->url = (uchar *)buffer;

finalize_it:
    if (iRet != RS_RET_OK && buffer != NULL) {
        free(buffer);
    }
    RETiRet;
}

typedef struct severity_mapping_s {
    uint32_t number;
    const char *text;
} severity_mapping_t;

static const severity_mapping_t severity_lookup[8] = {{24u, "EMERGENCY"}, {23u, "ALERT"},   {22u, "CRITICAL"},
                                                      {17u, "ERROR"},     {13u, "WARNING"}, {11u, "NOTICE"},
                                                      {9u, "INFO"},       {5u, "DEBUG"}};

static void mapSeverity(int syslogSeverity, omotlp_log_record_t *record) {
    if (syslogSeverity < 0 || syslogSeverity > 7) {
        record->severity_number = 0u;
        record->severity_text = NULL;
        return;
    }

    record->severity_number = severity_lookup[syslogSeverity].number;
    record->severity_text = severity_lookup[syslogSeverity].text;
}

static uint64_t scaleFractionToNanos(int fraction, int precision) {
    uint64_t value;

    if (precision <= 0 || fraction <= 0) {
        return 0u;
    }

    value = (uint64_t)fraction;
    if (precision > 9) {
        int diff = precision - 9;
        while (diff-- > 0 && value > 0u) {
            value /= 10u;
        }
    } else if (precision < 9) {
        int diff = 9 - precision;
        while (diff-- > 0) {
            value *= 10u;
        }
    }

    return value;
}

static uint64_t syslogTimeToUnixNanos(const struct syslogTime *timestamp) {
    if (timestamp == NULL) {
        return 0u;
    }

    return ((uint64_t)datetime.syslogTime2time_t(timestamp) * 1000000000ull) +
           scaleFractionToNanos(timestamp->secfrac, timestamp->secfracPrecision);
}

static const char *cstrToConst(cstr_t *value) {
    return value == NULL ? NULL : (const char *)rsCStrGetSzStrNoNULL(value);
}

static const char *extractAppName(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSAPPNAME);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    if (msg->iLenPROGNAME > 0 && msg->PROGNAME.ptr != NULL) {
        return (const char *)msg->PROGNAME.ptr;
    }

    return NULL;
}

static const char *extractProcId(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSPROCID);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    return NULL;
}

static const char *extractMsgId(const smsg_t *msg) {
    const char *candidate;

    if (msg == NULL) {
        return NULL;
    }

    candidate = cstrToConst(msg->pCSMSGID);
    if (candidate != NULL && candidate[0] != '\0') {
        return candidate;
    }

    return NULL;
}

static rsRetVal populateLogRecord(smsg_t *msg, const char *body, omotlp_log_record_t *record) {
    int severity;

    DEFiRet;

    memset(record, 0, sizeof(*record));

    CHKiRet(MsgGetSeverity(msg, &severity));
    mapSeverity(severity, record);

    record->body = body;
    record->hostname = (msg->pszHOSTNAME != NULL) ? (const char *)msg->pszHOSTNAME : NULL;
    record->app_name = extractAppName(msg);
    record->proc_id = extractProcId(msg);
    record->msg_id = extractMsgId(msg);
    record->facility = (uint16_t)msg->iFacility;
    record->time_unix_nano = syslogTimeToUnixNanos(&msg->tTIMESTAMP);
    record->observed_time_unix_nano = syslogTimeToUnixNanos(&msg->tRcvdAt);
    record->trace_id = NULL;
    record->span_id = NULL;
    record->trace_flags = 0u;

finalize_it:
    RETiRet;
}

static inline void setInstParamDefaults(instanceData *pData) {
    pData->endpoint = NULL;
    pData->path = NULL;
    pData->protocol = NULL;
    pData->bodyTemplateName = NULL;
    pData->url = NULL;
    pData->requestTimeoutMs = 10000;
}

BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
    CODESTARTendCnfLoad;
ENDendCnfLoad

BEGINcheckCnf
    CODESTARTcheckCnf;
ENDcheckCnf

BEGINactivateCnf
    CODESTARTactivateCnf;
    runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
    CODESTARTfreeCnf;
ENDfreeCnf

BEGINcreateInstance
    CODESTARTcreateInstance;
    setInstParamDefaults(pData);
ENDcreateInstance

BEGINcreateWrkrInstance
    omotlp_http_client_config_t http_cfg;
    CODESTARTcreateWrkrInstance;
    pWrkrData->pData = pData;
    pWrkrData->http_client = NULL;

    if (pData == NULL || pData->url == NULL) {
        iRet = RS_RET_INTERNAL_ERROR;
        goto finalize_it;
    }

    http_cfg.url = (const char *)pData->url;
    http_cfg.timeout_ms = pData->requestTimeoutMs;
    http_cfg.user_agent = "rsyslog-omotlp/" VERSION;
    iRet = omotlp_http_client_create(&http_cfg, &pWrkrData->http_client);
    if (iRet != RS_RET_OK) {
        goto finalize_it;
    }

finalize_it:
    if (iRet != RS_RET_OK) {
        omotlp_http_client_destroy(&pWrkrData->http_client);
        free(pWrkrData);
        pWrkrData = NULL;
    }
ENDcreateWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
    if (pData != NULL) {
        free(pData->endpoint);
        free(pData->path);
        free(pData->protocol);
        free(pData->bodyTemplateName);
        free(pData->url);
    }
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    if (pWrkrData != NULL) {
        omotlp_http_client_destroy(&pWrkrData->http_client);
    }
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("omotlp\n");
    dbgprintf("\tendpoint='%s'\n", pData->endpoint ? (char *)pData->endpoint : "(default)");
    dbgprintf("\tpath='%s'\n", pData->path ? (char *)pData->path : "(default)");
    dbgprintf("\tprotocol='%s'\n", pData->protocol ? (char *)pData->protocol : "(default)");
    dbgprintf("\ttemplate='%s'\n", pData->bodyTemplateName ? (char *)pData->bodyTemplateName : "RSYSLOG_FileFormat");
    dbgprintf("\turl='%s'\n", pData->url ? (char *)pData->url : "(unresolved)");
    dbgprintf("\ttimeout.ms=%ld\n", pData->requestTimeoutMs);
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

static rsRetVal assignParamFromEStr(uchar **target, es_str_t *value) {
    uchar *tmp;
    DEFiRet;

    free(*target);
    *target = NULL;
    tmp = (uchar *)es_str2cstr(value, NULL);
    if (tmp == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    *target = tmp;

finalize_it:
    RETiRet;
}

BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    uchar *tplToUse = NULL;
    CODESTARTnewActInst;

    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "omotlp: error reading config parameters");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CHKiRet(createInstance(&pData));

    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;

        if (!strcmp(actpblk.descr[i].name, "endpoint")) {
            CHKiRet(assignParamFromEStr(&pData->endpoint, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "path")) {
            CHKiRet(assignParamFromEStr(&pData->path, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "protocol")) {
            CHKiRet(assignParamFromEStr(&pData->protocol, pvals[i].val.d.estr));
        } else if (!strcmp(actpblk.descr[i].name, "template")) {
            CHKiRet(assignParamFromEStr(&pData->bodyTemplateName, pvals[i].val.d.estr));
        } else {
            dbgprintf("omotlp: unhandled parameter '%s'\n", actpblk.descr[i].name);
        }
    }

    CHKiRet(applyEnvDefaults(pData));
    CHKiRet(ensureEndpointPathSplit(pData));

    if (pData->protocol == NULL) CHKmalloc(pData->protocol = (uchar *)strdup("http/json"));
    if (pData->endpoint == NULL) CHKmalloc(pData->endpoint = (uchar *)strdup("http://127.0.0.1:4318"));
    if (pData->path == NULL) CHKmalloc(pData->path = (uchar *)strdup("/v1/logs"));
    if (pData->bodyTemplateName == NULL) CHKmalloc(pData->bodyTemplateName = (uchar *)strdup("RSYSLOG_FileFormat"));

    lowercaseInPlace(pData->protocol);
    CHKiRet(validateProtocol(pData));
    CHKiRet(buildEffectiveUrl(pData));

    CODE_STD_STRING_REQUESTnewActInst(2);
    tplToUse = (uchar *)strdup((char *)pData->bodyTemplateName);
    if (tplToUse == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, tplToUse, OMSR_NO_RQD_TPL_OPTS));
    CHKiRet(OMSRsetEntry(*ppOMSR, 1, NULL, OMSR_TPL_AS_MSG));

    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdoAction
    char *payload = NULL;
    char *body = NULL;
    smsg_t *msg = NULL;
    omotlp_log_record_t record;
    size_t payload_len = 0u;
    CODESTARTdoAction;

    if (pWrkrData->pData == NULL) {
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (pWrkrData->http_client == NULL) {
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    if (ppString != NULL) {
        body = (char *)ppString[0];
        if (ppString[1] != NULL) {
            msg = (smsg_t *)(uintptr_t)ppString[1];
        }
    }

    if (msg == NULL) {
        LogError(0, RS_RET_INTERNAL_ERROR, "omotlp: missing message context for OTLP serialization");
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }

    CHKiRet(populateLogRecord(msg, body, &record));
    CHKiRet(omotlp_json_build_export(&record, 1, &payload));

    if (payload != NULL) {
        payload_len = strlen(payload);
    }

    if (Debug && payload != NULL) {
        dbgprintf("omotlp: preview OTLP/HTTP payload: %s\n", payload);
    }

    CHKiRet(omotlp_http_client_post(pWrkrData->http_client, payload, payload_len));
finalize_it:
    free(payload);
ENDdoAction

NO_LEGACY_CONF_parseSelectorAct /* clang-format off */
BEGINmodExit
    CODESTARTmodExit;
    omotlp_http_global_cleanup();
    objRelease(datetime, CORE_COMPONENT);
ENDmodExit

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
ENDisCompatibleWithFeature

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt /* clang-format on */

BEGINmodInit()
    CODESTARTmodInit;
    CHKiRet(omotlp_http_global_init());
    CHKiRet(objUse(datetime, CORE_COMPONENT));
ENDmodInit
