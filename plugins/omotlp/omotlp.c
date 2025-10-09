/* omotlp.c - OpenTelemetry Logs (OTLP) output module - Phase 1: HTTP/JSON */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(__FreeBSD__)
    #include <unistd.h>
#endif
#include <json.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "statsobj.h"
#include "omotlp.h"
#include "msg.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omotlp")

/* internal structures */
DEF_OMOD_STATIC_DATA;
DEFobjCurrIf(statsobj)
    statsobj_t *otlpStats;
STATSCOUNTER_DEF(ctrSent, mutCtrSent)
STATSCOUNTER_DEF(ctrRetried, mutCtrRetried)
STATSCOUNTER_DEF(ctrDropped, mutCtrDropped)
STATSCOUNTER_DEF(ctrHttp4xx, mutCtrHttp4xx)
STATSCOUNTER_DEF(ctrHttp5xx, mutCtrHttp5xx)

static prop_t *pInputName = NULL;

typedef struct configSettings_s {
    int dummy;
} configSettings_t;
static configSettings_t cs;
/* module config data for conf2 interface */
struct modConfData_s {
    rsconf_t *pConf; /* overall config object */
};
static modConfData_t *loadModConf = NULL; /* during load */
static modConfData_t *runModConf = NULL;  /* during runtime */

BEGINinitConfVars /* (re)set config variables to default values */
    CODESTARTinitConfVars;
ENDinitConfVars


/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
    {"endpoint", eCmdHdlrArray, 0},
    {"path", eCmdHdlrGetWord, 0},
    {"timeout.ms", eCmdHdlrInt, 0},
    {"bearer_token", eCmdHdlrString, 0},
    {"httpheaders", eCmdHdlrArray, 0},
    {"usehttps", eCmdHdlrBinary, 0},
    {"allowunsignedcerts", eCmdHdlrBinary, 0},
    {"skipverifyhost", eCmdHdlrBinary, 0},
    {"tls.cacert", eCmdHdlrString, 0},
    {"tls.mycert", eCmdHdlrString, 0},
    {"tls.myprivkey", eCmdHdlrString, 0},
    {"compress", eCmdHdlrBinary, 0},
    {"compress.level", eCmdHdlrInt, 0},
    {"batch.max_items", eCmdHdlrSize, 0},
    {"batch.max_bytes", eCmdHdlrSize, 0},
    {"batch.timeout.ms", eCmdHdlrInt, 0},
    {"retry", eCmdHdlrBinary, 0},
    {"httpretrycodes", eCmdHdlrArray, 0},
    {"httpignorablecodes", eCmdHdlrArray, 0},
    {"resource", eCmdHdlrString, 0},
    {"template", eCmdHdlrGetWord, 0},
};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

BEGINcreateInstance
    CODESTARTcreateInstance;
    /* defaults */
    pData->defaultPort = 4318;
    pData->numServers = 0;
    pData->serverBaseUrls = NULL;
    pData->path = (uchar *)strdup("/v1/logs");
    pData->timeoutMs = 5000;
    pData->bearerToken = NULL;
    pData->httpHeaders = NULL;
    pData->nHttpHeaders = 0;
    pData->useHttps = 0;
    pData->allowUnsignedCerts = 0;
    pData->skipVerifyHost = 0;
    pData->caCertFile = NULL;
    pData->myCertFile = NULL;
    pData->myPrivKeyFile = NULL;
    pData->compress = 0;
    pData->compressionLevel = -1;
    pData->maxBatchItems = 0;
    pData->maxBatchBytes = 0;
    pData->batchTimeoutMs = 0;
    pData->retryFailures = 1;
    pData->nhttpRetryCodes = 0;
    pData->httpRetryCodes = NULL;
    pData->nIgnorableCodes = 0;
    pData->ignorableCodes = NULL;
    pData->resourceJson = NULL;
    pData->tplName = NULL;
    /* register module-global stats object */
    otlpStats = NULL;
ENDcreateInstance

BEGINcreateWrkrInstance
    CODESTARTcreateWrkrInstance;
    ((wrkrInstanceData_t *)pWrkrData)->restURL = NULL;
    ((wrkrInstanceData_t *)pWrkrData)->curlPostHandle = NULL;
    ((wrkrInstanceData_t *)pWrkrData)->curlHeader = NULL;
    if (pData != NULL && pData->serverBaseUrls != NULL && pData->numServers > 0) {
        const char *base = (const char *)pData->serverBaseUrls[0];
        const char *path = (const char *)(pData->path ? pData->path : (uchar *)"/v1/logs");
        es_str_t *url = es_newStr(256);
        if (url != NULL) {
            es_addBuf(&url, base, strlen(base));
            size_t blen = strlen(base);
            if (blen == 0 || base[blen - 1] != '/') es_addChar(&url, '/');
            if (*path == '/') path++;
            es_addBuf(&url, path, strlen(path));
            ((wrkrInstanceData_t *)pWrkrData)->restURL = (uchar *)es_str2cstr(url, NULL);
            es_deleteStr(url);
        }
    }
    /* init batch buffer */
    ((wrkrInstanceData_t *)pWrkrData)->batch.buf = es_newStr(2048);
    ((wrkrInstanceData_t *)pWrkrData)->batch.items = 0;
    ((wrkrInstanceData_t *)pWrkrData)->batch.bytes = 0;
ENDcreateWrkrInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    omotlp_http_cleanup((wrkrInstanceData_t *)pWrkrData);
    if (((wrkrInstanceData_t *)pWrkrData)->batch.buf) es_deleteStr(((wrkrInstanceData_t *)pWrkrData)->batch.buf);
ENDfreeWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
ENDfreeInstance
BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
    CODESTARTendCnfLoad;
    loadModConf = NULL;
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


BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("omotlp\n");
ENDdbgPrintInstInfo

static inline rsRetVal otlp_flush_batch(wrkrInstanceData_t *const wi);

BEGINendTransaction
    CODESTARTendTransaction;
    (void) otlp_flush_batch((wrkrInstanceData_t *)pWrkrData);
ENDendTransaction

static inline rsRetVal otlp_flush_batch(wrkrInstanceData_t *const wi) {
    DEFiRet;
    if (wi->batch.items == 0) RETiRet;
    /* Build top-level ExportLogsServiceRequest with fjson */
    struct fjson_object *req = fjson_object_new_object();
    struct fjson_object *resourceLogs = fjson_object_new_array();
    struct fjson_object *resLog = fjson_object_new_object();
    struct fjson_object *resource = fjson_object_new_object();
    struct fjson_object *attributes = fjson_object_new_array();
    /* If resourceJson provided, parse and add raw attributes if possible (future work). */
    fjson_object_object_add(resource, "attributes", attributes);
    fjson_object_object_add(resLog, "resource", resource);
    struct fjson_object *scopeLogs = fjson_object_new_array();
    struct fjson_object *scopeLog = fjson_object_new_object();
    fjson_object_object_add(scopeLog, "logRecords", wi->batch.records ? wi->batch.records : fjson_object_new_array());
    fjson_object_array_add(scopeLogs, scopeLog);
    fjson_object_object_add(resLog, "scopeLogs", scopeLogs);
    fjson_object_array_add(resourceLogs, resLog);
    fjson_object_object_add(req, "resourceLogs", resourceLogs);
    const char *payloadStr = fjson_object_to_json_string_ext(req, FJSON_TO_STRING_PLAIN);
    long httpCode = 0;
    CHKiRet(omotlp_http_post(wi, (uchar *)payloadStr, strlen(payloadStr), &httpCode,
                             wi->pData ? wi->pData->timeoutMs : 1000, wi->pData ? wi->pData->compress : 0,
                             wi->pData ? wi->pData->compressionLevel : -1));
    if (httpCode >= 200 && httpCode < 300) {
        STATSCOUNTER_ADD(ctrSent, mutCtrSent, wi->batch.items);
        wi->batch.items = 0;
        wi->batch.bytes = 0;
        if (wi->batch.records) {
            fjson_object_put(wi->batch.records);
            wi->batch.records = NULL;
        }
        iRet = RS_RET_OK;
    } else if ((wi->pData && wi->pData->retryFailures && (httpCode == 429 || (httpCode >= 500 && httpCode < 600))) ||
               (wi->pData && wi->pData->nhttpRetryCodes > 0)) {
        if (wi->pData && wi->pData->nhttpRetryCodes > 0) {
            for (int i = 0; i < wi->pData->nhttpRetryCodes; ++i) {
                if ((unsigned int)httpCode == wi->pData->httpRetryCodes[i]) {
                    STATSCOUNTER_INC(ctrRetried, mutCtrRetried);
                    ABORT_FINALIZE(RS_RET_SUSPENDED);
                }
            }
        }
        STATSCOUNTER_INC(ctrRetried, mutCtrRetried);
        STATSCOUNTER_INC(ctrHttp5xx, mutCtrHttp5xx);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    } else {
        sbool ignorable = 0;
        if (wi->pData && wi->pData->nIgnorableCodes > 0) {
            for (int i = 0; i < wi->pData->nIgnorableCodes; ++i) {
                if ((unsigned int)httpCode == wi->pData->ignorableCodes[i]) {
                    ignorable = 1;
                    break;
                }
            }
        }
        if (!ignorable) {
            STATSCOUNTER_INC(ctrDropped, mutCtrDropped);
            if (httpCode >= 400 && httpCode < 500) STATSCOUNTER_INC(ctrHttp4xx, mutCtrHttp4xx);
        }
        iRet = RS_RET_OK; /* drop */
        wi->batch.items = 0;
        wi->batch.bytes = 0;
        if (wi->batch.records) {
            fjson_object_put(wi->batch.records);
            wi->batch.records = NULL;
        }
    }
finalize_it:
    if (req) fjson_object_put(req);
    RETiRet;
}

BEGINdoAction
    CODESTARTdoAction;
    /* build record and append into batch */
    const uchar *body = (ppString != NULL && ppString[0] != NULL) ? ppString[0] : (uchar *)"";
    int sev = 0;
    CHKiRet(MsgGetSeverity((smsg_t *)pMsgData, &sev));
    const uchar *sevText = (uchar *)"DEBUG";
    int sevNum = 1;
    switch (sev) {
        case 0: sevText = (uchar *)"EMERGENCY"; sevNum = 1; break;
        case 1: sevText = (uchar *)"ALERT"; sevNum = 2; break;
        case 2: sevText = (uchar *)"CRITICAL"; sevNum = 3; break;
        case 3: sevText = (uchar *)"ERROR"; sevNum = 17; break;
        case 4: sevText = (uchar *)"WARNING"; sevNum = 13; break;
        case 5: sevText = (uchar *)"NOTICE"; sevNum = 9; break;
        case 6: sevText = (uchar *)"INFO"; sevNum = 9; break;
        case 7: sevText = (uchar *)"DEBUG"; sevNum = 5; break;
        default: break;
    }
    /* lazy CURL setup */
    if (((wrkrInstanceData_t *)pWrkrData)->restURL == NULL) {
        /* if endpoint not set, use default */
        ((wrkrInstanceData_t *)pWrkrData)->restURL = (uchar *)strdup("http://127.0.0.1:4318/v1/logs");
    }
    CHKiRet(omotlp_http_setup((wrkrInstanceData_t *)pWrkrData));
    /* append record into batch (fjson array + size tracking) */
    if (((wrkrInstanceData_t *)pWrkrData)->batch.records == NULL) {
        ((wrkrInstanceData_t *)pWrkrData)->batch.records = fjson_object_new_array();
    }
    struct fjson_object *recObj = omotlp_json_build_record_obj((smsg_t *)pMsgData, body, sevText, sevNum, NULL, NULL, 0);
    fjson_object_array_add(((wrkrInstanceData_t *)pWrkrData)->batch.records, recObj);
    const char *recStrTmp = fjson_object_to_json_string_ext(recObj, FJSON_TO_STRING_PLAIN);
    if (recStrTmp != NULL) ((wrkrInstanceData_t *)pWrkrData)->batch.bytes += strlen(recStrTmp) + 1; /* + comma */
    ((wrkrInstanceData_t *)pWrkrData)->batch.items++;
    if (((wrkrInstanceData_t *)pWrkrData)->batch.items == 1) {
        ((wrkrInstanceData_t *)pWrkrData)->batch.firstItemNsec = (int64_t)currentTimeMills();
    }
    /* flush on thresholds */
    if ((((wrkrInstanceData_t *)pWrkrData)->pData && ((wrkrInstanceData_t *)pWrkrData)->pData->maxBatchItems > 0 &&
         ((wrkrInstanceData_t *)pWrkrData)->batch.items >= ((wrkrInstanceData_t *)pWrkrData)->pData->maxBatchItems) ||
        (((wrkrInstanceData_t *)pWrkrData)->pData && ((wrkrInstanceData_t *)pWrkrData)->pData->maxBatchBytes > 0 &&
         ((wrkrInstanceData_t *)pWrkrData)->batch.bytes >= ((wrkrInstanceData_t *)pWrkrData)->pData->maxBatchBytes)) {
        CHKiRet(otlp_flush_batch((wrkrInstanceData_t *)pWrkrData));
    }
    if (((wrkrInstanceData_t *)pWrkrData)->pData && ((wrkrInstanceData_t *)pWrkrData)->pData->batchTimeoutMs > 0) {
        long long nowMs = currentTimeMills();
        long long firstMs = (long long)((wrkrInstanceData_t *)pWrkrData)->batch.firstItemNsec;
        if (((wrkrInstanceData_t *)pWrkrData)->batch.items > 0 && (nowMs - firstMs) >= ((wrkrInstanceData_t *)pWrkrData)->pData->batchTimeoutMs) {
            CHKiRet(otlp_flush_batch((wrkrInstanceData_t *)pWrkrData));
        }
    }
finalize_it:
ENDdoAction

BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    CODESTARTnewActInst;
    pvals = nvlstGetParams(lst, &actpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "omotlp: error reading config parameters");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    /* allocate and fill instance config */
    CHKiRet(createInstance(&pData));
    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(actpblk.descr[i].name, "endpoint")) {
            /* accept one URL for now */
            pData->numServers = pvals[i].val.d.ar ? pvals[i].val.d.ar->nmemb : 1;
            CHKmalloc(pData->serverBaseUrls = calloc(pData->numServers, sizeof(uchar *)));
            if (pvals[i].val.d.ar) {
                for (int j = 0; j < pvals[i].val.d.ar->nmemb; ++j) {
                    pData->serverBaseUrls[j] = (uchar *)es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
                }
            } else {
                pData->serverBaseUrls[0] = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
            }
        } else if (!strcmp(actpblk.descr[i].name, "path")) {
            pData->path = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "timeout.ms")) {
            pData->timeoutMs = (long)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "bearer_token")) {
            pData->bearerToken = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "httpheaders")) {
            pData->nHttpHeaders = pvals[i].val.d.ar->nmemb;
            CHKmalloc(pData->httpHeaders = calloc(pData->nHttpHeaders, sizeof(uchar *)));
            for (int j = 0; j < pvals[i].val.d.ar->nmemb; ++j) {
                pData->httpHeaders[j] = (uchar *)es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
            }
        } else if (!strcmp(actpblk.descr[i].name, "usehttps")) {
            pData->useHttps = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "allowunsignedcerts")) {
            pData->allowUnsignedCerts = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "skipverifyhost")) {
            pData->skipVerifyHost = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "tls.cacert")) {
            pData->caCertFile = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "tls.mycert")) {
            pData->myCertFile = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "tls.myprivkey")) {
            pData->myPrivKeyFile = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "compress")) {
            pData->compress = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "compress.level")) {
            pData->compressionLevel = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "batch.max_items")) {
            pData->maxBatchItems = (size_t)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "batch.max_bytes")) {
            pData->maxBatchBytes = (size_t)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "batch.timeout.ms")) {
            pData->batchTimeoutMs = (long)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "retry")) {
            pData->retryFailures = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "httpretrycodes")) {
            pData->nhttpRetryCodes = pvals[i].val.d.ar->nmemb;
            CHKmalloc(pData->httpRetryCodes = calloc(pData->nhttpRetryCodes, sizeof(unsigned int)));
            for (int j = 0; j < pvals[i].val.d.ar->nmemb; ++j) {
                int ok = 0; long long n = es_str2num(pvals[i].val.d.ar->arr[j], &ok);
                if (ok) pData->httpRetryCodes[j] = (unsigned int)n;
            }
        } else if (!strcmp(actpblk.descr[i].name, "httpignorablecodes")) {
            pData->nIgnorableCodes = pvals[i].val.d.ar->nmemb;
            CHKmalloc(pData->ignorableCodes = calloc(pData->nIgnorableCodes, sizeof(unsigned int)));
            for (int j = 0; j < pvals[i].val.d.ar->nmemb; ++j) {
                int ok = 0; long long n = es_str2num(pvals[i].val.d.ar->arr[j], &ok);
                if (ok) pData->ignorableCodes[j] = (unsigned int)n;
            }
        } else if (!strcmp(actpblk.descr[i].name, "resource")) {
            pData->resourceJson = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "template")) {
            pData->tplName = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        }
    }
    /* template for message body */
    CODE_STD_STRING_REQUESTnewActInst(1);
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar *)"RSYSLOG_TraditionalFileFormat", OMSR_NO_RQD_TPL_OPTS));
    CODE_STD_FINALIZERnewActInst;
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINparseSelectorAct
    CODESTARTparseSelectorAct;
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
    CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

/* forward declarations for queryEtryPt symbols */
static rsRetVal isCompatibleWithFeature(syslogFeature eFeat);
static rsRetVal tryResume(void);

BEGINmodInit(omotlp)
    CODESTARTmodInit;
    /* no legacy conf vars to init */
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    /* global stats registration */
    statsobj.Destruct(&otlpStats);
    CHKiRet(statsobj.Construct(&otlpStats));
    CHKiRet(statsobj.SetName(otlpStats, (uchar *)"omotlp"));
    CHKiRet(statsobj.SetOrigin(otlpStats, (uchar *)"omotlp"));
    CHKiRet(statsobj.AddCounter(otlpStats, (uchar *)"sent", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrSent));
    CHKiRet(statsobj.AddCounter(otlpStats, (uchar *)"retried", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrRetried));
    CHKiRet(statsobj.AddCounter(otlpStats, (uchar *)"dropped", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrDropped));
    CHKiRet(statsobj.AddCounter(otlpStats, (uchar *)"http.4xx", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrHttp4xx));
    CHKiRet(statsobj.AddCounter(otlpStats, (uchar *)"http.5xx", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrHttp5xx));
    CHKiRet(statsobj.ConstructFinalize(otlpStats));
finalize_it:
ENDmodInit

BEGINmodExit
    CODESTARTmodExit;
    statsobj.Destruct(&otlpStats);
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_CNFNAME_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
ENDqueryEtryPt

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
    if (eFeat == sFEATURERepeatedMsgReduction) iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

