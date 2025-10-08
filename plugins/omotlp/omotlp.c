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

static prop_t *pInputName = NULL;

typedef struct configSettings_s {
    int dummy;
} configSettings_t;
static configSettings_t cs;

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
ENDcreateWrkrInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    omotlp_http_cleanup((wrkrInstanceData_t *)pWrkrData);
ENDfreeWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
ENDfreeInstance

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("omotlp\n");
ENDdbgPrintInstInfo

BEGINdoAction
    CODESTARTdoAction;
    es_str_t *buf = NULL;
    long httpCode = 0;
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
    }
    CHKiRet(omotlp_json_begin(&buf, NULL));
    CHKiRet(omotlp_json_add_record(buf, (smsg_t *)pMsgData, body, sevText, sevNum, NULL, NULL, 0));
    CHKiRet(omotlp_json_end(buf));
    if (((wrkrInstanceData_t *)pWrkrData)->restURL == NULL) {
        ((wrkrInstanceData_t *)pWrkrData)->restURL = (uchar *)strdup("http://127.0.0.1:4318/v1/logs");
        CHKiRet(omotlp_http_setup((wrkrInstanceData_t *)pWrkrData));
    }
    CHKiRet(omotlp_http_post((wrkrInstanceData_t *)pWrkrData, (uchar *)es_str2cstr(buf, NULL), es_strlen(buf), &httpCode, 1000, 0, -1));
    es_deleteStr(buf);
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
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar *)"RSYSLOG_TraditionalFileFormat", OMSR_NO_RQD_TPL_OPTS));
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINparseSelectorAct
    CODESTARTparseSelectorAct;
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
ENDparseSelectorAct

BEGINmodInit()
    CODESTARTmodInit;
    INITLegCnfVars;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    /* nothing to register beyond std queries */
ENDmodInit

BEGINmodExit
    CODESTARTmodExit;
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_CNFNAME_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
ENDqueryEtryPt

