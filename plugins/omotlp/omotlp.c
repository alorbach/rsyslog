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
ENDcreateWrkrInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
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
    /* build minimal one-record payload and POST; this is a placeholder */
    es_str_t *buf = NULL;
    long httpCode = 0;
    const uchar *body = (ppString != NULL && ppString[0] != NULL) ? ppString[0] : (uchar *)"";
    CHKiRet(omotlp_json_begin(&buf, NULL));
    CHKiRet(omotlp_json_add_record(buf, (smsg_t *)pMsgData, body, (uchar *)"INFO", 9, NULL, NULL, 0));
    CHKiRet(omotlp_json_end(buf));
    /* dummy URL; real code will compute from instance config */
    pWrkrData->restURL = (uchar *)strdup("http://127.0.0.1:4318/v1/logs");
    CHKiRet(omotlp_http_setup((omotlp_wrkr_instance_t *)pWrkrData));
    CHKiRet(omotlp_http_post((omotlp_wrkr_instance_t *)pWrkrData, es_str2cstr(buf, NULL), es_strlen(buf), &httpCode, 1000, 0, -1));
    (void)httpCode;
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
        /* placeholder; real parsing implemented later */
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

