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

#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("omotlp")

DEF_OMOD_STATIC_DATA;

typedef struct _instanceData {
    uchar *endpoint;
    uchar *path;
    uchar *protocol;
    uchar *bodyTemplateName;
    int warnedNotImplemented;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
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

static inline void setInstParamDefaults(instanceData *pData) {
    pData->endpoint = NULL;
    pData->path = NULL;
    pData->protocol = NULL;
    pData->bodyTemplateName = NULL;
    pData->warnedNotImplemented = 0;
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
    CODESTARTcreateWrkrInstance;
ENDcreateWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
    if (pData != NULL) {
        free(pData->endpoint);
        free(pData->path);
        free(pData->protocol);
        free(pData->bodyTemplateName);
    }
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("omotlp\n");
    dbgprintf("\tendpoint='%s'\n", pData->endpoint ? (char *)pData->endpoint : "(default)");
    dbgprintf("\tpath='%s'\n", pData->path ? (char *)pData->path : "(default)");
    dbgprintf("\tprotocol='%s'\n", pData->protocol ? (char *)pData->protocol : "(default)");
    dbgprintf("\ttemplate='%s'\n", pData->bodyTemplateName ? (char *)pData->bodyTemplateName : "RSYSLOG_FileFormat");
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

    if (pData->protocol == NULL) CHKmalloc(pData->protocol = (uchar *)strdup("http/json"));
    if (pData->endpoint == NULL) CHKmalloc(pData->endpoint = (uchar *)strdup("http://127.0.0.1:4318"));
    if (pData->path == NULL) CHKmalloc(pData->path = (uchar *)strdup("/v1/logs"));
    if (pData->bodyTemplateName == NULL) CHKmalloc(pData->bodyTemplateName = (uchar *)strdup("RSYSLOG_FileFormat"));

    CODE_STD_STRING_REQUESTnewActInst(1);
    tplToUse = (uchar *)strdup((char *)pData->bodyTemplateName);
    if (tplToUse == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, tplToUse, OMSR_NO_RQD_TPL_OPTS));

    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdoAction
    CODESTARTdoAction;

    if (pWrkrData->pData != NULL && !pWrkrData->pData->warnedNotImplemented) {
        LogError(0, RS_RET_NOT_IMPLEMENTED, "omotlp: transport layer not yet implemented; message dropped");
        pWrkrData->pData->warnedNotImplemented = 1;
    }

    ABORT_FINALIZE(RS_RET_NOT_IMPLEMENTED);
ENDdoAction

NO_LEGACY_CONF_parseSelectorAct

BEGINmodInit() CODESTARTmodInit;
/* no module-level initialization required for the scaffolding phase */
ENDmodInit

BEGINmodExit()
    CODESTARTmodExit;
    /* nothing to clean up yet */
ENDmodExit
