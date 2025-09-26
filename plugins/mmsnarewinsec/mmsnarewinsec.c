/**
 * @file mmsnarewinsec.c
 * @brief NXLog Snare Windows Security parser module.
 *
 * The module consumes Snare-formatted Windows Security events that are either
 * embedded in RFC3164/RFC5424 syslog envelopes or delivered as JSON payloads.
 * Incoming events are normalized and attached to the rsyslog message as a JSON
 * representation that mirrors the structure documented by NXLog and Snare.
 *
 * @note Concurrency & Locking: Module configuration lives in ::instanceData
 *       and becomes immutable after activation. Worker instances maintain only
 *       a pointer to the shared configuration, so no explicit locking is
 *       required.
 */

#include "config.h"
#include "rsyslog.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <json.h>
#include <json_object_iterator.h>
#include <json_tokener.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/stat.h>

#include "conf.h"
#include "datetime.h"
#include "errmsg.h"
#include "glbl.h"
#include "module-template.h"
#include "msg.h"
#include "syslogd-types.h"
#include "template.h"
#include "unicode-helper.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("mmsnarewinsec")

/**
 * @brief Default message container that receives parsed JSON output.
 */
#define MMSNAREWINSEC_CONTAINER_DEFAULT "!win"

#define SECTION_FLAG_NONE 0u
#define SECTION_FLAG_NETWORK (1u << 0)
#define SECTION_FLAG_LAPS (1u << 1)
#define SECTION_FLAG_TLS (1u << 2)
#define SECTION_FLAG_WDAC (1u << 3)

#define MAX_PARSING_ERRORS 64u

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/**
 * @brief Describes how a description block behaves while parsing.
 */
typedef enum section_behavior {
    sectionBehaviorStandard = 0,
    sectionBehaviorInlineValue,
    sectionBehaviorSemicolon,
    sectionBehaviorList
} section_behavior_t;

/**
 * @brief Metadata describing a description section inside Snare messages.
 *
 * @var section_descriptor::label Human-readable section label.
 * @var section_descriptor::canonical Canonical name used in the JSON output.
 * @var section_descriptor::behavior Parsing behavior applied to the section.
 * @var section_descriptor::flags Feature flags gating optional sections.
 */
typedef enum field_pattern_sensitivity {
    fieldSensitivityCanonical = 0,
    fieldSensitivityCaseSensitive,
    fieldSensitivityCaseInsensitive
} field_pattern_sensitivity_t;

typedef struct section_descriptor {
    const char *pattern;
    const char *canonical;
    section_behavior_t behavior;
    uint32_t flags;
    int priority;
    field_pattern_sensitivity_t sensitivity;
} section_descriptor_t;

/**
 * @brief Maps numeric Windows logon types to friendly names.
 *
 * @var logon_type_map::type_id Numeric Windows logon type identifier.
 * @var logon_type_map::description Canonical text description used in JSON output.
 */
typedef struct logon_type_map {
    int type_id;
    const char *description;
} logon_type_map_t;

/**
 * @brief Associates selected Event IDs with derived metadata.
 *
 * @var event_mapping::event_id Windows Event ID.
 * @var event_mapping::category High level category such as Logon or Process.
 * @var event_mapping::subtype Specific subtype within the category.
 * @var event_mapping::outcome Default outcome assigned when audit results are
 *      ambiguous.
 */
typedef struct event_mapping {
    int event_id;
    const char *category;
    const char *subtype;
    const char *outcome;
} event_mapping_t;

typedef enum field_value_type {
    fieldValueString = 0,
    fieldValueInt64,
    fieldValueInt64WithRaw,
    fieldValueBool,
    fieldValueJson,
    fieldValueLogonType,
    fieldValueRemoteCredentialGuard,
    fieldValuePrivilegeList
} field_value_type_t;

typedef struct field_pattern {
    const char *pattern;
    const char *canonical;
    field_value_type_t value_type;
    const char *section;
    int priority;
    field_pattern_sensitivity_t sensitivity;
} field_pattern_t;

typedef struct event_field_mapping {
    int event_id;
    field_pattern_t *patterns;
    size_t pattern_count;
    uint32_t required_flags;
} event_field_mapping_t;

typedef struct runtime_config {
    field_pattern_t *custom_patterns;
    size_t custom_pattern_count;
    section_descriptor_t *custom_sections;
    size_t custom_section_count;
    event_field_mapping_t *custom_event_mappings;
    size_t custom_event_mapping_count;
    event_mapping_t *custom_events;
    size_t custom_event_count;
    bool enable_debug;
    bool enable_fallback;
    char *config_file;
    char *raw_text;
} runtime_config_t;

typedef enum validation_mode {
    VALIDATION_STRICT = 0,
    VALIDATION_MODERATE,
    VALIDATION_PERMISSIVE
} validation_mode_t;

typedef struct validation_context {
    validation_mode_t mode;
    bool enable_debug;
    bool log_parsing_errors;
    bool continue_on_error;
    size_t max_errors_before_fail;
    size_t current_error_count;
} validation_context_t;

typedef struct field_detection_context {
    validation_context_t *validation;
    struct json_object *error_array;
    struct json_object *stats_object;
    size_t parsing_errors;
    size_t total_fields;
    size_t successful_parses;
    bool enable_debug;
} field_detection_context_t;

typedef void (*token_callback_t)(const char *token, size_t len, void *user_data);

static rsRetVal handle_parsing_error(field_detection_context_t *ctx,
                                     const char *error_message,
                                     const char *context);

#define FIELD_PRIORITY_BASE 10
#define FIELD_PRIORITY_EVENT_OVERRIDE 100

#define SECTION_PRIORITY_DEFAULT 100
#define SECTION_PRIORITY_OVERRIDE 200

#define FIELD_SECTION_EVENT_DATA "EventData"
#define FIELD_SECTION_LOGON "Logon"
#define FIELD_SECTION_ROOT "Root"

static const field_pattern_t g_coreFieldPatterns[] = {
    {"LogonType", "LogonType", fieldValueLogonType, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"SecurityID", "SecurityID", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"AccountName", "AccountName", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"AccountDomain", "AccountDomain", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"LogonID", "LogonID", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"LinkedLogonID", "LinkedLogonID", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"NetworkAccountName", "NetworkAccountName", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"NetworkAccountDomain", "NetworkAccountDomain", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"LogonGUID", "LogonGUID", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ProcessID", "ProcessID", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ProcessName", "ProcessName", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ProcessCommandLine", "ProcessCommandLine", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"TokenElevationType", "TokenElevationType", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"MandatoryLabel", "MandatoryLabel", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"WorkstationName", "WorkstationName", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"SourceNetworkAddress", "SourceNetworkAddress", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"SourcePort", "SourcePort", fieldValueInt64, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ClientAddress", "ClientAddress", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ClientPort", "ClientPort", fieldValueInt64, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"DestinationAddress", "DestinationAddress", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"DestinationPort", "DestinationPort", fieldValueInt64, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"NetworkAddress", "NetworkAddress", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"Protocol", "Protocol", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"Direction", "Direction", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"LogonProcess", "LogonProcess", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"AuthenticationPackage", "AuthenticationPackage", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"TransitedServices", "TransitedServices", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"PackageName", "PackageName", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"RestrictedAdminMode", "RestrictedAdminMode", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"VirtualAccount", "VirtualAccount", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ElevatedToken", "ElevatedToken", fieldValueString, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"ImpersonationLevel", "ImpersonationLevel", fieldValueString, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"KeyLength", "KeyLength", fieldValueInt64, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},
    {"RemoteCredentialGuard", "RemoteCredentialGuard", fieldValueRemoteCredentialGuard, NULL, FIELD_PRIORITY_BASE,
     fieldSensitivityCanonical},
    {"Privileges", "Privileges", fieldValuePrivilegeList, NULL, FIELD_PRIORITY_BASE, fieldSensitivityCanonical},

    /* Subject section */
    {"SubjectSecurityID", "SecurityID", fieldValueString, "Subject", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"SubjectAccountName", "AccountName", fieldValueString, "Subject", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"SubjectAccountDomain", "AccountDomain", fieldValueString, "Subject", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"SubjectLogonID", "LogonID", fieldValueString, "Subject", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Logon Information section */
    {"LogonInformationLogonType", "LogonType", fieldValueLogonType, "LogonInformation", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"LogonInformationRestrictedAdminMode", "RestrictedAdminMode", fieldValueString, "LogonInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"LogonInformationVirtualAccount", "VirtualAccount", fieldValueString, "LogonInformation", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"LogonInformationElevatedToken", "ElevatedToken", fieldValueString, "LogonInformation", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"LogonInformationImpersonationLevel", "ImpersonationLevel", fieldValueString, "LogonInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* New Logon section */
    {"NewLogonLinkedLogonID", "LinkedLogonID", fieldValueString, "NewLogon", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"NewLogonNetworkAccountName", "NetworkAccountName", fieldValueString, "NewLogon", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NewLogonNetworkAccountDomain", "NetworkAccountDomain", fieldValueString, "NewLogon", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NewLogonLogonGUID", "LogonGUID", fieldValueString, "NewLogon", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Network Information section */
    {"NetworkWorkstationName", "WorkstationName", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkSourceNetworkAddress", "SourceNetworkAddress", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkSourcePort", "SourcePort", fieldValueInt64, "Network", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"NetworkClientAddress", "ClientAddress", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkClientPort", "ClientPort", fieldValueInt64, "Network", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"NetworkDestinationAddress", "DestinationAddress", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkDestinationPort", "DestinationPort", fieldValueInt64, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkNetworkAddress", "NetworkAddress", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"NetworkProtocol", "Protocol", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"NetworkDirection", "Direction", fieldValueString, "Network", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Process Information section */
    {"ProcessCallerProcessID", "CallerProcessID", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"ProcessCallerProcessName", "CallerProcessName", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"ProcessNewProcessID", "NewProcessID", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"ProcessNewProcessName", "NewProcessName", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"ProcessCreatorProcessID", "CreatorProcessID", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"ProcessCreatorProcessName", "CreatorProcessName", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"ProcessProcessCommandLine", "ProcessCommandLine", fieldValueString, "Process", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},

    /* Detailed Authentication Information section */
    {"DetailedAuthenticationLogonProcess", "LogonProcess", fieldValueString, "DetailedAuthentication",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"DetailedAuthenticationAuthenticationPackage", "AuthenticationPackage", fieldValueString, "DetailedAuthentication",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"DetailedAuthenticationTransitedServices", "TransitedServices", fieldValueString, "DetailedAuthentication",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"DetailedAuthenticationPackageNameNtlmOnly", "PackageName", fieldValueString, "DetailedAuthentication",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"DetailedAuthenticationKeyLength", "KeyLength", fieldValueInt64, "DetailedAuthentication", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"DetailedAuthenticationRemoteCredentialGuard", "RemoteCredentialGuard", fieldValueRemoteCredentialGuard,
     "DetailedAuthentication", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Failure Information section */
    {"FailureFailureReason", "FailureReason", fieldValueString, "Failure", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"FailureStatus", "Status", fieldValueString, "Failure", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"FailureSubStatus", "SubStatus", fieldValueString, "Failure", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* WDAC section */
    {"WDACPolicyName", "PolicyName", fieldValueString, "WDAC", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WDACPolicyVersion", "PolicyVersion", fieldValueString, "WDAC", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WDACEnforcementMode", "EnforcementMode", fieldValueString, "WDAC", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WDACUser", "User", fieldValueString, "WDAC", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WDACProcessID", "ProcessID", fieldValueInt64WithRaw, "WDAC", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Windows Update for Business section */
    {"WUFBPolicyID", "PolicyID", fieldValueString, "WUFB", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WUFBRing", "Ring", fieldValueString, "WUFB", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WUFBFromService", "FromService", fieldValueString, "WUFB", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"WUFBEnforcementResult", "EnforcementResult", fieldValueString, "WUFB", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Service Information section */
    {"ServiceServiceName", "ServiceName", fieldValueString, "Service", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"ServiceServiceID", "ServiceID", fieldValueString, "Service", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Additional Information section */
    {"AdditionalInformationTicketOptions", "TicketOptions", fieldValueString, "AdditionalInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"AdditionalInformationResultCode", "ResultCode", fieldValueString, "AdditionalInformation", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"AdditionalInformationTicketEncryptionType", "TicketEncryptionType", fieldValueString, "AdditionalInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"AdditionalInformationPreAuthenticationType", "PreAuthenticationType", fieldValueString, "AdditionalInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"AdditionalInformationTransitedServices", "TransitedServices", fieldValueString, "AdditionalInformation",
     FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Certificate Information section */
    {"CertificateCertificateInfo", "CertificateInfo", fieldValueString, "Certificate", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},

    /* LAPS section */
    {"LAPSContext", "LAPSContext", fieldValueString, "LAPS", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"LAPSPolicyVersion", "PolicyVersion", fieldValueInt64, "LAPS", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"LAPSCredentialRotation", "CredentialRotation", fieldValueBool, "LAPS", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},

    /* TLS Inspection section */
    {"TLSInspectionReason", "Reason", fieldValueString, "TLSInspection", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"TLSInspectionPolicy", "Policy", fieldValueString, "TLSInspection", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Filter Information section */
    {"FilterFilterInformation", "FilterInformation", fieldValueString, "Filter", FIELD_PRIORITY_BASE + 20,
     fieldSensitivityCanonical},
    {"FilterFilterRuntimeID", "FilterRuntimeID", fieldValueString, "Filter", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"FilterLayerName", "LayerName", fieldValueString, "Filter", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},
    {"FilterLayerRuntimeID", "LayerRuntimeID", fieldValueString, "Filter", FIELD_PRIORITY_BASE + 20, fieldSensitivityCanonical},

    /* Generic fallback */
    {".*", NULL, fieldValueString, FIELD_SECTION_EVENT_DATA, FIELD_PRIORITY_BASE - 100, fieldSensitivityCanonical},
};

static field_pattern_t g_event6281FieldPatterns[] = {
    {"PolicyName", "PolicyName", fieldValueString, "WDAC", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
    {"PolicyVersion", "PolicyVersion", fieldValueString, "WDAC", FIELD_PRIORITY_EVENT_OVERRIDE,
     fieldSensitivityCanonical},
    {"EnforcementMode", "EnforcementMode", fieldValueString, "WDAC", FIELD_PRIORITY_EVENT_OVERRIDE,
     fieldSensitivityCanonical},
    {"User", "User", fieldValueString, "WDAC", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
    {"PID", "PID", fieldValueInt64WithRaw, "WDAC", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
};

static field_pattern_t g_event1243FieldPatterns[] = {
    {"PolicyID", "PolicyID", fieldValueString, "WUFB", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
    {"Ring", "Ring", fieldValueString, "WUFB", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
    {"FromService", "FromService", fieldValueString, "WUFB", FIELD_PRIORITY_EVENT_OVERRIDE, fieldSensitivityCanonical},
    {"EnforcementResult", "EnforcementResult", fieldValueString, "WUFB", FIELD_PRIORITY_EVENT_OVERRIDE,
     fieldSensitivityCanonical},
};

static const event_field_mapping_t g_eventFieldMappings[] = {
    {6281, g_event6281FieldPatterns, ARRAY_SIZE(g_event6281FieldPatterns), SECTION_FLAG_WDAC},
    {1243, g_event1243FieldPatterns, ARRAY_SIZE(g_event1243FieldPatterns), SECTION_FLAG_NONE},
};

/**
 * @brief Per-instance configuration shared across workers.
 *
 * @var instanceData::container Target container for parsed JSON output.
 * @var instanceData::enableNetwork Controls whether Network sections are
 *      captured.
 * @var instanceData::enableLaps Controls whether Local Administrator Password
 *      Solution data is parsed.
 * @var instanceData::enableTls Controls whether TLS Inspection sections are
 *      captured.
 * @var instanceData::enableWdac Enables parsing of Windows Defender Application
 *      Control metadata.
 * @var instanceData::emitRawPayload Emits raw Snare text or JSON payload
 *      alongside parsed data when true.
 * @var instanceData::emitDebugJson Forces creation of an empty Unparsed array
 *      for easier diagnostics when true.
 * @var instanceData::runtimeConfig Holds dynamically loaded section/field
 *      mappings and runtime overrides.
 * @var instanceData::validationCtx Defines validation behavior during module
 *      initialization and runtime parsing.
* @var instanceData::sectionDescriptors Runtime section descriptor table.
 * @var instanceData::sectionDescriptorCount Number of active section
 *      descriptors.
 * @var instanceData::corePatterns Runtime field pattern table shared by all
 *      events.
 * @var instanceData::corePatternCount Number of entries in ::corePatterns.
 * @var instanceData::eventFieldMappings Runtime event-specific pattern table.
 * @var instanceData::eventFieldMappingCount Number of event-specific mappings.
 * @var instanceData::eventMappings Runtime event metadata overrides.
 * @var instanceData::eventMappingCount Number of event metadata entries.
 */
typedef struct _instanceData {
    uchar *container;
    sbool enableNetwork;
    sbool enableLaps;
    sbool enableTls;
    sbool enableWdac;
    sbool emitRawPayload;
    sbool emitDebugJson;
    runtime_config_t runtimeConfig;
    validation_context_t validationCtx;
    section_descriptor_t *sectionDescriptors;
    size_t sectionDescriptorCount;
    field_pattern_t *corePatterns;
    size_t corePatternCount;
    event_field_mapping_t *eventFieldMappings;
    size_t eventFieldMappingCount;
    event_mapping_t *eventMappings;
    size_t eventMappingCount;
} instanceData;

static void free_runtime_tables(instanceData *pData);
static rsRetVal parse_validation_mode(const char *mode, validation_mode_t *modeOut);

/** worker data */
typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;
    char *definitionFile;
    char *definitionJson;
    validation_mode_t validationMode;
    char *runtimeConfigFile;
};
static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

static const section_descriptor_t g_builtinSectionDescriptors[] = {
    {"Subject", "Subject", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Logon Information", "LogonInformation", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"New Logon", "NewLogon", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Account For Which Logon Failed", "TargetAccount", sectionBehaviorStandard, SECTION_FLAG_NONE,
     SECTION_PRIORITY_DEFAULT, fieldSensitivityCaseSensitive},
    {"Failure Information", "Failure", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Network Information", "Network", sectionBehaviorStandard, SECTION_FLAG_NETWORK, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Process Information", "Process", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Detailed Authentication Information", "DetailedAuthentication", sectionBehaviorStandard, SECTION_FLAG_NONE,
     SECTION_PRIORITY_DEFAULT, fieldSensitivityCaseSensitive},
    {"Application Information", "Application", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Filter Information", "Filter", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Account Information", "AccountInformation", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Service Information", "Service", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Additional Information", "AdditionalInformation", sectionBehaviorStandard, SECTION_FLAG_NONE,
     SECTION_PRIORITY_DEFAULT, fieldSensitivityCaseSensitive},
    {"Share Information", "Share", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Certificate Information", "Certificate", sectionBehaviorStandard, SECTION_FLAG_NONE, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Remote Credential Guard", "RemoteCredentialGuard", sectionBehaviorInlineValue, SECTION_FLAG_NONE,
     SECTION_PRIORITY_OVERRIDE, fieldSensitivityCaseInsensitive},
    {"LAPS Context", "LAPS", sectionBehaviorSemicolon, SECTION_FLAG_LAPS, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"TLS Inspection", "TLSInspection", sectionBehaviorStandard, SECTION_FLAG_TLS, SECTION_PRIORITY_DEFAULT,
     fieldSensitivityCaseSensitive},
    {"Privileges", "Privileges", sectionBehaviorList, SECTION_FLAG_NONE, SECTION_PRIORITY_OVERRIDE,
     fieldSensitivityCaseSensitive},
};

static const logon_type_map_t g_logonTypeMap[] = {{0, "System"},
                                                  {1, "System"},
                                                  {2, "Interactive"},
                                                  {3, "Network"},
                                                  {4, "Batch"},
                                                  {5, "Service"},
                                                  {7, "Unlock"},
                                                  {8, "NetworkCleartext"},
                                                  {9, "NewCredentials"},
                                                  {10, "RemoteInteractive"},
                                                  {11, "CachedInteractive"},
                                                  {12, "CachedRemoteInteractive"},
                                                  {13, "CachedUnlock"}};

static const event_mapping_t g_eventMappings[] = {{4624, "Logon", "Success", "success"},
                                                  {4625, "Logon", "Failure", "failure"},
                                                  {4672, "Privilege", "Assignment", "success"},
                                                  {4688, "Process", "Creation", "success"},
                                                  {4768, "Kerberos", "TGTRequest", NULL},
                                                  {4769, "Kerberos", "ServiceTicket", NULL},
                                                  {4771, "Kerberos", "PreAuthFailure", NULL},
                                                  {5140, "FileShare", "Access", NULL},
                                                  {5157, "FilteringPlatform", "PacketDrop", "failure"},
                                                  {6281, "WDAC", "Enforcement", NULL},
                                                  {1102, "Audit", "LogCleared", NULL},
                                                  {1243, "WindowsUpdate", "Deployment", NULL}};

static int is_placeholder(const char *value) {
    if (value == NULL) return 1;
    while (*value && isspace((unsigned char)*value)) ++value;
    if (*value == '\0') return 1;
    if (!strcmp(value, "-")) return 1;
    if (!strcasecmp(value, "N/A")) return 1;
    return 0;
}

static inline char *strdup_range(const char *start, size_t len) {
    char *out;
    out = malloc(len + 1);
    if (out == NULL) return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static inline char *trim_copy(const char *start, size_t len) {
    while (len > 0 && isspace((unsigned char)*start)) {
        ++start;
        --len;
    }
    while (len > 0 && isspace((unsigned char)start[len - 1])) {
        --len;
    }
    return strdup_range(start, len);
}

static inline void trim_inplace(char *s) {
    char *start;
    char *end;
    size_t len;
    if (s == NULL) return;
    start = s;
    while (*start && isspace((unsigned char)*start)) ++start;
    if (start != s) memmove(s, start, strlen(start) + 1);
    len = strlen(s);
    end = s + len;
    while (end > s && isspace((unsigned char)*(end - 1))) --end;
    *end = '\0';
}

static void unescape_hash_sequences(char *s) {
    char *src = s;
    char *dst = s;
    while (*src != '\0') {
        if (src[0] == '#' && src[1] >= '0' && src[1] <= '7' && src[2] >= '0' && src[2] <= '7' && src[3] >= '0' &&
            src[3] <= '7') {
            int val = ((src[1] - '0') << 6) | ((src[2] - '0') << 3) | (src[3] - '0');
            *dst++ = (char)val;
            src += 4;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static inline char *normalize_label(const char *label) {
    size_t len = strlen(label);
    char *out = malloc(len + 1);
    size_t j = 0;
    sbool upperNext = 1;
    unsigned int parenDepth = 0;
    if (out == NULL) return NULL;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)label[i];
        if (c == '(') {
            ++parenDepth;
            upperNext = 1;
            continue;
        }
        if (c == ')' && parenDepth > 0) {
            --parenDepth;
            upperNext = 1;
            continue;
        }
        if (parenDepth > 0) {
            continue;
        }
        if (isalnum(c)) {
            if (upperNext)
                out[j++] = (char)toupper(c);
            else
                out[j++] = (char)c;
            upperNext = 0;
        } else {
            upperNext = 1;
        }
    }
    out[j] = '\0';
    if (j == 0) {
        free(out);
        out = NULL;
    }
    return out;
}

static void cleanup_section_descriptor(section_descriptor_t *desc) {
    if (desc == NULL) return;
    free((char *)desc->pattern);
    free((char *)desc->canonical);
    desc->pattern = NULL;
    desc->canonical = NULL;
}

static void cleanup_field_pattern(field_pattern_t *pattern) {
    if (pattern == NULL) return;
    free((char *)pattern->pattern);
    free((char *)pattern->canonical);
    free((char *)pattern->section);
    pattern->pattern = NULL;
    pattern->canonical = NULL;
    pattern->section = NULL;
}

static void cleanup_event_mapping(event_mapping_t *mapping) {
    if (mapping == NULL) return;
    free((char *)mapping->category);
    free((char *)mapping->subtype);
    free((char *)mapping->outcome);
    mapping->category = NULL;
    mapping->subtype = NULL;
    mapping->outcome = NULL;
}

static void cleanup_event_field_mapping(event_field_mapping_t *mapping) {
    if (mapping == NULL) return;
    if (mapping->patterns != NULL) {
        for (size_t i = 0; i < mapping->pattern_count; ++i) {
            cleanup_field_pattern(&mapping->patterns[i]);
        }
        free(mapping->patterns);
    }
    mapping->patterns = NULL;
    mapping->pattern_count = 0;
}

static rsRetVal copy_section_descriptor(section_descriptor_t *dst, const section_descriptor_t *src) {
    if (dst == NULL || src == NULL) return RS_RET_INVALID_PARAMS;
    memset(dst, 0, sizeof(*dst));
    if (src->pattern != NULL) {
        dst->pattern = strdup(src->pattern);
        if (dst->pattern == NULL) return RS_RET_OUT_OF_MEMORY;
    }
    if (src->canonical != NULL) {
        dst->canonical = strdup(src->canonical);
        if (dst->canonical == NULL) {
            cleanup_section_descriptor(dst);
            return RS_RET_OUT_OF_MEMORY;
        }
    }
    dst->behavior = src->behavior;
    dst->flags = src->flags;
    dst->priority = src->priority;
    dst->sensitivity = src->sensitivity;
    return RS_RET_OK;
}

static rsRetVal copy_field_pattern(field_pattern_t *dst, const field_pattern_t *src) {
    if (dst == NULL || src == NULL) return RS_RET_INVALID_PARAMS;
    memset(dst, 0, sizeof(*dst));
    if (src->pattern != NULL) {
        dst->pattern = strdup(src->pattern);
        if (dst->pattern == NULL) return RS_RET_OUT_OF_MEMORY;
    }
    if (src->canonical != NULL) {
        dst->canonical = strdup(src->canonical);
        if (dst->canonical == NULL) {
            cleanup_field_pattern(dst);
            return RS_RET_OUT_OF_MEMORY;
        }
    }
    if (src->section != NULL) {
        dst->section = strdup(src->section);
        if (dst->section == NULL) {
            cleanup_field_pattern(dst);
            return RS_RET_OUT_OF_MEMORY;
        }
    }
    dst->value_type = src->value_type;
    dst->priority = src->priority;
    dst->sensitivity = src->sensitivity;
    return RS_RET_OK;
}

static rsRetVal copy_event_mapping(event_mapping_t *dst, const event_mapping_t *src) {
    if (dst == NULL || src == NULL) return RS_RET_INVALID_PARAMS;
    memset(dst, 0, sizeof(*dst));
    dst->event_id = src->event_id;
    if (src->category != NULL) {
        dst->category = strdup(src->category);
        if (dst->category == NULL) return RS_RET_OUT_OF_MEMORY;
    }
    if (src->subtype != NULL) {
        dst->subtype = strdup(src->subtype);
        if (dst->subtype == NULL) {
            cleanup_event_mapping(dst);
            return RS_RET_OUT_OF_MEMORY;
        }
    }
    if (src->outcome != NULL) {
        dst->outcome = strdup(src->outcome);
        if (dst->outcome == NULL) {
            cleanup_event_mapping(dst);
            return RS_RET_OUT_OF_MEMORY;
        }
    }
    return RS_RET_OK;
}

static rsRetVal copy_event_field_mapping(event_field_mapping_t *dst, const event_field_mapping_t *src) {
    if (dst == NULL || src == NULL) return RS_RET_INVALID_PARAMS;
    memset(dst, 0, sizeof(*dst));
    dst->event_id = src->event_id;
    dst->required_flags = src->required_flags;
    if (src->pattern_count == 0) return RS_RET_OK;
    dst->patterns = calloc(src->pattern_count, sizeof(field_pattern_t));
    if (dst->patterns == NULL) return RS_RET_OUT_OF_MEMORY;
    dst->pattern_count = src->pattern_count;
    for (size_t i = 0; i < src->pattern_count; ++i) {
        rsRetVal r = copy_field_pattern(&dst->patterns[i], &src->patterns[i]);
        if (r != RS_RET_OK) {
            dst->pattern_count = i;
            cleanup_event_field_mapping(dst);
            return r;
        }
    }
    return RS_RET_OK;
}

static rsRetVal append_section_descriptor_owned(section_descriptor_t **array,
                                                size_t *count,
                                                section_descriptor_t *desc) {
    section_descriptor_t *tmp;
    if (array == NULL || count == NULL || desc == NULL) return RS_RET_INVALID_PARAMS;
    tmp = realloc(*array, (*count + 1) * sizeof(section_descriptor_t));
    if (tmp == NULL) {
        cleanup_section_descriptor(desc);
        return RS_RET_OUT_OF_MEMORY;
    }
    tmp[*count] = *desc;
    *array = tmp;
    ++(*count);
    memset(desc, 0, sizeof(*desc));
    return RS_RET_OK;
}

static rsRetVal append_field_pattern_owned(field_pattern_t **array, size_t *count, field_pattern_t *pattern) {
    field_pattern_t *tmp;
    if (array == NULL || count == NULL || pattern == NULL) return RS_RET_INVALID_PARAMS;
    tmp = realloc(*array, (*count + 1) * sizeof(field_pattern_t));
    if (tmp == NULL) {
        cleanup_field_pattern(pattern);
        return RS_RET_OUT_OF_MEMORY;
    }
    tmp[*count] = *pattern;
    *array = tmp;
    ++(*count);
    memset(pattern, 0, sizeof(*pattern));
    return RS_RET_OK;
}

static rsRetVal append_event_field_mapping_owned(event_field_mapping_t **array,
                                                 size_t *count,
                                                 event_field_mapping_t *mapping) {
    event_field_mapping_t *tmp;
    if (array == NULL || count == NULL || mapping == NULL) return RS_RET_INVALID_PARAMS;
    tmp = realloc(*array, (*count + 1) * sizeof(event_field_mapping_t));
    if (tmp == NULL) {
        cleanup_event_field_mapping(mapping);
        return RS_RET_OUT_OF_MEMORY;
    }
    tmp[*count] = *mapping;
    *array = tmp;
    ++(*count);
    memset(mapping, 0, sizeof(*mapping));
    return RS_RET_OK;
}

static rsRetVal append_event_mapping_owned(event_mapping_t **array, size_t *count, event_mapping_t *mapping) {
    event_mapping_t *tmp;
    if (array == NULL || count == NULL || mapping == NULL) return RS_RET_INVALID_PARAMS;
    tmp = realloc(*array, (*count + 1) * sizeof(event_mapping_t));
    if (tmp == NULL) {
        cleanup_event_mapping(mapping);
        return RS_RET_OUT_OF_MEMORY;
    }
    tmp[*count] = *mapping;
    *array = tmp;
    ++(*count);
    memset(mapping, 0, sizeof(*mapping));
    return RS_RET_OK;
}

static event_field_mapping_t *find_event_field_mapping(instanceData *pData, int eventId) {
    if (pData == NULL) return NULL;
    for (size_t i = 0; i < pData->eventFieldMappingCount; ++i) {
        if (pData->eventFieldMappings[i].event_id == eventId) return &pData->eventFieldMappings[i];
    }
    return NULL;
}

static event_mapping_t *find_event_mapping(instanceData *pData, int eventId) {
    if (pData == NULL) return NULL;
    for (size_t i = 0; i < pData->eventMappingCount; ++i) {
        if (pData->eventMappings[i].event_id == eventId) return &pData->eventMappings[i];
    }
    return NULL;
}

static rsRetVal append_field_pattern_to_mapping(event_field_mapping_t *mapping, field_pattern_t *pattern) {
    field_pattern_t *tmp;
    if (mapping == NULL || pattern == NULL) return RS_RET_INVALID_PARAMS;
    tmp = realloc(mapping->patterns, (mapping->pattern_count + 1) * sizeof(field_pattern_t));
    if (tmp == NULL) {
        cleanup_field_pattern(pattern);
        return RS_RET_OUT_OF_MEMORY;
    }
    tmp[mapping->pattern_count] = *pattern;
    mapping->patterns = tmp;
    ++mapping->pattern_count;
    memset(pattern, 0, sizeof(*pattern));
    return RS_RET_OK;
}

static rsRetVal merge_event_field_mapping(instanceData *pData, event_field_mapping_t *mapping) {
    event_field_mapping_t *existing;
    rsRetVal r;
    if (pData == NULL || mapping == NULL) return RS_RET_INVALID_PARAMS;
    existing = find_event_field_mapping(pData, mapping->event_id);
    if (existing != NULL) {
        if (mapping->required_flags != 0) existing->required_flags |= mapping->required_flags;
        for (size_t i = 0; i < mapping->pattern_count; ++i) {
            r = append_field_pattern_to_mapping(existing, &mapping->patterns[i]);
            if (r != RS_RET_OK) {
                for (size_t j = i; j < mapping->pattern_count; ++j) cleanup_field_pattern(&mapping->patterns[j]);
                free(mapping->patterns);
                mapping->patterns = NULL;
                mapping->pattern_count = 0;
                return r;
            }
        }
        free(mapping->patterns);
        mapping->patterns = NULL;
        mapping->pattern_count = 0;
        return RS_RET_OK;
    }
    return append_event_field_mapping_owned(&pData->eventFieldMappings, &pData->eventFieldMappingCount, mapping);
}

static rsRetVal merge_event_mapping(instanceData *pData, event_mapping_t *mapping) {
    event_mapping_t *existing;
    if (pData == NULL || mapping == NULL) return RS_RET_INVALID_PARAMS;
    existing = find_event_mapping(pData, mapping->event_id);
    if (existing != NULL) {
        cleanup_event_mapping(existing);
        *existing = *mapping;
        memset(mapping, 0, sizeof(*mapping));
        return RS_RET_OK;
    }
    return append_event_mapping_owned(&pData->eventMappings, &pData->eventMappingCount, mapping);
}

static rsRetVal initialize_runtime_tables(instanceData *pData) {
    section_descriptor_t descCopy;
    field_pattern_t patternCopy;
    event_field_mapping_t mappingCopy;
    event_mapping_t eventCopy;
    rsRetVal r;
    if (pData == NULL) return RS_RET_INVALID_PARAMS;
    for (size_t i = 0; i < ARRAY_SIZE(g_builtinSectionDescriptors); ++i) {
        r = copy_section_descriptor(&descCopy, &g_builtinSectionDescriptors[i]);
        if (r != RS_RET_OK) {
            free_runtime_tables(pData);
            return r;
        }
        r = append_section_descriptor_owned(&pData->sectionDescriptors, &pData->sectionDescriptorCount, &descCopy);
        if (r != RS_RET_OK) {
            cleanup_section_descriptor(&descCopy);
            free_runtime_tables(pData);
            return r;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(g_coreFieldPatterns); ++i) {
        r = copy_field_pattern(&patternCopy, &g_coreFieldPatterns[i]);
        if (r != RS_RET_OK) {
            free_runtime_tables(pData);
            return r;
        }
        r = append_field_pattern_owned(&pData->corePatterns, &pData->corePatternCount, &patternCopy);
        if (r != RS_RET_OK) {
            cleanup_field_pattern(&patternCopy);
            free_runtime_tables(pData);
            return r;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(g_eventFieldMappings); ++i) {
        r = copy_event_field_mapping(&mappingCopy, &g_eventFieldMappings[i]);
        if (r != RS_RET_OK) {
            free_runtime_tables(pData);
            return r;
        }
        r = append_event_field_mapping_owned(&pData->eventFieldMappings, &pData->eventFieldMappingCount, &mappingCopy);
        if (r != RS_RET_OK) {
            cleanup_event_field_mapping(&mappingCopy);
            free_runtime_tables(pData);
            return r;
        }
    }
    for (size_t i = 0; i < ARRAY_SIZE(g_eventMappings); ++i) {
        r = copy_event_mapping(&eventCopy, &g_eventMappings[i]);
        if (r != RS_RET_OK) {
            free_runtime_tables(pData);
            return r;
        }
        r = append_event_mapping_owned(&pData->eventMappings, &pData->eventMappingCount, &eventCopy);
        if (r != RS_RET_OK) {
            cleanup_event_mapping(&eventCopy);
            free_runtime_tables(pData);
            return r;
        }
    }
    return RS_RET_OK;
}

static void free_runtime_tables(instanceData *pData) {
    if (pData == NULL) return;
    if (pData->sectionDescriptors != NULL) {
        for (size_t i = 0; i < pData->sectionDescriptorCount; ++i) {
            cleanup_section_descriptor(&pData->sectionDescriptors[i]);
        }
        free(pData->sectionDescriptors);
        pData->sectionDescriptors = NULL;
        pData->sectionDescriptorCount = 0;
    }
    if (pData->corePatterns != NULL) {
        for (size_t i = 0; i < pData->corePatternCount; ++i) {
            cleanup_field_pattern(&pData->corePatterns[i]);
        }
        free(pData->corePatterns);
        pData->corePatterns = NULL;
        pData->corePatternCount = 0;
    }
    if (pData->eventFieldMappings != NULL) {
        for (size_t i = 0; i < pData->eventFieldMappingCount; ++i) {
            cleanup_event_field_mapping(&pData->eventFieldMappings[i]);
        }
        free(pData->eventFieldMappings);
        pData->eventFieldMappings = NULL;
        pData->eventFieldMappingCount = 0;
    }
    if (pData->eventMappings != NULL) {
        for (size_t i = 0; i < pData->eventMappingCount; ++i) {
            cleanup_event_mapping(&pData->eventMappings[i]);
        }
        free(pData->eventMappings);
        pData->eventMappings = NULL;
        pData->eventMappingCount = 0;
    }
}

static void free_runtime_config(runtime_config_t *config) {
    if (config == NULL) return;
    if (config->custom_sections != NULL) {
        for (size_t i = 0; i < config->custom_section_count; ++i) {
            cleanup_section_descriptor(&config->custom_sections[i]);
        }
        free(config->custom_sections);
        config->custom_sections = NULL;
        config->custom_section_count = 0;
    }
    if (config->custom_patterns != NULL) {
        for (size_t i = 0; i < config->custom_pattern_count; ++i) {
            cleanup_field_pattern(&config->custom_patterns[i]);
        }
        free(config->custom_patterns);
        config->custom_patterns = NULL;
        config->custom_pattern_count = 0;
    }
    if (config->custom_event_mappings != NULL) {
        for (size_t i = 0; i < config->custom_event_mapping_count; ++i) {
            cleanup_event_field_mapping(&config->custom_event_mappings[i]);
        }
        free(config->custom_event_mappings);
        config->custom_event_mappings = NULL;
        config->custom_event_mapping_count = 0;
    }
    if (config->custom_events != NULL) {
        for (size_t i = 0; i < config->custom_event_count; ++i) {
            cleanup_event_mapping(&config->custom_events[i]);
        }
        free(config->custom_events);
        config->custom_events = NULL;
        config->custom_event_count = 0;
    }
    free(config->config_file);
    config->config_file = NULL;
    free(config->raw_text);
    config->raw_text = NULL;
}

static rsRetVal parse_validation_mode(const char *mode, validation_mode_t *modeOut) {
    if (mode == NULL || modeOut == NULL) return RS_RET_INVALID_PARAMS;
    if (!strcasecmp(mode, "strict")) {
        *modeOut = VALIDATION_STRICT;
        return RS_RET_OK;
    }
    if (!strcasecmp(mode, "moderate") || !strcasecmp(mode, "default")) {
        *modeOut = VALIDATION_MODERATE;
        return RS_RET_OK;
    }
    if (!strcasecmp(mode, "permissive") || !strcasecmp(mode, "lenient")) {
        *modeOut = VALIDATION_PERMISSIVE;
        return RS_RET_OK;
    }
    LogError(0, RS_RET_INVALID_PARAMS, "mmsnarewinsec: unknown validation.mode '%s'", mode);
    return RS_RET_INVALID_PARAMS;
}

static rsRetVal set_validation_mode(instanceData *pData, const char *mode) {
    rsRetVal r;
    if (pData == NULL || mode == NULL) return RS_RET_INVALID_PARAMS;
    r = parse_validation_mode(mode, &pData->validationCtx.mode);
    return r;
}

static rsRetVal read_text_file(const char *path, char **out) {
    FILE *fp;
    long len;
    size_t readLen;
    char *buf;
    if (out == NULL || path == NULL) return RS_RET_INVALID_PARAMS;
    *out = NULL;
    fp = fopen(path, "rb");
    if (fp == NULL) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to open definition file '%s'", path);
        return RS_RET_IO_ERROR;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to seek definition file '%s'", path);
        fclose(fp);
        return RS_RET_IO_ERROR;
    }
    len = ftell(fp);
    if (len < 0) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to determine size of definition file '%s'", path);
        fclose(fp);
        return RS_RET_IO_ERROR;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to rewind definition file '%s'", path);
        fclose(fp);
        return RS_RET_IO_ERROR;
    }
    buf = malloc((size_t)len + 1u);
    if (buf == NULL) {
        fclose(fp);
        return RS_RET_OUT_OF_MEMORY;
    }
    readLen = fread(buf, 1, (size_t)len, fp);
    if (readLen != (size_t)len) {
        if (ferror(fp)) {
            LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: error reading definition file '%s'", path);
        } else {
            LogError(0, RS_RET_IO_ERROR, "mmsnarewinsec: unexpected end of file reading definition file '%s'", path);
        }
        free(buf);
        fclose(fp);
        return RS_RET_IO_ERROR;
    }
    buf[len] = '\0';
    fclose(fp);
    *out = buf;
    return RS_RET_OK;
}

static rsRetVal report_validation_issue(instanceData *pData, const char *source, const char *message) {
    if (pData == NULL) return RS_RET_INVALID_PARAMS;
    switch (pData->validationCtx.mode) {
        case VALIDATION_STRICT:
            LogError(0, RS_RET_INVALID_PARAMS, "mmsnarewinsec: %s rejected: %s", source, message);
            return RS_RET_INVALID_PARAMS;
        case VALIDATION_MODERATE:
            LogError(0, RS_RET_INVALID_PARAMS, "mmsnarewinsec: %s warning: %s", source, message);
            return RS_RET_OK;
        case VALIDATION_PERMISSIVE:
        default:
            LogError(0, RS_RET_INVALID_PARAMS, "mmsnarewinsec: %s ignored (permissive mode): %s", source, message);
            return RS_RET_OK;
    }
}

static sbool parse_section_behavior_string(const char *text, section_behavior_t *behavior) {
    if (text == NULL || behavior == NULL) return 0;
    if (!strcasecmp(text, "standard")) {
        *behavior = sectionBehaviorStandard;
        return 1;
    }
    if (!strcasecmp(text, "inline") || !strcasecmp(text, "inline_value") || !strcasecmp(text, "inline-value")) {
        *behavior = sectionBehaviorInlineValue;
        return 1;
    }
    if (!strcasecmp(text, "semicolon") || !strcasecmp(text, "kv")) {
        *behavior = sectionBehaviorSemicolon;
        return 1;
    }
    if (!strcasecmp(text, "list")) {
        *behavior = sectionBehaviorList;
        return 1;
    }
    return 0;
}

static sbool parse_field_value_type_string(const char *text, field_value_type_t *type) {
    if (text == NULL || type == NULL) return 0;
    if (!strcasecmp(text, "string")) {
        *type = fieldValueString;
        return 1;
    }
    if (!strcasecmp(text, "int64") || !strcasecmp(text, "integer")) {
        *type = fieldValueInt64;
        return 1;
    }
    if (!strcasecmp(text, "int64_with_raw") || !strcasecmp(text, "int64-with-raw")) {
        *type = fieldValueInt64WithRaw;
        return 1;
    }
    if (!strcasecmp(text, "bool") || !strcasecmp(text, "boolean")) {
        *type = fieldValueBool;
        return 1;
    }
    if (!strcasecmp(text, "json")) {
        *type = fieldValueJson;
        return 1;
    }
    if (!strcasecmp(text, "logon_type") || !strcasecmp(text, "logon-type")) {
        *type = fieldValueLogonType;
        return 1;
    }
    if (!strcasecmp(text, "remote_credential_guard") || !strcasecmp(text, "remote-credential-guard")) {
        *type = fieldValueRemoteCredentialGuard;
        return 1;
    }
    if (!strcasecmp(text, "privilege_list") || !strcasecmp(text, "privilege-list")) {
        *type = fieldValuePrivilegeList;
        return 1;
    }
    return 0;
}

static sbool parse_field_sensitivity_string(const char *text, field_pattern_sensitivity_t *sensitivity) {
    if (text == NULL || sensitivity == NULL) return 0;
    if (!strcasecmp(text, "canonical")) {
        *sensitivity = fieldSensitivityCanonical;
        return 1;
    }
    if (!strcasecmp(text, "case_sensitive") || !strcasecmp(text, "case-sensitive") || !strcasecmp(text, "sensitive")) {
        *sensitivity = fieldSensitivityCaseSensitive;
        return 1;
    }
    if (!strcasecmp(text, "case_insensitive") || !strcasecmp(text, "case-insensitive") ||
        !strcasecmp(text, "insensitive")) {
        *sensitivity = fieldSensitivityCaseInsensitive;
        return 1;
    }
    return 0;
}

static uint32_t parse_section_flags_array(struct json_object *value, sbool *ok) {
    uint32_t flags = SECTION_FLAG_NONE;
    if (ok != NULL) *ok = 1;
    if (value == NULL) return flags;
    if (!json_object_is_type(value, json_type_array)) {
        if (ok != NULL) *ok = 0;
        return SECTION_FLAG_NONE;
    }
    size_t len = json_object_array_length(value);
    for (size_t i = 0; i < len; ++i) {
        struct json_object *entry = json_object_array_get_idx(value, (int)i);
        const char *flag = json_object_get_string(entry);
        if (flag == NULL) continue;
        if (!strcasecmp(flag, "network"))
            flags |= SECTION_FLAG_NETWORK;
        else if (!strcasecmp(flag, "laps"))
            flags |= SECTION_FLAG_LAPS;
        else if (!strcasecmp(flag, "tls"))
            flags |= SECTION_FLAG_TLS;
        else if (!strcasecmp(flag, "wdac"))
            flags |= SECTION_FLAG_WDAC;
        else if (ok != NULL)
            *ok = 0;
    }
    return flags;
}

static rsRetVal load_section_definitions(instanceData *pData, struct json_object *array, const char *source) {
    size_t len;
    if (array == NULL) return RS_RET_OK;
    if (!json_object_is_type(array, json_type_array))
        return report_validation_issue(pData, source, "sections must be an array");
    len = json_object_array_length(array);
    for (size_t i = 0; i < len; ++i) {
        struct json_object *entry = json_object_array_get_idx(array, (int)i);
        section_descriptor_t desc;
        struct json_object *value;
        const char *pattern;
        const char *canonical = NULL;
        char context[128];
        rsRetVal r;
        snprintf(context, sizeof(context), "%s sections[%zu]", source, i);
        if (!json_object_is_type(entry, json_type_object)) {
            r = report_validation_issue(pData, context, "entry must be an object");
            if (r != RS_RET_OK) return r;
            continue;
        }
        memset(&desc, 0, sizeof(desc));
        desc.behavior = sectionBehaviorStandard;
        desc.priority = SECTION_PRIORITY_DEFAULT;
        desc.sensitivity = fieldSensitivityCaseSensitive;
        if (!json_object_object_get_ex(entry, "pattern", &value) || !json_object_is_type(value, json_type_string)) {
            r = report_validation_issue(pData, context, "missing pattern");
            if (r != RS_RET_OK) return r;
            continue;
        }
        pattern = json_object_get_string(value);
        desc.pattern = strdup(pattern);
        if (desc.pattern == NULL) return RS_RET_OUT_OF_MEMORY;
        if (json_object_object_get_ex(entry, "canonical", &value) && json_object_is_type(value, json_type_string)) {
            canonical = json_object_get_string(value);
        }
        if (canonical != NULL) {
            desc.canonical = strdup(canonical);
            if (desc.canonical == NULL) {
                cleanup_section_descriptor(&desc);
                return RS_RET_OUT_OF_MEMORY;
            }
        } else {
            char *normalized = normalize_label(pattern);
            if (normalized == NULL) {
                cleanup_section_descriptor(&desc);
                r = report_validation_issue(pData, context, "could not derive canonical name");
                if (r != RS_RET_OK) return r;
                continue;
            }
            desc.canonical = normalized;
        }
        if (json_object_object_get_ex(entry, "behavior", &value) && json_object_is_type(value, json_type_string)) {
            const char *behaviorText = json_object_get_string(value);
            if (!parse_section_behavior_string(behaviorText, &desc.behavior)) {
                cleanup_section_descriptor(&desc);
                r = report_validation_issue(pData, context, "unknown behavior");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        if (json_object_object_get_ex(entry, "priority", &value) && json_object_is_type(value, json_type_int)) {
            desc.priority = json_object_get_int(value);
        }
        if (json_object_object_get_ex(entry, "sensitivity", &value) && json_object_is_type(value, json_type_string)) {
            const char *sens = json_object_get_string(value);
            if (!parse_field_sensitivity_string(sens, &desc.sensitivity)) {
                cleanup_section_descriptor(&desc);
                r = report_validation_issue(pData, context, "unknown sensitivity");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        if (json_object_object_get_ex(entry, "flags", &value)) {
            sbool ok = 0;
            desc.flags = parse_section_flags_array(value, &ok);
            if (!ok) {
                cleanup_section_descriptor(&desc);
                r = report_validation_issue(pData, context, "unknown flag value");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        r = append_section_descriptor_owned(&pData->sectionDescriptors, &pData->sectionDescriptorCount, &desc);
        if (r != RS_RET_OK) {
            cleanup_section_descriptor(&desc);
            return r;
        }
    }
    return RS_RET_OK;
}

static rsRetVal load_field_definitions(instanceData *pData, struct json_object *array, const char *source) {
    size_t len;
    if (array == NULL) return RS_RET_OK;
    if (!json_object_is_type(array, json_type_array))
        return report_validation_issue(pData, source, "fields must be an array");
    len = json_object_array_length(array);
    for (size_t i = 0; i < len; ++i) {
        struct json_object *entry = json_object_array_get_idx(array, (int)i);
        struct json_object *value;
        field_pattern_t pattern;
        const char *patternText;
        const char *canonical = NULL;
        const char *section = NULL;
        char context[128];
        rsRetVal r;
        snprintf(context, sizeof(context), "%s fields[%zu]", source, i);
        if (!json_object_is_type(entry, json_type_object)) {
            r = report_validation_issue(pData, context, "entry must be an object");
            if (r != RS_RET_OK) return r;
            continue;
        }
        memset(&pattern, 0, sizeof(pattern));
        pattern.value_type = fieldValueString;
        pattern.priority = FIELD_PRIORITY_BASE;
        pattern.sensitivity = fieldSensitivityCaseSensitive;
        if (!json_object_object_get_ex(entry, "pattern", &value) || !json_object_is_type(value, json_type_string)) {
            r = report_validation_issue(pData, context, "missing pattern");
            if (r != RS_RET_OK) return r;
            continue;
        }
        patternText = json_object_get_string(value);
        pattern.pattern = strdup(patternText);
        if (pattern.pattern == NULL) return RS_RET_OUT_OF_MEMORY;
        if (json_object_object_get_ex(entry, "canonical", &value) && json_object_is_type(value, json_type_string))
            canonical = json_object_get_string(value);
        if (canonical != NULL) {
            pattern.canonical = strdup(canonical);
            if (pattern.canonical == NULL) {
                cleanup_field_pattern(&pattern);
                return RS_RET_OUT_OF_MEMORY;
            }
        } else {
            char *normalized = normalize_label(patternText);
            if (normalized == NULL) {
                cleanup_field_pattern(&pattern);
                r = report_validation_issue(pData, context, "could not derive canonical name");
                if (r != RS_RET_OK) return r;
                continue;
            }
            pattern.canonical = normalized;
        }
        if (json_object_object_get_ex(entry, "section", &value) && json_object_is_type(value, json_type_string)) {
            section = json_object_get_string(value);
            if (section != NULL) {
                pattern.section = strdup(section);
                if (pattern.section == NULL) {
                    cleanup_field_pattern(&pattern);
                    return RS_RET_OUT_OF_MEMORY;
                }
            }
        }
        if (json_object_object_get_ex(entry, "priority", &value) && json_object_is_type(value, json_type_int))
            pattern.priority = json_object_get_int(value);
        if (json_object_object_get_ex(entry, "value_type", &value) && json_object_is_type(value, json_type_string)) {
            const char *typeText = json_object_get_string(value);
            if (!parse_field_value_type_string(typeText, &pattern.value_type)) {
                cleanup_field_pattern(&pattern);
                r = report_validation_issue(pData, context, "unknown value_type");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        if (json_object_object_get_ex(entry, "sensitivity", &value) && json_object_is_type(value, json_type_string)) {
            const char *sens = json_object_get_string(value);
            if (!parse_field_sensitivity_string(sens, &pattern.sensitivity)) {
                cleanup_field_pattern(&pattern);
                r = report_validation_issue(pData, context, "unknown sensitivity");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        r = append_field_pattern_owned(&pData->corePatterns, &pData->corePatternCount, &pattern);
        if (r != RS_RET_OK) {
            cleanup_field_pattern(&pattern);
            return r;
        }
    }
    return RS_RET_OK;
}

static rsRetVal load_event_field_definitions(instanceData *pData, struct json_object *array, const char *source) {
    size_t len;
    if (array == NULL) return RS_RET_OK;
    if (!json_object_is_type(array, json_type_array))
        return report_validation_issue(pData, source, "eventFields must be an array");
    len = json_object_array_length(array);
    for (size_t i = 0; i < len; ++i) {
        struct json_object *entry = json_object_array_get_idx(array, (int)i);
        struct json_object *value;
        event_field_mapping_t mapping;
        char context[128];
        rsRetVal r;
        snprintf(context, sizeof(context), "%s eventFields[%zu]", source, i);
        if (!json_object_is_type(entry, json_type_object)) {
            r = report_validation_issue(pData, context, "entry must be an object");
            if (r != RS_RET_OK) return r;
            continue;
        }
        memset(&mapping, 0, sizeof(mapping));
        if (!json_object_object_get_ex(entry, "event_id", &value) || !json_object_is_type(value, json_type_int)) {
            r = report_validation_issue(pData, context, "missing event_id");
            if (r != RS_RET_OK) return r;
            continue;
        }
        mapping.event_id = json_object_get_int(value);
        if (json_object_object_get_ex(entry, "required_flags", &value)) {
            sbool ok = 0;
            mapping.required_flags = parse_section_flags_array(value, &ok);
            if (!ok) {
                r = report_validation_issue(pData, context, "unknown required flag");
                if (r != RS_RET_OK) return r;
                continue;
            }
        }
        if (!json_object_object_get_ex(entry, "patterns", &value) || !json_object_is_type(value, json_type_array)) {
            r = report_validation_issue(pData, context, "patterns must be an array");
            if (r != RS_RET_OK) return r;
            continue;
        }
        size_t plen = json_object_array_length(value);
        for (size_t j = 0; j < plen; ++j) {
            struct json_object *patternObj = json_object_array_get_idx(value, (int)j);
            field_pattern_t patternEntry;
            const char *patternText;
            const char *canonical = NULL;
            struct json_object *pv;
            char itemContext[160];
            snprintf(itemContext, sizeof(itemContext), "%s patterns[%zu]", context, j);
            if (!json_object_is_type(patternObj, json_type_object)) {
                r = report_validation_issue(pData, itemContext, "entry must be an object");
                if (r != RS_RET_OK) return r;
                continue;
            }
            memset(&patternEntry, 0, sizeof(patternEntry));
            patternEntry.value_type = fieldValueString;
            patternEntry.priority = FIELD_PRIORITY_EVENT_OVERRIDE;
            patternEntry.sensitivity = fieldSensitivityCaseSensitive;
            if (!json_object_object_get_ex(patternObj, "pattern", &pv) || !json_object_is_type(pv, json_type_string)) {
                r = report_validation_issue(pData, itemContext, "missing pattern");
                if (r != RS_RET_OK) return r;
                continue;
            }
            patternText = json_object_get_string(pv);
            patternEntry.pattern = strdup(patternText);
            if (patternEntry.pattern == NULL) {
                cleanup_event_field_mapping(&mapping);
                return RS_RET_OUT_OF_MEMORY;
            }
            if (json_object_object_get_ex(patternObj, "canonical", &pv) && json_object_is_type(pv, json_type_string))
                canonical = json_object_get_string(pv);
            if (canonical != NULL) {
                patternEntry.canonical = strdup(canonical);
                if (patternEntry.canonical == NULL) {
                    cleanup_field_pattern(&patternEntry);
                    cleanup_event_field_mapping(&mapping);
                    return RS_RET_OUT_OF_MEMORY;
                }
            } else {
                char *normalized = normalize_label(patternText);
                if (normalized == NULL) {
                    cleanup_field_pattern(&patternEntry);
                    r = report_validation_issue(pData, itemContext, "could not derive canonical name");
                    if (r != RS_RET_OK) {
                        cleanup_event_field_mapping(&mapping);
                        return r;
                    }
                    continue;
                }
                patternEntry.canonical = normalized;
            }
            if (json_object_object_get_ex(patternObj, "section", &pv) && json_object_is_type(pv, json_type_string)) {
                const char *section = json_object_get_string(pv);
                if (section != NULL) {
                    patternEntry.section = strdup(section);
                    if (patternEntry.section == NULL) {
                        cleanup_field_pattern(&patternEntry);
                        cleanup_event_field_mapping(&mapping);
                        return RS_RET_OUT_OF_MEMORY;
                    }
                }
            }
            if (json_object_object_get_ex(patternObj, "priority", &pv) && json_object_is_type(pv, json_type_int))
                patternEntry.priority = json_object_get_int(pv);
            if (json_object_object_get_ex(patternObj, "value_type", &pv) && json_object_is_type(pv, json_type_string)) {
                const char *typeText = json_object_get_string(pv);
                if (!parse_field_value_type_string(typeText, &patternEntry.value_type)) {
                    cleanup_field_pattern(&patternEntry);
                    r = report_validation_issue(pData, itemContext, "unknown value_type");
                    if (r != RS_RET_OK) {
                        cleanup_event_field_mapping(&mapping);
                        return r;
                    }
                    continue;
                }
            }
            if (json_object_object_get_ex(patternObj, "sensitivity", &pv) &&
                json_object_is_type(pv, json_type_string)) {
                const char *sens = json_object_get_string(pv);
                if (!parse_field_sensitivity_string(sens, &patternEntry.sensitivity)) {
                    cleanup_field_pattern(&patternEntry);
                    r = report_validation_issue(pData, itemContext, "unknown sensitivity");
                    if (r != RS_RET_OK) {
                        cleanup_event_field_mapping(&mapping);
                        return r;
                    }
                    continue;
                }
            }
            r = append_field_pattern_owned(&mapping.patterns, &mapping.pattern_count, &patternEntry);
            if (r != RS_RET_OK) {
                cleanup_field_pattern(&patternEntry);
                cleanup_event_field_mapping(&mapping);
                return r;
            }
        }
        r = merge_event_field_mapping(pData, &mapping);
        if (r != RS_RET_OK) {
            cleanup_event_field_mapping(&mapping);
            return r;
        }
    }
    return RS_RET_OK;
}

static rsRetVal load_event_metadata_definitions(instanceData *pData, struct json_object *array, const char *source) {
    size_t len;
    if (array == NULL) return RS_RET_OK;
    if (!json_object_is_type(array, json_type_array))
        return report_validation_issue(pData, source, "events must be an array");
    len = json_object_array_length(array);
    for (size_t i = 0; i < len; ++i) {
        struct json_object *entry = json_object_array_get_idx(array, (int)i);
        struct json_object *value;
        event_mapping_t mapping;
        char context[128];
        rsRetVal r;
        snprintf(context, sizeof(context), "%s events[%zu]", source, i);
        if (!json_object_is_type(entry, json_type_object)) {
            r = report_validation_issue(pData, context, "entry must be an object");
            if (r != RS_RET_OK) return r;
            continue;
        }
        memset(&mapping, 0, sizeof(mapping));
        if (!json_object_object_get_ex(entry, "event_id", &value) || !json_object_is_type(value, json_type_int)) {
            r = report_validation_issue(pData, context, "missing event_id");
            if (r != RS_RET_OK) return r;
            continue;
        }
        mapping.event_id = json_object_get_int(value);
        if (json_object_object_get_ex(entry, "category", &value) && json_object_is_type(value, json_type_string)) {
            mapping.category = strdup(json_object_get_string(value));
            if (mapping.category == NULL) {
                cleanup_event_mapping(&mapping);
                return RS_RET_OUT_OF_MEMORY;
            }
        }
        if (json_object_object_get_ex(entry, "subtype", &value) && json_object_is_type(value, json_type_string)) {
            mapping.subtype = strdup(json_object_get_string(value));
            if (mapping.subtype == NULL) {
                cleanup_event_mapping(&mapping);
                return RS_RET_OUT_OF_MEMORY;
            }
        }
        if (json_object_object_get_ex(entry, "outcome", &value) && json_object_is_type(value, json_type_string)) {
            mapping.outcome = strdup(json_object_get_string(value));
            if (mapping.outcome == NULL) {
                cleanup_event_mapping(&mapping);
                return RS_RET_OUT_OF_MEMORY;
            }
        }
        r = merge_event_mapping(pData, &mapping);
        if (r != RS_RET_OK) {
            cleanup_event_mapping(&mapping);
            return r;
        }
    }
    return RS_RET_OK;
}

static rsRetVal load_custom_definition_text(instanceData *pData, const char *jsonText, const char *sourceLabel) {
    struct json_tokener *tokener;
    struct json_object *root;
    enum fjson_tokener_error err;
    rsRetVal r = RS_RET_OK;
    if (jsonText == NULL || pData == NULL) return RS_RET_INVALID_PARAMS;
    tokener = json_tokener_new();
    if (tokener == NULL) return RS_RET_OUT_OF_MEMORY;
    root = json_tokener_parse_ex(tokener, jsonText, (int)strlen(jsonText));
    err = fjson_tokener_get_error(tokener);
    json_tokener_free(tokener);
    if (err != fjson_tokener_success || root == NULL) {
        return report_validation_issue(pData, sourceLabel, "invalid JSON definitions");
    }
    if (!json_object_is_type(root, json_type_object)) {
        r = report_validation_issue(pData, sourceLabel, "definition root must be an object");
        json_object_put(root);
        return r;
    }
    if (json_object_object_length(root) == 0) {
        json_object_put(root);
        return RS_RET_OK;
    }
    struct json_object *sections;
    struct json_object *fields;
    struct json_object *eventFields;
    struct json_object *events;
    if (json_object_object_get_ex(root, "sections", &sections)) {
        r = load_section_definitions(pData, sections, sourceLabel);
        if (r != RS_RET_OK) {
            json_object_put(root);
            return r;
        }
    }
    if (json_object_object_get_ex(root, "fields", &fields)) {
        r = load_field_definitions(pData, fields, sourceLabel);
        if (r != RS_RET_OK) {
            json_object_put(root);
            return r;
        }
    }
    if (json_object_object_get_ex(root, "eventFields", &eventFields)) {
        r = load_event_field_definitions(pData, eventFields, sourceLabel);
        if (r != RS_RET_OK) {
            json_object_put(root);
            return r;
        }
    }
    if (json_object_object_get_ex(root, "events", &events)) {
        r = load_event_metadata_definitions(pData, events, sourceLabel);
        if (r != RS_RET_OK) {
            json_object_put(root);
            return r;
        }
    }
    json_object_put(root);
    return RS_RET_OK;
}

static rsRetVal load_custom_definition_file(instanceData *pData, const char *path) {
    char *content = NULL;
    rsRetVal r;
    if (path == NULL) return RS_RET_INVALID_PARAMS;
    r = read_text_file(path, &content);
    if (r != RS_RET_OK) return r;
    r = load_custom_definition_text(pData, content, path);
    free(content);
    return r;
}

static rsRetVal load_configuration(runtime_config_t *config, const char *config_file) {
    struct json_tokener *tok = NULL;
    struct json_object *root = NULL;
    struct json_object *options = NULL;
    struct json_object *value = NULL;
    enum fjson_tokener_error err;
    rsRetVal r;
    char *content = NULL;
    struct stat st;

    if (config == NULL) return RS_RET_INVALID_PARAMS;
    if (config_file == NULL) return RS_RET_OK;

    free_runtime_config(config);

    if (stat(config_file, &st) != 0) {
        if (errno == ENOENT) {
            dbgprintf("mmsnarewinsec: runtime configuration '%s' not found, continuing with defaults\n", config_file);
            return RS_RET_OK;
        }
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to stat runtime configuration '%s'", config_file);
        return RS_RET_IO_ERROR;
    }
    if (!S_ISREG(st.st_mode)) {
        LogError(0, RS_RET_INVALID_PARAMS, "mmsnarewinsec: runtime configuration '%s' is not a regular file", config_file);
        return RS_RET_INVALID_PARAMS;
    }

    r = read_text_file(config_file, &content);
    if (r != RS_RET_OK) return r;

    tok = json_tokener_new();
    if (tok == NULL) {
        free(content);
        return RS_RET_OUT_OF_MEMORY;
    }

    root = json_tokener_parse_ex(tok, content, (int)strlen(content));
    err = fjson_tokener_get_error(tok);
    if (err != fjson_tokener_success || root == NULL || !json_object_is_type(root, json_type_object)) {
        LogError(0, RS_RET_PARSE_ERR, "mmsnarewinsec: failed to parse runtime configuration '%s': %s", config_file,
                 fjson_tokener_error_desc(err));
        if (root != NULL) json_object_put(root);
        json_tokener_free(tok);
        free(content);
        return RS_RET_PARSE_ERR;
    }

    config->config_file = strdup(config_file);
    if (config->config_file == NULL) {
        json_object_put(root);
        json_tokener_free(tok);
        free(content);
        return RS_RET_OUT_OF_MEMORY;
    }

    config->raw_text = content;
    config->enable_debug = false;
    config->enable_fallback = true;

    if (json_object_object_get_ex(root, "options", &options) && json_object_is_type(options, json_type_object)) {
        if (json_object_object_get_ex(options, "enable_debug", &value) && json_object_is_type(value, json_type_boolean))
            config->enable_debug = json_object_get_boolean(value) != 0;
        if (json_object_object_get_ex(options, "enable_fallback", &value) && json_object_is_type(value, json_type_boolean))
            config->enable_fallback = json_object_get_boolean(value) != 0;
    }

    if (json_object_object_get_ex(root, "enable_debug", &value) && json_object_is_type(value, json_type_boolean))
        config->enable_debug = json_object_get_boolean(value) != 0;
    if (json_object_object_get_ex(root, "enable_fallback", &value) && json_object_is_type(value, json_type_boolean))
        config->enable_fallback = json_object_get_boolean(value) != 0;

    json_object_put(root);
    json_tokener_free(tok);

    return RS_RET_OK;
}

static rsRetVal save_configuration(const runtime_config_t *config, const char *config_file) {
    const char *path = config_file != NULL ? config_file : (config != NULL ? config->config_file : NULL);
    FILE *fp;
    size_t len;
    if (config == NULL || config->raw_text == NULL) return RS_RET_OK;
    if (path == NULL) return RS_RET_OK;
    fp = fopen(path, "wb");
    if (fp == NULL) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to open configuration file '%s' for writing", path);
        return RS_RET_IO_ERROR;
    }
    len = strlen(config->raw_text);
    if (len > 0 && fwrite(config->raw_text, 1, len, fp) != len) {
        LogError(errno, RS_RET_IO_ERROR, "mmsnarewinsec: failed to write configuration file '%s'", path);
        fclose(fp);
        return RS_RET_IO_ERROR;
    }
    fclose(fp);
    return RS_RET_OK;
}

static rsRetVal apply_runtime_configuration(instanceData *pData) {
    runtime_config_t *cfg;
    if (pData == NULL) return RS_RET_INVALID_PARAMS;
    cfg = &pData->runtimeConfig;
    if (cfg->raw_text == NULL) return RS_RET_OK;
    return load_custom_definition_text(pData, cfg->raw_text,
                                       cfg->config_file != NULL ? cfg->config_file : "runtime configuration");
}

static rsRetVal validate_field_count(
    const char *message, size_t actual_count, size_t expected_count, validation_context_t *ctx) {
    if (ctx == NULL) return RS_RET_OK;
    if (actual_count == expected_count) return RS_RET_OK;
    if (ctx->mode == VALIDATION_STRICT) {
        if (ctx->enable_debug)
            dbgprintf("mmsnarewinsec: strict validation failed field count (expected %zu, got %zu)\n", expected_count,
                      actual_count);
        return RS_RET_PARSE_ERR;
    }
    if (ctx->mode == VALIDATION_MODERATE && ctx->log_parsing_errors) {
        dbgprintf("mmsnarewinsec: field count mismatch - expected %zu, got %zu in message '%s'\n", expected_count,
                  actual_count, message != NULL ? message : "<unknown>");
    }
    return RS_RET_OK;
}

static rsRetVal validate_required_fields(
    const char *message, const char *required_fields[], size_t required_count, validation_context_t *ctx) {
    if (ctx == NULL || required_fields == NULL) return RS_RET_OK;
    for (size_t i = 0; i < required_count; ++i) {
        if (message == NULL || strstr(message, required_fields[i]) == NULL) {
            if (ctx->mode == VALIDATION_STRICT) {
                if (ctx->enable_debug)
                    dbgprintf("mmsnarewinsec: strict validation missing required field '%s'\n", required_fields[i]);
                return RS_RET_PARSE_ERR;
            }
            if (ctx->mode == VALIDATION_MODERATE && ctx->log_parsing_errors) {
                dbgprintf("mmsnarewinsec: missing required field '%s'\n", required_fields[i]);
            }
        }
    }
    return RS_RET_OK;
}

static rsRetVal handle_parsing_error(field_detection_context_t *ctx, const char *error_message, const char *context) {
    struct json_object *entry;
    if (ctx == NULL) return RS_RET_INVALID_PARAMS;
    ctx->parsing_errors++;
    if (ctx->validation != NULL) {
        ctx->validation->current_error_count++;
        if (ctx->validation->max_errors_before_fail > 0 &&
            ctx->validation->current_error_count > ctx->validation->max_errors_before_fail)
            return RS_RET_PARSE_ERR;
        if (!ctx->validation->continue_on_error && ctx->validation->mode == VALIDATION_STRICT)
            return RS_RET_PARSE_ERR;
    }
    if (ctx->enable_debug && error_message != NULL)
        dbgprintf("mmsnarewinsec: parsing error%s%s: %s\n", context ? " (" : "", context ? context : "", context ? ")" : "",
                  error_message);
    if (ctx->error_array != NULL) {
        entry = json_object_new_object();
        if (entry != NULL) {
            if (context != NULL && *context != '\0') json_add_string(entry, "context", context);
            if (error_message != NULL) json_add_string(entry, "message", error_message);
            json_object_array_add(ctx->error_array, entry);
        }
    }
    return RS_RET_OK;
}

static sbool wildcard_match(const char *pattern, const char *text, sbool caseInsensitive) {
    const char *p = pattern;
    const char *t = text;
    const char *star = NULL;
    const char *backup = NULL;
    if (pattern == NULL || text == NULL) return 0;
    while (*t != '\0') {
        char pc;
        char tc;
        if (*p == '*') {
            star = p++;
            backup = t;
            continue;
        }
        pc = *p;
        tc = *t;
        if (caseInsensitive) {
            pc = (char)tolower((unsigned char)pc);
            tc = (char)tolower((unsigned char)tc);
        }
        if (pc == tc || (pc == '?' && *t != '\0')) {
            ++p;
            ++t;
            continue;
        }
        if (star != NULL) {
            p = star + 1;
            t = ++backup;
            continue;
        }
        return 0;
    }
    while (*p == '*') ++p;
    return *p == '\0';
}

static size_t pattern_specificity(const char *pattern) {
    size_t score = 0;
    if (pattern == NULL) return 0;
    while (*pattern != '\0') {
        if (*pattern != '*' && *pattern != '?') ++score;
        ++pattern;
    }
    return score;
}

static sbool section_pattern_matches(const section_descriptor_t *desc, const char *label) {
    const char *subject = label;
    char *normalized = NULL;
    sbool matched;
    if (desc == NULL || label == NULL || desc->pattern == NULL) return 0;
    switch (desc->sensitivity) {
        case fieldSensitivityCanonical:
            normalized = normalize_label(label);
            subject = normalized;
            matched = wildcard_match(desc->pattern, subject ? subject : label, 0);
            free(normalized);
            return matched;
        case fieldSensitivityCaseInsensitive:
            return wildcard_match(desc->pattern, label, 1);
        case fieldSensitivityCaseSensitive:
        default:
            return wildcard_match(desc->pattern, label, 0);
    }
}

static inline int section_is_enabled(const instanceData *pData, uint32_t flags);

static const section_descriptor_t *select_section_descriptor(const instanceData *inst, const char *label) {
    const section_descriptor_t *best = NULL;
    int bestPriority = INT_MIN;
    size_t bestSpecificity = 0;
    if (inst == NULL || label == NULL) return NULL;
    for (size_t i = 0; i < inst->sectionDescriptorCount; ++i) {
        const section_descriptor_t *candidate = &inst->sectionDescriptors[i];
        if (!section_is_enabled(inst, candidate->flags)) continue;
        if (!section_pattern_matches(candidate, label)) continue;
        size_t specificity = pattern_specificity(candidate->pattern);
        if (candidate->priority > bestPriority ||
            (candidate->priority == bestPriority && specificity > bestSpecificity)) {
            best = candidate;
            bestPriority = candidate->priority;
            bestSpecificity = specificity;
        }
    }
    return best;
}

static inline int section_is_enabled(const instanceData *pData, uint32_t flags) {
    if ((flags & SECTION_FLAG_NETWORK) && !pData->enableNetwork) return 0;
    if ((flags & SECTION_FLAG_LAPS) && !pData->enableLaps) return 0;
    if ((flags & SECTION_FLAG_TLS) && !pData->enableTls) return 0;
    if ((flags & SECTION_FLAG_WDAC) && !pData->enableWdac) return 0;
    return 1;
}

static inline const char *lookup_logon_description(int logonType) {
    for (size_t i = 0; i < ARRAY_SIZE(g_logonTypeMap); ++i) {
        if (g_logonTypeMap[i].type_id == logonType) return g_logonTypeMap[i].description;
    }
    return NULL;
}

static inline const event_mapping_t *lookup_event_mapping(const instanceData *inst, int eventId) {
    if (inst != NULL && inst->eventMappings != NULL) {
        for (size_t i = 0; i < inst->eventMappingCount; ++i) {
            if (inst->eventMappings[i].event_id == eventId) return &inst->eventMappings[i];
        }
    }
    return NULL;
}

static const char *find_case_insensitive(const char *haystack, const char *needle) {
    size_t nlen;
    if (haystack == NULL || needle == NULL) return NULL;
    nlen = strlen(needle);
    if (nlen == 0) return haystack;
    for (const char *p = haystack; *p; ++p) {
        if (strncasecmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

static inline const char *skip_lws_const(const char *p) {
    if (p == NULL) return NULL;
    while (*p != '\0' && isspace((unsigned char)*p)) ++p;
    return p;
}

static inline const char *skip_nonspace_const(const char *p) {
    if (p == NULL) return NULL;
    while (*p != '\0' && !isspace((unsigned char)*p)) ++p;
    return p;
}

static inline sbool is_all_digits_range(const char *start, const char *end) {
    if (start == NULL || end == NULL || start >= end) return 0;
    for (const char *p = start; p < end; ++p) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

static const char *skip_structured_data_sections(const char *p) {
    const char *cur = p;
    if (cur == NULL) return NULL;
    while (*cur == '[') {
        ++cur;
        while (*cur != '\0' && *cur != ']') {
            if (*cur == '\\' && cur[1] != '\0') {
                cur += 2;
                continue;
            }
            ++cur;
        }
        if (*cur != ']') return NULL;
        ++cur;
        while (*cur != '\0' && isspace((unsigned char)*cur)) ++cur;
    }
    return cur;
}

static const char *skip_rfc5424_header(const char *p) {
    const char *cur = skip_lws_const(p);
    const char *end;
    if (cur == NULL) return NULL;
    end = skip_nonspace_const(cur);
    if (!is_all_digits_range(cur, end)) return NULL;
    cur = skip_lws_const(end);
    for (int i = 0; i < 5; ++i) {
        end = skip_nonspace_const(cur);
        if (end == cur) return NULL;
        cur = skip_lws_const(end);
    }
    if (*cur == '-') {
        ++cur;
        cur = skip_lws_const(cur);
    } else if (*cur == '[') {
        cur = skip_structured_data_sections(cur);
        if (cur == NULL) return NULL;
        cur = skip_lws_const(cur);
    } else {
        return NULL;
    }
    return cur;
}

static const char *skip_rfc3164_header(const char *p) {
    const char *cur = skip_lws_const(p);
    const char *end;
    if (cur == NULL) return NULL;
    for (int i = 0; i < 3; ++i) {
        end = skip_nonspace_const(cur);
        if (end == cur) return NULL;
        cur = skip_lws_const(end);
    }
    end = skip_nonspace_const(cur);
    if (end == cur) return NULL;
    cur = skip_lws_const(end);
    return cur;
}

/**
 * @brief Locate the start of the Snare payload within a syslog message.
 *
 * The parser receives messages that may contain RFC3164 or RFC5424 envelopes,
 * pre-parsed payloads, or bare Snare messages. This function applies a series
 * of heuristics to find the beginning of either the textual or JSON Snare
 * event block.
 *
 * @param msg Raw message text as received by the action.
 * @return Pointer to the beginning of the Snare payload or @c NULL when no
 *         payload could be identified.
 */
static const char *locate_snare_payload(const char *msg) {
    const char *cursor;
    const char *afterPri;
    const char *candidate;
    if (msg == NULL) return NULL;
    dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: input msg='%s'\n", msg);
    cursor = skip_lws_const(msg);
    afterPri = cursor;
    if (cursor != NULL && *cursor == '<') {
        const char *p = cursor + 1;
        sbool haveDigits = 0;
        while (*p >= '0' && *p <= '9') {
            haveDigits = 1;
            ++p;
        }
        if (haveDigits && *p == '>') {
            afterPri = p + 1;
        }
    }
    cursor = skip_lws_const(afterPri);
    if (cursor != NULL && strncmp(cursor, "MSWinEventLog", 13) == 0) {
        dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: found MSWinEventLog at '%s'\n", cursor);
        return cursor;
    }

    // Handle case where syslog header has been parsed and we have a timestamp followed by MSWinEventLog
    if (cursor != NULL) {
        // Look for MSWinEventLog in the message (after syslog parsing)
        const char *msWinEventLog = strstr(cursor, "MSWinEventLog");
        if (msWinEventLog != NULL) {
            dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: found MSWinEventLog after parsing at '%s'\n",
                      msWinEventLog);
            return msWinEventLog;
        }
        // Look for the EventID pattern (4-digit number) which comes before the provider
        const char *eventIdStart = cursor;
        while (*eventIdStart != '\0') {
            if (*eventIdStart >= '0' && *eventIdStart <= '9') {
                // Found a digit, check if it's a 4-digit EventID
                const char *eventIdEnd = eventIdStart;
                while (*eventIdEnd >= '0' && *eventIdEnd <= '9') {
                    eventIdEnd++;
                }
                if (eventIdEnd - eventIdStart == 4) {
                    // Found a 4-digit number, check if it's followed by tab and provider
                    if (*eventIdEnd == '\t' || *eventIdEnd == ' ') {
                        const char *afterEventId = skip_lws_const(eventIdEnd);
                        if (afterEventId != NULL &&
                            strstr(afterEventId, "Microsoft-Windows-Security-Auditing") != NULL) {
                            dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: found EventID pattern at '%s'\n",
                                      eventIdStart);
                            return eventIdStart;
                        }
                    }
                }
            }
            eventIdStart++;
        }
        // If we didn't find EventID pattern, try looking for Microsoft-Windows-Security-Auditing
        // but we need to go back to find the EventID that comes before it
        const char *msWinSec = strstr(cursor, "Microsoft-Windows-Security-Auditing");
        if (msWinSec != NULL) {
            // Go back from the provider to find the EventID
            const char *searchStart = cursor;
            while (searchStart < msWinSec) {
                if (*searchStart >= '0' && *searchStart <= '9') {
                    const char *eventIdEnd = searchStart;
                    while (*eventIdEnd >= '0' && *eventIdEnd <= '9') {
                        eventIdEnd++;
                    }
                    if (eventIdEnd - searchStart == 4) {
                        // Found a 4-digit number before the provider
                        dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: found EventID before provider at '%s'\n",
                                  searchStart);
                        return searchStart;
                    }
                }
                searchStart++;
            }
            // If we still can't find EventID, fall back to provider
            dbgprintf("[mmsnarewinsec DEBUG] locate_snare_payload: found Microsoft-Windows-Security-Auditing at '%s'\n",
                      msWinSec);
            return msWinSec;
        }
    }
    if (cursor != NULL) {
        const char *versionEnd = skip_nonspace_const(cursor);
        if (is_all_digits_range(cursor, versionEnd)) {
            candidate = skip_rfc5424_header(cursor);
            if (candidate != NULL && strncmp(candidate, "MSWinEventLog", 13) == 0) return candidate;
        }
        candidate = skip_rfc3164_header(cursor);
        if (candidate != NULL && strncmp(candidate, "MSWinEventLog", 13) == 0) return candidate;
    }
    if (afterPri != NULL) {
        candidate = strstr(afterPri, "MSWinEventLog");
        if (candidate != NULL) return candidate;
    }
    return NULL;
}

/**
 * @brief Aggregates parsing state while transforming a Snare message.
 *
 * @var parse_context::inst Active module configuration shared by workers.
 * @var parse_context::msg  Message currently processed.
 * @var parse_context::root Root JSON container produced by the parser.
 * @var parse_context::event JSON object containing Event-level metadata.
 * @var parse_context::eventData Lazily created EventData object.
 * @var parse_context::unparsed Bucket for text that could not be normalized.
 * @var parse_context::logonDerived Derived fields attached to the Logon node.
 * @var parse_context::eventId Numeric Windows Event ID currently in scope.
 * @var parse_context::activeSection Descriptor for the active description section.
 * @var parse_context::activeSectionObj JSON object representing the active section.
 * @var parse_context::summarySet Tracks whether the Summary field was populated.
 */
typedef struct parse_context {
    instanceData *inst;
    smsg_t *msg;
    struct json_object *root;
    struct json_object *event;
    struct json_object *eventData;
    struct json_object *unparsed;
    struct json_object *logonDerived;
    int eventId;
    const section_descriptor_t *activeSection;
    struct json_object *activeSectionObj;
    sbool summarySet;
    const field_pattern_t *corePatterns;
    size_t corePatternCount;
    const field_pattern_t *eventPatterns;
    size_t eventPatternCount;
    int patternEventId;
    sbool patternsPrepared;
    validation_context_t *validation;
    field_detection_context_t detection;
    struct json_object *validationErrors;
    struct json_object *parsingStats;
} parse_context_t;

static struct json_object *ensure_object(struct json_object *parent, const char *name) {
    struct json_object *existing;
    if (parent == NULL || name == NULL) return NULL;
    if (json_object_object_get_ex(parent, name, &existing)) return existing;
    existing = json_object_new_object();
    if (existing == NULL) return NULL;
    json_object_object_add(parent, name, existing);
    return existing;
}

static inline struct json_object *ensure_event_data(parse_context_t *ctx) {
    if (ctx->eventData == NULL) {
        ctx->eventData = json_object_new_object();
        if (ctx->eventData != NULL) json_object_object_add(ctx->root, "EventData", ctx->eventData);
    }
    return ctx->eventData;
}

static inline struct json_object *ensure_logon_root(parse_context_t *ctx) {
    if (ctx->logonDerived == NULL) {
        ctx->logonDerived = json_object_new_object();
        if (ctx->logonDerived != NULL) json_object_object_add(ctx->root, "Logon", ctx->logonDerived);
    }
    return ctx->logonDerived;
}

static inline void append_unparsed(parse_context_t *ctx, const char *text) {
    struct json_object *arr;
    if (text == NULL || *text == '\0') return;
    if (ctx->unparsed == NULL) {
        ctx->unparsed = json_object_new_array();
        if (ctx->unparsed != NULL) json_object_object_add(ctx->root, "Unparsed", ctx->unparsed);
    }
    arr = ctx->unparsed;
    if (arr != NULL) json_object_array_add(arr, json_object_new_string(text));
}

static void json_add_string(struct json_object *obj, const char *name, const char *value) {
    if (obj == NULL || name == NULL || value == NULL) return;
    json_object_object_add(obj, name, json_object_new_string(value));
}

static void json_add_int64(struct json_object *obj, const char *name, long long value) {
    if (obj == NULL || name == NULL) return;
    json_object_object_add(obj, name, json_object_new_int64(value));
}

static void json_add_bool(struct json_object *obj, const char *name, sbool value) {
    if (obj == NULL || name == NULL) return;
    json_object_object_add(obj, name, json_object_new_boolean(value ? 1 : 0));
}

static sbool try_parse_int64(const char *value, long long *outVal) {
    char *end = NULL;
    long long val;
    if (value == NULL || *value == '\0') return 0;
    val = strtoll(value, &end, 0);
    if (end == value || (end != NULL && *end != '\0' && !isspace((unsigned char)*end))) return 0;
    if (outVal != NULL) *outVal = val;
    return 1;
}

static sbool try_parse_bool(const char *value, sbool *outVal) {
    if (value == NULL) return 0;
    if (!strcasecmp(value, "true") || !strcasecmp(value, "yes") || !strcasecmp(value, "enabled") ||
        !strcasecmp(value, "on")) {
        if (outVal != NULL) *outVal = 1;
        return 1;
    }
    if (!strcasecmp(value, "false") || !strcasecmp(value, "no") || !strcasecmp(value, "disabled") ||
        !strcasecmp(value, "off")) {
        if (outVal != NULL) *outVal = 0;
        return 1;
    }
    if (!strcmp(value, "1")) {
        if (outVal != NULL) *outVal = 1;
        return 1;
    }
    if (!strcmp(value, "0")) {
        if (outVal != NULL) *outVal = 0;
        return 1;
    }
    return 0;
}

static void add_raw_string(struct json_object *obj, const char *baseName, const char *value);
static void parse_privilege_sequence(parse_context_t *ctx, const char *text);

static struct json_object *try_parse_json_block(const char *value) {
    struct json_tokener *tokener;
    struct json_object *parsed;
    enum json_tokener_error err;
    if (value == NULL) return NULL;
    tokener = json_tokener_new();
    if (tokener == NULL) return NULL;
    parsed = json_tokener_parse_ex(tokener, value, (int)strlen(value));
    err = fjson_tokener_get_error(tokener);
    json_tokener_free(tokener);
    if (err != fjson_tokener_success || parsed == NULL) {
        if (parsed != NULL) json_object_put(parsed);
        return NULL;
    }
    return parsed;
}

static char *trim_whitespace_enhanced(const char *input) {
    if (input == NULL) return NULL;
    size_t len = strlen(input);
    if (len == 0) return strdup("");
    const char *start = input;
    const char *end = input + len - 1;
    while (start <= end && isspace((unsigned char)*start)) ++start;
    while (end >= start && isspace((unsigned char)*end)) --end;
    size_t new_len = (size_t)(end - start + 1);
    char *result = malloc(new_len + 1);
    if (result == NULL) return NULL;
    if (new_len > 0) memcpy(result, start, new_len);
    result[new_len] = '\0';
    return result;
}

static bool is_placeholder_value(const char *value) {
    static const char *placeholders[] = {"-",         "N/A",      "n/a",
                                         "NULL",      "null",     "None",
                                         "none",      "Not Available",
                                         "not available",          "Unknown",
                                         "unknown",  "<never>",  "<value not set>",
                                         "<not set>", ""};
    if (value == NULL) return true;
    for (size_t i = 0; i < ARRAY_SIZE(placeholders); ++i) {
        if (!strcasecmp(value, placeholders[i])) return true;
    }
    return false;
}

static bool is_guid_format(const char *value) {
    if (value == NULL) return false;
    if (strlen(value) == 38 && value[0] == '{' && value[37] == '}') return true;
    return false;
}

static bool is_ip_address(const char *value) {
    int dots = 0;
    int digits = 0;
    if (value == NULL) return false;
    for (const char *p = value; *p; ++p) {
        if (*p == '.') {
            if (digits == 0) return false;
            ++dots;
            digits = 0;
        } else if (isdigit((unsigned char)*p)) {
            ++digits;
        } else {
            return false;
        }
    }
    return dots == 3 && digits > 0;
}

static bool is_timestamp_format(const char *value) {
    static const char *dow[] = {"Mon ", "Tue ", "Wed ", "Thu ", "Fri ", "Sat ", "Sun "};
    if (value == NULL) return false;
    if (strstr(value, "T") != NULL && strstr(value, "Z") != NULL) return true;
    for (size_t i = 0; i < ARRAY_SIZE(dow); ++i) {
        if (strstr(value, dow[i]) != NULL) return true;
    }
    return false;
}

static bool is_json_format(const char *value) {
    size_t len;
    if (value == NULL) return false;
    len = strlen(value);
    if (len < 2) return false;
    if ((value[0] == '{' && value[len - 1] == '}') || (value[0] == '[' && value[len - 1] == ']')) return true;
    return false;
}

static rsRetVal tokenize_on_multispace(const char *str, size_t len, token_callback_t callback, void *user_data) {
    size_t i = 0;
    size_t start = 0;
    bool in_token = false;
    if (callback == NULL) return RS_RET_INVALID_PARAMS;
    if (str == NULL || len == 0) return RS_RET_OK;
    while (i < len) {
        if (str[i] == ' ' || str[i] == '\t') {
            size_t j = i;
            while (j < len && (str[j] == ' ' || str[j] == '\t')) ++j;
            size_t spaces = j - i;
            if (spaces >= 2 || str[i] == '\t') {
                if (in_token) {
                    callback(str + start, i - start, user_data);
                    in_token = false;
                }
                i = j;
                continue;
            }
            if (!in_token) {
                start = i;
                in_token = true;
            }
            i = j;
            continue;
        }
        if (!in_token) {
            start = i;
            in_token = true;
        }
        ++i;
    }
    if (in_token) callback(str + start, len - start, user_data);
    return RS_RET_OK;
}

static rsRetVal parse_field_value_enhanced(const char *value,
                                           field_value_type_t type,
                                           struct json_object *target,
                                           const char *key,
                                           const char *section_context,
                                           int event_id,
                                           parse_context_t *ctx) {
    rsRetVal r = RS_RET_OK;
    char *trimmed = NULL;
    (void)section_context;
    (void)event_id;
    if (target == NULL || key == NULL) return RS_RET_INVALID_PARAMS;
    if (value == NULL || *value == '\0') return RS_RET_OK;
    trimmed = trim_whitespace_enhanced(value);
    if (trimmed == NULL) return RS_RET_OUT_OF_MEMORY;
    if (*trimmed == '\0') {
        free(trimmed);
        return RS_RET_OK;
    }
    if (is_placeholder_value(trimmed)) {
        free(trimmed);
        return RS_RET_OK;
    }
    switch (type) {
        case fieldValueString:
            if (is_guid_format(trimmed)) json_add_string(target, key, trimmed);
            else if (is_ip_address(trimmed)) json_add_string(target, key, trimmed);
            else if (is_timestamp_format(trimmed)) json_add_string(target, key, trimmed);
            else json_add_string(target, key, trimmed);
            break;
        case fieldValueInt64: {
            long long num;
            if (try_parse_int64(trimmed, &num))
                json_add_int64(target, key, num);
            else
                json_add_string(target, key, trimmed);
            break;
        }
        case fieldValueInt64WithRaw: {
            long long num;
            if (try_parse_int64(trimmed, &num)) {
                json_add_int64(target, key, num);
            } else {
                json_add_string(target, key, trimmed);
                if (ctx != NULL) add_raw_string(target, key, trimmed);
            }
            break;
        }
        case fieldValueBool: {
            sbool bool_val;
            if (try_parse_bool(trimmed, &bool_val))
                json_add_bool(target, key, bool_val);
            else
                json_add_string(target, key, trimmed);
            break;
        }
        case fieldValueLogonType: {
            long long num;
            if (try_parse_int64(trimmed, &num)) {
                json_add_int64(target, key, num);
                const char *desc = lookup_logon_description((int)num);
                if (desc != NULL) {
                    json_add_string(target, "LogonTypeName", desc);
                    if (ctx != NULL) json_add_string(ensure_logon_root(ctx), "LogonTypeName", desc);
                }
            } else {
                json_add_string(target, key, trimmed);
            }
            break;
        }
        case fieldValueJson: {
            struct json_object *jsonBlock = NULL;
            if (is_json_format(trimmed)) jsonBlock = try_parse_json_block(trimmed);
            if (jsonBlock != NULL)
                json_object_object_add(target, key, jsonBlock);
            else
                json_add_string(target, key, trimmed);
            break;
        }
        case fieldValueRemoteCredentialGuard: {
            sbool bool_val;
            if (try_parse_bool(trimmed, &bool_val)) {
                json_add_bool(target, key, bool_val);
                if (ctx != NULL) json_add_bool(ensure_logon_root(ctx), key, bool_val);
            } else {
                json_add_string(target, key, trimmed);
            }
            break;
        }
        case fieldValuePrivilegeList:
            if (ctx != NULL) parse_privilege_sequence(ctx, trimmed);
            break;
        default:
            json_add_string(target, key, trimmed);
            break;
    }
    free(trimmed);
    return r;
}

static void ensure_event_patterns(parse_context_t *ctx) {
    if (ctx == NULL) return;
    if (ctx->patternsPrepared && ctx->patternEventId == ctx->eventId) return;
    ctx->eventPatterns = NULL;
    ctx->eventPatternCount = 0;
    ctx->patternEventId = ctx->eventId;
    if (ctx->inst->eventFieldMappings != NULL) {
        for (size_t i = 0; i < ctx->inst->eventFieldMappingCount; ++i) {
            const event_field_mapping_t *mapping = &ctx->inst->eventFieldMappings[i];
            if (mapping->event_id == ctx->eventId) {
                if (section_is_enabled(ctx->inst, mapping->required_flags)) {
                    ctx->eventPatterns = mapping->patterns;
                    ctx->eventPatternCount = mapping->pattern_count;
                }
                break;
            }
        }
    }
    ctx->patternsPrepared = 1;
}

static sbool pattern_matches(const field_pattern_t *pattern, const char *label, const char *canon) {
    if (pattern == NULL) return 0;
    const char *pat = pattern->pattern;
    sbool hasWildcard = 0;
    if (pat != NULL) {
        if (strchr(pat, '*') != NULL || strchr(pat, '?') != NULL) hasWildcard = 1;
    }
    switch (pattern->sensitivity) {
        case fieldSensitivityCanonical:
            if (canon == NULL) return 0;
            if (hasWildcard) return wildcard_match(pattern->pattern, canon, 0);
            return strcmp(pattern->pattern, canon) == 0;
        case fieldSensitivityCaseSensitive:
            if (label == NULL) return 0;
            if (hasWildcard) return wildcard_match(pattern->pattern, label, 0);
            return strcmp(pattern->pattern, label) == 0;
        case fieldSensitivityCaseInsensitive:
            if (label == NULL) return 0;
            if (hasWildcard) return wildcard_match(pattern->pattern, label, 1);
            return strcasecmp(pattern->pattern, label) == 0;
        default:
            return 0;
    }
}

static const field_pattern_t *select_field_pattern(parse_context_t *ctx, const char *label, const char *canon) {
    const field_pattern_t *best = NULL;
    int bestPriority = INT_MIN;
    if (ctx == NULL) return NULL;
    if (ctx->eventPatterns != NULL) {
        for (size_t i = 0; i < ctx->eventPatternCount; ++i) {
            const field_pattern_t *candidate = &ctx->eventPatterns[i];
            if (pattern_matches(candidate, label, canon) && candidate->priority > bestPriority) {
                bestPriority = candidate->priority;
                best = candidate;
            }
        }
    }
    if (ctx->corePatterns != NULL) {
        for (size_t i = 0; i < ctx->corePatternCount; ++i) {
            const field_pattern_t *candidate = &ctx->corePatterns[i];
            if (pattern_matches(candidate, label, canon) && candidate->priority > bestPriority) {
                bestPriority = candidate->priority;
                best = candidate;
            }
        }
    }
    return best;
}

static void add_raw_string(struct json_object *obj, const char *baseName, const char *value) {
    size_t len;
    char *rawName;
    if (obj == NULL || baseName == NULL || value == NULL) return;
    len = strlen(baseName) + 4 + 1; /* "Raw" suffix */
    rawName = malloc(len);
    if (rawName == NULL) {
        json_add_string(obj, baseName, value);
        return;
    }
    snprintf(rawName, len, "%sRaw", baseName);
    json_add_string(obj, rawName, value);
    free(rawName);
}

static struct json_object *resolve_target_object(parse_context_t *ctx,
                                                 struct json_object *hint,
                                                 const field_pattern_t *pattern) {
    if (ctx == NULL) return NULL;
    if (pattern == NULL || pattern->section == NULL) {
        if (hint != NULL) return hint;
        return ensure_event_data(ctx);
    }
    if (!strcmp(pattern->section, FIELD_SECTION_EVENT_DATA)) return ensure_event_data(ctx);
    if (!strcmp(pattern->section, FIELD_SECTION_LOGON)) return ensure_logon_root(ctx);
    if (!strcmp(pattern->section, FIELD_SECTION_ROOT)) return ctx->root;
    return ensure_object(ctx->root, pattern->section);
}

static void dispatch_field(parse_context_t *ctx,
                           struct json_object *target,
                           const char *sectionName,
                           const char *label,
                           const char *value) {
    (void)sectionName;
    if (ctx == NULL || label == NULL) return;
    if (value == NULL) value = "";

    ensure_event_patterns(ctx);

    char *canon = normalize_label(label);
    char *composite = NULL;
    const field_pattern_t *pattern = NULL;
    if (canon == NULL) return;

    if (sectionName != NULL && *sectionName != '\0') {
        size_t secLen = strlen(sectionName);
        size_t canonLen = strlen(canon);
        composite = malloc(secLen + canonLen + 1);
        if (composite != NULL) {
            memcpy(composite, sectionName, secLen);
            memcpy(composite + secLen, canon, canonLen);
            composite[secLen + canonLen] = '\0';
            pattern = select_field_pattern(ctx, label, composite);
        }
    }
    if (pattern == NULL) pattern = select_field_pattern(ctx, label, canon);
    struct json_object *dest = resolve_target_object(ctx, target, pattern);
    if (dest == NULL && target != NULL) dest = target;
    if (dest == NULL) dest = ensure_event_data(ctx);

    ctx->detection.total_fields++;

    if (dest != NULL) {
        const char *fieldName = (pattern != NULL && pattern->canonical != NULL) ? pattern->canonical : canon;
        if (fieldName == NULL) fieldName = canon;
        if (pattern != NULL) {
            rsRetVal pr = parse_field_value_enhanced(
                value, pattern->value_type, dest, fieldName, pattern->section, ctx->eventId, ctx);
            if (pr == RS_RET_OK) {
                ctx->detection.successful_parses++;
            } else {
                handle_parsing_error(&ctx->detection, "failed to parse field value", fieldName);
            }
        } else {
            json_add_string(dest, fieldName, value);
            ctx->detection.successful_parses++;
        }
    } else {
        handle_parsing_error(&ctx->detection, "no destination object for field", canon);
    }

    free(composite);
    free(canon);
}


static const char *derive_outcome(const char *auditResult) {
    if (auditResult == NULL) return NULL;
    if (find_case_insensitive(auditResult, "success") != NULL) return "success";
    if (find_case_insensitive(auditResult, "failure") != NULL || find_case_insensitive(auditResult, "fail") != NULL)
        return "failure";
    if (find_case_insensitive(auditResult, "error") != NULL) return "error";
    if (find_case_insensitive(auditResult, "warning") != NULL) return "warning";
    if (find_case_insensitive(auditResult, "information") != NULL) return "information";
    return NULL;
}

static void apply_event_mapping(parse_context_t *ctx, const char *auditResult) {
    const event_mapping_t *mapping;
    const char *outcome = NULL;
    if (ctx->event == NULL) return;
    mapping = lookup_event_mapping(ctx->inst, ctx->eventId);
    if (mapping != NULL) {
        if (mapping->category != NULL) json_add_string(ctx->event, "Category", mapping->category);
        if (mapping->subtype != NULL) json_add_string(ctx->event, "Subtype", mapping->subtype);
        if (mapping->outcome != NULL) outcome = mapping->outcome;
    }
    if (outcome == NULL) outcome = derive_outcome(auditResult);
    if (outcome != NULL) json_add_string(ctx->event, "Outcome", outcome);
}

static void handle_key_value(
    parse_context_t *ctx, struct json_object *target, const char *sectionName, const char *label, const char *value);

/**
 * @brief Parse a whitespace-delimited sequence of key-value pairs.
 *
 * Snare description blocks often condense multiple @c key: value tokens into a
 * single line separated by runs of spaces. The function walks through the
 * sequence, extracts each pair, and dispatches the normalized data to
 * ::handle_key_value.
 *
 * @param ctx          Active parsing context.
 * @param target       JSON object that receives the parsed keys.
 * @param text         Source text containing the condensed key-value sequence.
 * @param sectionName  Optional section name used to drive section-specific
 *                     normalization.
 */
typedef struct kv_token_context {
    parse_context_t *ctx;
    struct json_object *target;
    const char *sectionName;
    bool treat_as_general;
} kv_token_context_t;

static void kv_token_handler(const char *token, size_t len, void *user_data) {
    kv_token_context_t *cb = (kv_token_context_t *)user_data;
    char *copy;
    char *colon;
    char *label;
    char *value;
    if (cb == NULL || cb->ctx == NULL) return;
    copy = strdup_range(token, len);
    if (copy == NULL) return;
    trim_inplace(copy);
    if (*copy == '\0') {
        free(copy);
        return;
    }
    colon = strchr(copy, ':');
    if (colon == NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] kv_token_handler: missing colon in token '%s'\n", copy);
        append_unparsed(cb->ctx, copy);
        handle_parsing_error(&cb->ctx->detection, "missing colon in token", copy);
        free(copy);
        return;
    }
    *colon = '\0';
    label = copy;
    value = colon + 1;
    while (*value == ' ') ++value;
    dbgprintf("[mmsnarewinsec DEBUG] kv_token_handler: label='%s', value='%s'\n", label, value);
    if (cb->treat_as_general || cb->target == NULL)
        handle_general_key(cb->ctx, label, value);
    else
        handle_key_value(cb->ctx, cb->target, cb->sectionName, label, value);
    free(copy);
}

static void parse_key_value_sequence(parse_context_t *ctx,
                                     struct json_object *target,
                                     const char *text,
                                     const char *sectionName) {
    kv_token_context_t cbCtx;
    if (text == NULL) return;

    dbgprintf("[mmsnarewinsec DEBUG] parse_key_value_sequence: text='%s', sectionName='%s'\n", text, sectionName);

    cbCtx.ctx = ctx;
    cbCtx.target = target;
    cbCtx.sectionName = sectionName;
    cbCtx.treat_as_general = (target == NULL);
    tokenize_on_multispace(text, strlen(text), kv_token_handler, &cbCtx);
}

static void parse_privilege_sequence(parse_context_t *ctx, const char *text) {
    struct json_object *arr;
    const char *cursor = text;
    if (cursor == NULL || !section_is_enabled(ctx->inst, SECTION_FLAG_NONE)) return;
    arr = json_object_new_array();
    if (arr == NULL) return;
    while (*cursor) {
        while (*cursor == ' ') ++cursor;
        if (*cursor == '\0') break;
        const char *start = cursor;
        while (*cursor != '\0' && *cursor != ' ') ++cursor;
        if (cursor > start) {
            char *token = strdup_range(start, (size_t)(cursor - start));
            if (token != NULL) {
                json_object_array_add(arr, json_object_new_string(token));
                free(token);
            }
        }
    }
    json_object_object_add(ctx->root, "Privileges", arr);
}

static void handle_inline_remote_credential_guard(parse_context_t *ctx,
                                                  struct json_object *sectionObj,
                                                  const char *value) {
    sbool boolVal = 0;
    if (value == NULL) return;
    if (try_parse_bool(value, &boolVal)) {
        json_add_bool(sectionObj, "Enabled", boolVal);
        json_add_bool(ensure_logon_root(ctx), "RemoteCredentialGuard", boolVal);
    }
    json_add_string(sectionObj, "Status", value);
}

static void parse_semicolon_sequence(parse_context_t *ctx, struct json_object *sectionObj, const char *text) {
    char *mutable;
    char *saveptr = NULL;
    if (text == NULL || sectionObj == NULL) return;
    mutable = strdup(text);
    if (mutable == NULL) return;
    for (char *token = strtok_r(mutable, ";", &saveptr); token != NULL; token = strtok_r(NULL, ";", &saveptr)) {
        char *kv = token;
        char *eq;
        trim_inplace(kv);
        if (*kv == '\0') continue;
        eq = strchr(kv, '=');
        if (eq == NULL) {
            append_unparsed(ctx, kv);
            continue;
        }
        *eq = '\0';
        char *key = kv;
        char *val = eq + 1;
        trim_inplace(key);
        trim_inplace(val);
        if (*key == '\0') continue;
        char *canon = normalize_label(key);
        if (canon == NULL) continue;
        if (!strcmp(canon, "CredentialRotation")) {
            sbool boolVal = 0;
            if (try_parse_bool(val, &boolVal))
                json_add_bool(sectionObj, canon, boolVal);
            else
                json_add_string(sectionObj, canon, val);
        } else {
            json_add_string(sectionObj, canon, val);
        }
        free(canon);
    }
    free(mutable);
}

/**
 * @brief Store a general key-value pair in the EventData container.
 *
 * The helper performs event-specific adjustments (for example WDAC and Windows
 * Update for Business events) and then writes the normalized value into the
 * \c EventData object.
 *
 * @param ctx   Active parsing context.
 * @param label Raw field label from the message.
 * @param value Raw value associated with @p label.
 */
static void handle_general_key(parse_context_t *ctx, const char *label, const char *value) {
    dispatch_field(ctx, NULL, NULL, label, value);
}

/**
 * @brief Normalize and store a key-value pair for a specific section.
 *
 * This function canonicalizes labels, performs numeric conversions, derives
 * helper metadata (such as @c LogonTypeName), and routes fields to derived
 * JSON locations like the Logon container.
 *
 * @param ctx         Active parsing context.
 * @param target      JSON object representing the current section.
 * @param sectionName Canonical name of the active section or @c NULL for
 *                    top-level handling.
 * @param label       Raw key extracted from the message.
 * @param value       Raw value associated with @p label.
 */
static void handle_key_value(
    parse_context_t *ctx, struct json_object *target, const char *sectionName, const char *label, const char *value) {
    dispatch_field(ctx, target, sectionName, label, value);
}

static char *normalize_description(const char *desc) {
    size_t len;
    char *out;
    size_t j = 0;
    if (desc == NULL) return NULL;
    len = strlen(desc);
    out = malloc(len + 1);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < len;) {
        if (desc[i] == '\r') {
            ++i;
            continue;
        }
        if (desc[i] == '\n') {
            out[j++] = '\n';
            ++i;
            continue;
        }
        // Handle Windows Security Event Log format with multiple spaces
        // Look for patterns like "   " (3+ spaces) that separate sections
        if (desc[i] == ' ') {
            size_t spaceCount = 0;
            size_t k = i;
            while (k < len && desc[k] == ' ') {
                spaceCount++;
                k++;
            }
            // If we have 3 or more spaces, treat as section separator
            if (spaceCount >= 3) {
                out[j++] = '\n';
                i = k;
                continue;
            }
        }
        out[j++] = desc[i++];
    }
    out[j] = '\0';
    return out;
}

/**
 * @brief Parse a single normalized description line.
 *
 * Each line may introduce a new description section, extend the active section
 * with condensed key-value data, or provide fallback text that is stored in the
 * Summary or Unparsed buckets.
 *
 * @param ctx  Active parsing context.
 * @param line Mutable line buffer produced by ::normalize_description.
 */
static void parse_line(parse_context_t *ctx, char *line) {
    char *colon;
    char *label;
    char *rest;
    const section_descriptor_t *desc;
    struct json_object *sectionObj;
    if (line == NULL) return;
    trim_inplace(line);
    if (*line == '\0') return;

    dbgprintf("[mmsnarewinsec DEBUG] parse_line: processing line='%s'\n", line);

    colon = strchr(line, ':');
    if (colon == NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_line: no colon found, treating as content\n");

        // Special handling for Privileges section - collect privilege names
        if (ctx->activeSection != NULL && strcmp(ctx->activeSection->canonical, "Privileges") == 0 &&
            ctx->activeSection->behavior == sectionBehaviorList) {
            dbgprintf("[mmsnarewinsec DEBUG] parse_line: collecting privilege name '%s' in Privileges section\n", line);

            // Get or create the Privileges object
            struct json_object *privileges_obj = NULL;
            if (!json_object_object_get_ex(ctx->root, "Privileges", &privileges_obj)) {
                privileges_obj = json_object_new_object();
                json_object_object_add(ctx->root, "Privileges", privileges_obj);
            }

            // Get the current PrivilegeList string
            struct json_object *privilege_list = NULL;
            const char *current_list = "";
            if (json_object_object_get_ex(privileges_obj, "PrivilegeList", &privilege_list)) {
                current_list = json_object_get_string(privilege_list);
            }

            // Create the new privilege list string
            char *new_list = NULL;
            if (strlen(current_list) > 0) {
                int ret = asprintf(&new_list, "%s %s", current_list, line);
                if (ret < 0) new_list = NULL;
            } else {
                new_list = strdup(line);
            }

            if (new_list != NULL) {
                json_object_object_add(privileges_obj, "PrivilegeList", json_object_new_string(new_list));
                free(new_list);
            }

            return;
        }

        if (!ctx->summarySet) {
            json_add_string(ctx->root, "Summary", line);
            ctx->summarySet = 1;
        } else if (ctx->activeSection != NULL && ctx->activeSectionObj != NULL) {
            dbgprintf("[mmsnarewinsec DEBUG] parse_line: parsing as key-value in active section '%s'\n",
                      ctx->activeSection->canonical);
            parse_key_value_sequence(ctx, ctx->activeSectionObj, line, ctx->activeSection->canonical);
        } else {
            dbgprintf("[mmsnarewinsec DEBUG] parse_line: no active section, appending to unparsed\n");
            append_unparsed(ctx, line);
        }
        return;
    }
    *colon = '\0';
    label = line;
    rest = colon + 1;
    trim_inplace(label);
    while (*rest == ' ') ++rest;

    dbgprintf("[mmsnarewinsec DEBUG] parse_line: label='%s', rest='%s'\n", label, rest);

    desc = select_section_descriptor(ctx->inst, label);
    if (desc != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_line: matched section pattern '%s' -> '%s'\n", desc->pattern,
                  desc->canonical);
        switch (desc->behavior) {
            case sectionBehaviorStandard:
                sectionObj = ensure_object(ctx->root, desc->canonical);
                if (sectionObj != NULL && *rest != '\0') {
                    parse_key_value_sequence(ctx, sectionObj, rest, desc->canonical);
                    ctx->activeSection = desc;
                    ctx->activeSectionObj = sectionObj;
                } else {
                    ctx->activeSection = desc;
                    ctx->activeSectionObj = sectionObj;
                }
                break;
            case sectionBehaviorInlineValue:
                sectionObj = ensure_object(ctx->root, desc->canonical);
                if (sectionObj != NULL) handle_inline_remote_credential_guard(ctx, sectionObj, rest);
                ctx->activeSection = NULL;
                ctx->activeSectionObj = NULL;
                break;
            case sectionBehaviorSemicolon:
                sectionObj = ensure_object(ctx->root, desc->canonical);
                if (sectionObj != NULL) parse_semicolon_sequence(ctx, sectionObj, rest);
                ctx->activeSection = NULL;
                ctx->activeSectionObj = NULL;
                break;
            case sectionBehaviorList: {
                // Start building the privileges list - keep section active to collect more privilege names
                struct json_object *privileges_obj = NULL;
                if (!json_object_object_get_ex(ctx->root, "Privileges", &privileges_obj)) {
                    privileges_obj = json_object_new_object();
                    json_object_object_add(ctx->root, "Privileges", privileges_obj);
                }

                // Initialize with the first privilege name
                json_object_object_add(privileges_obj, "PrivilegeList", json_object_new_string(rest));

                // Keep the section active to collect more privilege names
                ctx->activeSection = desc;
                ctx->activeSectionObj = privileges_obj;
                break;
            }
            default:
                /* Unknown section behavior - this should not happen with current enum values */
                break;
        }
        return;
    }
    // Check if we have an active section - if so, store the key-value pair in that section
    if (ctx->activeSection != NULL && ctx->activeSectionObj != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_line: storing in active section '%s': label='%s', rest='%s'\n",
                  ctx->activeSection->canonical, label, rest);
        handle_key_value(ctx, ctx->activeSectionObj, ctx->activeSection->canonical, label, rest);
        return;
    }

    // No active section, clear the context and process as general key-value pair
    ctx->activeSection = NULL;
    ctx->activeSectionObj = NULL;
    if (!strcmp(label, "Privileges")) {
        parse_privilege_sequence(ctx, rest);
        return;
    }
    if (*rest == '\0') {
        dbgprintf("[mmsnarewinsec DEBUG] parse_line: rest is empty, appending to unparsed\n");
        append_unparsed(ctx, label);
        return;
    }
    dbgprintf("[mmsnarewinsec DEBUG] parse_line: processing general key-value pair: label='%s', rest='%s'\n", label,
              rest);
    {
        const char *restEnd = rest + strlen(rest);
        const char *valueStart = rest;
        const char *nextToken;
        const char *valueEnd;
        char *valueCopy = NULL;
        while (valueStart < restEnd && *valueStart == ' ') ++valueStart;
        nextToken = find_next_token(valueStart, restEnd);
        valueEnd = (nextToken != NULL) ? nextToken : restEnd;
        if (valueStart < valueEnd) {
            valueCopy = trim_copy(valueStart, (size_t)(valueEnd - valueStart));
        }
        dbgprintf("[mmsnarewinsec DEBUG] parse_line: valueCopy='%s', calling handle_general_key\n",
                  valueCopy ? valueCopy : "NULL");
        if (valueCopy != NULL) {
            handle_general_key(ctx, label, valueCopy);
            free(valueCopy);
        } else if (valueStart < valueEnd) {
            char saved = *((char *)valueEnd);
            *((char *)valueEnd) = '\0';
            handle_general_key(ctx, label, valueStart);
            *((char *)valueEnd) = saved;
        } else {
            handle_general_key(ctx, label, "");
        }
        if (nextToken != NULL) {
            parse_key_value_sequence(ctx, NULL, nextToken, NULL);
        }
    }
}

/**
 * @brief Normalize and parse the Snare description text.
 *
 * The routine flattens carriage returns, converts triple-space boundaries into
 * line breaks, and then feeds each logical line to ::parse_line.
 *
 * @param ctx  Active parsing context.
 * @param desc Raw description string extracted from the Snare payload.
 */
static void parse_description(parse_context_t *ctx, const char *desc) {
    char *normalized;
    char *save;
    char *line;

    dbgprintf("[mmsnarewinsec DEBUG] parse_description: input desc='%s'\n", desc);

    normalized = normalize_description(desc);
    if (normalized == NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_description: normalize_description returned NULL\n");
        return;
    }

    dbgprintf("[mmsnarewinsec DEBUG] parse_description: normalized='%s'\n", normalized);

    save = normalized;
    int lineNum = 1;
    while ((line = strsep(&normalized, "\n")) != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_description: processing line %d: '%s'\n", lineNum, line);
        parse_line(ctx, line);
        lineNum++;
    }
    free(save);
}

/**
 * @brief Extract core metadata fields from the header token array.
 *
 * Both RFC3164 and RFC5424 Snare formats are supported. The function populates
 * the @c Event object with identifiers, source system information, and derived
 * outcome data.
 *
 * @param ctx        Active parsing context.
 * @param tokens     Array of tab-delimited tokens that form the header.
 * @param tokenCount Number of valid entries in @p tokens.
 */
static void populate_event_metadata(parse_context_t *ctx, char **tokens, size_t tokenCount) {
    // Detect format based on token structure
    // RFC5424 format: MSWinEventLog, version, channel, record, timestamp, eventid, provider, n/a, n/a, eventtype,
    // computer, categorytext, empty, empty, description RFC3164 format: year, eventid, provider, n/a, n/a, eventtype,
    // computer, categorytext, empty, empty, description

    size_t eventIdIdx, providerIdx, eventTypeIdx, computerIdx, categoryTextIdx;

    // Check if this is RFC5424 format (MSWinEventLog at tokens[0])
    if (tokenCount > 0 && !is_placeholder(tokens[0]) && strcmp(tokens[0], "MSWinEventLog") == 0) {
        // RFC5424 format
        eventIdIdx = 5;
        providerIdx = 6;
        eventTypeIdx = 9;
        computerIdx = 10;
        categoryTextIdx = 11;
    } else {
        // RFC3164 format
        eventIdIdx = 1;
        providerIdx = 2;
        eventTypeIdx = 5;
        computerIdx = 6;
        categoryTextIdx = 7;
    }

    if (tokenCount > eventIdIdx && !is_placeholder(tokens[eventIdIdx])) {
        long long eid;
        if (try_parse_int64(tokens[eventIdIdx], &eid)) {
            ctx->eventId = (int)eid;
            json_add_int64(ctx->event, "EventID", eid);
        } else {
            json_add_string(ctx->event, "EventIDRaw", tokens[eventIdIdx]);
        }
    }
    if (tokenCount > providerIdx && !is_placeholder(tokens[providerIdx]))
        json_add_string(ctx->event, "Provider", tokens[providerIdx]);
    if (tokenCount > eventTypeIdx && !is_placeholder(tokens[eventTypeIdx]))
        json_add_string(ctx->event, "EventType", tokens[eventTypeIdx]);
    // Add Channel field - for Windows security events, this is typically "Security"
    json_add_string(ctx->event, "Channel", "Security");
    if (tokenCount > computerIdx && !is_placeholder(tokens[computerIdx]))
        json_add_string(ctx->event, "Computer", tokens[computerIdx]);
    if (tokenCount > categoryTextIdx && !is_placeholder(tokens[categoryTextIdx]))
        json_add_string(ctx->event, "CategoryText", tokens[categoryTextIdx]);
    {
        const char *normalized = getTimeReported(ctx->msg, tplFmtRFC3339Date);
        if (normalized != NULL && *normalized != '\0') {
            struct json_object *timeObj = ensure_object(ctx->event, "TimeCreated");
            if (timeObj != NULL) json_add_string(timeObj, "Normalized", normalized);
        }
    }
    const char *auditResult = NULL;
    if (tokenCount > eventTypeIdx && !is_placeholder(tokens[eventTypeIdx])) auditResult = tokens[eventTypeIdx];
    apply_event_mapping(ctx, auditResult);
}

/**
 * @brief Parse a traditional tab-delimited Snare payload.
 *
 * The payload is provided as an array of tokens split on tab characters. The
 * function builds the JSON representation, processes the message description,
 * and attaches the resulting JSON document to the message.
 *
 * @param pData       Module instance configuration.
 * @param pMsg        Message currently being processed.
 * @param rawMsg      Pointer to the raw payload text for debugging and optional
 *                    emission.
 * @param tokens      Array of tab-delimited tokens.
 * @param tokenCount  Number of valid entries in @p tokens.
 * @return ::RS_RET_OK on success or an error code on allocation failures.
 */
static rsRetVal parse_snare_text(
    instanceData *pData, smsg_t *pMsg, const char *rawMsg, char **tokens, size_t tokenCount) {
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.inst = pData;
    ctx.msg = pMsg;
    ctx.corePatterns = pData->corePatterns;
    ctx.corePatternCount = pData->corePatternCount;
    ctx.eventPatterns = NULL;
    ctx.eventPatternCount = 0;
    ctx.patternEventId = -1;
    ctx.patternsPrepared = 0;
    ctx.validation = &pData->validationCtx;
    ctx.detection.validation = ctx.validation;
    ctx.detection.error_array = NULL;
    ctx.detection.stats_object = NULL;
    ctx.detection.parsing_errors = 0;
    ctx.detection.total_fields = 0;
    ctx.detection.successful_parses = 0;
    ctx.detection.enable_debug = (ctx.validation != NULL && ctx.validation->enable_debug);
    ctx.validationErrors = NULL;
    ctx.parsingStats = NULL;
    ctx.validation = &pData->validationCtx;
    ctx.detection.validation = ctx.validation;
    ctx.detection.error_array = NULL;
    ctx.detection.stats_object = NULL;
    ctx.detection.parsing_errors = 0;
    ctx.detection.total_fields = 0;
    ctx.detection.successful_parses = 0;
    ctx.detection.enable_debug = (ctx.validation != NULL && ctx.validation->enable_debug);
    ctx.root = json_object_new_object();
    if (ctx.root == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to create root JSON object");
        return RS_RET_OUT_OF_MEMORY;
    }
    ctx.event = json_object_new_object();
    if (ctx.event == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to create event JSON object");
        json_object_put(ctx.root);
        return RS_RET_OUT_OF_MEMORY;
    }
    json_object_object_add(ctx.root, "Event", ctx.event);

    struct json_object *validationObj = ensure_object(ctx.root, "Validation");
    if (validationObj != NULL) {
        ctx.validationErrors = json_object_new_array();
        if (ctx.validationErrors != NULL) {
            json_object_object_add(validationObj, "Errors", ctx.validationErrors);
            ctx.detection.error_array = ctx.validationErrors;
        }
    }
    struct json_object *statsObj = ensure_object(ctx.root, "Stats");
    if (statsObj != NULL) {
        ctx.parsingStats = json_object_new_object();
        if (ctx.parsingStats != NULL) {
            json_object_object_add(statsObj, "ParsingStats", ctx.parsingStats);
            ctx.detection.stats_object = ctx.parsingStats;
        }
    }

    dbgprintf("[mmsnarewinsec DEBUG] Processing SNARE text message with %zu tokens\n", tokenCount);
    if (rawMsg != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] Raw message: %s\n", rawMsg);
    }

    if (pData->emitRawPayload && rawMsg != NULL) json_add_string(ctx.root, "Raw", rawMsg);
    if (ctx.validation != NULL) {
        static const char *required_tokens[] = {"MSWinEventLog", "Security"};
        if (validate_field_count(rawMsg, tokenCount, 12, ctx.validation) != RS_RET_OK)
            handle_parsing_error(&ctx.detection, "insufficient header tokens", "header");
        if (validate_required_fields(rawMsg, required_tokens, ARRAY_SIZE(required_tokens), ctx.validation) !=
            RS_RET_OK)
            handle_parsing_error(&ctx.detection, "missing required header tokens", "header");
    }
    populate_event_metadata(&ctx, tokens, tokenCount);

    // Determine the correct description index based on message format
    size_t descriptionIdx;
    if (tokenCount > 0 && !is_placeholder(tokens[0]) && strcmp(tokens[0], "MSWinEventLog") == 0) {
        // RFC5424 format
        descriptionIdx = 13;
    } else {
        // RFC3164 format
        descriptionIdx = 9;
    }

    if (tokenCount > descriptionIdx && !is_placeholder(tokens[descriptionIdx])) {
        dbgprintf("[mmsnarewinsec DEBUG] parse_snare_text: calling parse_description with tokens[%zu]='%s'\n",
                  descriptionIdx, tokens[descriptionIdx]);
        parse_description(&ctx, tokens[descriptionIdx]);
    } else {
        dbgprintf(
            "[mmsnarewinsec DEBUG] parse_snare_text: not calling parse_description (tokenCount=%zu, "
            "tokens[%zu]='%s')\n",
            tokenCount, descriptionIdx, tokenCount > descriptionIdx ? tokens[descriptionIdx] : "N/A");
    }
    if (ctx.unparsed == NULL && pData->emitDebugJson) ctx.unparsed = json_object_new_array();
    if (ctx.detection.stats_object != NULL) {
        json_add_int64(ctx.detection.stats_object, "total_fields", (long long)ctx.detection.total_fields);
        json_add_int64(ctx.detection.stats_object, "successful_parses", (long long)ctx.detection.successful_parses);
        json_add_int64(ctx.detection.stats_object, "errors", (long long)ctx.detection.parsing_errors);
    }
    if (ctx.validationErrors == NULL && validationObj != NULL && pData->emitDebugJson) {
        ctx.validationErrors = json_object_new_array();
        if (ctx.validationErrors != NULL) {
            json_object_object_add(validationObj, "Errors", ctx.validationErrors);
            ctx.detection.error_array = ctx.validationErrors;
        }
    }

    const char *json_str = json_object_to_json_string_ext(ctx.root, JSON_C_TO_STRING_PRETTY);
    if (json_str != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] Final parsed JSON:\n%s\n", json_str);
    }
    msgAddJSON(pMsg, pData->container, ctx.root, 0, 0);
    return RS_RET_OK;
}

/**
 * @brief Ingest EventData content from a JSON Snare payload.
 *
 * @param ctx       Active parsing context.
 * @param eventData Parsed JSON object containing EventData members.
 */
static void parse_json_event_data(parse_context_t *ctx, struct json_object *eventData) {
    struct json_object_iterator it = json_object_iter_begin(eventData);
    struct json_object_iterator itEnd = json_object_iter_end(eventData);
    while (!json_object_iter_equal(&it, &itEnd)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *valObj = json_object_iter_peek_value(&it);
        if (key != NULL && valObj != NULL) {
            if (json_object_is_type(valObj, json_type_string)) {
                handle_general_key(ctx, key, json_object_get_string(valObj));
            } else if (json_object_is_type(valObj, json_type_int)) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%lld", (long long)json_object_get_int64(valObj));
                handle_general_key(ctx, key, buf);
            } else if (json_object_is_type(valObj, json_type_boolean)) {
                handle_general_key(ctx, key, json_object_get_boolean(valObj) ? "true" : "false");
            } else if (json_object_is_type(valObj, json_type_double)) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%f", json_object_get_double(valObj));
                handle_general_key(ctx, key, buf);
            }
        }
        json_object_iter_next(&it);
    }
}

/**
 * @brief Parse a Snare payload delivered as a JSON document.
 *
 * @param pData       Module instance configuration.
 * @param pMsg        Message currently being processed.
 * @param jsonPayload JSON string to parse.
 * @return ::RS_RET_OK on success or a negative error value.
 */
static rsRetVal parse_snare_json(instanceData *pData, smsg_t *pMsg, const char *jsonPayload) {
    parse_context_t ctx;
    struct json_tokener *tokener;
    struct json_object *payload;
    struct json_object *value;
    memset(&ctx, 0, sizeof(ctx));
    ctx.inst = pData;
    ctx.msg = pMsg;
    ctx.corePatterns = pData->corePatterns;
    ctx.corePatternCount = pData->corePatternCount;
    ctx.eventPatterns = NULL;
    ctx.eventPatternCount = 0;
    ctx.patternEventId = -1;
    ctx.patternsPrepared = 0;
    ctx.root = json_object_new_object();
    if (ctx.root == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to create root JSON object");
        return RS_RET_OUT_OF_MEMORY;
    }
    ctx.event = json_object_new_object();
    if (ctx.event == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to create event JSON object");
        json_object_put(ctx.root);
        return RS_RET_OUT_OF_MEMORY;
    }
    json_object_object_add(ctx.root, "Event", ctx.event);

    struct json_object *validationObj = ensure_object(ctx.root, "Validation");
    if (validationObj != NULL) {
        ctx.validationErrors = json_object_new_array();
        if (ctx.validationErrors != NULL) {
            json_object_object_add(validationObj, "Errors", ctx.validationErrors);
            ctx.detection.error_array = ctx.validationErrors;
        }
    }
    struct json_object *statsObj = ensure_object(ctx.root, "Stats");
    if (statsObj != NULL) {
        ctx.parsingStats = json_object_new_object();
        if (ctx.parsingStats != NULL) {
            json_object_object_add(statsObj, "ParsingStats", ctx.parsingStats);
            ctx.detection.stats_object = ctx.parsingStats;
        }
    }

    dbgprintf("[mmsnarewinsec DEBUG] Processing SNARE JSON message\n");
    dbgprintf("[mmsnarewinsec DEBUG] JSON payload: %s\n", jsonPayload);

    tokener = json_tokener_new();
    if (tokener == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to create JSON tokener");
        json_object_put(ctx.root);
        return RS_RET_OUT_OF_MEMORY;
    }
    payload = json_tokener_parse_ex(tokener, jsonPayload, (int)strlen(jsonPayload));
    if (payload == NULL) {
        LogError(0, RS_RET_COULD_NOT_PARSE, "mmsnarewinsec: failed to parse JSON payload: %s", jsonPayload);
        dbgprintf("[mmsnarewinsec DEBUG] Failed to parse JSON payload\n");
        json_tokener_free(tokener);
        json_add_string(ctx.root, "RawJSON", jsonPayload);
        msgAddJSON(pMsg, pData->container, ctx.root, 0, 0);
        return RS_RET_OK;
    }

    const char *json_str = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PRETTY);
    if (json_str != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] Parsed JSON payload:\n%s\n", json_str);
    }

    if (pData->emitRawPayload) json_object_object_add(ctx.root, "RawJSON", json_object_get(payload));
    if (json_object_object_get_ex(payload, "EventID", &value)) {
        long long eid = json_object_get_int64(value);
        json_add_int64(ctx.event, "EventID", eid);
        ctx.eventId = (int)eid;
    }
    if (json_object_object_get_ex(payload, "Channel", &value) && json_object_is_type(value, json_type_string))
        json_add_string(ctx.event, "Channel", json_object_get_string(value));
    if (json_object_object_get_ex(payload, "Provider", &value) && json_object_is_type(value, json_type_string))
        json_add_string(ctx.event, "Provider", json_object_get_string(value));
    if (json_object_object_get_ex(payload, "EventTime", &value) && json_object_is_type(value, json_type_string)) {
        struct json_object *timeObj = ensure_object(ctx.event, "TimeCreated");
        if (timeObj != NULL) json_add_string(timeObj, "Raw", json_object_get_string(value));
    }
    if (json_object_object_get_ex(payload, "Message", &value) && json_object_is_type(value, json_type_string)) {
        json_add_string(ctx.root, "Summary", json_object_get_string(value));
        ctx.summarySet = 1;
    }
    if (json_object_object_get_ex(payload, "EventData", &value) && json_object_is_type(value, json_type_object))
        parse_json_event_data(&ctx, value);
    if (json_object_object_get_ex(payload, "System", &value) && json_object_is_type(value, json_type_object)) {
        struct json_object *systemObj = value;
        struct json_object *inner;
        if (json_object_object_get_ex(systemObj, "EventRecordID", &inner) &&
            json_object_is_type(inner, json_type_string))
            json_add_string(ctx.event, "RecordNumberRaw", json_object_get_string(inner));
        if (json_object_object_get_ex(systemObj, "Level", &inner) && json_object_is_type(inner, json_type_int))
            json_add_int64(ctx.event, "Level", json_object_get_int64(inner));
        if (json_object_object_get_ex(systemObj, "Computer", &inner) && json_object_is_type(inner, json_type_string))
            json_add_string(ctx.event, "Computer", json_object_get_string(inner));
    }
    apply_event_mapping(&ctx, NULL);

    if (ctx.detection.stats_object != NULL) {
        json_add_int64(ctx.detection.stats_object, "total_fields", (long long)ctx.detection.total_fields);
        json_add_int64(ctx.detection.stats_object, "successful_parses", (long long)ctx.detection.successful_parses);
        json_add_int64(ctx.detection.stats_object, "errors", (long long)ctx.detection.parsing_errors);
    }
    if (ctx.validationErrors == NULL && validationObj != NULL && pData->emitDebugJson) {
        ctx.validationErrors = json_object_new_array();
        if (ctx.validationErrors != NULL) {
            json_object_object_add(validationObj, "Errors", ctx.validationErrors);
            ctx.detection.error_array = ctx.validationErrors;
        }
    }

    const char *json_str2 = json_object_to_json_string_ext(ctx.root, JSON_C_TO_STRING_PRETTY);
    if (json_str2 != NULL) {
        dbgprintf("[mmsnarewinsec DEBUG] Final parsed JSON:\n%s\n", json_str2);
    }

    json_tokener_free(tokener);
    msgAddJSON(pMsg, pData->container, ctx.root, 0, 0);
    json_object_put(payload);
    return RS_RET_OK;
}

/**
 * @brief Detect the payload type, parse it, and attach JSON metadata.
 *
 * This is the main entry point for each message processed by the action. It
 * locates the Snare payload, determines whether the content is text or JSON,
 * and invokes the appropriate parser.
 *
 * @param pData   Module instance configuration.
 * @param pMsg    Message currently being processed.
 * @param msgText Raw text buffer owned by the message.
 * @return ::RS_RET_OK when parsing succeeds or ::RS_RET_COULD_NOT_PARSE when
 *         no Snare payload could be located.
 */
static rsRetVal process_message(instanceData *pData, smsg_t *pMsg, uchar *msgText) {
    rsRetVal iRet = RS_RET_COULD_NOT_PARSE;
    char *mutableMsg;
    char *cursor;
    char *tokens[32];
    size_t tokenCount = 0;
    const char *rawMsg;
    const char *payloadStart;
    if (msgText == NULL) return RS_RET_COULD_NOT_PARSE;
    payloadStart = locate_snare_payload((const char *)msgText);
    if (payloadStart == NULL) return RS_RET_COULD_NOT_PARSE;
    rawMsg = payloadStart;
    mutableMsg = strdup(payloadStart);
    if (mutableMsg == NULL) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to duplicate message text");
        return RS_RET_OUT_OF_MEMORY;
    }
    unescape_hash_sequences(mutableMsg);
    dbgprintf("[mmsnarewinsec DEBUG] After unescaping: '%s'\n", mutableMsg);
    cursor = mutableMsg;
    while (cursor != NULL && tokenCount < ARRAY_SIZE(tokens)) {
        tokens[tokenCount++] = cursor;
        char *tab = strchr(cursor, '\t');
        if (tab == NULL) break;
        *tab = '\0';
        cursor = tab + 1;
    }

    dbgprintf("[mmsnarewinsec DEBUG] Processing message with %zu tokens\n", tokenCount);
    dbgprintf("[mmsnarewinsec DEBUG] Message type: %s\n",
              (tokenCount >= 3 && !strcmp(tokens[1], "0") && tokens[2][0] == '{') ? "JSON" : "Text");

    // Debug: Print first few tokens
    for (size_t i = 0; i < tokenCount && i < 5; i++) {
        dbgprintf("[mmsnarewinsec DEBUG] Token %zu: '%s'\n", i, tokens[i]);
    }

    if (tokenCount >= 3 && !strcmp(tokens[1], "0") && tokens[2][0] == '{') {
        iRet = parse_snare_json(pData, pMsg, tokens[2]);
    } else if (tokenCount >= 2) {
        iRet = parse_snare_text(pData, pMsg, rawMsg, tokens, tokenCount);
    }
    free(mutableMsg);
    return iRet;
}

DEF_OMOD_STATIC_DATA;

static struct cnfparamdescr modpdescr[] = {{"definition.file", eCmdHdlrString, 0},
                                           {"definition.json", eCmdHdlrString, 0},
                                           {"runtime.config", eCmdHdlrString, 0},
                                           {"validation.mode", eCmdHdlrString, 0}};
static struct cnfparamblk modpblk = {CNFPARAMBLK_VERSION, ARRAY_SIZE(modpdescr), modpdescr};

static struct cnfparamdescr actpdescr[] = {
    {"container", eCmdHdlrString, 0},     {"enable.network", eCmdHdlrBinary, 0},
    {"enable.laps", eCmdHdlrBinary, 0},   {"enable.tls", eCmdHdlrBinary, 0},
    {"enable.wdac", eCmdHdlrBinary, 0},   {"emit.rawpayload", eCmdHdlrBinary, 0},
    {"emit.debugjson", eCmdHdlrBinary, 0}, {"definition.file", eCmdHdlrString, 0},
    {"definition.json", eCmdHdlrString, 0}, {"runtime.config", eCmdHdlrString, 0},
    {"validation.mode", eCmdHdlrString, 0}};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, ARRAY_SIZE(actpdescr), actpdescr};

BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
    free(pModConf->definitionFile);
    pModConf->definitionFile = NULL;
    free(pModConf->definitionJson);
    pModConf->definitionJson = NULL;
    pModConf->validationMode = VALIDATION_MODERATE;
    free(pModConf->runtimeConfigFile);
    pModConf->runtimeConfigFile = NULL;
ENDbeginCnfLoad

BEGINsetModCnf
    struct cnfparamvals *pvals = NULL;
    int i;
    CODESTARTsetModCnf;
    pvals = nvlstGetParams(lst, &modpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "mmsnarewinsec: error processing module config parameters [module(...)]");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    if (Debug) {
        dbgprintf("module (global) param blk for mmsnarewinsec:\n");
        cnfparamsPrint(&modpblk, pvals);
    }
    for (i = 0; i < (int)modpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(modpblk.descr[i].name, "definition.file")) {
            char *value = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (value == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            free(loadModConf->definitionFile);
            loadModConf->definitionFile = value;
        } else if (!strcmp(modpblk.descr[i].name, "definition.json")) {
            char *value = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (value == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            free(loadModConf->definitionJson);
            loadModConf->definitionJson = value;
        } else if (!strcmp(modpblk.descr[i].name, "runtime.config")) {
            char *value = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (value == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            free(loadModConf->runtimeConfigFile);
            loadModConf->runtimeConfigFile = value;
        } else if (!strcmp(modpblk.descr[i].name, "validation.mode")) {
            char *mode = es_str2cstr(pvals[i].val.d.estr, NULL);
            rsRetVal r;
            if (mode == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            r = parse_validation_mode(mode, &loadModConf->validationMode);
            free(mode);
            if (r != RS_RET_OK) {
                ABORT_FINALIZE(r);
            }
        } else {
            dbgprintf("mmsnarewinsec: unhandled module parameter '%s'\n", modpblk.descr[i].name);
        }
    }
finalize_it:
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

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
    if (pModConf != NULL) {
        free(pModConf->definitionFile);
        pModConf->definitionFile = NULL;
        free(pModConf->definitionJson);
        pModConf->definitionJson = NULL;
        free(pModConf->runtimeConfigFile);
        pModConf->runtimeConfigFile = NULL;
    }
ENDfreeCnf

BEGINcreateInstance
    CODESTARTcreateInstance;
ENDcreateInstance

BEGINcreateWrkrInstance
    CODESTARTcreateWrkrInstance;
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
ENDisCompatibleWithFeature

BEGINfreeInstance
    CODESTARTfreeInstance;
    free(pData->container);
    free_runtime_config(&pData->runtimeConfig);
    free_runtime_tables(pData);
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
ENDfreeWrkrInstance

/**
 * @brief Populate default configuration values for a new instance.
 */
static inline void setInstParamDefaults(instanceData *pData) {
    pData->container = NULL;
    pData->enableNetwork = 1;
    pData->enableLaps = 1;
    pData->enableTls = 1;
    pData->enableWdac = 1;
    pData->emitRawPayload = 1;
    pData->emitDebugJson = 0;
    memset(&pData->runtimeConfig, 0, sizeof(pData->runtimeConfig));
    pData->runtimeConfig.enable_fallback = true;
    pData->validationCtx.mode = VALIDATION_MODERATE;
    pData->validationCtx.enable_debug = 0;
    pData->validationCtx.log_parsing_errors = 1;
    pData->validationCtx.continue_on_error = 1;
    pData->validationCtx.max_errors_before_fail = MAX_PARSING_ERRORS;
    pData->validationCtx.current_error_count = 0;
    pData->sectionDescriptors = NULL;
    pData->sectionDescriptorCount = 0;
    pData->corePatterns = NULL;
    pData->corePatternCount = 0;
    pData->eventFieldMappings = NULL;
    pData->eventFieldMappingCount = 0;
    pData->eventMappings = NULL;
    pData->eventMappingCount = 0;
}

BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    char *definitionFile = NULL;
    char *definitionJson = NULL;
    char *runtimeConfigFile = NULL;
    bool runtimeEnableDebug = false;
    bool runtimeEnableFallback = true;
    CODESTARTnewActInst;
    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "mmsnarewinsec: missing configuration parameters");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    CODE_STD_STRING_REQUESTnewActInst(1);
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
    CHKiRet(createInstance(&pData));
    setInstParamDefaults(pData);
    if (loadModConf != NULL) {
        pData->validationCtx.mode = loadModConf->validationMode;
    }
    for (i = 0; i < (int)actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(actpblk.descr[i].name, "container")) {
            free(pData->container);
            pData->container = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
            if (pData->container != NULL && pData->container[0] == '$')
                memmove(pData->container, pData->container + 1, strlen((char *)pData->container));
        } else if (!strcmp(actpblk.descr[i].name, "enable.network")) {
            pData->enableNetwork = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "enable.laps")) {
            pData->enableLaps = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "enable.tls")) {
            pData->enableTls = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "enable.wdac")) {
            pData->enableWdac = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "emit.rawpayload")) {
            pData->emitRawPayload = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "emit.debugjson")) {
            pData->emitDebugJson = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "definition.file")) {
            free(definitionFile);
            definitionFile = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "definition.json")) {
            free(definitionJson);
            definitionJson = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "runtime.config")) {
            free(runtimeConfigFile);
            runtimeConfigFile = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "validation.mode")) {
            char *mode = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (mode == NULL) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            CHKiRet(set_validation_mode(pData, mode));
            free(mode);
        }
    }
    if (pData->container == NULL) {
        CHKmalloc(pData->container = (uchar *)strdup(MMSNAREWINSEC_CONTAINER_DEFAULT));
        if (pData->container == NULL) {
            LogError(0, RS_RET_OUT_OF_MEMORY, "mmsnarewinsec: failed to allocate default container name");
        }
    }
    CHKiRet(initialize_runtime_tables(pData));
    if (loadModConf != NULL) {
        if (loadModConf->definitionFile != NULL) {
            CHKiRet(load_custom_definition_file(pData, loadModConf->definitionFile));
        }
        if (loadModConf->definitionJson != NULL) {
            CHKiRet(load_custom_definition_text(pData, loadModConf->definitionJson, "module definition.json"));
        }
        if (loadModConf->runtimeConfigFile != NULL) {
            CHKiRet(load_configuration(&pData->runtimeConfig, loadModConf->runtimeConfigFile));
            runtimeEnableDebug = runtimeEnableDebug || pData->runtimeConfig.enable_debug;
            runtimeEnableFallback = runtimeEnableFallback && pData->runtimeConfig.enable_fallback;
            CHKiRet(apply_runtime_configuration(pData));
        }
    }
    if (definitionFile != NULL) {
        CHKiRet(load_custom_definition_file(pData, definitionFile));
    }
    if (definitionJson != NULL) {
        CHKiRet(load_custom_definition_text(pData, definitionJson, "inline definitions"));
    }
    if (runtimeConfigFile != NULL) {
        CHKiRet(load_configuration(&pData->runtimeConfig, runtimeConfigFile));
        runtimeEnableDebug = runtimeEnableDebug || pData->runtimeConfig.enable_debug;
        runtimeEnableFallback = runtimeEnableFallback && pData->runtimeConfig.enable_fallback;
        CHKiRet(apply_runtime_configuration(pData));
    }
    pData->runtimeConfig.enable_debug = runtimeEnableDebug;
    pData->runtimeConfig.enable_fallback = runtimeEnableFallback;
    if (pData->emitDebugJson) pData->validationCtx.enable_debug = 1;
    if (runtimeEnableDebug) pData->validationCtx.enable_debug = 1;
    if (!runtimeEnableFallback && pData->validationCtx.mode == VALIDATION_PERMISSIVE)
        pData->validationCtx.continue_on_error = 0;
    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
    free(definitionFile);
    free(definitionJson);
    free(runtimeConfigFile);
ENDnewActInst

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

BEGINdoAction_NoStrings
    smsg_t **ppMsg = (smsg_t **)pMsgData;
    smsg_t *pMsg = ppMsg[0];
    uchar *msgTxt;
    CODESTARTdoAction;
    msgTxt = getMSG(pMsg);
    iRet = process_message(pWrkrData->pData, pMsg, msgTxt);
    if (iRet == RS_RET_OK) {
        MsgSetParseSuccess(pMsg, 1);
    } else if (iRet == RS_RET_COULD_NOT_PARSE) {
        iRet = RS_RET_OK;
    }
ENDdoAction

NO_LEGACY_CONF_parseSelectorAct

    BEGINmodExit CODESTARTmodExit;
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CODEmodInit_QueryRegCFSLineHdlr
ENDmodInit
