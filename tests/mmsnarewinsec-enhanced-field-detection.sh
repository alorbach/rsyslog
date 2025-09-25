#!/bin/bash
# Test enhanced field detection capabilities for mmsnarewinsec module
# Based on comprehensive dataset with 439 events across 12 categories

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

# Test enhanced field detection with pattern-based matching
template(name="enhanced_json" type="list" option.jsonf="on") {
    # Test all field categories from the comprehensive dataset
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="subject_securityid" name="$!win!Subject!SecurityID" format="jsonf")
    property(outname="subject_accountname" name="$!win!Subject!AccountName" format="jsonf")
    property(outname="subject_accountdomain" name="$!win!Subject!AccountDomain" format="jsonf")
    property(outname="subject_logonid" name="$!win!Subject!LogonID" format="jsonf")
    property(outname="logon_type" name="$!win!Logon!LogonType" format="jsonf")
    property(outname="logon_restrictedadmin" name="$!win!Logon!RestrictedAdminMode" format="jsonf")
    property(outname="logon_virtualaccount" name="$!win!Logon!VirtualAccount" format="jsonf")
    property(outname="logon_elevatedtoken" name="$!win!Logon!ElevatedToken" format="jsonf")
    property(outname="logon_impersonationlevel" name="$!win!Logon!ImpersonationLevel" format="jsonf")
    property(outname="newlogon_securityid" name="$!win!NewLogon!SecurityID" format="jsonf")
    property(outname="newlogon_accountname" name="$!win!NewLogon!AccountName" format="jsonf")
    property(outname="newlogon_accountdomain" name="$!win!NewLogon!AccountDomain" format="jsonf")
    property(outname="newlogon_logonid" name="$!win!NewLogon!LogonID" format="jsonf")
    property(outname="newlogon_logonguid" name="$!win!NewLogon!LogonGUID" format="jsonf")
    property(outname="network_workstationname" name="$!win!Network!WorkstationName" format="jsonf")
    property(outname="network_sourceaddress" name="$!win!Network!SourceAddress" format="jsonf")
    property(outname="network_sourceport" name="$!win!Network!SourcePort" format="jsonf")
    property(outname="network_clientaddress" name="$!win!Network!ClientAddress" format="jsonf")
    property(outname="network_clientport" name="$!win!Network!ClientPort" format="jsonf")
    property(outname="process_processid" name="$!win!Process!ProcessID" format="jsonf")
    property(outname="process_processname" name="$!win!Process!ProcessName" format="jsonf")
    property(outname="process_commandline" name="$!win!Process!CommandLine" format="jsonf")
    property(outname="process_tokenelevationtype" name="$!win!Process!TokenElevationType" format="jsonf")
    property(outname="process_mandatorylabel" name="$!win!Process!MandatoryLabel" format="jsonf")
    property(outname="authentication_logonprocess" name="$!win!Authentication!LogonProcess" format="jsonf")
    property(outname="authentication_package" name="$!win!Authentication!AuthenticationPackage" format="jsonf")
    property(outname="authentication_transitedservices" name="$!win!Authentication!TransitedServices" format="jsonf")
    property(outname="authentication_keylength" name="$!win!Authentication!KeyLength" format="jsonf")
    property(outname="authentication_remotecredguard" name="$!win!Authentication!RemoteCredentialGuard" format="jsonf")
    property(outname="failure_reason" name="$!win!Failure!FailureReason" format="jsonf")
    property(outname="failure_status" name="$!win!Failure!Status" format="jsonf")
    property(outname="failure_substatus" name="$!win!Failure!SubStatus" format="jsonf")
    property(outname="wdac_policyname" name="$!win!WDAC!PolicyName" format="jsonf")
    property(outname="wdac_policyversion" name="$!win!WDAC!PolicyVersion" format="jsonf")
    property(outname="wdac_enforcementmode" name="$!win!WDAC!EnforcementMode" format="jsonf")
    property(outname="wdac_user" name="$!win!WDAC!User" format="jsonf")
    property(outname="wdac_pid" name="$!win!WDAC!ProcessID" format="jsonf")
    property(outname="wufb_policyid" name="$!win!WUFB!PolicyID" format="jsonf")
    property(outname="wufb_ring" name="$!win!WUFB!Ring" format="jsonf")
    property(outname="wufb_fromservice" name="$!win!WUFB!FromService" format="jsonf")
    property(outname="wufb_enforcementresult" name="$!win!WUFB!EnforcementResult" format="jsonf")
    property(outname="kerberos_servicename" name="$!win!Kerberos!ServiceName" format="jsonf")
    property(outname="kerberos_serviceid" name="$!win!Kerberos!ServiceID" format="jsonf")
    property(outname="kerberos_ticketoptions" name="$!win!Kerberos!TicketOptions" format="jsonf")
    property(outname="kerberos_resultcode" name="$!win!Kerberos!ResultCode" format="jsonf")
    property(outname="kerberos_ticketencryptiontype" name="$!win!Kerberos!TicketEncryptionType" format="jsonf")
    property(outname="kerberos_preauthtype" name="$!win!Kerberos!PreAuthenticationType" format="jsonf")
    property(outname="kerberos_certificateinfo" name="$!win!Kerberos!CertificateInfo" format="jsonf")
    property(outname="laps_policyversion" name="$!win!LAPS!PolicyVersion" format="jsonf")
    property(outname="laps_credentialrotation" name="$!win!LAPS!CredentialRotation" format="jsonf")
    property(outname="tls_reason" name="$!win!TLS!Reason" format="jsonf")
    property(outname="tls_policy" name="$!win!TLS!Policy" format="jsonf")
    property(outname="filter_runtimeid" name="$!win!Filter!FilterRuntimeID" format="jsonf")
    property(outname="filter_layername" name="$!win!Filter!LayerName" format="jsonf")
    property(outname="filter_layerruntimeid" name="$!win!Filter!LayerRuntimeID" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="enhanced_json")
'

# Test with comprehensive dataset from Logon_Logoff category
startup
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4627\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tGroup Membership\t\tGroup membership information. Subject: Security ID: CLOUDDOMAIN\\User009 Account Name: User009 Account Domain: CLOUDDOMAIN Logon ID: 0x7A202 Logon Type: 2 New Logon:    Security ID: HOST-004\\admin Account Name: admin Account Domain: HOST-004 Logon ID: 0x1D80AF1 Event in sequence: 1 of 1 Group Membership: HOST-004\\None Everyone NT AUTHORITY\\Local account and member of admins   group BUILTIN\\admins BUILTIN\\Users NT AUTHORITY\\INTERACTIVE CONSOLE LOGON NT AUTHORITY\\Authenticated Users NT AUTHORITY\\This Organization NT AUTHORITY\\Authenticated Users3 LOCAL NT AUTHORITY\\NTLM Authentication Mandatory Label\\High Mandatory Level\t1\""
shutdown_when_empty
wait_shutdown

# Validate enhanced field extraction
content_check '{"eventid":4627,"subject_securityid":"CLOUDDOMAIN\\User009","subject_accountname":"User009","subject_accountdomain":"CLOUDDOMAIN","subject_logonid":"0x7A202","logon_type":2}'
exit_test