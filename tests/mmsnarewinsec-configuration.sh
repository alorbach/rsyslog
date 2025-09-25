#!/bin/bash
# Test runtime configuration and custom field mappings

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="config_test_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="custom_fields" name="$!win!Custom" format="jsonf")
    property(outname="aliased_fields" name="$!win!Aliased" format="jsonf")
    property(outname="enhanced_subject" name="$!win!Subject" format="jsonf")
    property(outname="enhanced_logon" name="$!win!Logon" format="jsonf")
    property(outname="enhanced_network" name="$!win!Network" format="jsonf")
    property(outname="enhanced_process" name="$!win!Process" format="jsonf")
    property(outname="enhanced_authentication" name="$!win!Authentication" format="jsonf")
    property(outname="enhanced_failure" name="$!win!Failure" format="jsonf")
    property(outname="enhanced_wdac" name="$!win!WDAC" format="jsonf")
    property(outname="enhanced_wufb" name="$!win!WUFB" format="jsonf")
    property(outname="enhanced_kerberos" name="$!win!Kerberos" format="jsonf")
    property(outname="enhanced_laps" name="$!win!LAPS" format="jsonf")
    property(outname="enhanced_tls" name="$!win!TLS" format="jsonf")
    property(outname="enhanced_filter" name="$!win!Filter" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="config_test_json")
'

# Test configuration-driven field mapping
startup
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tLogon\t\tAn account was successfully logged on. Subject: Security ID: SYSTEM Account Name: HOST-007\$ Account Domain: WORKGROUP Logon ID: 0x3E7 Logon Information: Logon Type: 7 Restricted Admin Mode: - Remote Credential Guard: - Virtual Account: No Elevated Token: No Impersonation Level: Impersonation New Logon: Security ID: CLOUDDOMAIN\\User009 Account Name: user010@example.com Account Domain: CLOUDDOMAIN Logon ID: 0xFD5113F Linked Logon ID: 0xFD5112A Network Account Name: - Network Account Domain: - Logon GUID: {00000000-0000-0000-0000-000000000000} Process Information: Process ID: 0x30c Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Workstation Name: HOST-007 Source Network Address: - Source Port: - Detailed Authentication Information: Logon Process: Negotiat Authentication Package: Negotiate Transited Services: - Package Name (NTLM only): - Key Length: 0\t1\""
shutdown_when_empty
wait_shutdown

# Validate configuration-driven field mapping
content_check '{"eventid":4624,"enhanced_subject":{"SecurityID":"SYSTEM","AccountName":"HOST-007$","AccountDomain":"WORKGROUP","LogonID":"0x3E7"}}'
content_check '{"eventid":4624,"enhanced_logon":{"LogonType":7,"RestrictedAdminMode":"-","VirtualAccount":"No","ElevatedToken":"No","ImpersonationLevel":"Impersonation"}}'
content_check '{"eventid":4624,"enhanced_network":{"WorkstationName":"HOST-007","SourceAddress":"-","SourcePort":"-"}}'
content_check '{"eventid":4624,"enhanced_process":{"ProcessID":"0x30c","ProcessName":"C:\\Windows\\System32\\lsass.exe"}}'
content_check '{"eventid":4624,"enhanced_authentication":{"LogonProcess":"Negotiat","AuthenticationPackage":"Negotiate","TransitedServices":"-","KeyLength":0}}'
exit_test