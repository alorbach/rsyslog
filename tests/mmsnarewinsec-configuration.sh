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

# Test configuration-driven field mapping with sample data
startup
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Logon_Logoff.data
shutdown_when_empty
wait_shutdown

# Validate configuration-driven field mapping
content_check '{"eventid":4624,"enhanced_subject":{"SecurityID":"SYSTEM","AccountName":"HOST-007$","AccountDomain":"WORKGROUP","LogonID":"0x3E7"}}'
content_check '{"eventid":4624,"enhanced_logon":{"LogonType":7,"RestrictedAdminMode":"-","VirtualAccount":"No","ElevatedToken":"No","ImpersonationLevel":"Impersonation"}}'
content_check '{"eventid":4624,"enhanced_network":{"WorkstationName":"HOST-007","SourceAddress":"-","SourcePort":"-"}}'
content_check '{"eventid":4624,"enhanced_process":{"ProcessID":"0x30c","ProcessName":"C:\\Windows\\System32\\lsass.exe"}}'
content_check '{"eventid":4624,"enhanced_authentication":{"LogonProcess":"Negotiat","AuthenticationPackage":"Negotiate","TransitedServices":"-","KeyLength":0}}'
exit_test