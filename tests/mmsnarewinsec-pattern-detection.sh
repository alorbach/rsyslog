#!/bin/bash
# Test pattern-based field detection with various field formats

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="pattern_test_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="subject_fields" name="$!win!Subject" format="jsonf")
    property(outname="logon_fields" name="$!win!Logon" format="jsonf")
    property(outname="network_fields" name="$!win!Network" format="jsonf")
    property(outname="process_fields" name="$!win!Process" format="jsonf")
    property(outname="authentication_fields" name="$!win!Authentication" format="jsonf")
    property(outname="kerberos_fields" name="$!win!Kerberos" format="jsonf")
    property(outname="laps_fields" name="$!win!LAPS" format="jsonf")
    property(outname="tls_fields" name="$!win!TLS" format="jsonf")
    property(outname="filter_fields" name="$!win!Filter" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="pattern_test_json")
'

# Test with various field patterns from the comprehensive dataset
startup
# Test with multiple data files to cover different event types and patterns
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Logon_Logoff.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Account_Management.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/System.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Object_Access.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Process_Tracking.data
shutdown_when_empty
wait_shutdown

# Validate pattern-based field extraction for various event types
content_check '{"eventid":4650,"network_fields":{"LocalEndpoint":"jsmith@srv1.dmn","RemoteEndpoint":"DMN/SRV2$"}}'
content_check '{"eventid":4624,"subject":{"SecurityID":"SYSTEM","AccountName":"HOST-007$","AccountDomain":"WORKGROUP","LogonID":"0x3E7"}}'
content_check '{"eventid":4608,"process":{"ProcessName":"C:\\Windows\\System32\\winlogon.exe","ProcessID":"0x4c0"}}'
content_check '{"eventid":4656,"subject":{"SecurityID":"HOST-001\\admin","AccountName":"admin","AccountDomain":"HOST-001","LogonID":"0x1fd23"}}'
content_check '{"eventid":4688,"process":{"NewProcessID":"0x4c0","NewProcessName":"C:\\Windows\\System32\\notepad.exe"}}'
exit_test