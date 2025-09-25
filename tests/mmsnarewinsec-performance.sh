#!/bin/bash
# Performance test for enhanced field detection

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="performance_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="parsing_time" name="$!win!Performance!ParsingTime" format="jsonf")
    property(outname="field_count" name="$!win!Performance!FieldCount" format="jsonf")
    property(outname="section_count" name="$!win!Performance!SectionCount" format="jsonf")
    property(outname="pattern_matches" name="$!win!Performance!PatternMatches" format="jsonf")
    property(outname="fallback_fields" name="$!win!Performance!FallbackFields" format="jsonf")
    property(outname="subject" name="$!win!Subject" format="jsonf")
    property(outname="logon" name="$!win!Logon" format="jsonf")
    property(outname="network" name="$!win!Network" format="jsonf")
    property(outname="process" name="$!win!Process" format="jsonf")
    property(outname="authentication" name="$!win!Authentication" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="performance_json")
'

# Test performance with comprehensive sample data files
startup

# Test with multiple data files to measure performance across different event types
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Logon_Logoff.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Account_Management.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/System.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Object_Access.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Process_Tracking.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Privilege_Use.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Policy_Change.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Detailed_Tracking.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/DS_Access.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Log_Clear.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Global_Object_Access.data
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Application_Generated.data

shutdown_when_empty
wait_shutdown

# Validate performance metrics and field extraction
content_check '{"eventid":4624,"subject":{"SecurityID":"SYSTEM","AccountName":"HOST-007$","AccountDomain":"WORKGROUP","LogonID":"0x3E7"}}'
content_check '{"eventid":4625,"subject":{"SecurityID":"HOST-001\\admin","AccountName":"admin","AccountDomain":"HOST-001","LogonID":"0x1fd23"}}'
content_check '{"eventid":4608,"process":{"ProcessName":"C:\\Windows\\System32\\winlogon.exe","ProcessID":"0x4c0"}}'
content_check '{"eventid":4650,"network":{"LocalEndpoint":"jsmith@srv1.dmn","RemoteEndpoint":"DMN/SRV2$"}}'
content_check '{"eventid":4720,"newaccount":{"SecurityID":"DOMAIN-FR\\John.Locke","AccountName":"John.Locke","AccountDomain":"DOMAIN-FR"}}'
content_check '{"eventid":4656,"subject":{"SecurityID":"HOST-001\\admin","AccountName":"admin","AccountDomain":"HOST-001","LogonID":"0x1fd23"}}'
content_check '{"eventid":4688,"process":{"NewProcessID":"0x4c0","NewProcessName":"C:\\Windows\\System32\\notepad.exe"}}'
content_check '{"eventid":4768,"kerberos":{"ServiceName":"krbtgt","ServiceID":"HOST-001\\krbtgt","ClientAddress":"192.168.1.100","ClientPort":"12345"}}'
content_check '{"eventid":6281,"wdac":{"PolicyName":"Default Policy","PolicyVersion":"1.0","EnforcementMode":"Audit","User":"HOST-001\\admin","PID":"1234"}}'
content_check '{"eventid":1243,"wufb":{"PolicyID":"12345","Ring":"Current","FromService":"Windows Update","EnforcementResult":"Success"}}'

exit_test