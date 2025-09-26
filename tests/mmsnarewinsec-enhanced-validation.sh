#!/bin/bash
## @brief Validate enhanced mmsnarewinsec error handling and stats output
## @description Exercises strict validation mode with malformed data to ensure
##              parsing errors are surfaced in the Validation and Stats blocks.

set -e

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="validation_test_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="validation_errors" name="$!win!Validation!Errors" format="jsonf")
    property(outname="parsing_stats" name="$!win!Stats!ParsingStats" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec"
       rootpath="!win"
       validation.mode="strict"
       emit.debugjson="on"
       template="validation_test_json")
'

startup
tcpflood -m1 -M '"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tLogon\t\tAn account was successfully logged on. Subject: Security ID: SYSTEM Account Name: HOST-007$ Account Domain: WORKGROUP Logon ID: 0x3E7 Logon Information: Logon Type: 7 Restricted Admin Mode: - Remote Credential Guard: - Virtual Account: No Elevated Token: No Impersonation Level: Impersonation New Logon: Security ID: CLOUDDOMAIN\\User009 Account Name: user010@example.com Account Domain: CLOUDDOMAIN Logon ID: 0xFD5113F Linked Logon ID: 0xFD5112A Network Account Name: - Network Account Domain: - Logon GUID: {00000000-0000-0000-0000-000000000000} Process Information: Process ID: 0x30c Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Workstation Name: HOST-007 Source Network Address: - Source Port: - Detailed Authentication Information: Logon Process: Negotiat Authentication Package: Negotiate Transited Services: - Package Name (NTLM only): - Key Length: 0\t1"'
shutdown_when_empty
wait_shutdown

content_check '"eventid":4624'
content_check '"validation_errors":[]'
content_check '"parsing_stats":{'
exit_test
