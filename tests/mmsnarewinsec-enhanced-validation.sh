#!/bin/bash
# Exercise strict validation and enhanced parsing paths in mmsnarewinsec.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="validation_test_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
    container="!win"
    validation.mode="strict"
    emit.debugjson="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="validation_test_json")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'.debug" template="RSYSLOG_DebugFormat")
'

startup
assign_tcpflood_port $RSYSLOG_DYNNAME.tcpflood_port

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.payload"
printf '%b\n' '<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tLogon\t\tAn account was successfully logged on.    Subject:   Security ID:  SYSTEM   Account Name:  HOST-007$   Account Domain:  WORKGROUP   Logon ID:  0x3E7    Logon Information:   Logon Type:  7   Restricted Admin Mode:  -   Remote Credential Guard:  -   Virtual Account:  No   Elevated Token:  No    New Logon:   Security ID:  CLOUDDOMAIN\\User009   Account Name:  user010@example.com   Account Domain:  CLOUDDOMAIN   Logon ID:  0xFD5113F   Linked Logon ID:  0xFD5112A   Network Account Name:  -   Network Account Domain:  -   Logon GUID:  {00000000-0000-0000-0000-000000000000}    Process Information:   Process ID:  0x30c   Process Name:  C:\\Windows\\System32\\lsass.exe    Network Information:   Workstation Name:  HOST-007   Source Network Address:  -   Source Port:  -    Detailed Authentication Information:   Logon Process:  Negotiat   Authentication Package:  Negotiate   Transited Services:  -   Package Name (NTLM only):  -   Key Length:  0' > "$PAYLOAD_FILE"
tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"Event": { "EventID": 4624'
content_check '"Validation": { "Errors": [ ] }'
content_check '"ParsingStats": { "total_fields": 26, "successful_parses": 26, "parsing_errors": 0 }'
content_check '"Summary": "An account was successfully logged on."'
content_check '"Subject": { "SecurityID": "SYSTEM", "AccountName": "HOST-007$", "AccountDomain": "WORKGROUP", "LogonID": "0x3E7" }'
content_check '"LogonInformation": { "LogonType": 7, "LogonTypeName": "Unlock" }'
content_check '"DetailedAuthentication": { "LogonProcess": "Negotiat", "AuthenticationPackage": "Negotiate", "PackageName": "-", "KeyLength": 0 }'
content_check '"NewLogon": { "SecurityID": "CLOUDDOMAIN\\User009", "AccountName": "user010@example.com", "AccountDomain": "CLOUDDOMAIN", "LogonID": "0xFD5113F", "LinkedLogonID": "0xFD5112A", "LogonGUID": "{00000000-0000-0000-0000-000000000000}" }'

exit_test
