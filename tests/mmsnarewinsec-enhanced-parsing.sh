#!/bin/bash
## Validate enhanced value parsing helpers (GUID, JSON, placeholders, booleans).
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.enhanced-parsing.payload"
head -n 1 "${srcdir}/testsuites/mmsnarewinsec/sample-events.data" >"${PAYLOAD_FILE}"

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="enhanced_parsing_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
       container="!win"
       emit.debugjson="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="enhanced_parsing_json")
'

startup
assign_tcpflood_port "$RSYSLOG_DYNNAME.tcpflood_port"

tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"LogonInformation": { "LogonType": 2, "LogonTypeName": "Interactive"'
content_check '"NewLogon": { "SecurityID": "S-1-5-21-88997766-1122334455-6677889900-500", "AccountName": "ADMIN-LAPS$", "AccountDomain": "FABRIKAM", "LogonID": "0x52F1A", "LinkedLogonID": "0x0", "LogonGUID": "{5a8f0679-9b23-4cb7-a8c7-3d650c9b52ec}"'
content_check '"Network": { "WorkstationName": "CORE25-01", "SourceNetworkAddress": "192.168.50.12"'
content_check '"LAPS": { "PolicyVersion": "2", "CredentialRotation": true }'
content_check '"Process": { "ProcessID": "0x66c", "ProcessName": "C:\\Windows\\System32\\winlogon.exe"'

exit_test
