#!/bin/bash
## Validate multi-space tokenization for Snare text payloads.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.tokenization.payload"
head -n 1 "${srcdir}/testsuites/mmsnarewinsec/sample-events.data" >"${PAYLOAD_FILE}"

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="tokenization_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
       container="!win"
       emit.debugjson="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="tokenization_json")
'

startup
assign_tcpflood_port "$RSYSLOG_DYNNAME.tcpflood_port"

tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"Event": { "RecordNumberRaw": "802301", "EventID": 4624, "Provider": "Microsoft-Windows-Security-Auditing"'
content_check '"Subject": { "SecurityID": "S-1-5-18", "AccountName": "SYSTEM", "AccountDomain": "NT AUTHORITY", "LogonID": "0x3E7" }'
content_check '"LogonInformation": { "LogonType": 2, "LogonTypeName": "Interactive", "VirtualAccount": "%%1843", "ElevatedToken": "%%1843" }'
content_check '"NewLogon": { "SecurityID": "S-1-5-21-88997766-1122334455-6677889900-500", "AccountName": "ADMIN-LAPS$", "AccountDomain": "FABRIKAM", "LogonID": "0x52F1A"'
content_check '"Network": { "WorkstationName": "CORE25-01", "SourceNetworkAddress": "192.168.50.12", "SourcePort": 59122 }'
content_check '"LAPS": { "PolicyVersion": "2", "CredentialRotation": true }'

exit_test
