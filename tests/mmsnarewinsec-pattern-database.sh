#!/bin/bash
## Confirm extended field pattern database maps modern telemetry sections.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.patterns.payload"
sed -n '2p' "${srcdir}/testsuites/mmsnarewinsec/sample-events.data" >"${PAYLOAD_FILE}"

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="pattern_database_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
       container="!win"
       emit.debugjson="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="pattern_database_json")
'

startup
assign_tcpflood_port "$RSYSLOG_DYNNAME.tcpflood_port"

tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"Event": { "RecordNumberRaw": "301221", "EventID": 5157, "Provider": "Microsoft-Windows-Security-Auditing"'
content_check '"Category": "FilteringPlatform"'
content_check '"Application": { "ProcessID": "948" }'
content_check '"Network": { "Direction": "Outbound", "SourcePort": 57912, "DestinationAddress": "104.45.23.110", "DestinationPort": 443'
content_check '"Filter": { "FilterRunTimeID": "89041", "LayerName": "%%14596", "LayerRunTimeID": "44" }'
content_check '"TLSInspection": { "Reason": "Unapproved Root Authority", "Policy": "ContosoOutboundTLS" }'

exit_test
