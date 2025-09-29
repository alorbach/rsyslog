#!/bin/bash
## Exercise moderate validation mode and ensure parsing errors are reported.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.validation.payload"
head -n 1 "${srcdir}/testsuites/mmsnarewinsec/samples-all-data/Account_Logon.data" >"${PAYLOAD_FILE}"

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="validation_moderate_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
       container="!win"
       validation.mode="moderate"
       emit.debugjson="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="validation_moderate_json")
'

startup
assign_tcpflood_port "$RSYSLOG_DYNNAME.tcpflood_port"

tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"Event": { "RecordNumberRaw": "10001", "EventID": 4774'
content_check '"Validation": { "Errors": [ ] }'
content_check '"EventData": { "AuthenticationPackage": "%1 Account UPN: %2 Mapped Name: %3" }'

exit_test
