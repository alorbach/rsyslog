#!/bin/bash
## Verify runtime configuration overrides add custom sections and fields.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

PAYLOAD_FILE="${RSYSLOG_DYNNAME}.runtime.payload"
head -n 1 "${srcdir}/testsuites/mmsnarewinsec/sample-custom-pattern.data" >"${PAYLOAD_FILE}"

RUNTIME_FILE="${RSYSLOG_DYNNAME}.runtime.json"
cat >"${RUNTIME_FILE}" <<'EOF'
{
  "sections": [
    {
      "pattern": "Custom Block Delta",
      "canonical": "CustomDelta",
      "behavior": "standard",
      "priority": 180
    }
  ],
  "fields": [
    {
      "pattern": "WidgetID",
      "canonical": "WidgetId",
      "section": "CustomDelta",
      "value_type": "string",
      "priority": 180
    },
    {
      "pattern": "CustomEventTag",
      "canonical": "EventTag",
      "section": "CustomDelta",
      "value_type": "string",
      "priority": 180
    }
  ]
}
EOF

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="runtime_config_json" type="string" string="%$!win:json%\n")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="mmsnarewinsec"
       container="!win"
  runtime.config.file="'$RUNTIME_FILE'"
       runtime.config.debug="on")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="runtime_config_json")
'

startup
assign_tcpflood_port "$RSYSLOG_DYNNAME.tcpflood_port"

tcpflood -m 1 -I "$PAYLOAD_FILE"
rm -f "$PAYLOAD_FILE"
shutdown_when_empty
wait_shutdown

content_check '"Event": { "RecordNumberRaw": "4001", "EventID": 4001, "Provider": "Custom-Provider"'
content_check '"CustomDelta": { "WidgetId": "ZX-42", "EventTag": "Demo" }'

rm -f "$RUNTIME_FILE"

exit_test
