#!/bin/bash
# Validate custom pattern loading and section detection for mmsnarewinsec.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

DEF_FILE="${RSYSLOG_DYNNAME}.defs.json"
cat >"$DEF_FILE" <<'JSON'
{
  "sections": [
    {
      "pattern": "Custom Block*",
      "canonical": "CustomBlock",
      "behavior": "standard",
      "priority": 250,
      "sensitivity": "case_insensitive"
    }
  ],
  "fields": [
    {
      "pattern": "CustomEventTag",
      "canonical": "CustomEventTag",
      "section": "EventData",
      "priority": 80,
      "value_type": "string"
    }
  ],
  "eventFields": [
    {
      "event_id": 9999,
      "patterns": [
        {
          "pattern": "WidgetID",
          "canonical": "WidgetID",
          "section": "CustomBlock",
          "value_type": "string"
        }
      ]
    }
  ],
  "events": [
    {
      "event_id": 9999,
      "category": "Custom",
      "subtype": "Injected",
      "outcome": "success"
    }
  ]
}
JSON

generate_conf
add_conf "
module(load=\"../plugins/mmsnarewinsec/.libs/mmsnarewinsec\" \
       definition.file=\"${PWD}/${DEF_FILE}\" \
       validation.mode=\"strict\")

template(name=\"customfmt\" type=\"list\") {
    property(name=\"$!win!Event!Category\")
    constant(value=\",\")
    property(name=\"$!win!CustomBlock!WidgetID\")
    constant(value=\",\")
    property(name=\"$!win!EventData!CustomEventTag\")
    constant(value=\",\")
    property(name=\"$!win!Event!Outcome\")
    constant(value=\"\\n\")
}

action(type=\"mmsnarewinsec\")
action(type=\"omfile\" file=\"$RSYSLOG_OUT_LOG\" template=\"customfmt\")
"

startup

printf '%s\n' $'<13>1 2025-02-18T08:00:00.000000Z CUSTOMHOST - - - - MSWinEventLog\t1\tSecurity\t4001\tTue Feb 18 08:00:00 2025\t9999\tCustom-Provider\tN/A\tN/A\tSuccess Audit\tCUSTOMHOST\tCustomCategory\t\tCustom audit event triggered.    Custom Block Delta:   WidgetID:  ZX-42   CustomEventTag:  Demo      -4001' > "${RSYSLOG_DYNNAME}.input"

injectmsg_file "${RSYSLOG_DYNNAME}.input"

shutdown_when_empty
wait_shutdown

content_check 'Custom,ZX-42,Demo,success' "$RSYSLOG_OUT_LOG"

rm -f "$DEF_FILE"

exit_test
