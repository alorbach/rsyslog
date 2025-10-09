#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
## omotlp-http-otelcol.sh -- verify omotlp against a real otel collector file exporter
##
## Boots the OpenTelemetry Collector via the diag.sh helper on random HTTP and
## health-check ports, points omotlp at it, and asserts that the captured JSON
## payload contains the expected message body and service.name attribute.

. ${srcdir:=.}/diag.sh init

require_plugin omotlp

export EXTRA_EXIT=otelcol
otelcol_start

generate_conf
add_conf '
module(load="../plugins/omotlp/.libs/omotlp")
template(name="otlpBody" type="string" string="%msg%")
action(
  type="omotlp"
  name="omotlp-otelcol"
  template="otlpBody"
  endpoint="http://127.0.0.1:'"$otelcol_http_port"'"
  path="/v1/logs"
  resource='{ "service.name":"rsyslog" }'
  batch.max_items="1"
  batch.timeout.ms="60000"
)
'

startup

injectmsg_literal 'otelcol smoke test'

shutdown_when_empty
wait_shutdown

otelcol_wait_for_logs 1 30 || error_exit 1

python3 - "$otelcol_output_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    sys.stderr.write(f"missing collector output {path}\n")
    sys.exit(1)

documents = []
with path.open("r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        documents.append(json.loads(line))

if len(documents) != 1:
    sys.stderr.write(f"expected 1 payload, got {len(documents)}\n")
    sys.exit(1)

payload = documents[0]
resource_logs = payload.get("resourceLogs", [])
if len(resource_logs) != 1:
    sys.stderr.write(f"expected 1 resourceLogs entry, got {len(resource_logs)}\n")
    sys.exit(1)

scope_logs = resource_logs[0].get("scopeLogs", [])
if len(scope_logs) != 1:
    sys.stderr.write(f"expected 1 scopeLogs entry, got {len(scope_logs)}\n")
    sys.exit(1)

log_records = scope_logs[0].get("logRecords", [])
if len(log_records) != 1:
    sys.stderr.write(f"expected 1 logRecord, got {len(log_records)}\n")
    sys.exit(1)

record = log_records[0]
body = record.get("body", {}).get("stringValue")
if body != "otelcol smoke test":
    sys.stderr.write(f"unexpected body {body!r}\n")
    sys.exit(1)

resource = resource_logs[0].get("resource", {})
attributes = {}
for item in resource.get("attributes", []):
    key = item.get("key")
    value = item.get("value", {})
    if not isinstance(value, dict):
        continue
    if "stringValue" in value:
        attributes[key] = value["stringValue"]

if attributes.get("service.name") != "rsyslog":
    sys.stderr.write(f"service.name mismatch: {attributes.get('service.name')!r}\n")
    sys.exit(1)
PY
ret=$?

exit_test $ret
