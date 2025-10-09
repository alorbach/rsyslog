#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
## omotlp-http-batch.sh -- smoke-test OTLP batching and retries
##
## Starts the omhttp test server, emits four messages through omotlp with
## batching and gzip enabled, and verifies the collector captured two payloads
## with the expected retry behaviour and record order.

. ${srcdir:=.}/diag.sh init

omhttp_start_server 0 --decompress --fail-every 2 --fail-with 503

generate_conf
add_conf '
module(load="../plugins/omotlp/.libs/omotlp")
template(name="otlpBody" type="string" string="%msg%")
action(
  name="omotlp-http"
  type="omotlp"
  template="otlpBody"
  endpoint="http://127.0.0.1:$omhttp_server_lstnport"
  path="/v1/logs"
  batch.max_items="2"
  batch.timeout.ms="60000"
  compression="gzip"
  retry.initial.ms="10"
  retry.max.ms="100"
  retry.max_retries="3"
  headers='{ "X-Test-Header": "omotlp" }'
)
'

startup
injectmsg_literal 'msg 1
msg 2
msg 3
msg 4'
shutdown_when_empty
wait_shutdown

attempt=0
ret=1
while [ $attempt -lt 30 ]; do
python3 - "$omhttp_server_lstnport" <<'PY'
import json
import sys
import urllib.request

port = int(sys.argv[1])
with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/logs") as resp:
    payloads = json.load(resp)

if len(payloads) != 2:
    sys.stderr.write(f"expected 2 payloads, got {len(payloads)}\n")
    sys.exit(1)

records = []
batch_sizes = []
for payload in payloads:
    document = json.loads(payload)
    logs = document["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    batch_sizes.append(len(logs))
    for entry in logs:
        body = entry.get("body", {}).get("stringValue")
        records.append(body)

expected = [f"msg {i}" for i in range(1, 5)]
if batch_sizes != [2, 2]:
    sys.stderr.write(f"unexpected batch sizes {batch_sizes}\n")
    sys.exit(1)

if records != expected:
    sys.stderr.write(f"unexpected bodies {records}\n")
    sys.exit(1)
PY
    ret=$?
    if [ $ret -eq 0 ]; then
        break
    fi
    attempt=$((attempt + 1))
    ./msleep 200
done

omhttp_stop_server

exit_test $ret
