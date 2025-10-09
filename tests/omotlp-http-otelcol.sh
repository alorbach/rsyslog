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
cat <<EOF >>"${TESTCONF_NM}.conf"
module(load="../plugins/omotlp/.libs/omotlp")
template(name="otlpBody" type="string" string="%msg%")
action(
  type="omotlp"
  name="omotlp-otelcol"
  template="otlpBody"
  endpoint="http://127.0.0.1:${otelcol_http_port}"
  path="/v1/logs"
  resource="{ \"service.name\": \"rsyslog\" }"
  batch.max_items="1"
  batch.timeout.ms="60000"
)
EOF

startup

injectmsg_literal 'otelcol smoke test'

shutdown_when_empty
wait_shutdown

otelcol_wait_for_logs 1 30 || error_exit 1

otelcol_expect_record "otelcol smoke test" "rsyslog" || error_exit 1

exit_test 0
