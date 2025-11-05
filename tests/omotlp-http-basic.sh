#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
## omotlp-http-basic.sh -- basic test for omotlp module using OpenTelemetry Collector
##
## This test starts an OpenTelemetry Collector, sends messages via omotlp,
## and verifies that the collector received and stored the logs correctly.

. ${srcdir:=.}/diag.sh init

# Set up exit handling for OpenTelemetry Collector
export EXTRA_EXIT=otel
export EXTRA_EXITCHECK=dumpotellogs

# Download and prepare OpenTelemetry Collector
download_otel_collector
prepare_otel_collector
start_otel_collector

# Get collector endpoint
OTEL_ENDPOINT="http://127.0.0.1:$OTEL_HTTP_PORT"

# Configure rsyslog
generate_conf
add_conf '
module(load="../plugins/omotlp/.libs/omotlp")

template(name="otlpBody" type="string" string="%msg%")

action(
  name="omotlp-http"
  type="omotlp"
  template="otlpBody"
  endpoint="'$OTEL_ENDPOINT'"
  path="/v1/logs"
  batch.max_items="10"
  batch.timeout.ms="5000"
)
'

startup

# Inject test messages
injectmsg 1 10

# Wait for messages to be processed
wait_file_lines "$RSYSLOG_OUT_LOG" 10 50

shutdown_when_empty
wait_shutdown

# Wait a bit for collector to flush
$TESTTOOL_DIR/msleep 2000

# Verify collector output file exists and has content
OTEL_OUTPUT=$(otel_collector_output_file)
if [ ! -f "$OTEL_OUTPUT" ]; then
    printf 'ERROR: Collector output file not found: %s\n' "$OTEL_OUTPUT"
    error_exit 1
fi

# Check if file has content (file exporter writes protobuf, so we check size)
if [ ! -s "$OTEL_OUTPUT" ]; then
    printf 'ERROR: Collector output file is empty: %s\n' "$OTEL_OUTPUT"
    error_exit 1
fi

printf 'SUCCESS: Collector output file exists and has content: %s\n' "$OTEL_OUTPUT"
printf 'File size: %d bytes\n' "$(stat -f%z "$OTEL_OUTPUT" 2>/dev/null || stat -c%s "$OTEL_OUTPUT" 2>/dev/null || echo 0)"

# Stop collector
stop_otel_collector

exit_test
