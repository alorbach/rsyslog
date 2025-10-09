#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
## omotlp-batch.sh -- batching test for omotlp module
##
## Tests that omotlp correctly batches multiple log records into
## single ExportLogsServiceRequest payloads.

. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=10000
export EXTRA_EXIT=otel

# Download and prepare OTEL Collector
download_otel_collector
prepare_otel_collector
start_otel_collector

# Read the port from the port file
otel_port=$(cat ${RSYSLOG_DYNNAME}.otel_port.file)

generate_conf
add_conf '
template(name="otlpBody" type="string" string="msgnum:%msg:F,58:2%")

module(load="../plugins/omotlp/.libs/omotlp")

if $msg contains "msgnum:" then
	action(
		name="omotlp-http"
		type="omotlp"
		template="otlpBody"
		endpoint="http://127.0.0.1:'$otel_port'"
		path="/v1/logs"
		batch.max_items="3"
		batch.timeout.ms="60000"
	)
'

startup
injectmsg
shutdown_when_empty
wait_shutdown

# Extract data from OTEL Collector output
otel_collector_get_data

seq_check
exit_test
