#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
## omotlp-http-batch.sh -- smoke-test OTLP batching and retries
##
## Starts the omhttp test server, emits four messages through omotlp with
## batching and gzip enabled, and verifies the collector captured two payloads
## with the expected retry behaviour and record order.

. ${srcdir:=.}/diag.sh init

require_plugin omotlp

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

otlp_http_expect_sequence "$omhttp_server_lstnport" "msg 1,msg 2,msg 3,msg 4" "2,2" || error_exit 1

omhttp_stop_server

exit_test 0
