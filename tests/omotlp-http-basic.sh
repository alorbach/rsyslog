#!/bin/bash
# basic smoke to ensure module loads and config parses; transport mocked by pointing to localhost
. ${srcdir:=.}/diag.sh init
export TCPFLOOD_MSG_COUNT=5
generate_conf >> $RSYSLOG_DYNNAME.conf << 'EOF'
module(load="omotlp")
action(type="omotlp" endpoint="http://127.0.0.1:4318" path="/v1/logs" timeout.ms="1000")
EOF
startup
tcpflood -m $TCPFLOOD_MSG_COUNT -I$$
shutdown_when_empty
wait_shutdown
exit_test
