#!/bin/bash
# Simulate a transient failure and ensure module does not crash; functional retry behavior will be added later.
. ${srcdir:=.}/diag.sh init
generate_conf >> $RSYSLOG_DYNNAME.conf << 'EOF'
module(load="omotlp")
action(type="omotlp" endpoint="http://127.0.0.1:4318" path="/v1/logs" retry="on" timeout.ms="1000")
EOF
startup
injectmsg 0 5
shutdown_when_empty
wait_shutdown
exit_test
