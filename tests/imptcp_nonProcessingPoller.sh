#!/bin/bash
# Test imptcp with poller not processing any messages
# added 2015-10-16 by singh.janmejay
# This file is part of the rsyslog project, released  under GPLv3

# Skip test if imptcp module is not available (e.g., on macOS)
if ! ls ../plugins/imptcp/.libs/imptcp.so* 1>/dev/null 2>&1; then
	echo "imptcp module not available - skipping test"
	exit 77
fi

. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=20000
generate_conf
add_conf '
$MaxMessageSize 10k
template(name="outfmt" type="string" string="%msg:F,58:2%,%msg:F,58:3%,%msg:F,58:4%\n")

module(load="../plugins/imptcp/.libs/imptcp" threads="32" processOnPoller="off")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")

if (prifilt("local0.*")) then {
   action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
'
startup
tcpflood -c1 -m $NUMMESSAGES -r -d10000 -P129 -O
wait_file_lines
shutdown_when_empty
wait_shutdown
seq_check 0 $((NUMMESSAGES - 1)) -E
exit_test
