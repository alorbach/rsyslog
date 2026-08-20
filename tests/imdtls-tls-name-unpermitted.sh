#!/bin/bash
# added 2026-08-20 by alorbach
# This file is part of the rsyslog project, released under ASL 2.0
#
# Verify that imdtls tls.authmode="name" plus tls.permittedpeer rejects a
# CA-signed client whose certificate identity is not on the allow-list.
# The client presents the testbench certificate (CN=rsyslog-client / SAN
# testbench.rsyslog.com), which chains to tls.cacert, but the listener only
# permits "trusted-host.corp".
#
# Oracle: wait until the configured omfile contains the identity-check
# failure diagnostic, then prove the injected syslog payload is absent.
# That wait is the handshake/auth completion signal; no extra sleep is
# used. tcpflood --check-only continues if the dropped session makes the
# client exit non-zero after a completed handshake.
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=1
generate_conf
PORT_RCVR_FILE="$RSYSLOG_DYNNAME.imdtls.port"

add_conf '
module(	load="../plugins/imdtls/.libs/imdtls" )
input(	type="imdtls"
	port="0"
	listenPortFileName="'$PORT_RCVR_FILE'"
	tls.authmode="name"
	tls.permittedpeer="trusted-host.corp"
	tls.cacert="'$srcdir/tls-certs/ca.pem'"
	tls.mycert="'$srcdir/tls-certs/cert.pem'"
	tls.myprivkey="'$srcdir/tls-certs/key.pem'")

action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
'
startup
assign_file_content PORT_RCVR "$PORT_RCVR_FILE"

tcpflood --check-only -b1 -W1000 -p"$PORT_RCVR" -m"$NUMMESSAGES" -Tdtls \
	-x"$srcdir/tls-certs/ca.pem" -Z"$srcdir/tls-certs/cert.pem" \
	-z"$srcdir/tls-certs/key.pem"

wait_content "Cert Verify FAILED" "$RSYSLOG_OUT_LOG"
shutdown_when_empty
wait_shutdown
content_check "Cert Verify FAILED"
check_not_present "msgnum:"
exit_test
