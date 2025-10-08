#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init

export OTLP_PORT=4318
export NUMMESSAGES=100

# Function to check if the queue is empty and validate OTLP stats
queue_empty_check() {
    # Check that all messages were submitted
    content_check --check-only --regex '"name": "omotlp".*"sent": '$NUMMESSAGES \
        $RSYSLOG_DYNNAME.spool/omotlp-stats.log
}

export QUEUE_EMPTY_CHECK_FUNC=queue_empty_check

# Start a simple HTTP server to capture OTLP requests
start_otlp_server() {
    python3 -c "
import http.server
import socketserver
import json
import sys

class OTLPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/v1/logs':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data.decode('utf-8'))
                print(f'Received OTLP payload with {len(data.get(\"resource_logs\", []))} resource logs', file=sys.stderr)

                # Validate basic structure
                if 'resource_logs' in data:
                    print('OTLP payload structure is valid', file=sys.stderr)

                    # Write to file for validation
                    with open('otlp_payload.json', 'w') as f:
                        json.dump(data, f, indent=2)

                else:
                    print('ERROR: Invalid OTLP payload structure', file=sys.stderr)
                    sys.exit(1)

            except json.JSONDecodeError as e:
                print(f'ERROR: Invalid JSON: {e}', file=sys.stderr)
                sys.exit(1)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging
        pass

PORT = $OTLP_PORT
with socketserver.TCPServer(('', PORT), OTLPHandler) as httpd:
    print(f'OTLP server listening on port {PORT}', file=sys.stderr)
    httpd.timeout = 30  # Timeout after 30 seconds
    try:
        httpd.handle_request()
    except:
        pass
" >otlp_server.out 2>&1 &
OTLP_SERVER_PID=$!

# Give the server time to start
sleep 2
}

# Function to generate configuration
generate_conf() {
    add_conf '
template(name="otlp_body" type="string" string="%msg%")

module(load="../plugins/impstats/.libs/impstats" interval="1"
       log.file="'"$RSYSLOG_DYNNAME.spool"'/omotlp-stats.log" log.syslog="off" format="cee")
module(load="../plugins/omotlp/.libs/omotlp")

if $msg contains "msgnum:" then
    action(type="omotlp"
           endpoint="http://127.0.0.1:'$OTLP_PORT'"
           path="/v1/logs"
           template="otlp_body"
           batch.max_items="10"
           batch.timeout_ms="1000")
'
}

# Start OTLP server
start_otlp_server

# Generate configuration
generate_conf
startup

# Inject test messages
injectmsg 0 $NUMMESSAGES

# Wait for shutdown
shutdown_when_empty
wait_shutdown

# Stop OTLP server
kill $OTLP_SERVER_PID 2>/dev/null || true
wait $OTLP_SERVER_PID 2>/dev/null || true

# Validate the received OTLP payload
if [ -f otlp_payload.json ]; then
    python3 -c "
import json
import sys

with open('otlp_payload.json', 'r') as f:
    data = json.load(f)

# Check basic structure
if 'resource_logs' not in data:
    print('ERROR: Missing resource_logs in OTLP payload')
    sys.exit(1)

resource_logs = data['resource_logs']
if len(resource_logs) == 0:
    print('ERROR: Empty resource_logs')
    sys.exit(1)

# Check for log records
found_records = 0
for rl in resource_logs:
    if 'resource' in rl and 'scope_logs' in rl:
        for sl in rl['scope_logs']:
            if 'log_records' in sl:
                found_records += len(sl['log_records'])

print(f'Found {found_records} log records in OTLP payload')

# Should have at least some messages
if found_records < 10:
    print('ERROR: Expected at least 10 log records')
    sys.exit(1)

print('OTLP payload validation passed')
"
else
    echo "ERROR: No OTLP payload received"
    exit 1
fi

# Check statistics
if [ -f ${RSYSLOG_DYNNAME}.spool/omotlp-stats.log ]; then
    python3 <${RSYSLOG_DYNNAME}.spool/omotlp-stats.log -c "
import sys, json

# Parse the stats log
stats_data = []
for line in sys.stdin:
    try:
        data = json.loads(line.strip())
        if data.get('name') == 'omotlp':
            stats_data.append(data)
    except:
        pass

if not stats_data:
    print('ERROR: No OTLP stats found')
    sys.exit(1)

# Check that messages were sent
latest_stats = stats_data[-1]
sent_count = latest_stats.get('sent', 0)
if sent_count < 10:
    print(f'ERROR: Expected at least 10 sent messages, got {sent_count}')
    sys.exit(1)

print(f'OTLP stats validation passed: {sent_count} messages sent')
"
else
    echo "ERROR: No OTLP stats log found"
    exit 1
fi

# Cleanup
rm -f otlp_payload.json otlp_server.out

exit 0