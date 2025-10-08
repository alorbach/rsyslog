#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
# OTLP gRPC Protocol Test (Phase 2 - requires gRPC bridge implementation)
. ${srcdir:=.}/diag.sh init

export OTLP_HTTP_PORT=4318
export OTLP_GRPC_PORT=4317
export NUMMESSAGES=50
export OTLP_CONTAINER_NAME="otlp-collector-grpc-test"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not available. Cannot run OTLP Collector tests."
    exit 77  # Skip test in test harness
fi

# Create OTLP Collector configuration
create_otlp_config() {
    cat > otel-collector-config.yaml << EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:${OTLP_GRPC_PORT}
      http:
        endpoint: 0.0.0.0:${OTLP_HTTP_PORT}
        cors:
          allowed_origins: ["*"]

exporters:
  logging:
    loglevel: info
    sampling_initial: 1
    sampling_thereafter: 1
  file:
    path: /data/otlp-grpc-logs.json
    format: json
    rotation:
      max_megabytes: 10
      max_backups: 3

processors:
  batch:

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging, file]
EOF
}

# Function to check if the queue is empty and validate OTLP stats
queue_empty_check() {
    # Check that all messages were submitted
    content_check --check-only --regex '"name": "omotlp".*"sent": '$NUMMESSAGES \
        $RSYSLOG_DYNNAME.spool/omotlp-stats.log
}

export QUEUE_EMPTY_CHECK_FUNC=queue_empty_check

# Start OTLP Collector using Docker
start_otlp_collector() {
    # Clean up any existing container
    docker rm -f ${OTLP_CONTAINER_NAME} 2>/dev/null || true

    # Create configuration
    create_otlp_config

    # Start collector
    docker run -d --name ${OTLP_CONTAINER_NAME} \
        -p ${OTLP_GRPC_PORT}:${OTLP_GRPC_PORT} \
        -p ${OTLP_HTTP_PORT}:${OTLP_HTTP_PORT} \
        -v "$(pwd)/otel-collector-config.yaml:/etc/otelcol/config.yaml" \
        -v "$(pwd):/data" \
        --health-cmd="curl -f http://localhost:${OTLP_HTTP_PORT}/health || exit 1" \
        --health-interval=10s \
        --health-timeout=5s \
        --health-retries=3 \
        otel/opentelemetry-collector:latest > /dev/null

    # Wait for collector to be ready
    echo "Waiting for OTLP Collector to start..."
    for i in $(seq 1 30); do
        if docker exec ${OTLP_CONTAINER_NAME} curl -f http://localhost:${OTLP_HTTP_PORT}/health 2>/dev/null; then
            echo "OTLP Collector is ready"
            return 0
        fi
        sleep 1
    done

    echo "ERROR: OTLP Collector failed to start"
    docker logs ${OTLP_CONTAINER_NAME}
    return 1
}

# Stop OTLP Collector
stop_otlp_collector() {
    docker rm -f ${OTLP_CONTAINER_NAME} 2>/dev/null || true
    rm -f otel-collector-config.yaml
}

# Function to validate OTLP gRPC results from collector output
validate_otlp_grpc_results() {
    echo "Validating OTLP gRPC results..."

    # Wait a moment for collector to finish writing
    sleep 2

    # Check collector logs for received data
    if docker logs ${OTLP_CONTAINER_NAME} 2>/dev/null | grep -q "ResourceLogs"; then
        echo "✓ OTLP Collector received log data via gRPC"

        # Check file output
        if [ -f otlp-grpc-logs.json ]; then
            python3 -c "
import json
import sys

try:
    with open('otlp-grpc-logs.json', 'r') as f:
        # Read last few lines to get the most recent data
        lines = f.readlines()
        if not lines:
            print('ERROR: Empty OTLP gRPC logs file')
            sys.exit(1)

        # Parse the last complete JSON object
        for line in reversed(lines):
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        # Validate structure
        if 'resourceLogs' not in data:
            print('ERROR: Missing resourceLogs in gRPC collector output')
            sys.exit(1)

        resource_logs = data['resourceLogs']
        if len(resource_logs) == 0:
            print('ERROR: Empty resourceLogs in gRPC collector output')
            sys.exit(1)

        # Count log records
        found_records = 0
        for rl in resource_logs:
            if 'scopeLogs' in rl:
                for sl in rl['scopeLogs']:
                    if 'logRecords' in sl:
                        found_records += len(sl['logRecords'])

        print(f'✓ Found {found_records} log records in OTLP gRPC collector output')

        # Should have received some messages
        if found_records < 5:
            print(f'ERROR: Expected at least 5 log records via gRPC, got {found_records}')
            sys.exit(1)

        print('✓ OTLP gRPC validation passed')

except FileNotFoundError:
    print('ERROR: OTLP gRPC logs file not found')
    sys.exit(1)
except Exception as e:
    print(f'ERROR: Failed to validate OTLP gRPC data: {e}')
    sys.exit(1)
"
        else
            echo "ERROR: No OTLP gRPC logs file found"
            exit 1
        fi
    else
        echo "ERROR: No log data received by OTLP Collector via gRPC"
        docker logs ${OTLP_CONTAINER_NAME}
        exit 1
    fi
}

# Function to generate gRPC configuration
generate_grpc_conf() {
    add_conf '
template(name="otlp_body" type="string" string="%msg%")

module(load="../plugins/impstats/.libs/impstats" interval="1"
       log.file="'"$RSYSLOG_DYNNAME.spool"'/omotlp-stats.log" log.syslog="off" format="cee")
module(load="../plugins/omotlp/.libs/omotlp")

if $msg contains "msgnum:" then
    action(type="omotlp"
           protocol="grpc"
           endpoint="127.0.0.1:'$OTLP_GRPC_PORT'"
           template="otlp_body"
           batch.max_items="5"
           batch.timeout_ms="1000")
'
}

# Start OTLP Collector
start_otlp_collector || exit 1

# Test gRPC protocol (Phase 2 - requires gRPC bridge)
echo "Testing OTLP gRPC protocol..."
generate_grpc_conf
startup

# Inject test messages
injectmsg 0 $NUMMESSAGES

# Wait for shutdown
shutdown_when_empty
wait_shutdown

# Validate gRPC results
validate_otlp_grpc_results

# Check statistics
if [ -f ${RSYSLOG_DYNAME}.spool/omotlp-stats.log ]; then
    python3 <${RSYSLOG_DYNAME}.spool/omotlp-stats.log -c "
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
if sent_count < 5:
    print(f'ERROR: Expected at least 5 sent messages via gRPC, got {sent_count}')
    sys.exit(1)

print(f'OTLP gRPC stats validation passed: {sent_count} messages sent')
"
else
    echo "ERROR: No OTLP stats log found"
    exit 1
fi

# Cleanup
stop_otlp_collector
rm -f otlp-grpc-logs.json

exit 0