# omotlp Test Infrastructure Implementation Prompt

## Goal

Implement test infrastructure for the `omotlp` module that uses a real OpenTelemetry Collector instance. The collector should:
- Receive OTLP logs on dynamically assigned ports (HTTP and/or gRPC)
- Export received logs to a flat file for verification
- Be automatically managed by helper functions in `tests/diag.sh` (similar to Kafka and Elasticsearch)

## Analysis: OpenTelemetry Collector Releases

### Required Components

From https://github.com/open-telemetry/opentelemetry-collector-releases:

1. **Binary**: `otelcol-contrib` (recommended) or `otelcol`
   - **Location**: `https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v<version>/otelcol-contrib_<version>_<platform>.tar.gz`
   - **Platform**: Linux, architecture: `amd64` (or `arm64` for ARM systems)
   - **Version**: Use latest stable release (e.g., `v0.100.0` or newer)
   - **Why contrib**: Includes all receivers and exporters, including `filelog` exporter needed for file output

2. **Configuration Template**: YAML config file that:
   - Configures OTLP receiver(s) on dynamic ports
   - Uses file exporter to write logs to a test-specific output file
   - Minimal pipeline: `receivers -> processors -> exporters`

### Architecture Pattern

Follow the existing pattern from `tests/diag.sh` for Elasticsearch and Kafka:

1. **Download function**: `download_otel_collector()` - downloads and caches the collector binary
2. **Prepare function**: `prepare_otel_collector()` - sets up working directory, config file, output file
3. **Start function**: `start_otel_collector()` - starts collector with dynamic port assignment
4. **Stop function**: `stop_otel_collector()` - stops collector gracefully
5. **Cleanup function**: `cleanup_otel_collector()` - removes working directory and files
6. **Wait function**: `wait_for_otel_collector_ready()` - checks collector is ready to accept connections
7. **Helper variables**: Port assignments, PID file, output file paths

### Collector Configuration Requirements

The collector config should:
- Use environment variables or file substitution for dynamic ports
- Configure OTLP HTTP receiver on `0.0.0.0:${OTEL_HTTP_PORT}` (default: dynamic, e.g., 4318)
- Optionally configure OTLP gRPC receiver on `0.0.0.0:${OTEL_GRPC_PORT}` (default: dynamic, e.g., 4317)
- Use `filelog` exporter to write to `${OTEL_OUTPUT_FILE}` (absolute path)
- Include minimal processors (e.g., `batch` for efficiency)
- Disable verbose logging in production mode

### Dynamic Port Assignment

- Use `get_free_port()` or similar mechanism from `diag.sh` to assign ports
- Store ports in environment variables: `OTEL_HTTP_PORT`, `OTEL_GRPC_PORT`
- Export these for use in test configurations

### Output File Format

The collector's `filelog` exporter writes one JSON object per line (JSONL format). Each line represents an `ExportLogsServiceRequest` payload. Tests should parse this format to verify:
- Correct number of log records
- Correct field mappings (severity, body, attributes, resource)
- Correct ordering
- Timestamp accuracy

### Implementation Steps

1. **Add helper functions to `tests/diag.sh`**:
   - `download_otel_collector()` - downloads and caches binary
   - `prepare_otel_collector()` - prepares working directory and config
   - `start_otel_collector()` - starts collector with dynamic ports
   - `stop_otel_collector()` - stops collector
   - `cleanup_otel_collector()` - cleans up files
   - `wait_for_otel_collector_ready()` - waits for readiness
   - Helper to get output file path: `otel_collector_output_file()`

2. **Create collector config template**:
   - Location: `tests/testsuites/otel-collector-config.yaml`
   - Use environment variable substitution or `envsubst` for dynamic ports
   - Minimal config with OTLP receiver(s) and file exporter

3. **Create simple test**:
   - `tests/omotlp-http-basic.sh` or `tests/omotlp-basic.sh`
   - Starts collector
   - Sends a few test messages via omotlp
   - Verifies output file contains expected records
   - Cleans up collector

4. **Exit handling**:
   - Add `EXTRA_EXIT=otel` support similar to `kafka_exit_handling()`
   - Ensure collector is stopped on test exit

### Example Collector Config Template

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:${OTEL_HTTP_PORT}
      grpc:
        endpoint: 0.0.0.0:${OTEL_GRPC_PORT}

processors:
  batch:

exporters:
  file:
    path: ${OTEL_OUTPUT_FILE}

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [file]
```

### Download URL Pattern

For version `v0.100.0` on Linux amd64:
```
https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.100.0/otelcol-contrib_0.100.0_linux_amd64.tar.gz
```

Pattern:
```
https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v<VERSION>/otelcol-contrib_<VERSION>_linux_<ARCH>.tar.gz
```

### Test Example Structure

```bash
#!/bin/bash
. ${srcdir:=.}/diag.sh init

# Start OpenTelemetry Collector
start_otel_collector

# Get collector endpoint
OTEL_ENDPOINT="http://127.0.0.1:$OTEL_HTTP_PORT"

# Configure rsyslog
generate_conf
add_conf '
module(load="../plugins/omotlp/.libs/omotlp")
action(
  type="omotlp"
  endpoint="'$OTEL_ENDPOINT'"
  path="/v1/logs"
)
'

startup
injectmsg 1 10
shutdown_when_empty
wait_shutdown

# Verify collector output
OTEL_OUTPUT=$(otel_collector_output_file)
if [ ! -f "$OTEL_OUTPUT" ]; then
    error_exit "Collector output file not found: $OTEL_OUTPUT"
fi

# Parse and verify JSONL output
# ... verification logic ...

stop_otel_collector
exit_test
```

### Key Considerations

1. **Port conflicts**: Use dynamic port assignment to avoid conflicts
2. **File locking**: Ensure collector can write to output file
3. **Startup time**: Collector may take 1-2 seconds to start; add appropriate wait logic
4. **Graceful shutdown**: Use SIGTERM and wait for process termination
5. **Error handling**: Check collector logs if startup fails
6. **Binary size**: Collector binary is ~50-100MB; cache appropriately
7. **Platform compatibility**: Ensure binary matches host architecture
8. **Output format**: File exporter writes JSONL; parse line-by-line
9. **Resource cleanup**: Always clean up PID files and temp directories
10. **External instance support**: Similar to Elasticsearch, support `RSYSLOG_TESTBENCH_USE_EXTERNAL_OTEL` for CI environments

### Integration with Existing Test Framework

- Follow naming conventions: `otel_*` functions
- Use `dep_work_dir` pattern for working directory
- Store PID in `otel.pid` file
- Use `dep_cache_dir` for binary cache
- Support `KEEP_OTEL_RUNNING` environment variable for debugging
- Add `EXTRA_EXITCHECK=dumpotellogs` for debug output on failure

### Verification Functions

Consider adding helper functions to:
- Parse JSONL output file: `otel_parse_output_file()`
- Count log records: `otel_count_records()`
- Extract specific field: `otel_extract_field()`
- Compare with expected: `otel_verify_records()`

## Implementation Checklist

- [ ] Add download function for otelcol-contrib binary
- [ ] Add prepare function with config template
- [ ] Add start function with dynamic port assignment
- [ ] Add stop and cleanup functions
- [ ] Add wait/readiness check function
- [ ] Create collector config template
- [ ] Add exit handling for EXTRA_EXIT=otel
- [ ] Create simple test `tests/omotlp-http-basic.sh`
- [ ] Test collector startup/shutdown
- [ ] Test basic log forwarding
- [ ] Verify output file parsing
- [ ] Add error handling and logging
- [ ] Document in test comments
- [ ] Ensure compatibility with existing test framework
