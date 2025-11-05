# OpenTelemetry Collector Test Infrastructure Implementation

## Summary

This document summarizes the implementation of test infrastructure for the `omotlp` module using a real OpenTelemetry Collector instance.

## What Was Implemented

### 1. Helper Functions in `tests/diag.sh`

Added the following functions following the pattern used for Kafka and Elasticsearch:

- **`download_otel_collector()`**: Downloads and caches the OpenTelemetry Collector binary from GitHub releases
  - Supports architecture detection (amd64, arm64)
  - Default version: 0.100.0
  - Caches binary in `.dep_cache` directory
  - Supports external cache (`/local_dep_cache`)

- **`prepare_otel_collector()`**: Prepares the collector execution environment
  - Extracts binary from tarball
  - Assigns dynamic ports for HTTP and gRPC
  - Creates config file from template with variable substitution
  - Sets up output file path

- **`start_otel_collector()`**: Starts the collector instance
  - Runs collector in background
  - Waits for readiness (checks HTTP endpoint)
  - Stores PID in `otel.pid`
  - Logs to `collector.log`

- **`stop_otel_collector()`**: Stops the collector gracefully
  - Sends SIGTERM, waits for termination
  - Falls back to SIGKILL if needed
  - Respects `KEEP_OTEL_RUNNING` environment variable

- **`cleanup_otel_collector()`**: Cleans up all collector files
  - Stops collector
  - Removes working directory
  - Cleans up PID file

- **`otel_collector_output_file()`**: Returns the path to collector output file

- **`wait_for_otel_collector_ready()`**: Waits for collector to be ready (optional timeout)

- **`otel_exit_handling()`**: Exit handler for `EXTRA_EXIT=otel`

### 2. Collector Configuration Template

Created `tests/testsuites/otel-collector-config.yaml`:
- Configures OTLP receiver for HTTP and gRPC on dynamic ports
- Uses batch processor
- Uses file exporter to write logs to output file
- Includes logging exporter for debug output

**Note**: The file exporter writes in OTLP protobuf format (binary). For easier verification in tests, consider:
- Using a protobuf parser to read the output
- Adding a JSON exporter if available in contrib
- Verifying via HTTP endpoint checks

### 3. Simple Test

Created `tests/omotlp-http-basic.sh`:
- Downloads and starts OpenTelemetry Collector
- Sends 10 test messages via omotlp
- Verifies collector output file exists and has content
- Cleans up collector on exit

### 4. Exit Handling

Added support for:
- `EXTRA_EXIT=otel` to automatically stop collector on test exit
- `EXTRA_EXITCHECK=dumpotellogs` to dump collector logs on failure

## Usage Example

```bash
#!/bin/bash
. ${srcdir:=.}/diag.sh init

export EXTRA_EXIT=otel
export EXTRA_EXITCHECK=dumpotellogs

# Start collector
download_otel_collector
prepare_otel_collector
start_otel_collector

# Use $OTEL_HTTP_PORT in your rsyslog config
OTEL_ENDPOINT="http://127.0.0.1:$OTEL_HTTP_PORT"

# ... configure rsyslog and run test ...

# Stop collector
stop_otel_collector
```

## Environment Variables

- `OTEL_COLLECTOR_VERSION`: Collector version to download (default: 0.100.0)
- `OTEL_COLLECTOR_DOWNLOAD`: Override download filename
- `OTEL_HTTP_PORT`: HTTP port (auto-assigned if not set)
- `OTEL_GRPC_PORT`: gRPC port (auto-assigned if not set)
- `OTEL_OUTPUT_FILE`: Output file path (auto-assigned if not set)
- `RSYSLOG_TESTBENCH_USE_EXTERNAL_OTEL`: Use external collector instance
- `KEEP_OTEL_RUNNING`: Keep collector running after test (for debugging)

## Download URL Pattern

The collector is downloaded from:
```
https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v<VERSION>/otelcol-contrib_<VERSION>_linux_<ARCH>.tar.gz
```

Example for v0.100.0 on amd64:
```
https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.100.0/otelcol-contrib_0.100.0_linux_amd64.tar.gz
```

## Future Enhancements

1. **JSON Output**: Add support for JSON file exporter or protobuf parsing
2. **Verification Helpers**: Add functions to parse and verify collector output
3. **gRPC Testing**: Add tests for gRPC transport
4. **Retry Testing**: Test retry logic with collector failures
5. **TLS Testing**: Test TLS connections to collector
6. **Performance Testing**: Test high-throughput scenarios

## Notes

- The collector binary is ~50-100MB, so it's cached in `.dep_cache`
- The file exporter writes binary protobuf format, not JSON
- For JSON verification, consider using a protobuf parser or adding a JSON exporter
- The collector startup may take 1-2 seconds; readiness checks handle this
- Ports are dynamically assigned to avoid conflicts in parallel tests
