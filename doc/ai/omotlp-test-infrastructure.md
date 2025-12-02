# OTEL Collector Test Infrastructure Guide

This document provides instructions for AI agents working with the OTEL Collector test infrastructure for the `omotlp` module in rsyslog.

## Overview

The test infrastructure uses OpenTelemetry Collector as a test receiver. The collector receives OTLP/HTTP JSON on a dynamic port and exports to a flat file for verification, following the same patterns as Kafka and Elasticsearch helpers in `tests/diag.sh`.

## Components

### Helper Functions in `tests/diag.sh`

The following helper functions are available for OTEL Collector testing:

#### `download_otel_collector()`

Downloads the OTEL Collector binary from opentelemetry-collector-releases repository.

- **Binary**: `otelcol-contrib` (includes file exporter)
- **Cache location**: `$dep_cache_dir`
- **Environment variables**:
  - `OTEL_COLLECTOR_VERSION`: Version to download (default: "0.100.0")
  - `OTEL_COLLECTOR_DOWNLOAD`: Full filename override (default: `otelcol-contrib_${OTEL_COLLECTOR_VERSION}_linux_amd64.tar.gz`)
- **Download URL pattern**: 
  ```
  https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{version}/{download}
  ```
- **Caching**: Checks `/local_dep_cache/` first, then downloads if not cached
- **Error handling**: Exits with code 77 (SKIP) if download fails after retries

#### `prepare_otel_collector()`

Extracts and prepares a collector instance for testing.

- **Extraction location**: `$dep_work_dir/otelcol`
- **Binary discovery**: Automatically finds `otelcol-contrib` binary regardless of tarball structure
- **Config generation**: Creates `config.yaml` from template `tests/testsuites/otel-collector-config.yaml`
- **Output file**: Sets `OTEL_OUTPUT_FILE` to `${RSYSLOG_DYNNAME}.otel-output.json`
- **Cleanup**: Stops any existing collector instance before preparing new one

#### `start_otel_collector()`

Starts the collector and captures the dynamic port.

- **Port discovery**: 
  - Primary: Parses collector logs for "Listening on" or "HTTP receiver listening on" patterns
  - Fallback: Uses `lsof` to find listening port after 5 seconds
- **Port file**: Writes port to `${RSYSLOG_DYNNAME}.otel_port.file`
- **Readiness check**: Verifies port is listening with `nc`
- **Timeout**: 30 seconds for port discovery
- **Log file**: Collector output written to `$dep_work_dir/otelcol/otelcol.log`
- **PID file**: Process ID stored in `$dep_work_dir/otelcol/otelcol.pid`

#### `stop_otel_collector()`

Gracefully stops the collector.

- **Signal**: Sends SIGTERM first
- **Timeout**: Uses `$TB_TIMEOUT_STARTSTOP` for graceful shutdown
- **Force kill**: Sends SIGKILL if graceful shutdown times out
- **Cleanup**: Removes PID file after shutdown

#### `cleanup_otel_collector()`

Removes all collector files.

- **Sequence**: Calls `stop_otel_collector()` first, then removes `$dep_work_dir/otelcol` directory

#### `otel_collector_get_data()`

Extracts and formats log records from the collector output file.

- **Input file**: `${RSYSLOG_DYNNAME}.otel-output.json`
- **OTLP structure navigation**:
  ```
  resourceLogs[].scopeLogs[].logRecords[]
  ```
- **Body extraction**: 
  - Primary: Extracts `body.stringValue` from each log record
  - Fallback: Handles `body.bytesValue` (base64 decoded)
  - Regex fallback: Extracts `msgnum` patterns if JSON parsing fails
- **Output**: Writes to `${RSYSLOG_OUT_LOG}` for `seq_check` compatibility
- **Sorting**: Records are sorted before output

### Configuration Template

The collector configuration template is located at `tests/testsuites/otel-collector-config.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:0

exporters:
  file:
    path: ${OTEL_OUTPUT_FILE}
    format: json

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [file]
```

Key points:
- **Dynamic port**: `0.0.0.0:0` allows the collector to bind to any available port
- **File exporter**: Writes OTLP JSON format to the specified file
- **Environment variable**: `${OTEL_OUTPUT_FILE}` is replaced during `prepare_otel_collector()`

## OTLP/HTTP JSON Structure

The collector receives OTLP/HTTP JSON requests with the following structure:

```json
{
  "resourceLogs": [{
    "scopeLogs": [{
      "logRecords": [
        {
          "body": {
            "stringValue": "msgnum:00000001"
          },
          "severityNumber": 9,
          "timeUnixNano": "1234567890000000000",
          "attributes": []
        }
      ]
    }]
  }]
}
```

### Validation

When validating OTLP structure in tests:

1. **Resource logs**: Check `resourceLogs` array exists
2. **Scope logs**: Navigate to `resourceLogs[].scopeLogs[]`
3. **Log records**: Extract `scopeLogs[].logRecords[]`
4. **Body values**: Extract `logRecords[].body.stringValue` or handle `bytesValue`
5. **Severity**: Verify `severityNumber` mapping (rsyslog priority → OTLP severity)
6. **Timestamps**: Check `timeUnixNano` is present and valid
7. **Attributes**: Verify custom attributes are preserved

## Port Configuration

The OTEL Collector port is configured explicitly via the `OTEL_COLLECTOR_PORT` environment
variable set by `prepare_otel_collector()`. This approach ensures predictable port assignment
and avoids race conditions during startup.

### How Port Configuration Works

1. **`prepare_otel_collector()`** allocates an available port using `get_free_port()` and
   exports it as `OTEL_COLLECTOR_PORT`.

2. **`start_otel_collector()`** uses this port directly:
   ```bash
   otel_port="$OTEL_COLLECTOR_PORT"
   if [ -z "$otel_port" ]; then
       echo "ERROR: OTEL_COLLECTOR_PORT not set. Did you call prepare_otel_collector()?"
       error_exit 1
   fi
   ```

3. **Port file**: The port is written to `${RSYSLOG_DYNNAME}.otel_port.file` for test scripts:
   ```bash
   otel_port=$(cat ${RSYSLOG_DYNNAME}.otel_port.file)
   ```

### Overriding the Port

To use a specific port, set `OTEL_COLLECTOR_PORT` before calling `prepare_otel_collector()`:
```bash
export OTEL_COLLECTOR_PORT=4318
prepare_otel_collector
start_otel_collector
```

## Integration with rsyslog Test Framework

### Test Script Pattern

```bash
#!/bin/bash
. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=100
export EXTRA_EXIT=otel  # Enables automatic cleanup on exit

# Download and prepare OTEL Collector
download_otel_collector
prepare_otel_collector
start_otel_collector

# Read the port from the port file
otel_port=$(cat ${RSYSLOG_DYNNAME}.otel_port.file)

generate_conf
add_conf '
module(load="../plugins/omotlp/.libs/omotlp")
template(name="otlpBody" type="string" string="msgnum:%msg:F,58:2%")

if $msg contains "msgnum:" then
	action(
		name="omotlp-http"
		type="omotlp"
		template="otlpBody"
		endpoint="http://127.0.0.1:'$otel_port'"
		path="/v1/logs"
		batch.max_items="100"
		batch.timeout.ms="1000"
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
```

### Key Points

1. **EXTRA_EXIT**: Set to `'otel'` to enable automatic cleanup on test exit (success or failure)
2. **Port reading**: Must read port from file after `start_otel_collector()`
3. **Endpoint configuration**: Use `http://127.0.0.1:$otel_port` in omotlp action
4. **Data extraction**: Call `otel_collector_get_data` before `seq_check`
5. **Cleanup**: Handled automatically via `EXTRA_EXIT=otel`, no manual cleanup needed

## Common Troubleshooting Scenarios

### Collector Fails to Start

**Symptoms**: Timeout waiting for port, collector log shows errors

**Diagnosis**:
1. Check `$dep_work_dir/otelcol/otelcol.log` for errors
2. Verify binary is executable: `ls -l $dep_work_dir/otelcol/otelcol-contrib`
3. Check config file exists: `cat $dep_work_dir/otelcol/config.yaml`
4. Verify output file path is valid

**Solutions**:
- Ensure binary was downloaded correctly (`download_otel_collector` succeeded)
- Check config file syntax is valid YAML
- Verify output file path is writable
- Check for port conflicts (collector should use dynamic port 0)

### Port Discovery Fails

**Symptoms**: `start_otel_collector` times out, port file not created

**Diagnosis**:
1. Check collector log for "Listening on" messages
2. Verify collector process is running: `ps aux | grep otelcol-contrib`
3. Try manual port discovery: `lsof -p $(cat $dep_work_dir/otelcol/otelcol.pid) -a -iTCP`

**Solutions**:
- Increase timeout in `start_otel_collector()` if needed
- Check collector log format hasn't changed
- Verify `lsof` is available on the system

### No Data in Output File

**Symptoms**: `otel_collector_get_data` fails or returns empty results

**Diagnosis**:
1. Check output file exists: `ls -l ${RSYSLOG_DYNNAME}.otel-output.json`
2. Inspect file contents: `cat ${RSYSLOG_DYNNAME}.otel-output.json`
3. Verify collector received requests (check collector log)
4. Check rsyslog sent messages (check rsyslog log)

**Solutions**:
- Ensure rsyslog is sending to correct endpoint and port
- Verify omotlp action is configured correctly
- Check OTLP JSON structure matches expected format
- Verify file exporter is working (check collector log)

### Data Extraction Fails

**Symptoms**: `otel_collector_get_data` produces empty or incorrect output

**Diagnosis**:
1. Manually inspect output file JSON structure
2. Check Python parsing logic handles actual OTLP structure
3. Verify log records contain expected `body.stringValue` fields

**Solutions**:
- Update parsing logic if OTLP structure differs
- Check for encoding issues (UTF-8 vs base64)
- Verify message template produces expected format
- Test regex fallback extraction if JSON parsing fails

### Binary Not Found After Extraction

**Symptoms**: `prepare_otel_collector` fails with "Could not find otelcol-contrib binary"

**Diagnosis**:
1. Check tarball contents: `tar -tzf $dep_otel_collector_cached_file | head -20`
2. Verify extraction succeeded: `ls -la $dep_work_dir/otelcol/`
3. Check binary name may differ (e.g., `otelcol-contrib_linux_amd64`)

**Solutions**:
- Update binary discovery logic in `prepare_otel_collector()`
- Check tarball structure has changed
- Verify binary name matches expected pattern

### Collector Doesn't Stop Gracefully

**Symptoms**: `stop_otel_collector` times out, requires SIGKILL

**Diagnosis**:
1. Check collector log for shutdown messages
2. Verify collector handles SIGTERM correctly
3. Check for hanging goroutines or file handles

**Solutions**:
- Increase `TB_TIMEOUT_STARTSTOP` timeout
- Check collector version for known shutdown issues
- Verify no file locks on output file

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_COLLECTOR_VERSION` | `"0.100.0"` | Collector version to download |
| `OTEL_COLLECTOR_DOWNLOAD` | `otelcol-contrib_${VERSION}_linux_amd64.tar.gz` | Full download filename |
| `EXTRA_EXIT` | (unset) | Set to `'otel'` to enable automatic cleanup |
| `OTEL_OUTPUT_FILE` | `${RSYSLOG_DYNNAME}.otel-output.json` | Collector output file path (set by `prepare_otel_collector`) |

## Version Selection Strategy

- **Default version**: `0.100.0` (stable, includes file exporter)
- **Version override**: Set `OTEL_COLLECTOR_VERSION` environment variable
- **Platform**: Linux x86_64 (amd64) for CI/test environments
- **Binary**: `otelcol-contrib` (not `otelcol`) - includes all contrib components including file exporter
- **Format**: Tarball (`.tar.gz`)

## Best Practices

1. **Always use `EXTRA_EXIT=otel`**: Ensures cleanup even on test failure
2. **Check port file exists**: Verify `start_otel_collector()` succeeded before reading port
3. **Wait for collector readiness**: Don't send messages immediately after `start_otel_collector()`
4. **Inspect logs on failure**: Check both rsyslog and collector logs
5. **Validate OTLP structure**: Verify JSON structure matches OTLP spec
6. **Test with small message counts first**: Use `NUMMESSAGES=10` for initial testing
7. **Handle version compatibility**: Test with multiple collector versions if needed

## Related Files

- `tests/diag.sh`: Helper function implementations
- `tests/testsuites/otel-collector-config.yaml`: Collector configuration template
- `tests/omotlp-basic.sh`: Basic functionality test
- `tests/omotlp-batch.sh`: Batching test
- `tests/omotlp-compression.sh`: Compression test
- `tests/Makefile.am`: Test registration

## References

- [OpenTelemetry Collector Releases](https://github.com/open-telemetry/opentelemetry-collector-releases)
- [OTLP Protocol Specification](https://github.com/open-telemetry/opentelemetry-proto)
- [OTEL Collector File Exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/fileexporter)
