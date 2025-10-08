# OTLP Module Test Setup

This document describes how to run the OTLP module tests and what they validate.

## Overview

The OTLP module tests use the official **OpenTelemetry Collector** as a test server to validate that the module correctly sends OTLP-formatted data. This provides a production-faithful testing environment.

## Test Files

- `omotlp-basic.sh` - Tests HTTP/JSON protocol (Phase 1)
- `omotlp-grpc.sh` - Tests gRPC protocol (Phase 2 - requires gRPC bridge)

## Prerequisites

- Docker (for running OpenTelemetry Collector)
- Standard rsyslog test environment (see `diag.sh`)

## Running Tests

### Basic HTTP Test

```bash
# Run from the tests directory
./omotlp-basic.sh
```

This test:
1. Starts an OpenTelemetry Collector via Docker
2. Configures rsyslog to send messages via OTLP HTTP
3. Validates that the collector receives properly formatted OTLP data
4. Checks rsyslog statistics counters

### gRPC Test (Phase 2)

```bash
# Run from the tests directory (requires gRPC bridge implementation)
./omotlp-grpc.sh
```

## OpenTelemetry Collector Setup

The tests automatically create and start an OpenTelemetry Collector with this configuration:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

exporters:
  logging:
    loglevel: info
  file:
    path: /data/otlp-logs.json
    format: json

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [logging, file]
```

## Validation

The tests validate:

1. **Payload Structure**: Correct OTLP JSON/Protobuf format
2. **Field Mapping**: Syslog → OTLP field conversion
3. **Statistics**: Sent, retried, and error counters
4. **Error Handling**: Proper handling of network issues

## Manual Testing

You can also manually test the module:

1. **Start the collector manually**:
   ```bash
   docker run -d --name otlp-test \
     -p 4317:4317 -p 4318:4318 \
     -v "$(pwd)/otel-collector-config.yaml:/etc/otelcol/config.yaml" \
     -v "$(pwd):/data" \
     otel/opentelemetry-collector:latest
   ```

2. **Create a test config** (`otel-collector-config.yaml`):
   ```yaml
   receivers:
     otlp:
       protocols:
         grpc: {}
         http: {}

   exporters:
     logging:
       loglevel: info
     file:
       path: /data/otlp-logs.json

   service:
     pipelines:
       logs:
         receivers: [otlp]
         exporters: [logging, file]
   ```

3. **Configure rsyslog**:
   ```rsyslog
   module(load="omotlp")

   action(type="omotlp"
          endpoint="http://localhost:4318/v1/logs"
          batch.max_items="10")
   ```

4. **Monitor collector output**:
   ```bash
   # Watch collector logs
   docker logs -f otlp-test

   # Check written data
   cat otlp-logs.json
   ```

## Troubleshooting

**Docker not available**: Tests will skip if Docker is not installed.

**Collector startup issues**: Check that ports 4317 and 4318 are available.

**Network connectivity**: Ensure the collector is accessible at the configured endpoints.

**Test failures**: Check the collector logs for detailed error information.

## Environment Variables

The tests use these environment variables:

- `OTLP_HTTP_PORT=4318` - HTTP port for OTLP collector
- `OTLP_GRPC_PORT=4317` - gRPC port for OTLP collector
- `NUMMESSAGES=100` - Number of test messages to send
- `OTLP_CONTAINER_NAME` - Docker container name for cleanup