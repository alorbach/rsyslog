<!-- 931be265-c871-4de7-8841-b39eefc43b36 c6acebc4-adaa-497e-937c-cd644013fe72 -->
# omotlp (OTLP Output Module)

### Goal

Create a core output plugin `plugins/omotlp` that exports rsyslog messages as OpenTelemetry Logs (OTLP). Phase 1 ships OTLP/HTTP with JSON payloads; Phase 2 adds optional OTLP/gRPC via a small C bridge to the C++ SDK.

### Scope & Phasing

- Phase 1 (v1): OTLP/HTTP JSON
  - Default endpoint: `http://127.0.0.1:4318/v1/logs`
  - Content-Type: `application/json`; optional gzip (`Content-Encoding: gzip`)
  - No runtime dependency on Protobuf or `opentelemetry-cpp`.
- Phase 2 (optional): OTLP/gRPC
  - Default target: `host:4317`
  - Thin C-compatible shim over `opentelemetry-cpp` (creates `LoggerProvider` + `BatchLogRecordProcessor` + `OtlpGrpcLogRecordExporter`)
  - Compile-time opt-in; disabled by default
  - Optional HTTP/protobuf (`application/x-protobuf`) support can be added here as well if needed

### Architecture options (recorded decision)

- Adopt A) C++ SDK bridge for gRPC in Phase 2, keep Phase 1 pure C (HTTP/JSON).
- Keep a fallback path B) Pure-C OTLP (generated protos + gRPC C core) as a contingency only.

### Module layout (new)

- `plugins/omotlp/`
  - `omotlp.c`, `omotlp.h` (module entry, config, batching orchestration)
  - `otlp_json.c` (build `ExportLogsServiceRequest` JSON with libfastjson)
  - `omotlp_http.c` (HTTP transport via libcurl; TLS, headers, gzip, retries)
  - `grpc_bridge.{cc,h}` (Phase 2 only; C API shim around `opentelemetry-cpp`)
  - `MODULE_METADATA.yaml`, `Makefile.am`
- Build wiring: `plugins/Makefile.am`, `configure.ac`, `m4/omotlp.m4`

### Concurrency & locking (per v8)

- Keep shared mutable state in per-action `pData` protected by a module-owned mutex.
- Do not share `wrkrInstanceData_t` across workers; use worker-local handles (e.g., CURL easy) or serialize inherently serial resources via the `pData` mutex.
- Rely on rsyslog action queues (incl. disk-assisted queues) for backpressure; module provides bounded batching and clear drop policies on explicit non-retryable responses (e.g., HTTP 4xx if configured).

### Transport specifics

- HTTP (v1)
  - Endpoint: `http[s]://host:4318/v1/logs`
  - `Content-Type: application/json`; `Accept: application/json`
  - Optional `Content-Encoding: gzip`
  - Retries: exponential backoff on 5xx/429; configurable handling for 4xx (drop vs retry)
- gRPC (v2)
  - Service: `opentelemetry.proto.collector.logs.v1.LogsService.Export`
  - Optional channel compression (gzip); bearer token via call metadata

### Data mapping (rsyslog → OTel LogRecord)

- `time_unix_nano`: rsyslog event timestamp (ns)
- `observed_time_unix_nano`: arrival time (optional)
- `body`: from template (string; allow JSON if template yields JSON)
- `severity_number` + `severity_text`: RFC5424 level mapped to OTel (sensible defaults)
- Attributes: `hostname`, `app-name`, `procid`, `msgid`, `facility`, and user-defined attribute map
- Trace correlation (optional): `trace_id`, `span_id`, `flags` if present as hex
- Resource: configured static attributes (`service.name`, `host.name`, ...)

### Configuration (initial)

- Endpoint & protocol
  - `protocol="http/json" | "grpc"`
  - `endpoint` (e.g., `http://collector:4318` for HTTP, `collector:4317` for gRPC)
  - `path` (HTTP only, default `/v1/logs`)
- HTTP options
  - `headers` (map), `bearer_token`, `compression=none|gzip`, `timeout.ms`, `proxy`, TLS knobs (CA file, cert/key, verify)
- Batching
  - `batch.max_items`, `batch.max_bytes`, `batch.timeout.ms`, flush on shutdown/idle
- Retries
  - `retry.initial.ms`, `retry.max.ms`, `retry.max_retries`, `retry.jitter`
- Mapping
  - `resource` (JSON), `attributeMap` (rsyslog props → OTel attributes), `severity.map`, `bodyTemplate`
  - `trace_id`, `span_id`, `trace_flags` property names (optional)
- Env-var parity (defaults if config not set)
  - Honor `OTEL_EXPORTER_OTLP_(LOGS_)ENDPOINT`, `(LOGS_)PROTOCOL`, `(LOGS_)HEADERS`, `(LOGS_)COMPRESSION`, timeouts, etc.

Example:

```rainerscript
module(load="omotlp")
action(
  type="omotlp"
  protocol="http/json"
  endpoint="https://otel-collector:4318"
  path="/v1/logs"
  resource='{ "service.name":"rsyslog", "service.instance.id":"$hostname" }'
  bodyTemplate="RSYSLOG_TraditionalFileFormat"
  batch.max_items="512"
  retry.max_retries="5"
  compression="gzip"
  bearer_token="${env:OTEL_TOKEN}"
)
```

### Phase 1 implementation (HTTP/JSON)

- Build JSON for `ExportLogsServiceRequest` per Protobuf JSON mapping: `resourceLogs[] → scopeLogs[] → logRecords[]` (libfastjson)
- POST to `/v1/logs` with libcurl; support TLS, headers, gzip, timeouts
- Batching: thresholds by items/bytes/time; flush on shutdown and idle
- Error handling: follow OTLP exporter guidance (retry 5xx/429, treat 4xx as non-retry by default; configurable)
- Stats: counters for sent, retried, dropped, http_4xx, http_5xx, and request latency if feasible

### Phase 2 implementation (gRPC)

- `grpc_bridge.h` (extern "C") C API: init(config), export(batch), flush, shutdown
- `grpc_bridge.cc`: uses `opentelemetry-cpp` to instantiate provider + `BatchLogRecordProcessor` + `OtlpGrpcLogRecordExporter`
- Translate our prepared log structures to SDK log records; forward headers/metadata and TLS
- Build guarded by `--enable-omotlp-grpc` (requires C++17, `opentelemetry-cpp`, `grpc`, `protobuf`)

### Build & packaging

- Phase 1 requires `libcurl`, `libfastjson`
- Phase 2 (optional) requires C++17 toolchain and `opentelemetry-cpp` + deps
- Autotools options:
  - `--enable-omotlp` (default on if HTTP deps present)
  - `--enable-omotlp-grpc` (default off)
- Keep runtime deps minimal in default builds

### Testing

- Add focused tests under `tests/` using `diag.sh`
  - HTTP happy path: verify payload structure via a small local HTTP capture script
  - Retry/backoff: simulate 5xx → 2xx transitions
  - Batching: thresholds for size/time; flush on shutdown/idle
- Interop smoke: document a minimal Collector config with both HTTP+gRPC receivers and `logging` exporter
- Failure modes: TLS error, 4xx vs 5xx handling, gzip on/off, large message size

Collector example (docs):

```
receivers: { otlp: { protocols: { grpc: {}, http: {} } } }
exporters: { logging: {} }
service: { pipelines: { logs: { receivers: [otlp], processors: [], exporters: [logging] } } }
```

### Documentation

- `doc/source/configuration/modules/omotlp.rst`: configuration reference, defaults, examples, mapping table, env-var defaults, troubleshooting
- Add `doc/ai/module_map.yaml` entry for locking hints

### Acceptance criteria (v1)

- Builds by default with `--enable-omotlp` on typical Linux
- Sends valid OTLP JSON payloads to `/v1/logs` with correct mapping
- Configurable batching, retries, timeouts, TLS, headers, gzip
- Clean shutdown with flush and basic tests passing

### Risks & mitigations

- JSON mapping correctness → golden-sample tests and Collector `logging` exporter validation
- Backpressure → rely on rsyslog queues; keep module batches bounded
- C++ bridge complexity → isolate in small adapter; make optional

### Files to add/change (essentials)

- `plugins/omotlp/*` (new)
- `plugins/Makefile.am`, `configure.ac`, `m4/omotlp.m4`
- `doc/source/configuration/modules/omotlp.rst`
- `tests/omotlp-http-*.sh`

### To-dos

- [ ] Add omotlp module skeleton and build wiring under plugins/omotlp
- [ ] Implement OTLP LogRecord JSON builder with libfastjson
- [ ] Implement HTTP transport with libcurl, headers, gzip, TLS
- [ ] Add batching, flush policies, and retry/backoff with jitter
- [ ] Map syslog severity and timestamps to OTLP fields
- [ ] Implement action parameters parsing and validation
- [ ] Expose stats counters (sent, retried, dropped, http_4xx/5xx)
- [ ] Create diag.sh tests for HTTP success, retry, batching
- [ ] Write omotlp module documentation with examples and mapping table
- [ ] Design C API and build flags for optional C++ gRPC bridge
- [ ] Prototype C++ bridge using opentelemetry-cpp exporter
- [ ] Run format-code.sh and ensure CI/lint passes