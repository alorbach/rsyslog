<!-- 931be265-c871-4de7-8841-b39eefc43b36 e4d6d4e4-1f75-4d3d-b0d9-117f1680dea6 -->
# omotlp (OTLP Output Module)

### Goal

Create a core output plugin `plugins/omotlp` that exports rsyslog messages as OpenTelemetry Logs (OTLP). Phase 1 ships OTLP/HTTP with JSON payloads; Phase 2 adds optional OTLP/gRPC via a small C façade over the C++ SDK.

### Scope & Phasing

- Phase 1 (v1): OTLP/HTTP JSON
  - Default endpoint: `http://127.0.0.1:4318/v1/logs`
  - Content-Type: `application/json`; optional gzip (`Content-Encoding: gzip`)
  - No runtime dependency on Protobuf or `opentelemetry-cpp`.
- Phase 2 (optional): OTLP/gRPC (preferred path) and optional HTTP/protobuf
  - Default target: `host:4317`
  - Thin C-compatible shim over `opentelemetry-cpp` (creates `LoggerProvider` + `BatchLogRecordProcessor` + `OtlpGrpcLogRecordExporter`)
  - Compile-time opt-in; disabled by default
  - If HTTP/protobuf is enabled, reuse the same generated protos as gRPC

### Sequencing & risk mitigation

- Phase A: Dependency spike for gRPC — small standalone harness to verify `opentelemetry-cpp`/gRPC/protobuf toolchain and linking
- Phase B: Module scaffolding — config plumbing, metadata, enable flags, build wiring
- Phase C: Transports — implement HTTP/JSON (v1), then gRPC via façade (v2), optional HTTP/protobuf (v2)
- Phase D: Batching/retry/backoff and status→action outcome mapping
- Phase E: Tests, docs, formatting, and upstream readiness

### Architecture decisions

- gRPC path: C++ SDK façade (preferred); pure-C (generated protos + gRPC C core) only as contingency
- v1 stays pure C with HTTP/JSON; v2 may add HTTP/protobuf and gRPC using shared protos

### Module layout

- `plugins/omotlp/`
  - `omotlp.c`, `omotlp.h` — module entry, config, batching orchestration
  - `otlp_json.c` — build `ExportLogsServiceRequest` JSON with libfastjson
  - `omotlp_http.c` — HTTP transport via libcurl; TLS, headers, gzip, retries
  - `grpc_bridge.{cc,h}` — Phase 2 only; C API shim around `opentelemetry-cpp`
  - `MODULE_METADATA.yaml`, `Makefile.am`
- Build wiring: `plugins/Makefile.am`, `configure.ac`, `m4/omotlp.m4`

### Autotools switches & detection

- `--enable-omotlp[=yes|no|auto]` (default auto; enables if HTTP deps present)
- `--enable-omotlp-grpc[=yes|no]` (default no)
- Detect: HTTP deps (`libcurl`, `libfastjson`), optional gRPC deps (`opentelemetry-cpp`, `grpc++`, `protobuf`, `absl`, C++17)
- Use `PKG_CHECK_MODULES`/custom checks; fail fast with `AC_MSG_ERROR` listing missing libs/headers and suggested packages

### ABI & symbol hygiene (gRPC façade)

- Compile C++ sources with `-fvisibility=hidden`; export only C façade symbols (version script if needed)
- Link order explicit: `opentelemetry-cpp` exporters/logs + `grpc++` + `protobuf` + `absl` + `libstdc++`
- Keep STL and SDK types out of the C boundary; façade surface is C-only

### gRPC façade surface (Phase 2)

- `omotlp_grpc_init(const omotlp_grpc_config*)`
- `omotlp_grpc_emit(const omotlp_log_record*, size_t count)` — batch export
- `omotlp_grpc_flush(void)`
- `omotlp_grpc_shutdown(void)`
- Config includes endpoint, TLS, headers/metadata, compression, timeouts

### Concurrency & locking (per v8)

- Shared mutable state lives in per-action `pData` protected by a module-owned mutex
- Do not share `wrkrInstanceData_t` across workers; use worker-local transient objects (e.g., CURL easy) or serialize serial resources via `pData` mutex
- Backpressure: rely on rsyslog action queues (incl. disk-assisted queues); module keeps bounded batches and clear drop policies

### Transport specifics

- HTTP (v1)
  - Endpoint: `http[s]://host:4318/v1/logs`
  - `Content-Type: application/json`; `Accept: application/json`
  - Optional `Content-Encoding: gzip`
  - Retries: exponential backoff with jitter on 5xx/429; configurable 4xx handling (drop vs retry)
- gRPC (v2)
  - Service: `opentelemetry.proto.collector.logs.v1.LogsService.Export`
  - Optional channel compression (gzip); bearer token via call metadata

### Error mapping & action outcomes

- Success: 2xx (HTTP) / OK (gRPC) → mark batch sent
- Soft-fail (retry): 5xx/429 (HTTP) / UNAVAILABLE/DEADLINE_EXCEEDED (gRPC) → requeue with backoff
- Hard-fail (drop): 4xx (HTTP, configurable exceptions) / INVALID_ARGUMENT/PERMISSION_DENIED (gRPC) → drop or park per policy

### Data mapping (rsyslog → OTel LogRecord)

- `time_unix_nano`: rsyslog event timestamp (ns)
- `observed_time_unix_nano`: arrival time (optional)
- `body`: from template (string; allow JSON if template yields JSON)
- `severity_number` + `severity_text`: RFC5424 level mapped to OTel
- Attributes: `hostname`, `app-name`, `procid`, `msgid`, `facility`, user-defined map
- Trace correlation (optional): `trace_id`, `span_id`, `flags` if present as hex
- Resource: configured static attributes (`service.name`, `host.name`, ...)

### Configuration (initial)

- Endpoint & protocol
  - `protocol="http/json" | "grpc"`
  - `endpoint` (e.g., `http://collector:4318` for HTTP, `collector:4317` for gRPC)
  - `path` (HTTP only, default `/v1/logs`)
- HTTP options
  - `headers` (map), `bearer_token`, `compression=none|gzip`, `timeout.ms`, `proxy`, TLS knobs (CA file/dir, cert/key, verify)
- Batching
  - `batch.max_items`, `batch.max_bytes`, `batch.timeout.ms`, flush on shutdown/idle
- Retries
  - `retry.initial.ms`, `retry.max.ms`, `retry.max_retries`, `retry.jitter`
- Mapping
  - `resource` (JSON), `attributeMap` (rsyslog props → OTel attributes), `severity.map`, `bodyTemplate`
  - `trace_id`, `span_id`, `trace_flags` property names (optional)
- Env-var parity & precedence
  - Honor `OTEL_EXPORTER_OTLP_(LOGS_)ENDPOINT`, `(LOGS_)PROTOCOL`, `(LOGS_)HEADERS`, `(LOGS_)COMPRESSION`, timeouts, etc.
  - Precedence: action parameter > environment variable > module default

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
- Error handling: OTLP exporter guidance (retry 5xx/429, treat 4xx as non-retry by default; configurable)
- Stats: counters for sent, retried, dropped, http_4xx, http_5xx, and request latency if feasible
- Security: support mTLS (CA file/dir, client cert/key), hostname verification toggle; redact secrets in diagnostics

### Phase 2 implementation (gRPC)

- Façade C API (above); implement in `grpc_bridge.cc` using `opentelemetry-cpp`
- Instantiate provider + `BatchLogRecordProcessor` + `OtlpGrpcLogRecordExporter`
- Translate our prepared log structures to SDK log records; pass headers/metadata, TLS, compression
- Build guarded by `--enable-omotlp-grpc` (requires C++17, `opentelemetry-cpp`, `grpc`, `protobuf`)
- Optional: add HTTP/protobuf path using shared generated protos for high-throughput mode

### Build & packaging

- Phase 1 requires `libcurl`, `libfastjson`
- Phase 2 (optional) requires C++17 and `opentelemetry-cpp` + deps (`grpc++`, `protobuf`, `absl`)
- Autotools options:
  - `--enable-omotlp[=yes|no|auto]` (default auto)
  - `--enable-omotlp-grpc[=yes|no]` (default no)
- Keep runtime deps minimal in default builds; run `devtools/format-code.sh` before commit

### Testing

- Test harnesses (v2/A): small standalone gRPC harness to validate toolchain/linking
- `tests/` via `diag.sh`
  - HTTP happy path: local capture server verifies payload structure
  - Retry/backoff: simulate 5xx → 2xx transitions
  - Batching: thresholds for size/time; flush on shutdown/idle
  - Golden-file checks: decode captured OTLP and assert mappings (severity, resource, attributes)
- Interop smoke: document minimal Collector config with gRPC+HTTP receivers and `logging` exporter
- Failure modes: TLS error, 4xx vs 5xx handling, gzip on/off, large messages

Collector example (docs):

```
receivers: { otlp: { protocols: { grpc: {}, http: {} } } }
exporters: { logging: {} }
service: { pipelines: { logs: { receivers: [otlp], processors: [], exporters: [logging] } } }
```

### CI matrix & quality gates (guidance)

- Validate on Ubuntu LTS, Debian stable, RHEL/CentOS Stream where possible
- Sanitizers for façade (ASan/UBSan) and `-Werror` on façade build to keep API tight
- Style/format checks (`clang-format`, repo scripts) and basic smoke tests

### Documentation

- `doc/source/configuration/modules/omotlp.rst`: configuration reference, defaults, examples, mapping table, env-var defaults, troubleshooting and precedence rules
- Add `doc/ai/module_map.yaml` entry for locking hints
- In-tree docs in module folder: `README.md` (quickstart), `BUILDING.md` (deps, switches, link order), `OPS.md` (env parity, TLS/auth, common errors)

### Acceptance criteria (v1)

- Builds by default with `--enable-omotlp` on typical Linux
- Sends valid OTLP JSON payloads to `/v1/logs` with correct mapping
- Configurable batching, retries, timeouts, TLS, headers, gzip
- Clean shutdown with flush and basic tests passing

### Risks & mitigations

- JSON mapping correctness → golden-sample tests and Collector `logging` exporter validation
- Backpressure → rely on rsyslog queues; keep module batches bounded
- C++ façade complexity → isolate in small adapter; hide symbols; make optional

### Files to add/change

- `plugins/omotlp/*` (new)
- `plugins/Makefile.am`, `configure.ac`, `m4/omotlp.m4`
- `doc/source/configuration/modules/omotlp.rst`
- `tests/omotlp-http-*.sh`
- (Phase 2) Optional: small gRPC harness under `tools/` for dependency spike

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