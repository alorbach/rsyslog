<!-- 931be265-c871-4de7-8841-b39eefc43b36 847470c9-3f7f-45ec-bdfb-d11b37ba08da -->
# omotlp (OTLP Output Module)

### Goal

Implement a new rsyslog output plugin `plugins/omotlp` that exports rsyslog messages as OpenTelemetry Logs using OTLP. Phase 1 delivers OTLP/HTTP with JSON payloads; Phase 2 adds optional OTLP/gRPC.

### Scope & Phasing

- Phase 1 (v1): OTLP/HTTP JSON only
  - No dependency on Protobuf at runtime; generate payloads using the Protobuf JSON mapping for OTel Logs
  - Transport via libcurl (reuse patterns from `omhttp`, `omhttpfs`, `omelasticsearch`)
- Phase 2 (optional): OTLP/gRPC
  - Prefer a thin C API bridge around `opentelemetry-cpp` gRPC exporter compiled as a small C++ helper library
  - Compile-time flag to enable; disabled by default in rsyslog builds

### Key Decision: C++ SDK usage

- v1: Do not embed the C++ SDK; strictly JSON over HTTP
- v2: Two options, chosen at configure time:
  - Recommended: Small C-compatible bridge wrapping `opentelemetry-cpp` (stable and maintained exporter implementation; lower surface area exposed to C)
  - Alternative (fallback): Pure-C route using gRPC C core + generated Protobuf C types (higher effort; fragile tooling)

### Module Architecture

- Files under `plugins/omotlp/`:
  - `Makefile.am`, `omotlp.c`, `omotlp.h`
  - `omotlp_http.c` (HTTP transport and retry/backoff)
  - `otlp_json.c` (build OTLP LogRecord JSON using libfastjson)
  - `grpc_bridge.{cc,h}` (Phase 2; C++ adapter exposing a C API)
  - `MODULE_METADATA.yaml`
- Build system:
  - `configure.ac`/`m4/omotlp.m4`: `--enable-omotlp` (default on if libcurl present), `--enable-omotlp-grpc` (default off, requires C++17, opentelemetry-cpp, grpc, protobuf)
  - Add to `plugins/Makefile.am`
- Concurrency & locking (per v8 guidelines):
  - Keep shared mutable state in per-action `pData`, protected by a module-owned mutex/rwlock
  - Avoid sharing `wrkrInstanceData_t` (WID) across workers; use worker-local transient objects (e.g., CURL easy handles) or serialize inherently serial resources via `pData` mutex
  - Document “Concurrency & Locking” at file top

### Configuration (initial set)

- Endpoint & protocol
  - `endpoint` (default `http://127.0.0.1:4318/v1/logs`)
  - `protocol="http/json"` (v1) | `protocol="grpc"` (v2)
- HTTP options
  - `headers` (custom headers map), `authToken`, `gzip=true|false`, `timeout`, `proxy`, TLS knobs mirroring `omhttp`
- Batching & flow
  - `batch.maxItems`, `batch.maxBytes`, `batch.timeoutMs`, `maxConcurrency`
- Retries & backoff
  - `retry.maxRetries`, `retry.baseMs`, `retry.maxMs`, `retry.jitter`
- Mapping
  - `resource` static JSON (merged into Resource attributes)
  - `attributeMap` list of rsyslog properties -> OTel attributes
  - `severity.map` (syslog 0..7 -> OTel 1..24) with sensible default
  - `bodyTemplate` name of rsyslog template for LogRecord body
  - Optional: `trace_id`, `span_id`, `trace_flags` property names to propagate if present

Example (docs):

```rainerscript
module(load="omotlp")
action(
  type="omotlp"
  endpoint="http://otel-collector:4318/v1/logs"
  protocol="http/json"
  resource='{ "service.name":"rsyslog", "service.instance.id":"$hostname" }'
  bodyTemplate="RSYSLOG_TraditionalFileFormat"
  batch.maxItems="512"
  retry.maxRetries="5"
)
```

### OTLP Log mapping (defaults)

- `time_unix_nano`: event timestamp in nanoseconds
- `observed_time_unix_nano`: arrival timestamp (optional, configurable)
- `severity_number`: map syslog level
  - 0 EMERG->FATAL4(24), 1 ALERT->FATAL3(23), 2 CRIT->ERROR4(20), 3 ERR->ERROR3(19),

4 WARNING->WARN3(15), 5 NOTICE->INFO3(11), 6 INFO->INFO2(10), 7 DEBUG->DEBUG2(6)

- `severity_text`: syslog level name
- `body`: string from `bodyTemplate` (or JSON if template renders JSON)
- `attributes`: facility, hostname, app-name, procid, msgid, and user-defined `attributeMap`
- `resource`: configured static attributes (e.g., `service.name`, `host.name`)
- `trace_id`, `span_id`, `flags`: from configured properties if present (hex decoding)

### HTTP/JSON implementation (Phase 1)

- Build JSON payload according to `ExportLogsServiceRequest` Protobuf JSON mapping
  - Structure: `resourceLogs[] -> scopeLogs[] -> logRecords[]`
  - Use libfastjson to build payloads efficiently
- Transport via libcurl
  - POST `application/json` to `/v1/logs` with optional gzip compression
  - Handle 2xx success, 4xx drop (configurable), 5xx retry with exponential backoff
- Batching
  - Accumulate LogRecords per action; flush on size/time thresholds; serialize per `pData` mutex
- Stats & observability
  - Counters via `statsobj`: sent, retried, dropped, http_4xx, http_5xx, latency histograms (if feasible)

### gRPC implementation (Phase 2)

- Preferred approach: C bridge to `opentelemetry-cpp` OTLP gRPC exporter
  - `grpc_bridge.h` C API (extern "C") to init exporter, export a batch, shutdown
  - `grpc_bridge.cc` uses OTel SDK types; translate our prepared OTel LogRecords (structs mirroring proto) into SDK records
  - Build guarded by `--enable-omotlp-grpc`
- Alternative approach (fallback): generate Protobuf C types and use gRPC C core
  - Higher complexity; only pursued if the bridge is not viable on target platforms

### Build & Packaging

- Autotools checks:
  - Phase 1 requires: libcurl, libfastjson
  - Phase 2 (optional): C++17, `opentelemetry-cpp` (+ its deps), `grpc`, `protobuf`
- `--enable-omotlp` enabled by default if deps present; `--enable-omotlp-grpc` off by default
- Keep runtime deps minimal in default builds

### Testing

- Add focused tests under `tests/` using `diag.sh`
  - HTTP sink: simple local HTTP server (Python minimal server) capturing payloads; validate required fields and structure
  - Retry/backoff: simulate 5xx then 2xx
  - Batch flush on size and timeout
- No gRPC tests in CI initially
- Smoke test doc: run against a local OTel Collector (`4318`) and verify logs arrival

### Documentation

- `doc/source/configuration/modules/omotlp.rst`: configuration, defaults, examples, mapping table, limits
- Cross-reference in module lists; add to `doc/ai/module_map.yaml`

### Acceptance Criteria (v1)

- Builds by default on typical Linux with libcurl
- Sends well-formed OTLP/HTTP JSON payloads to `/v1/logs`
- Configurable batching, retry/backoff, headers, TLS
- Documented with at least one runnable example; basic tests passing

### Risks & Mitigations

- Payload correctness: follow Protobuf JSON mapping strictly; add golden-sample tests
- Backpressure: bounded queues + drop policies configurable
- C++ bridge complexity: isolate in a tiny adapter; make optional

### Most important files to change/add

- `plugins/omotlp/*` (new)
- `plugins/Makefile.am`, `configure.ac`, `m4/omotlp.m4` (build wiring)
- `doc/source/configuration/modules/omotlp.rst` (docs)
- `tests/omotlp-http-*.sh` (tests)

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