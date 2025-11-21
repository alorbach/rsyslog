# omotlp Output Module Development Plan

## 1. Goals and scope
- Deliver a dynamically loaded output module that exports rsyslog events via OpenTelemetry Protocol (OTLP) over both gRPC (binary) and HTTP/JSON transports.
- Provide configuration controls for endpoints, authentication, batching, retry/backoff, and payload shaping so rsyslog operators can match collector expectations.

## 2. Dependency and ABI strategy
- Adopt OpenTelemetry's official C++ SDK (`opentelemetry-cpp`) for OTLP serialization, exporter lifecycles, and retry logic so we avoid re-implementing protocol details.
- Build a thin C-compatible façade around the C++ exporter objects. Compile the façade with g++ (for example, `omotlp_exporter.cc`) and expose only `extern "C"` entry points for the C module to call. This lets us keep the module itself in C while linking against C++ runtime libraries in the plugin's `Makefile.am`.
- Scope the façade to the minimum required surface: initialize/shutdown exporters, translate rsyslog options into exporter configuration, hand off batches, and surface status codes. If the façade becomes unwieldy, fall back to generating OTLP protobufs directly with `protobuf-c` plus gRPC C core or libcurl, but keep the façade as the preferred path unless build portability becomes problematic.
- Vendor or reference upstream OTLP `.proto` files and generate `protobuf-c` bindings for fallback/HTTP serialization. Share the generated code between transports.

## 3. Module skeleton and repository integration
- Create `plugins/omotlp/` with the standard module layout (`omotlp.c`, `module-template.h`, metadata, façade sources).
- Add `MODULE_METADATA.yaml` describing support level, maturity, dependencies, and contacts, and create a module-specific `AGENTS.md` documenting build prerequisites and collector setup notes.
- Update `configure.ac`, `plugins/Makefile.am`, and any necessary `m4` macros to detect protobuf, gRPC, and optional opentelemetry-cpp headers/libraries, providing `--enable-omotlp`/`--disable-omotlp` switches if the dependency chain is heavy.
- Ensure autotools invokes the C++ compiler for façade sources and links the resulting `.so` against `libstdc++`, `libopentelemetry_*`, protobuf, and gRPC libs in the correct order.

## 4. Concurrency, state, and configuration
- Follow the module author checklist: keep shared configuration in `pData`, worker-local handles in `wrkrInstanceData_t`, and protect inherently serial exporter resources with mutexes or RW locks. Document the strategy in the top-of-file "Concurrency & Locking" block and Doxygen comments.
- Map rsyslog action parameters to OTLP concepts (resource attributes, instrumentation scope, severity, structured data). Provide configuration for static resource attributes and per-message overrides.
- Implement batching queues per worker and optional shared flush timers in `pData`, respecting the checklist guidance that worker instances must remain independent.
- Surface transport-neutral error reporting (stats counters, structured error messages) so administrators can troubleshoot collector connectivity.

## 5. Transport implementations
- **gRPC path:** Use the C façade to drive the opentelemetry-cpp OTLP exporter. Support TLS, mTLS, and collector authentication hooks exposed by the SDK. Allow tuning of exporter options (max batch size, timeout, retry policy).
- **HTTP/JSON path:** Either reuse opentelemetry-cpp's HTTP exporter via the façade or, if that is impractical, serialize protobuf payloads and POST them through libcurl (mirroring `omhttp`'s hardened HTTP handling). Share configuration flags (endpoint, headers, compression) between both transports for a consistent UX.
- Provide failover behavior (e.g., fallback from gRPC to HTTP) if requested, otherwise make the transport explicit and mutually exclusive.

## 6. Testing strategy
- Create targeted regression scripts under `tests/` (for example, `omotlp-grpc-basic.sh`, `omotlp-http-basic.sh`) that spin up a local OpenTelemetry Collector or mock server, emit sample messages, and verify receipt. Ensure they can be run directly via `./tests/<script>.sh` and integrate with `make check` later.
- Add unit tests for configuration parsing and façade error translation if feasible (possibly using rsyslog's existing C test harnesses).
- Validate multi-worker behavior with `queue.workerThreads > 1` to stress concurrency as required by the checklist.

## 7. Documentation and release readiness
- Document module usage, configuration parameters, dependency prerequisites, and known limitations in `doc/` (e.g., a new `omotlp.rst`) and ensure it is cross-linked from the appropriate index pages.
- Note the new module and dependency requirements in `NEWS` or release notes when the feature merges.
- Prepare packaging notes for downstream distributions (e.g., optional subpackages for opentelemetry-cpp and gRPC).

## 8. Sequencing and risk mitigation
- **Phase 1: Dependency spike** — validate that opentelemetry-cpp can be built and linked from autotools, design the C façade, and prototype gRPC export in a standalone test harness.
- **Phase 2: Module scaffolding** — add build-system plumbing, metadata, and minimal configuration parsing.
- **Phase 3: Transport implementation** — finish gRPC exporter, then add HTTP/JSON path; implement batching, retries, and error handling.
- **Phase 4: Testing & docs** — finalize regression scripts, document module behavior, and polish observability (stats counters, debug logging).
- **Phase 5: Upstream review** — run formatting/tooling, gather test evidence, and prepare the PR/commit message following repository conventions.

## 9. Decision on C vs. C++ integration
Given the repo's C-only module ecosystem, the safest approach is to keep `omotlp` written in C while compiling a contained C++ shim that wraps `opentelemetry-cpp`. This preserves rsyslog's plugin ABI expectations yet allows reuse of the official exporter. If the shim reveals blocking portability issues, fall back to a pure-C stack built on protobuf-c and gRPC/HTTP clients, but treat that as a contingency rather than the primary plan.

---

### Testing
No tests were run (not applicable for planning-only work).