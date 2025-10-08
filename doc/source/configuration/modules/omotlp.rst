omotlp: OpenTelemetry Logs (OTLP) output module
===============================================

Phase 1 provides OTLP/HTTP JSON export compatible with the Collector `otlphttp` receiver.

Basic example::

  module(load="omotlp")
  action(
    type="omotlp"
    endpoint="http://127.0.0.1:4318"
    path="/v1/logs"
    template="RSYSLOG_TraditionalFileFormat"
  )

Parameters
----------

- endpoint: Array of base URLs (http or https). Default: http://127.0.0.1:4318
- path: HTTP path. Default: /v1/logs
- timeout.ms: Request timeout in milliseconds. Default: 5000
- bearer_token: Bearer token for Authorization header
- httpheaders: Additional HTTP headers (array of strings "Key: Value")
- usehttps: Enable HTTPS
- allowunsignedcerts: Disable TLS peer verification
- skipverifyhost: Disable TLS host verification
- tls.cacert, tls.mycert, tls.myprivkey: TLS files
- compress: Enable gzip compression of payload
- compress.level: zlib compression level (-1..9)
- batch.max_items, batch.max_bytes, batch.timeout.ms: batching controls
- retry: Enable retry for transient HTTP statuses (5xx/429)
- httpretrycodes: Extra retry HTTP codes (array of integers)
- httpignorablecodes: Treat these HTTP codes as success (array of integers)
- resource: JSON object of resource attributes (e.g., {"service.name":"rsyslog"})
- template: Message body template name

Status and Counters
-------------------

The module exposes counters for sent, retries, drops, and HTTP status classes.

Notes
-----

- Phase 1 uses JSON over HTTP and has no dependency on Protobuf or the C++ SDK.
- Phase 2 may add optional gRPC export using a C facade over opentelemetry-cpp.

