# omotlp: OpenTelemetry Logs (OTLP) output module

Phase 1 implements OTLP/HTTP JSON export to `/v1/logs` using libcurl and libfastjson.

Defaults:
- endpoint: http://127.0.0.1:4318
- path: /v1/logs
- content-type: application/json

Example rainerscript:

```
module(load="omotlp")
action(
  type="omotlp"
  endpoint="http://127.0.0.1:4318"
  path="/v1/logs"
  template="RSYSLOG_TraditionalFileFormat"
)
```

