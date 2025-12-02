.. _module-omotlp:

.. meta::
   :description: Scaffolding for the omotlp OpenTelemetry output module.
   :keywords: omotlp, otlp, opentelemetry, rsyslog module

.. summary-start

Phase 1 of the omotlp output plugin streams OpenTelemetry logs over
OTLP/HTTP JSON with configurable batching, gzip compression, and retry/backoff
controls.

.. summary-end

omotlp: OpenTelemetry output module (preview)
=============================================

.. warning::

   The OTLP/HTTP JSON transport is ready for preview deployments. The optional
   OTLP/gRPC façade and HTTP/protobuf fast-path remain under development, so
   keep action queues enabled and plan future upgrades accordingly.

Overview
--------

``omotlp`` prepares rsyslog for native :abbr:`OTLP (OpenTelemetry Log Protocol)`
exports. Phase 1 focuses on the OTLP/HTTP JSON transport path: the module maps
rsyslog metadata into the canonical OTLP JSON structure, joins the configured
endpoint and path, and posts batches of rendered payloads via ``libcurl`` using
``application/json`` semantics. Batching thresholds, gzip compression, retry and
backoff policies, and custom headers are all configurable. Subsequent phases
will extend the module with the gRPC façade and, optionally, HTTP/protobuf
support.

Availability
------------

The module is built only when ``./configure`` is invoked with
``--enable-omotlp=yes`` and both ``libcurl`` and ``libfastjson`` are present.
The default ``--enable-omotlp`` setting is ``no``, so you must opt in
explicitly. The HTTP transport depends on ``libcurl`` at runtime.

Configuration
-------------

The action parameters listed below mirror the current transport design. All
parameters are optional and fall back to sensible defaults inspired by the
`OTLP specification <https://opentelemetry.io/docs/specs/otlp/>`_.

.. csv-table:: ``omotlp`` action parameters
   :header: "Parameter", "Type", "Default", "Description"
   :widths: auto

   "endpoint", "string", "http://127.0.0.1:4318", "Base OTLP collector URL"
   "path", "string", "/v1/logs", "Request path appended to the endpoint"
   "protocol", "word", "http/json", "Transport variant"
   "template", "word", "RSYSLOG_FileFormat", "Message template used for the log body"
   "timeout.ms", "integer", "10000", "HTTP request timeout in milliseconds"
   "compression", "word", "none", "Request payload compression (``none`` or ``gzip``)"
   "batch.max_items", "integer", "512", "Flush the batch after this many records (``0`` disables the limit)"
   "batch.max_bytes", "integer", "524288", "Approximate uncompressed payload threshold in bytes (``0`` disables the limit)"
   "batch.timeout.ms", "integer", "5000", "Flush the oldest batch after this idle period in milliseconds (``0`` disables the user-configured timer, but a short safety flush still runs periodically to avoid indefinite buffering)"
   "retry.initial.ms", "integer", "1000", "Initial backoff before retrying retryable HTTP responses"
   "retry.max.ms", "integer", "30000", "Maximum backoff applied between retries"
   "retry.max_retries", "integer", "5", "Attempts made before returning the batch to the action queue"
   "retry.jitter.percent", "integer", "20", "Jitter applied to retry delays (``0``–``100``)"
   "headers", "string (JSON object)", "—", "Additional HTTP headers expressed as a JSON object"
   "bearer_token", "string", "—", "Convenience token that expands to ``Authorization: Bearer <token>``"

Batch sizes are estimated from the body length plus per-record overhead so the
module can limit payloads without rendering JSON for each candidate message.
When a threshold is reached the batch is flushed immediately; otherwise it is
sent when either the timeout elapses or rsyslog finishes the current queue
transaction.

Environment variables from the OpenTelemetry specification are consulted when a
configuration omits explicit values. ``endpoint`` falls back to
``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` and then ``OTEL_EXPORTER_OTLP_ENDPOINT``;
``protocol`` and ``compression`` honour the matching ``*_PROTOCOL`` and
``*_COMPRESSION`` variables; ``timeout.ms`` defaults to
``OTEL_EXPORTER_OTLP_LOGS_TIMEOUT`` or ``OTEL_EXPORTER_OTLP_TIMEOUT``; and
``headers`` consumes ``OTEL_EXPORTER_OTLP_LOGS_HEADERS`` or the generic
``OTEL_EXPORTER_OTLP_HEADERS`` when no explicit headers are configured. Action
parameters always take precedence, giving operators an easy override when
reusing existing collector deployments.

When the endpoint string includes an explicit path (for example,
``https://otel:4318/v1/logs``), the module automatically splits the final path
segment into the ``path`` parameter so that future HTTP transport code can join
the pieces without duplicating ``/v1/logs``.

Example
-------

The example below batches up to 200 records or 256 KiB every two seconds, uses
gzip compression, and adds a custom tenant header alongside an Authorization
bearer token read from the environment. Retry/backoff settings align with the
default action queue behaviour: HTTP status codes ``429`` and ``5xx`` trigger
``RS_RET_SUSPENDED`` so queued records are retried with jittered backoff, while
other non-success responses discard the message and log an error.

.. code-block:: none

   module(load="omotlp")
   action(
     type="omotlp"
     endpoint="https://otel-collector:4318"
     path="/v1/logs"
     protocol="http/json"
     template="RSYSLOG_SyslogProtocol23Format"
     batch.max_items="200"
     batch.max_bytes="262144"
     batch.timeout.ms="2000"
     compression="gzip"
     retry.max_retries="7"
     retry.max.ms="45000"
     headers='{ "X-OTel-Tenant": "blue" }'
     bearer_token="${env:OTEL_TOKEN}"
   )

OTLP Payload Structure
----------------------

The module generates OTLP/HTTP JSON payloads conforming to the OpenTelemetry
log data model. Each batch wraps log records in the following hierarchy:

**Resource attributes** (per-batch, automatically populated):

.. csv-table::
   :header: "Attribute", "Value"
   :widths: auto

   "``service.name``", "``rsyslog``"
   "``telemetry.sdk.name``", "``rsyslog-omotlp``"
   "``telemetry.sdk.language``", "``C``"
   "``telemetry.sdk.version``", "rsyslog version string"
   "``host.name``", "hostname (only if uniform across all records in batch)"

**Scope metadata** (per-batch):

.. csv-table::
   :header: "Field", "Value"
   :widths: auto

   "``scope.name``", "``rsyslog.omotlp``"
   "``scope.version``", "rsyslog version string"

**Per-record attributes** (derived from syslog metadata):

.. csv-table::
   :header: "Attribute", "Source"
   :widths: auto

   "``log.syslog.appname``", "syslog APP-NAME field"
   "``log.syslog.procid``", "syslog PROCID field"
   "``log.syslog.msgid``", "syslog MSGID field"
   "``log.syslog.facility``", "syslog facility code (integer)"
   "``log.syslog.hostname``", "syslog HOSTNAME field"

**Per-record fields**:

- ``body.stringValue``: rendered template output
- ``timeUnixNano``: message timestamp in nanoseconds
- ``observedTimeUnixNano``: reception timestamp in nanoseconds
- ``severityNumber``: mapped OTLP severity (see table below)
- ``severityText``: severity name string

All of the attributes and fields above are emitted for every record; values are
only omitted when the originating syslog message does not carry the associated
property (for example, when ``APP-NAME`` is empty).

Severity Mapping
^^^^^^^^^^^^^^^^

Syslog priority values are mapped to OTLP severity numbers following the
OpenTelemetry semantic conventions:

.. csv-table::
   :header: "Syslog Priority", "OTLP SeverityNumber", "OTLP SeverityText"
   :widths: auto

   "0 (Emergency)", "24", "EMERGENCY"
   "1 (Alert)", "23", "ALERT"
   "2 (Critical)", "22", "CRITICAL"
   "3 (Error)", "17", "ERROR"
   "4 (Warning)", "13", "WARNING"
   "5 (Notice)", "11", "NOTICE"
   "6 (Info)", "9", "INFO"
   "7 (Debug)", "5", "DEBUG"

Implementation status
---------------------

The module is being implemented in phases. The checklist below tracks the
original build plan and the current status of each item:

* ✅ Configuration plumbing, environment-variable defaults, and JSON payload
  assembly helpers are in place.
* ✅ HTTP/JSON transport now batches records, applies optional gzip compression,
  and retries transient collector failures with jittered backoff.
* ✅ Shell regression coverage validates batching, gzip, and retry behaviour.
* ⏳ Optional gRPC façade and HTTP/protobuf variants remain unimplemented.

Roadmap
-------

The remaining work mirrors the outstanding checklist items above. Upcoming
patches will focus on the optional gRPC façade, the HTTP/protobuf fast-path, and
any feedback-driven refinements that stem from preview deployments.
