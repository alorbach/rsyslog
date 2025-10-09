.. _module-omotlp:

.. meta::
   :description: Scaffolding for the omotlp OpenTelemetry output module.
   :keywords: omotlp, otlp, opentelemetry, rsyslog module

.. summary-start

Initial HTTP/JSON implementation of the omotlp output plugin, which now posts
OpenTelemetry payloads to collectors while batching, compression, and retry
controls remain under development.

.. summary-end

omotlp: OpenTelemetry output module (preview)
=============================================

.. warning::

   The current build streams each log record immediately via OTLP/HTTP JSON.
   Advanced features such as batching, gzip compression, and configurable
   retry/backoff policies are still in progress. Plan capacity accordingly and
   keep action queues enabled so rsyslog can absorb collector outages.

Overview
--------

``omotlp`` prepares rsyslog for native :abbr:`OTLP (OpenTelemetry Log Protocol)`
exports. The module currently supports the OTLP/HTTP JSON transport path: it
maps rsyslog metadata into the canonical OTLP JSON structure, joins the
configured endpoint and path, and posts each rendered payload via ``libcurl``
using ``application/json`` semantics. Subsequent phases will extend the module
with batching, retry controls, optional compression, and the gRPC façade.

Availability
------------

The module is built when ``--enable-omotlp`` is left at its default ``auto``
value and the configure script detects both ``libcurl`` and ``libfastjson``.
Explicitly request the module with ``--enable-omotlp=yes`` or disable it with
``--enable-omotlp=no``. The HTTP transport depends on ``libcurl`` at runtime.

Configuration
-------------

The action parameters listed below mirror the initial transport design. All
parameters are optional and fall back to the OpenTelemetry defaults described in
`OTLP specification <https://opentelemetry.io/docs/specs/otlp/>`_.

.. csv-table:: ``omotlp`` action parameters
   :header: "Parameter", "Type", "Default", "Description"
   :widths: auto

   "endpoint", "string", "http://127.0.0.1:4318", "Base OTLP collector URL"
   "path", "string", "/v1/logs", "Request path appended to the endpoint"
   "protocol", "word", "http/json", "Intended transport variant"
   "template", "word", "RSYSLOG_FileFormat", "Message template used for the log body"

Requests use a 10-second timeout by default. Future revisions will expose this
value, along with batching and retry knobs, as additional parameters.

Environment variables that originate from the OpenTelemetry specification are
consulted when the configuration omits explicit values. ``endpoint`` falls back
to ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` and then
``OTEL_EXPORTER_OTLP_ENDPOINT`` if set; ``protocol`` follows the matching
``*_PROTOCOL`` variables. The action parameters always take precedence, giving
operators an easy override when reusing existing collector deployments.

When the endpoint string includes an explicit path (for example,
``https://otel:4318/v1/logs``), the module automatically splits the final path
segment into the ``path`` parameter so that future HTTP transport code can join
the pieces without duplicating ``/v1/logs``.

Example
-------

The example below sends each message to the default OTLP HTTP collector using
the JSON encoding. Retrying relies on rsyslog's built-in action queues: HTTP
status codes ``429`` and ``5xx`` trigger ``RS_RET_SUSPENDED`` so queued records
are retried according to the queue settings, while other non-success responses
discard the message and log an error.

.. code-block:: none

   module(load="omotlp")
   action(
     type="omotlp"
     endpoint="https://otel-collector:4318"
     path="/v1/logs"
     protocol="http/json"
     template="RSYSLOG_SyslogProtocol23Format"
   )

Implementation status
---------------------

The module is being implemented in phases. The checklist below tracks the
original build plan and the current status of each item:

* ✅ Configuration plumbing, environment-variable defaults, and JSON payload
  assembly helpers are in place.
* ✅ Basic HTTP/JSON transport is active. Each event is delivered immediately
  with simple status-based retry/drop handling; batching, compression, and
  shell tests remain outstanding.
* ⏳ Optional gRPC façade and HTTP/protobuf variants remain unimplemented.

Roadmap
-------

The remaining work mirrors the outstanding checklist items above. Upcoming
patches will focus on the transport stack, batching policies, retry handling,
and the optional gRPC integration.
