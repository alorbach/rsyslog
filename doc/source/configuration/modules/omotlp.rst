.. _module-omotlp:

.. meta::
   :description: Scaffolding for the omotlp OpenTelemetry output module.
   :keywords: omotlp, otlp, opentelemetry, rsyslog module

.. summary-start

Initial scaffolding for the omotlp output plugin, which will export rsyslog
messages to OpenTelemetry collectors once transport support is implemented.

.. summary-end

omotlp: OpenTelemetry output module (preview)
=============================================

.. warning::

   The ``omotlp`` module is currently a skeleton implementation. It accepts
   configuration but does not yet forward messages. Additional phases will
   supply the HTTP/JSON and gRPC transports.

Overview
--------

``omotlp`` prepares rsyslog for native :abbr:`OTLP (OpenTelemetry Log Protocol)`
exports. The module introduces configuration hooks for the default OTLP HTTP
endpoint, request path, protocol selection, and body template that will shape
future transport integrations.

Availability
------------

The module is built when ``--enable-omotlp`` is left at its default ``auto``
value and the configure script detects both ``libcurl`` and ``libfastjson``.
Explicitly request the module with ``--enable-omotlp=yes`` or disable it with
``--enable-omotlp=no``. The skeleton does not currently link against the HTTP
stack, but the dependency probe is in place for upcoming phases.

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

The example below shows how to configure an action for the upcoming HTTP/JSON
transport. At the moment the module emits a single warning and drops messages,
which keeps existing pipelines safe while development continues.

.. code-block:: none

   module(load="omotlp")
   action(
     type="omotlp"
     endpoint="https://otel-collector:4318"
     path="/v1/logs"
     protocol="http/json"
     template="RSYSLOG_SyslogProtocol23Format"
   )

Roadmap
-------

The following milestones remain before ``omotlp`` becomes production ready:

* Serialize batches to the OTLP JSON structure with ``libfastjson``.
* Stream payloads to OTLP/HTTP collectors with ``libcurl`` including retry
  handling, TLS, and optional gzip compression.
* Add shell tests that validate happy-path exports and retry decisions.
* Document the gRPC façade and HTTP protobuf options introduced in later phases.
