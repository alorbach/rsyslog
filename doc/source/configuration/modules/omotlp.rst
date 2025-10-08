.. _omotlp:

OTLP Output Module
==================

.. currentmodule:: omotlp

The **omotlp** output module exports rsyslog messages as OpenTelemetry Logs via the OpenTelemetry Protocol (OTLP). This module implements the OTLP/HTTP with JSON payloads specification.

Module Configuration Parameters
--------------------------------

.. function:: module(load="omotlp")

   Loads the omotlp module.

Action Configuration Parameters
-------------------------------

.. function:: action(type="omotlp" ...)

   Exports messages to an OTLP endpoint.

**Required Parameters**

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter
     - Type
     - Description
   * - endpoint
     - string
     - OTLP endpoint URL (e.g., ``http://otel-collector:4318``)

**Optional Parameters**

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter
     - Type
     - Default
     - Description
   * - protocol
     - string
     - ``"http/json"``
     - Protocol to use (currently only ``"http/json"`` is supported)
   * - path
     - string
     - ``"/v1/logs"``
     - HTTP path for the OTLP endpoint
   * - bearer_token
     - string
     - none
     - Bearer token for authentication
   * - compression
     - string
     - ``"none"``
     - Compression method (``"none"`` or ``"gzip"``)
   * - proxy
     - string
     - none
     - HTTP proxy URL
   * - ca_file
     - string
     - none
     - Path to CA certificate file for TLS verification
   * - cert_file
     - string
     - none
     - Path to client certificate file for mTLS
   * - key_file
     - string
     - none
     - Path to client private key file for mTLS
   * - verify_ssl
     - boolean
     - ``true``
     - Whether to verify SSL certificates
   * - timeout_ms
     - integer
     - ``30000``
     - Request timeout in milliseconds

**Batching Parameters**

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter
     - Type
     - Default
     - Description
   * - batch.max_items
     - integer
     - ``512``
     - Maximum number of messages per batch
   * - batch.max_bytes
     - integer
     - ``1048576`` (1MB)
     - Maximum batch size in bytes
   * - batch.timeout_ms
     - integer
     - ``5000``
     - Maximum time to wait before flushing incomplete batches

**Retry Parameters**

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter
     - Type
     - Default
     - Description
   * - retry.max_retries
     - integer
     - ``5``
     - Maximum number of retry attempts
   * - retry.initial_ms
     - integer
     - ``1000``
     - Initial retry delay in milliseconds
   * - retry.max_ms
     - integer
     - ``30000``
     - Maximum retry delay in milliseconds
   * - retry.jitter
     - float
     - ``0.1``
     - Jitter factor for retry delays (0.0 to 1.0)

**Data Mapping Parameters**

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Parameter
     - Type
     - Default
     - Description
   * - resource
     - string
     - ``{"service.name":"rsyslog","service.version":"8.2510.0"}``
     - JSON string defining resource attributes
   * - attribute_map
     - string
     - none
     - JSON string mapping rsyslog properties to OTLP attributes
   * - severity_map
     - string
     - none
     - JSON string defining custom severity mapping
   * - body_template
     - string
     - ``RSYSLOG_TraditionalFileFormat``
     - Template for the log record body
   * - trace_id_prop
     - string
     - none
     - Property name containing trace ID (hex string)
   * - span_id_prop
     - string
     - none
     - Property name containing span ID (hex string)
   * - trace_flags_prop
     - string
     - none
     - Property name containing trace flags (hex string)

Examples
--------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: rsyslog

   module(load="omotlp")

   action(type="omotlp"
          endpoint="http://otel-collector:4318"
          bearer_token="${env:OTEL_TOKEN}"
          batch.max_items="512"
          compression="gzip")

Configuration with Custom Resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: rsyslog

   module(load="omotlp")

   action(type="omotlp"
          endpoint="https://otel-collector.example.com:4318"
          bearer_token="${env:OTEL_TOKEN}"
          resource='{"service.name":"my-app","service.version":"1.2.3","service.environment":"production"}'
          batch.max_items="100"
          batch.timeout_ms="2000"
          retry.max_retries="3"
          verify_ssl="true"
          ca_file="/etc/ssl/certs/ca-certificates.crt")

Configuration with Trace Correlation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: rsyslog

   module(load="omotlp")

   action(type="omotlp"
          endpoint="http://otel-collector:4318"
          trace_id_prop="trace_id"
          span_id_prop="span_id"
          trace_flags_prop="trace_flags"
          attribute_map='{"custom.field":"%msg:F:10:2%"}')

Data Mapping
------------

The module automatically maps rsyslog message properties to OTLP LogRecord fields:

**Timestamp Mapping**

- ``time_unix_nano``: rsyslog event timestamp in nanoseconds

**Severity Mapping**

The module maps syslog severity levels to OTLP severity numbers and texts:

.. list-table::
   :header-rows: 1
   :widths: 20 20 20

   * - Syslog Severity
     - OTLP Severity Number
     - OTLP Severity Text
   * - 0 (Emergency)
     - 2
     - TRACE2
   * - 1 (Alert)
     - 21
     - FATAL
   * - 2 (Critical)
     - 20
     - ERROR4
   * - 3 (Error)
     - 17
     - ERROR
   * - 4 (Warning)
     - 13
     - WARN
   * - 5 (Notice)
     - 9
     - INFO
   * - 6 (Info)
     - 5
     - DEBUG
   * - 7 (Debug)
     - 1
     - TRACE

**Attribute Mapping**

The module automatically adds the following attributes:

.. list-table::
   :header-rows: 1
   :widths: 25 25 50

   * - Attribute
     - Source
     - Description
   * - ``syslog.facility``
     - ``$!facility``
     - Syslog facility number
   * - ``syslog.severity``
     - ``$!severity``
     - Syslog severity number
   * - ``syslog.priority``
     - ``$!priority``
     - Syslog priority (facility * 8 + severity)
   * - ``host.name``
     - ``$!hostname``
     - Hostname (if available)
   * - ``syslog.app_name``
     - ``$!app-name``
     - Application name (if available)
   * - ``syslog.procid``
     - ``$!procid``
     - Process ID (if available)
   * - ``syslog.msgid``
     - ``$!msgid``
     - Message ID (if available)

**Trace Correlation**

If trace correlation properties are configured, the module will add:

- ``trace_id``: Trace ID from the specified property (hex string)
- ``span_id``: Span ID from the specified property (hex string)
- ``trace_flags``: Trace flags from the specified property (hex string)

Environment Variables
---------------------

The module supports OpenTelemetry environment variable conventions for configuration:

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Environment Variable
     - Parameter
     - Description
   * - ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``
     - ``endpoint``
     - OTLP endpoint URL
   * - ``OTEL_EXPORTER_OTLP_LOGS_PROTOCOL``
     - ``protocol``
     - Protocol (http/json)
   * - ``OTEL_EXPORTER_OTLP_LOGS_HEADERS``
     - ``headers``
     - Additional headers (comma-separated)
   * - ``OTEL_EXPORTER_OTLP_LOGS_COMPRESSION``
     - ``compression``
     - Compression method
   * - ``OTEL_EXPORTER_OTLP_TIMEOUT``
     - ``timeout_ms``
     - Request timeout

**Note:** Action parameters take precedence over environment variables, which take precedence over module defaults.

Statistics and Monitoring
-------------------------

The module exposes the following statistics counters:

- ``sent``: Number of messages successfully sent
- ``retried``: Number of messages retried due to failures
- ``dropped``: Number of messages dropped due to permanent failures
- ``http_2xx``: Number of successful HTTP responses (200-299)
- ``http_4xx``: Number of client error responses (400-499)
- ``http_5xx``: Number of server error responses (500-599)

Statistics can be monitored using the ``impstats`` module:

.. code-block:: rsyslog

   module(load="impstats"
          interval="60"
          log.file="/var/log/rsyslog/omotlp-stats.log"
          log.syslog="off")

Troubleshooting
---------------

**Common Issues**

1. **Connection refused**: Verify the OTLP collector endpoint is reachable and the port is correct.

2. **TLS/SSL errors**: Check certificate paths and ensure ``verify_ssl`` is set appropriately for your environment.

3. **Authentication failures**: Verify the bearer token is correct and not expired.

4. **Large message drops**: Increase ``batch.max_bytes`` if messages are being dropped due to size limits.

5. **Timeout errors**: Increase ``timeout_ms`` for slow networks or large batches.

**Debug Logging**

Enable debug logging to troubleshoot issues:

.. code-block:: rsyslog

   global(debug.on="yes"
          debug.level="2"
          debug.file="/var/log/rsyslog/debug.log")

**Testing Configuration**

The module includes comprehensive tests using the official OpenTelemetry Collector for validation. The test setup uses Docker to run a collector instance that receives OTLP data and validates the payload structure.

**Test Setup**

The test creates an OpenTelemetry Collector with the following configuration:

.. code-block:: yaml

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

**Running Tests**

.. code-block:: bash

   # Run HTTP protocol tests
   ./tests/omotlp-basic.sh

   # Run gRPC protocol tests (Phase 2)
   ./tests/omotlp-grpc.sh

The tests validate:

- Proper OTLP JSON/Protobuf payload structure
- Correct field mapping from syslog to OTLP
- Statistics reporting accuracy
- Error handling and retry logic

Compatibility
-------------

- **rsyslog version**: 8.2510.0 and later
- **OTLP specification**: v1.21.0
- **HTTP methods**: POST
- **Content-Type**: ``application/json``
- **Compression**: gzip (optional)
- **TLS support**: Yes, with mTLS support

See Also
--------

- :doc:`../concepts/modules`
- :doc:`../configuration/actions`
- :doc:`../configuration/templates`
- `OpenTelemetry Protocol Specification <https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/otlp.md>`_