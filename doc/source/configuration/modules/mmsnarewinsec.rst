mmsnarewinsec - NXLog Snare Windows Security parser
===================================================

The ``mmsnarewinsec`` parser module extracts structured metadata from NXLog
Snare-formatted Windows Security events that are transported inside RFC3164 or
RFC5424 envelopes. It was designed using Windows Server 2016 through Windows
Server 2025 samples and preserves the original payload while exposing a
normalized JSON view under a configurable container (``!win`` by default).

The module has been enhanced with a comprehensive, pattern-based field detection
system that can handle the full spectrum of Windows Security events. This
enhancement replaces the previous hardcoded field matching with a flexible,
configurable system supporting 153 field patterns across all event categories.

Highlights
----------

* Supports classic tab-delimited ``MSWinEventLog`` payloads as well as the
  Snare JSON variant (``MSWinEventLog\t0\t{...}``).
* Derives event-level metadata such as event IDs (with integer promotion when
  possible), provider, NXLog event type, channel, computer, and RFC 3339
  timestamps, and maps high-value event IDs to semantic categories
  (``4624``, ``4625``, ``4672``, ``4688``, ``4768``, ``4769``, ``4771``,
  ``5140``, ``5157``, ``6281``, ``1102``, ``1243``) while populating derived
  ``Category``, ``Subtype``, and ``Outcome`` fields.
* Interprets well-known sections (Subject, Logon Information, New Logon,
  Network Information, Process Information, Detailed Authentication
  Information, Account For Which Logon Failed, Failure Information, Application
  Information, Filter Information, Share Information, Additional Information,
  Certificate Information) and exposes their fields as nested objects such as
  ``!win!Subject!AccountName`` or ``!win!Network!SourceNetworkAddress``.
* Recognizes modern Windows telemetry blocks:

  * **LAPS Context** -> ``!win!LAPS!PolicyVersion``,
    ``!win!LAPS!CredentialRotation``
  * **TLS Inspection** -> ``!win!TLSInspection!Reason``,
    ``!win!TLSInspection!Policy``
  * **WDAC Enforcement** -> ``!win!WDAC!PolicyName``,
    ``!win!WDAC!PolicyVersion``, ``!win!WDAC!EnforcementMode``
  * **WUFB Deployment** -> ``!win!WUFB!PolicyID``, ``!win!WUFB!Ring``,
    ``!win!WUFB!EnforcementResult``
  * Remote Credential Guard surface (``!win!Logon!RemoteCredentialGuard``)

* Performs lookup translation for logon type codes, deriving
  ``LogonTypeName`` strings, and emits boolean interpretations for Remote
  Credential Guard and LAPS credential rotation indicators.
* Stores any unmapped segments in ``!win!Unparsed`` to ensure the payload is
  preserved for later review.

Enhanced Field Detection System
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The enhanced module provides:

* **Pattern-Based Field Detection**: Uses 153 configurable patterns instead of hardcoded string matching
* **Comprehensive Coverage**: Handles all 439 Windows Security events across 12 categories
* **Type-Aware Parsing**: Automatically detects and parses different data types (strings, integers, booleans, GUIDs, IP addresses, timestamps, JSON objects)
* **Priority-Based Matching**: Uses priority-based pattern matching (1-5 levels) for accurate field detection
* **Enhanced Error Handling**: Comprehensive validation and error handling with multiple validation modes
* **Runtime Configuration**: Support for runtime configuration of field mappings and behaviors
* **Performance Optimization**: Efficient pattern matching with statistics tracking

**Supported Data Types:**
* **FIELD_STRING**: Standard text fields with automatic trimming and validation
* **FIELD_INTEGER**: Numeric values with automatic parsing and fallback to string
* **FIELD_BOOLEAN**: Boolean values supporting true/false, yes/no, enabled/disabled, 1/0
* **FIELD_GUID**: GUID format detection and validation ({XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
* **FIELD_IP_ADDRESS**: IP address format detection (IPv4)
* **FIELD_TIMESTAMP**: Timestamp format detection (ISO 8601 and day-of-week formats)
* **FIELD_JSON_OBJECT**: JSON object format detection (objects and arrays)

**Field Categories with Priority Levels:**
* **Subject Fields** (Priority 100): Security ID, Account Name, Account Domain, Logon ID
* **Logon Information Fields** (Priority 95): Logon Type, Restricted Admin Mode, Virtual Account, Elevated Token, Impersonation Level
* **New Logon Fields** (Priority 90): Security ID, Account Name, Account Domain, Logon ID, Logon GUID
* **Network Information Fields** (Priority 85): Workstation Name, Source/Destination Addresses and Ports, Protocol, Direction
* **Process Information Fields** (Priority 80): Process ID, Process Name, Command Line, Token Elevation Type, Mandatory Label
* **Authentication Fields** (Priority 75): Logon Process, Authentication Package, Transited Services, Key Length, Remote Credential Guard
* **Failure Information Fields** (Priority 70): Failure Reason, Status, Sub Status
* **Specialized Fields**: WDAC (Priority 65), WUFB (Priority 60), Kerberos (Priority 55), LAPS (Priority 50), TLS (Priority 45), Filter (Priority 40)

Build & Runtime Requirements
-----------------------------

* No external libraries beyond the rsyslog core dependencies (libfastjson is
  already required by rsyslog).
* Tested against NXLog Snare output for Windows Server 2016, 2019, 2022, and the
  2025.
* Runs safely with multiple worker threads; configuration is immutable and each
  worker keeps its own scratch buffers.

JSON Field Overview
-------------------

The module emits a hierarchical JSON document under the configured root path. Key
nodes include:

* ``Event`` — Record metadata (log, record number, event ID, computer, timestamps,
  audit outcome, mapping category/subtype).
* ``Subject``, ``Logon``, ``NewLogon`` — Authentication identity details.
* ``Network`` — Source/destination addresses and ports (supports client address
  fields in Kerberos events).
* ``Process`` and ``Application`` — Process identifiers, names, command line data.
* ``Authentication`` — Logon process, packages, Remote Credential Guard status.
* ``Failure`` — Failure reason, status, sub-status for rejected logons.
* ``Privileges`` — Array of privileges assigned to special logon events.
* ``Kerberos`` — Account, service, additional, and certificate information for
  Kerberos ticket events.
* ``LAPS``, ``TLS``, ``WDAC``, ``WUFB`` — Dedicated blocks for modern telemetry
  (LAPS context, TLS inspection, Windows Defender Application Control, Windows
  Update for Business deployment events).
* ``Payload.Raw`` — Original message body without the syslog header.
* ``Payload.Unparsed`` — Catch-all array for any sections the module could not map
  with the current release.

Event ID Mapping
----------------

.. csv-table::
   :header: "Event ID", "Category", "Subtype", "Outcome"
   :widths: auto

   "4624", "Logon", "Success", "success"
   "4625", "Logon", "Failure", "failure"
   "4672", "Privilege", "Assignment", "success"
   "4688", "Process", "Creation", "success"
   "4768", "Kerberos", "TGTRequest", ""
   "4769", "Kerberos", "ServiceTicket", ""
   "4771", "Kerberos", "PreAuthFailure", ""
   "5140", "FileShare", "Access", ""
   "5157", "FilteringPlatform", "PacketDrop", "failure"
   "6281", "WDAC", "Enforcement", ""
   "1102", "Audit", "LogCleared", ""
   "1243", "WindowsUpdate", "Deployment", ""

Event IDs 4624, 4625, 4672, 4688, 4768–4771, 5140, 5157, 6281, 1102, 1243
and others are mapped to ``Event.Category``, ``Event.Subtype``, and
``Event.Outcome`` for quick filtering.

* Logon type codes are translated to ``Logon.TypeName``.
* NTSTATUS and Kerberos result codes are preserved in hex form; additional maps
  can be added easily in ``mmsnarewinsec.c``.
* Timestamps are normalised to ISO 8601 UTC using the rsyslog message timestamp
  if the payload does not contain a parseable value.

Error Handling & Observability
------------------------------

* Invalid or partial payloads are routed to ``Payload.Unparsed`` and flagged via
  the ``partial`` counter in the instance's impstats object.
* Parse failures increment the ``failed`` counter and can be redirected by a
  secondary action when ``$parsesuccess`` evaluates to anything other than ``OK``.
* Enable ``debugjson="on"`` to capture the tokenizer output or JSON text for
  troubleshooting.

Configuration
-------------

Basic Configuration with Error Handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

   module(load="imtcp")
   module(load="omfile")
   module(load="mmsnarewinsec")

   template(name="snareWin" type="string" string="%!win%\n")
   input(type="imtcp" port="5514")

   action(type="mmsnarewinsec"
          container="!win"
          enable.network="on"
          enable.laps="on"
          enable.tls="on"
          enable.wdac="on")
   if $parsesuccess == "OK" then {
       action(type="omfile" file="/var/log/winsec.json" template="snareWin")
   } else {
       action(type="omfile" file="/var/log/winsec.parsefail" template="RSYSLOG_DebugFormat")
   }

JSON Template Output for SIEM Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This configuration extracts specific fields into a structured JSON format suitable for SIEM platforms:

.. code-block:: none

   module(load="mmsnarewinsec")

   template(name="jsonfmt" type="list" option.jsonf="on") {
     property(outname="EventID" name="$!win!Event!EventID" format="jsonf")
     property(outname="LogonType" name="$!win!LogonInformation!LogonType" format="jsonf")
     property(outname="LogonTypeName" name="$!win!LogonInformation!LogonTypeName" format="jsonf")
     property(outname="LAPSPolicyVersion" name="$!win!LAPS!PolicyVersion" format="jsonf")
     property(outname="LAPSCredentialRotation" name="$!win!LAPS!CredentialRotation" format="jsonf")
     property(outname="TLSReason" name="$!win!TLSInspection!Reason" format="jsonf")
     property(outname="WDACPolicyVersion" name="$!win!WDAC!PolicyVersion" format="jsonf")
     property(outname="WUFBPolicyID" name="$!win!WUFB!PolicyID" format="jsonf")
   }

   action(type="mmsnarewinsec")
   action(type="omfile" file="/var/log/winsec.json" template="jsonfmt")

Comprehensive Field Extraction with Ruleset
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This configuration demonstrates comprehensive field extraction using a ruleset approach, suitable for detailed analysis and compliance reporting:

.. code-block:: none

   module(load="imtcp")
   module(load="mmsnarewinsec")

   # Template to extract comprehensive structured JSON output
   template(name="jsonfmt" type="list" option.jsonf="on") {
       # Event fields
       property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
       property(outname="channel" name="$!win!Event!Channel" format="jsonf")
       property(outname="eventtype" name="$!win!Event!EventType" format="jsonf")
       property(outname="categorytext" name="$!win!Event!CategoryText" format="jsonf")
       property(outname="computer" name="$!win!Event!Computer" format="jsonf")
       property(outname="provider" name="$!win!Event!Provider" format="jsonf")
       
       # Subject fields
       property(outname="subjectsecurityid" name="$!win!Subject!SecurityID" format="jsonf")
       property(outname="subjectaccountname" name="$!win!Subject!AccountName" format="jsonf")
       property(outname="subjectaccountdomain" name="$!win!Subject!AccountDomain" format="jsonf")
       property(outname="subjectlogonid" name="$!win!Subject!LogonID" format="jsonf")
       
       # LogonInformation fields
       property(outname="logontype" name="$!win!LogonInformation!LogonType" format="jsonf")
       property(outname="logontypename" name="$!win!LogonInformation!LogonTypeName" format="jsonf")
       property(outname="restrictedadminmode" name="$!win!LogonInformation!RestrictedAdminMode" format="jsonf")
       property(outname="virtualaccount" name="$!win!LogonInformation!VirtualAccount" format="jsonf")
       property(outname="elevatedtoken" name="$!win!LogonInformation!ElevatedToken" format="jsonf")
       property(outname="impersonationlevel" name="$!win!LogonInformation!ImpersonationLevel" format="jsonf")
       
       # NewLogon fields
       property(outname="newlogonsecurityid" name="$!win!NewLogon!SecurityID" format="jsonf")
       property(outname="newlogonaccountname" name="$!win!NewLogon!AccountName" format="jsonf")
       property(outname="newlogonaccountdomain" name="$!win!NewLogon!AccountDomain" format="jsonf")
       property(outname="newlogonlogonid" name="$!win!NewLogon!LogonID" format="jsonf")
       property(outname="linkedlogonid" name="$!win!NewLogon!LinkedLogonID" format="jsonf")
       property(outname="networkaccountname" name="$!win!NewLogon!NetworkAccountName" format="jsonf")
       property(outname="logonguid" name="$!win!NewLogon!LogonGUID" format="jsonf")
       
       # Process fields
       property(outname="processid" name="$!win!Process!ProcessID" format="jsonf")
       property(outname="processname" name="$!win!Process!ProcessName" format="jsonf")
       property(outname="processcommandline" name="$!win!Process!ProcessCommandLine" format="jsonf")
       property(outname="tokenelevationtype" name="$!win!Process!TokenElevationType" format="jsonf")
       property(outname="mandatorylabel" name="$!win!Process!MandatoryLabel" format="jsonf")
       
       # Network fields
       property(outname="workstationname" name="$!win!Network!WorkstationName" format="jsonf")
       property(outname="sourcenetworkaddress" name="$!win!Network!SourceNetworkAddress" format="jsonf")
       property(outname="sourceport" name="$!win!Network!SourcePort" format="jsonf")
       
       # DetailedAuthentication fields
       property(outname="logonprocess" name="$!win!DetailedAuthentication!LogonProcess" format="jsonf")
       property(outname="authenticationpackage" name="$!win!DetailedAuthentication!AuthenticationPackage" format="jsonf")
       property(outname="transitedservices" name="$!win!DetailedAuthentication!TransitedServices" format="jsonf")
       property(outname="packagename" name="$!win!DetailedAuthentication!PackageName" format="jsonf")
       property(outname="keylength" name="$!win!DetailedAuthentication!KeyLength" format="jsonf")
       
       # Privileges fields
       property(outname="privilegelist" name="$!win!Privileges!PrivilegeList" format="jsonf")
   }

   ruleset(name="winsec") {
       action(type="mmsnarewinsec")
       action(type="omfile" file="/var/log/winsec.json" template="jsonfmt")
   }

   input(type="imtcp" port="5514" ruleset="winsec")

Parameters
----------

.. csv-table::
   :header: "Parameter", "Type", "Default", "Description"
   :widths: auto
   :class: parameter-table

   "``container``", "string", "``!win``", "JSON container path that receives the parsed structure."
   "``enable.network``", "binary", "``on``", "Toggle extraction for ``Network Information`` blocks."
   "``enable.laps``", "binary", "``on``", "Toggle parsing of ``LAPS Context`` sections."
   "``enable.tls``", "binary", "``on``", "Toggle parsing of ``TLS Inspection`` sections."
   "``enable.wdac``", "binary", "``on``", "Toggle WDAC enrichment (``Policy Name``, ``Policy Version``, etc.)."
   "``emit.rawpayload``", "binary", "``on``", "When enabled, stores the original payload in ``!win!Raw`` (or ``!win!RawJSON`` for Snare JSON records)."
   "``emit.debugjson``", "binary", "``off``", "Adds an empty ``Unparsed`` array even when all sections are recognized, simplifying downstream assertions."

Extracted fields
----------------

A non-exhaustive list of notable properties exposed by the module:

* ``!win!Event!EventID`` (or ``EventIDRaw`` for non-numeric identifiers),
  ``!win!Event!Provider``, ``!win!Event!EventType``, ``!win!Event!Channel``,
  ``!win!Event!Computer``, ``!win!Event!CategoryText``, ``!win!Event!Category``,
  ``!win!Event!Subtype``, ``!win!Event!Outcome``, ``!win!Event!Level`` (for
  Snare JSON payloads), and ``!win!Event!RecordNumberRaw`` when a
  ``System.EventRecordID`` value is present.
* ``!win!Event!TimeCreated!Normalized`` (derived from the syslog envelope) and
  ``!win!Event!TimeCreated!Raw`` when Snare JSON payloads include an
  ``EventTime``.
* ``!win!Subject!SecurityID``, ``!win!Subject!AccountName``,
  ``!win!Subject!AccountDomain``, ``!win!Subject!LogonID``
* ``!win!LogonInformation!LogonType``, ``!win!LogonInformation!LogonTypeName``,
  ``!win!LogonInformation!VirtualAccount``,
  ``!win!LogonInformation!ElevatedToken``,
  ``!win!LogonInformation!RemoteCredentialGuard`` (with an aggregated
  ``!win!Logon!RemoteCredentialGuard`` boolean)
* ``!win!NewLogon!SecurityID``, ``!win!NewLogon!AccountName``,
  ``!win!NewLogon!LogonGUID``
* ``!win!Network!SourceNetworkAddress``, ``!win!Network!SourcePort``,
  ``!win!Network!DestinationAddress``, ``!win!Network!DestinationPort``
* ``!win!Process!ProcessID``, ``!win!Process!ProcessName``
* ``!win!Failure!FailureReason``, ``!win!Failure!Status``,
  ``!win!Failure!SubStatus``
* ``!win!DetailedAuthentication!LogonProcess``,
  ``!win!DetailedAuthentication!AuthenticationPackage``,
  ``!win!DetailedAuthentication!TransitedServices``,
  ``!win!DetailedAuthentication!PackageName``,
  ``!win!DetailedAuthentication!KeyLength``
* ``!win!Privileges`` (retains privilege enumerations for downstream review)
* ``!win!LAPS!PolicyVersion``, ``!win!LAPS!CredentialRotation``
* ``!win!TLSInspection!Reason``, ``!win!TLSInspection!Policy``
* ``!win!WDAC!PolicyName``, ``!win!WDAC!PolicyVersion``,
  ``!win!WDAC!EnforcementMode``, ``!win!WDAC!User``, ``!win!WDAC!PID``
* ``!win!WUFB!PolicyID``, ``!win!WUFB!Ring``, ``!win!WUFB!EnforcementResult``

Unknown fragments are preserved under ``!win!Unparsed`` to aid future
normalization efforts.

Error handling and observability
--------------------------------

* Residual tokens and unexpected sections are collected in ``!win!Unparsed``
  for follow-up analysis.
* Messages that do not contain an ``MSWinEventLog`` payload are ignored and
  ``$parsesuccess`` remains ``off``.
* When Snare JSON payloads cannot be parsed, the raw text is stored under
  ``!win!RawJSON`` so downstream tooling can inspect the failure.
* Optional raw payload storage (``emit.rawpayload``) simplifies error triage and
  regression analysis.

Testing
-------

The regression suite (``tests/mmsnarewinsec-basic.sh``,
``tests/mmsnarewinsec-json.sh``, ``tests/mmsnarewinsec-syslog.sh``,
``tests/mmsnarewinsec-comprehensive.sh``) replays canonical Windows Security
samples across Snare text, Snare JSON, and TCP/syslog delivery to ensure
extracted fields remain stable (for example, 4624 with LAPS, 5157 TLS
inspection, 6281 WDAC enforcement, and 1243 WUFB deployment).

Extending mappings
------------------

Event ID mappings and section recognition are driven by lookup tables at the
beginning of ``plugins/mmsnarewinsec/mmsnarewinsec.c``. New telemetry blocks can
be added by extending ``g_sectionDescriptors`` or by enhancing
``handle_general_key()`` to capture additional key/value pairs.


Troubleshooting
---------------

* Inspect ``$parsesuccess`` and the instance's impstats counters (``recordseen``,
  ``parsed``, ``partial``, ``failed``) to verify parsing behaviour.
* Use ``debugjson="on"`` to capture the tokenized description when new Windows
  releases add previously unknown sections; the raw block will appear under
  ``!win!Payload!Debug``.
* Extend section handlers or lookup tables in ``plugins/mmsnarewinsec/mmsnarewinsec.c`` when Microsoft introduces additional telemetry fields.
