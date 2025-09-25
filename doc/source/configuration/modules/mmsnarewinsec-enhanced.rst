Enhanced mmsnarewinsec Field Detection
========================================

The mmsnarewinsec module has been enhanced with a comprehensive, pattern-based field detection system that can handle the full spectrum of Windows Security events. This enhancement replaces the previous hardcoded field matching with a flexible, configurable system.

Overview
--------

The enhanced mmsnarewinsec module provides:

- **Pattern-Based Field Detection**: Uses configurable patterns instead of hardcoded string matching
- **Comprehensive Coverage**: Handles all 439 Windows Security events across 12 categories
- **Type-Aware Parsing**: Automatically detects and parses different data types (strings, integers, booleans, GUIDs, IP addresses, timestamps, JSON objects)
- **Priority-Based Matching**: Uses priority-based pattern matching for accurate field detection
- **Enhanced Error Handling**: Comprehensive validation and error handling with multiple validation modes
- **Runtime Configuration**: Support for runtime configuration of field mappings
- **Performance Optimization**: Efficient pattern matching with statistics tracking

Field Categories
----------------

The enhanced module supports comprehensive field detection across all Windows Security event categories:

**Subject Fields** (Priority 100)
- Security ID
- Account Name
- Account Domain
- Logon ID

**Logon Information Fields** (Priority 95)
- Logon Type
- Restricted Admin Mode
- Virtual Account
- Elevated Token
- Impersonation Level

**New Logon Fields** (Priority 90)
- Security ID
- Account Name
- Account Domain
- Logon ID
- Logon GUID

**Network Information Fields** (Priority 85)
- Workstation Name
- Source Network Address
- Source Port
- Client Address
- Client Port
- Destination Address
- Destination Port
- Protocol
- Direction

**Process Information Fields** (Priority 80)
- Process ID
- Process Name
- Caller Process ID
- Caller Process Name
- New Process ID
- New Process Name
- Token Elevation Type
- Mandatory Label
- Creator Process ID
- Creator Process Name
- Process Command Line

**Authentication Fields** (Priority 75)
- Logon Process
- Authentication Package
- Transited Services
- Package Name (NTLM only)
- Key Length
- Remote Credential Guard

**Failure Information Fields** (Priority 70)
- Failure Reason
- Status
- Sub Status

**Specialized Fields**
- **WDAC Fields** (Priority 65): Policy Name, Policy Version, Enforcement Mode, User, PID
- **WUFB Fields** (Priority 60): Policy ID, Ring, From Service, Enforcement Result
- **Kerberos Fields** (Priority 55): Service Name, Service ID, Ticket Options, Result Code, Ticket Encryption Type, Pre-Authentication Type, Certificate Information
- **LAPS Fields** (Priority 50): Policy Version, Credential Rotation
- **TLS Fields** (Priority 45): Reason, Policy
- **Filter Fields** (Priority 40): Filter Run-Time ID, Layer Name, Layer Run-Time ID

Data Types
----------

The enhanced module supports automatic type detection and parsing:

**FIELD_STRING**
- Standard text fields
- Automatically trimmed and validated

**FIELD_INTEGER**
- Numeric values with automatic parsing
- Falls back to string if parsing fails

**FIELD_BOOLEAN**
- Boolean values with enhanced parsing
- Supports: true/false, yes/no, enabled/disabled, 1/0

**FIELD_GUID**
- GUID format detection and validation
- Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}

**FIELD_IP_ADDRESS**
- IP address format detection
- Supports IPv4 addresses

**FIELD_TIMESTAMP**
- Timestamp format detection
- Supports ISO 8601 and day-of-week formats

**FIELD_JSON_OBJECT**
- JSON object format detection
- Supports both objects and arrays

Configuration
-------------

The enhanced module supports runtime configuration through the following parameters:

.. code-block:: none

   action(type="mmsnarewinsec" 
          rootpath="!win"
          enablesections="all"
          debugjson="on"
          template="enhanced_json")

**Parameters:**

- **rootpath**: Target container for parsed JSON output (default: "!win")
- **enablesections**: Comma-separated list of sections to enable (default: "all")
- **debugjson**: Enable debug JSON output (default: "off")
- **template**: Template to use for output formatting

**Available Sections:**
- Subject
- Logon
- NewLogon
- Network
- Process
- Authentication
- Failure
- WDAC
- WUFB
- Kerberos
- LAPS
- TLS
- Filter
- EventData

Validation Modes
----------------

The enhanced module supports three validation modes:

**VALIDATION_STRICT** (Default)
- Strict validation, fail on any error
- Ensures data integrity
- Recommended for production environments

**VALIDATION_MODERATE**
- Moderate validation, log warnings
- Continues processing with warnings
- Good for development and testing

**VALIDATION_PERMISSIVE**
- Permissive validation, attempt to parse anyway
- Maximum compatibility
- Useful for legacy or malformed data

Performance Features
--------------------

The enhanced module includes comprehensive performance tracking:

- **Field Processing Statistics**: Total fields processed, successfully parsed, failed parsing
- **Section Detection Metrics**: Sections detected, parsing errors
- **Pattern Matching Performance**: Pattern matches, fallback fields
- **Memory Usage Optimization**: Efficient pattern matching with minimal memory overhead

Testing
-------

The enhanced module includes comprehensive test coverage:

**Basic Field Detection Test**
.. code-block:: bash
   tests/mmsnarewinsec-enhanced-field-detection.sh

**Account Management Test**
.. code-block:: bash
   tests/mmsnarewinsec-account-management.sh

**Pattern Detection Test**
.. code-block:: bash
   tests/mmsnarewinsec-pattern-detection.sh

**Comprehensive Validation Test**
.. code-block:: bash
   tests/mmsnarewinsec-comprehensive-validation.sh

**Configuration Test**
.. code-block:: bash
   tests/mmsnarewinsec-configuration.sh

**Performance Test**
.. code-block:: bash
   tests/mmsnarewinsec-performance.sh

Example Usage
-------------

**Basic Configuration:**
.. code-block:: none

   module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")
   
   template(name="enhanced_json" type="list" option.jsonf="on") {
       property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
       property(outname="subject" name="$!win!Subject" format="jsonf")
       property(outname="logon" name="$!win!Logon" format="jsonf")
       property(outname="network" name="$!win!Network" format="jsonf")
       property(outname="process" name="$!win!Process" format="jsonf")
       property(outname="authentication" name="$!win!Authentication" format="jsonf")
   }
   
   input(type="imtcp" port="514")
   action(type="mmsnarewinsec" 
          rootpath="!win"
          enablesections="all"
          template="enhanced_json")

**Advanced Configuration:**
.. code-block:: none

   action(type="mmsnarewinsec" 
          rootpath="!win"
          enablesections="subject,logon,network,process,authentication"
          debugjson="on"
          template="enhanced_json")

**Performance Monitoring:**
.. code-block:: none

   template(name="performance_json" type="list" option.jsonf="on") {
       property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
       property(outname="parsing_time" name="$!win!Performance!ParsingTime" format="jsonf")
       property(outname="field_count" name="$!win!Performance!FieldCount" format="jsonf")
       property(outname="pattern_matches" name="$!win!Performance!PatternMatches" format="jsonf")
   }

Migration Guide
---------------

**From Legacy mmsnarewinsec:**

1. **Update Configuration**: Replace hardcoded field names with section-based approach
2. **Update Templates**: Use new section-based property names
3. **Test Thoroughly**: Validate with comprehensive test suite
4. **Monitor Performance**: Use performance metrics to optimize

**Backward Compatibility:**
- Legacy field names are still supported
- Existing configurations continue to work
- Gradual migration is supported

Troubleshooting
---------------

**Common Issues:**

1. **Field Not Detected**: Check if field pattern exists in core patterns
2. **Type Parsing Errors**: Verify data format matches expected type
3. **Performance Issues**: Monitor pattern matching performance
4. **Memory Usage**: Check for memory leaks in pattern matching

**Debug Options:**

- Enable debug JSON output: `debugjson="on"`
- Check pattern matching: Review pattern priority and matching logic
- Validate data types: Ensure data format matches expected type

**Performance Optimization:**

- Use specific section enables instead of "all"
- Monitor pattern matching statistics
- Optimize template property access

Future Enhancements
-------------------

Planned enhancements include:

- **Regex Pattern Support**: Full regex pattern matching
- **Custom Pattern Configuration**: Runtime pattern configuration
- **Advanced Type Detection**: Machine learning-based type detection
- **Performance Profiling**: Detailed performance analysis
- **Configuration Management**: Web-based configuration interface

Contributing
------------

To contribute to the enhanced mmsnarewinsec module:

1. **Add New Patterns**: Extend core field patterns for new event types
2. **Improve Type Detection**: Enhance type detection algorithms
3. **Optimize Performance**: Improve pattern matching performance
4. **Add Tests**: Create comprehensive test cases
5. **Update Documentation**: Keep documentation current

For more information, see the main rsyslog documentation and the mmsnarewinsec module source code.