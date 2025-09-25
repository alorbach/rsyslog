#!/bin/bash
# Performance test for enhanced field detection

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="performance_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="parsing_time" name="$!win!Performance!ParsingTime" format="jsonf")
    property(outname="field_count" name="$!win!Performance!FieldCount" format="jsonf")
    property(outname="section_count" name="$!win!Performance!SectionCount" format="jsonf")
    property(outname="pattern_matches" name="$!win!Performance!PatternMatches" format="jsonf")
    property(outname="fallback_fields" name="$!win!Performance!FallbackFields" format="jsonf")
    property(outname="subject" name="$!win!Subject" format="jsonf")
    property(outname="logon" name="$!win!Logon" format="jsonf")
    property(outname="network" name="$!win!Network" format="jsonf")
    property(outname="process" name="$!win!Process" format="jsonf")
    property(outname="authentication" name="$!win!Authentication" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="performance_json")
'

# Test performance with various event types
startup

# Test with high-complexity events that have many fields
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tLogon\t\tAn account was successfully logged on. Subject: Security ID: SYSTEM Account Name: HOST-007\$ Account Domain: WORKGROUP Logon ID: 0x3E7 Logon Information: Logon Type: 7 Restricted Admin Mode: - Remote Credential Guard: - Virtual Account: No Elevated Token: No Impersonation Level: Impersonation New Logon: Security ID: CLOUDDOMAIN\\User009 Account Name: user010@example.com Account Domain: CLOUDDOMAIN Logon ID: 0xFD5113F Linked Logon ID: 0xFD5112A Network Account Name: - Network Account Domain: - Logon GUID: {00000000-0000-0000-0000-000000000000} Process Information: Process ID: 0x30c Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Workstation Name: HOST-007 Source Network Address: - Source Port: - Detailed Authentication Information: Logon Process: Negotiat Authentication Package: Negotiate Transited Services: - Package Name (NTLM only): - Key Length: 0\t1\""

# Test with IPsec events that have complex field structures
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4650\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tIPsec Main Mode\t\tAn IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used. Local Endpoint: Principal Name: jsmith@srv1.dmn Network Address: 10.40.1.123 Keying Module Port: 500 Remote Endpoint: Principal Name: DMN/SRV2\$ Network Address: 10.40.1.101 Keying Module Port: 500 Security Association Information: Lifetime (minutes): 480 Quick Mode Limit: 0 Main Mode SA ID: 9 Cryptographic Information: Cipher Algorithm: 3DES Integrity Algorithm: SHA1 Diffie-Hellman Group: DH group 2 Additional Information: Keying Module Name: IKEv1 Authentication Method: Kerberos Role: Responder Impersonation State: Not enabled Main Mode Filter ID: 71695\t1\""

# Test with WDAC events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t6281\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tWDAC\t\tWindows Defender Application Control enforced a policy. Policy Name: Default Policy Policy Version: 1.0 Enforcement Mode: Audit User: HOST-001\\admin PID: 1234\t1\""

# Test with WUFB events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t1243\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tWindows Update for Business\t\tWindows Update for Business policy was applied. Policy ID: 12345 Ring: Current From Service: Windows Update Enforcement Result: Success\t1\""

# Test with Kerberos events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4768\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tKerberos Authentication Service\t\tA Kerberos authentication ticket (TGT) was requested. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Service Information: Service Name: krbtgt Service ID: HOST-001\\krbtgt Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Client Address: 192.168.1.100 Client Port: 12345 Additional Information: Ticket Options: 0x40810000 Ticket Encryption Type: 0x17 Pre-Authentication Type: 2 Certificate Information: Certificate Issuer Name: - Certificate Serial Number: - Certificate Thumbprint: -\t1\""

# Test with LAPS events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tLAPS\t\tLocal Administrator Password Solution (LAPS) was used. Policy Version: 1 Credential Rotation: true\t1\""

# Test with TLS events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tTLS\t\tTLS inspection was performed. Reason: Policy enforcement Policy: Default TLS Policy\t1\""

# Test with Filter events
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tFilter\t\tFiltering platform packet was dropped. Filter Run-Time ID: 12345 Layer Name: Network Layer Run-Time ID: 67890\t1\""

shutdown_when_empty
wait_shutdown

# Validate performance metrics and field extraction
content_check '{"eventid":4624,"subject":{"SecurityID":"SYSTEM","AccountName":"HOST-007$","AccountDomain":"WORKGROUP","LogonID":"0x3E7"}}'
content_check '{"eventid":4650,"network":{"LocalEndpoint":"jsmith@srv1.dmn","RemoteEndpoint":"DMN/SRV2$"}}'
content_check '{"eventid":6281,"wdac":{"PolicyName":"Default Policy","PolicyVersion":"1.0","EnforcementMode":"Audit","User":"HOST-001\\admin","ProcessID":"1234"}}'
content_check '{"eventid":1243,"wufb":{"PolicyID":"12345","Ring":"Current","FromService":"Windows Update","EnforcementResult":"Success"}}'
content_check '{"eventid":4768,"kerberos":{"ServiceName":"krbtgt","ServiceID":"HOST-001\\krbtgt","TicketOptions":"0x40810000","TicketEncryptionType":"0x17","PreAuthenticationType":"2"}}'
content_check '{"eventid":4624,"laps":{"PolicyVersion":"1","CredentialRotation":"true"}}'
content_check '{"eventid":4624,"tls":{"Reason":"Policy enforcement","Policy":"Default TLS Policy"}}'
content_check '{"eventid":4624,"filter":{"FilterRuntimeID":"12345","LayerName":"Network","LayerRuntimeID":"67890"}}'
exit_test