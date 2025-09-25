#!/bin/bash
# Comprehensive validation test using all 439 events from the test dataset

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="comprehensive_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="category" name="$!win!Event!Category" format="jsonf")
    property(outname="subtype" name="$!win!Event!Subtype" format="jsonf")
    property(outname="outcome" name="$!win!Event!Outcome" format="jsonf")
    property(outname="subject" name="$!win!Subject" format="jsonf")
    property(outname="logon" name="$!win!Logon" format="jsonf")
    property(outname="newlogon" name="$!win!NewLogon" format="jsonf")
    property(outname="network" name="$!win!Network" format="jsonf")
    property(outname="process" name="$!win!Process" format="jsonf")
    property(outname="authentication" name="$!win!Authentication" format="jsonf")
    property(outname="failure" name="$!win!Failure" format="jsonf")
    property(outname="wdac" name="$!win!WDAC" format="jsonf")
    property(outname="wufb" name="$!win!WUFB" format="jsonf")
    property(outname="kerberos" name="$!win!Kerberos" format="jsonf")
    property(outname="laps" name="$!win!LAPS" format="jsonf")
    property(outname="tls" name="$!win!TLS" format="jsonf")
    property(outname="filter" name="$!win!Filter" format="jsonf")
    property(outname="eventdata" name="$!win!EventData" format="jsonf")
    property(outname="unparsed" name="$!win!Unparsed" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       container="!win"
       enable.network="on"
       enable.laps="on"
       enable.tls="on"
       enable.wdac="on"
       emit.rawpayload="on"
       emit.debugjson="on")

*.* action(type="omfile" file="$RSYSLOG_OUT_LOG" template="comprehensive_json")
'

# Test with sample events from each category
startup

# Test Logon_Logoff events (4624-4627)
tcpflood -m1 -M "\"<14>Apr 08 09:16:05 LAB-LOGON126 MSWinEventLog\t1\tSecurity\t10126\tMon Apr 08 09:16:05 2024\t4624\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON126\tLogon\t\tAn account was successfully logged on. Subject: Security ID: SYSTEM Account Name: HOST-007\$ Account Domain: WORKGROUP Logon ID: 0x3E7 Logon Information: Logon Type: 7 Restricted Admin Mode: - Remote Credential Guard: - Virtual Account: No Elevated Token: No Impersonation Level: Impersonation New Logon: Security ID: CLOUDDOMAIN\\User009 Account Name: user010@example.com Account Domain: CLOUDDOMAIN Logon ID: 0xFD5113F Linked Logon ID: 0xFD5112A Network Account Name: - Network Account Domain: - Logon GUID: {00000000-0000-0000-0000-000000000000} Process Information: Process ID: 0x30c Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Workstation Name: HOST-007 Source Network Address: - Source Port: - Detailed Authentication Information: Logon Process: Negotiat Authentication Package: Negotiate Transited Services: - Package Name (NTLM only): - Key Length: 0\t1\""

# Test Account_Management events (4720-4799)
tcpflood -m1 -M "\"<14>Apr 08 09:16:07 LAB-ACCOU68 MSWinEventLog\t1\tSecurity\t10068\tMon Apr 08 09:16:07 2024\t4720\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-ACCOU68\tUser Account Management\t\tA user account was created. Subject: Security ID: DOMAIN-FR\\admin Account Name: admin Account Domain: DOMAIN-FR Logon ID: 0x20f9d New Account: Security ID: DOMAIN-FR\\John.Locke Account Name: John.Locke Account Domain: DOMAIN-FR Attributes: SAM Account Name: John.Locke Display Name: John Locke User Principal Name: John.Locke@domain-fr.local Home Directory: - Home Drive: - Script Path: - Profile Path: - User Workstations: - Password Last Set: <never> Account Expires: <never> Primary Group ID: 513 Allowed To Delegate To: - Old UAC Value: 0x0 New UAC Value: 0x15 User Account Control: Account Disabled 'Password Not Required' - Enabled 'Normal Account' - Enabled User Parameters: - SID History: - Logon Hours: <value not set> Additional Information: Privileges -\t1\""

# Test System events (4608-6418)
tcpflood -m1 -M "\"<14>Apr 08 09:16:00 LAB-SYSTEM001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:00 2024\t4608\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-SYSTEM001\tSystem\t\tWindows is starting up. Startup Type: Normal Process Name: C:\\Windows\\System32\\winlogon.exe Process ID: 0x4c0 Image File Name: C:\\Windows\\System32\\winlogon.exe Command Line: C:\\Windows\\System32\\winlogon.exe Current Directory: C:\\Windows\\System32 User Name: SYSTEM Logon ID: 0x3e7 Terminal Session ID: 0 Integrity Level: System Hashes: SHA1=1234567890ABCDEF1234567890ABCDEF12345678 Parent Process Name: C:\\Windows\\System32\\smss.exe Parent Process ID: 0x1 Parent Process Command Line: C:\\Windows\\System32\\smss.exe\t1\""

# Test Object_Access events (4656-5159)
tcpflood -m1 -M "\"<14>Apr 08 09:16:10 LAB-OBJECT001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:10 2024\t4656\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-OBJECT001\tObject Access\t\tA handle to an object was requested. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Object: Object Server: Security Object Type: File Object Name: C:\\Windows\\System32\\config\\SAM Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\lsass.exe Access Request Information: Accesses: ReadData (or ListDirectory) Access Mask: 0x1 Access Reasons: - Access Mask: 0x1\t1\""

# Test Process_Tracking events (4688-6424)
tcpflood -m1 -M "\"<14>Apr 08 09:16:15 LAB-PROCESS001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:15 2024\t4688\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-PROCESS001\tProcess Creation\t\tA new process has been created. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Process Information: New Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\notepad.exe Token Elevation Type: TokenElevationTypeDefault (1) Mandatory Label: Mandatory Label\\High Mandatory Level (S-1-16-12288) Creator Process ID: 0x1fc8 Creator Process Name: C:\\Windows\\System32\\winlogon.exe Process Command Line: C:\\Windows\\System32\\notepad.exe\t1\""

# Test Policy_Change events (4703-6145)
tcpflood -m1 -M "\"<14>Apr 08 09:16:20 LAB-POLICY001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:20 2024\t4703\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-POLICY001\tPolicy Change\t\tA user right was assigned. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 User Right: SeDebugPrivilege Account Name: HOST-001\\user003 Account Domain: HOST-001 Additional Information: Privileges: SeDebugPrivilege\t1\""

# Test Privilege_Use events (4673-4674)
tcpflood -m1 -M "\"<14>Apr 08 09:16:25 LAB-PRIVILEGE001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:25 2024\t4673\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-PRIVILEGE001\tPrivilege Use\t\tA privileged service was called. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Service: LsaRegisterLogonProcess() Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\lsass.exe Additional Information: Privileges: SeTcbPrivilege\t1\""

# Test Directory_Service events (4662-5170)
tcpflood -m1 -M "\"<14>Apr 08 09:16:30 LAB-DIRECTORY001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:30 2024\t4662\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-DIRECTORY001\tDirectory Service Access\t\tAn operation was performed on an object. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Object: Object Server: DS Object Type: user Object Name: CN=User003,CN=Users,DC=domain,DC=local Handle ID: 0x12345678 Operation Type: Object Access Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\dsquery.exe Additional Information: Access Mask: 0x10 Properties: - Additional Permissions: -\t1\""

# Test Account_Logon events (4768-4820)
tcpflood -m1 -M "\"<14>Apr 08 09:16:35 LAB-ACCOUNTLOGON001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:35 2024\t4768\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-ACCOUNTLOGON001\tKerberos Authentication Service\t\tA Kerberos authentication ticket (TGT) was requested. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Service Information: Service Name: krbtgt Service ID: HOST-001\\krbtgt Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\lsass.exe Network Information: Client Address: 192.168.1.100 Client Port: 12345 Additional Information: Ticket Options: 0x40810000 Ticket Encryption Type: 0x17 Pre-Authentication Type: 2 Certificate Information: Certificate Issuer Name: - Certificate Serial Number: - Certificate Thumbprint: -\t1\""

# Test Non_Audit_Event_Log events (1100-1108)
tcpflood -m1 -M "\"<14>Apr 08 09:16:40 LAB-NONAUDIT001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:40 2024\t1102\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-NONAUDIT001\tAudit Log Cleared\t\tThe audit log was cleared. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Additional Information: Process Information: Process ID: 0x4c0 Process Name: C:\\Windows\\System32\\wevtutil.exe\t1\""

# Test Uncategorized events (4864-5127)
tcpflood -m1 -M "\"<14>Apr 08 09:16:45 LAB-UNCATEGORIZED001 MSWinEventLog\t1\tSecurity\t10001\tMon Apr 08 09:16:45 2024\t4864\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-UNCATEGORIZED001\tOther\t\tA namespace collision was detected. Subject: Security ID: HOST-001\\admin Account Name: admin Account Domain: HOST-001 Logon ID: 0x1fd23 Additional Information: Namespace: Root\\CIMV2 Collision Type: Class Name: Win32_Process\t1\""

shutdown_when_empty
wait_shutdown

# Validate comprehensive field extraction across all categories
content_check '{"eventid":4624,"category":"Logon","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4720,"category":"User Account Management","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4608,"category":"System","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4656,"category":"Object Access","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4688,"category":"Process Creation","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4703,"category":"Policy Change","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4673,"category":"Privilege Use","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4662,"category":"Directory Service Access","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4768,"category":"Kerberos Authentication Service","subtype":"Success","outcome":"success"}'
content_check '{"eventid":1102,"category":"Audit Log Cleared","subtype":"Success","outcome":"success"}'
content_check '{"eventid":4864,"category":"Other","subtype":"Success","outcome":"success"}'
exit_test