#!/bin/bash
# Simple test for enhanced field detection capabilities
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="outfmt" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="subject_securityid" name="$!win!Subject!SecurityID" format="jsonf")
    property(outname="logon_type" name="$!win!Logon!LogonType" format="jsonf")
    property(outname="process_name" name="$!win!Process!ProcessName" format="jsonf")
    constant(value="\n")
}

action(type="mmsnarewinsec" 
       container="!win"
       enable.network="on"
       enable.laps="on"
       enable.tls="on"
       enable.wdac="on"
       emit.rawpayload="on"
       emit.debugjson="on")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'

startup
cat <<'MSG' > ${RSYSLOG_DYNNAME}.input
<13>1 2025-02-18T06:42:17.554128Z DC25-PREVIEW - - - - MSWinEventLog	1	Security	802301	Tue Feb 18 06:42:17 2025	4624	Microsoft-Windows-Security-Auditing	N/A	N/A	Success Audit	DC25-PREVIEW	Logon		An account was successfully logged on.    Subject:   Security ID:  S-1-5-18   Account Name:  SYSTEM   Account Domain:  NT AUTHORITY   Logon ID:  0x3E7    Logon Information:   Logon Type:  2   Restricted Admin Mode: -   Virtual Account:  %%1843   Elevated Token:  %%1843    New Logon:   Security ID:  S-1-5-21-88997766-1122334455-6677889900-500   Account Name:  ADMIN-LAPS$   Account Domain:  FABRIKAM   Logon ID:  0x52F1A   Linked Logon ID:  0x0   Network Account Name: -   Network Account Domain: -   Logon GUID:  {5a8f0679-9b23-4cb7-a8c7-3d650c9b52ec}    Process Information:   Process ID:  0x66c   Process Name:  C:\Windows\System32\winlogon.exe    Network Information:   Workstation Name:  CORE25-01   Source Network Address: 192.168.50.12   Source Port:  59122    Detailed Authentication Information:   Logon Process:  User32   Authentication Package:  Negotiate   Transited Services: -   Package Name (NTLM only): -   Key Length:  0    LAPS Context:  PolicyVersion=2; CredentialRotation=True   	-802301
MSG
injectmsg_file ${RSYSLOG_DYNNAME}.input

shutdown_when_empty
wait_shutdown

# Validate enhanced field extraction
content_check '"eventid":"4624"' $RSYSLOG_OUT_LOG
content_check '"subject_securityid":"S-1-5-18"' $RSYSLOG_OUT_LOG  
content_check '"logon_type":"2"' $RSYSLOG_OUT_LOG
content_check '"process_name":"C:\\\\Windows\\\\System32\\\\winlogon.exe"' $RSYSLOG_OUT_LOG

exit_test