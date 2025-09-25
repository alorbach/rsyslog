#!/bin/bash
# Test pattern-based field detection with various field formats

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="pattern_test_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="subject_fields" name="$!win!Subject" format="jsonf")
    property(outname="logon_fields" name="$!win!Logon" format="jsonf")
    property(outname="network_fields" name="$!win!Network" format="jsonf")
    property(outname="process_fields" name="$!win!Process" format="jsonf")
    property(outname="authentication_fields" name="$!win!Authentication" format="jsonf")
    property(outname="kerberos_fields" name="$!win!Kerberos" format="jsonf")
    property(outname="laps_fields" name="$!win!LAPS" format="jsonf")
    property(outname="tls_fields" name="$!win!TLS" format="jsonf")
    property(outname="filter_fields" name="$!win!Filter" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="pattern_test_json")
'

# Test with various field patterns from the comprehensive dataset
startup
# Test IPsec events (4650-4984)
tcpflood -m1 -M "\"<14>Jun 10 11:30:45 LAB-LOGON105 MSWinEventLog\t1\tSecurity\t10105\tMon Jun 10 11:30:45 2024\t4650\tMicrosoft-Windows-Security-Auditing\tN/A\tN/A\tSuccess Audit\tLAB-LOGON105\tIPsec Main Mode\t\tAn IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used. Local Endpoint: Principal Name: jsmith@srv1.dmn Network Address: 10.40.1.123 Keying Module Port: 500 Remote Endpoint: Principal Name: DMN/SRV2\$ Network Address: 10.40.1.101 Keying Module Port: 500 Security Association Information: Lifetime (minutes): 480 Quick Mode Limit: 0 Main Mode SA ID: 9 Cryptographic Information: Cipher Algorithm: 3DES Integrity Algorithm: SHA1 Diffie-Hellman Group: DH group 2 Additional Information: Keying Module Name: IKEv1 Authentication Method: Kerberos Role: Responder Impersonation State: Not enabled Main Mode Filter ID: 71695\t1\""
shutdown_when_empty
wait_shutdown

# Validate pattern-based field extraction
content_check '{"eventid":4650,"network_fields":{"LocalEndpoint":"jsmith@srv1.dmn","RemoteEndpoint":"DMN/SRV2$"}}'
exit_test