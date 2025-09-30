#!/bin/bash
# Comprehensive test for mmsnarewinsec module field extraction capabilities
# This test validates the module's ability to extract structured fields from
# Windows Security Event Log description sections using dynamic test data from
# sample-windows2022-security.data and sample-windows2025-security.data files.
unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

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

    # Membership and claims lists
    property(outname="groupmembership" name="$!win!GroupMembership" format="jsonf")
    property(outname="userclaims" name="$!win!UserClaims" format="jsonf")
    property(outname="deviceclaims" name="$!win!DeviceClaims" format="jsonf")
}

template(name="winraw" type="string" string="%$!win%\n")

# Template for basic field extraction (for comparison)
template(name="basicfmt" type="list") {
    property(name="$!win!Event!EventID")
    constant(value=",")
    property(name="$!win!Event!Channel")
    constant(value=",")
    property(name="$!win!Event!EventType")
    constant(value=",")
    property(name="$!win!Event!CategoryText")
    constant(value=",")
    property(name="$!win!Event!Computer")
    constant(value=",")
    property(name="$!win!Event!Provider")
    constant(value="\n")
}

ruleset(name="winsec") {
    action(type="mmsnarewinsec")
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'.json" template="jsonfmt")
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'.basic" template="basicfmt")
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'.raw.json" template="winraw")
}

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" ruleset="winsec")
'

startup
assign_tcpflood_port $RSYSLOG_DYNNAME.tcpflood_port

# Use dynamic test data from sample files
echo "Using Windows 2022 sample data..."
tcpflood -m 1 -I ${srcdir}/testsuites/mmsnarewinsec/sample-windows2022-security.data

echo "Using Windows 2025 sample data..."
tcpflood -m 1 -I ${srcdir}/testsuites/mmsnarewinsec/sample-windows2025-security.data

echo "Using sample events with detailed field information..."
tcpflood -m 1 -I ${srcdir}/testsuites/mmsnarewinsec/sample-events.data

echo "Using comprehensive logon/logoff samples..."
tcpflood -m 1 -I ${srcdir}/testsuites/mmsnarewinsec/samples-all-data/Logon_Logoff.data

shutdown_when_empty
wait_shutdown

# Validate basic fields are extracted correctly from Windows 2022 data
content_check '4624,Security,Success Audit,Logon,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4634,Security,Success Audit,Logoff,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4647,Security,Success Audit,Logoff,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4648,Security,Success Audit,Logon,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4672,Security,Success Audit,Special Logon,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4688,Security,Success Audit,Process Creation,WIN-5SB1I3G0V7U,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic

# Validate basic fields are extracted correctly from Windows 2025 data
content_check '4624,Security,Success Audit,Audit Policy Change,WIN-IKCCUTRJI52,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4647,Security,Success Audit,Audit Policy Change,WIN-IKCCUTRJI52,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4648,Security,Success Audit,Audit Policy Change,WIN-IKCCUTRJI52,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4672,Security,Success Audit,Audit Policy Change,WIN-IKCCUTRJI52,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic
content_check '4688,Security,Success Audit,Audit Policy Change,WIN-IKCCUTRJI52,Microsoft-Windows-Security-Auditing' $RSYSLOG_OUT_LOG.basic

# Validate that both Windows versions are properly parsed
content_check 'WIN-5SB1I3G0V7U' $RSYSLOG_OUT_LOG.json
content_check 'WIN-IKCCUTRJI52' $RSYSLOG_OUT_LOG.json

# Validate structured JSON extraction from Windows 2022 data
# Check for complete records with specific field combinations that actually exist
content_check '"eventid":"4624"' $RSYSLOG_OUT_LOG.json
content_check '"categorytext":"Logon"' $RSYSLOG_OUT_LOG.json
content_check '"computer":"DC25-PREVIEW"' $RSYSLOG_OUT_LOG.json
content_check '"subjectaccountname":"WIN-IKCCUTRJI52$"' $RSYSLOG_OUT_LOG.json
content_check '"logontype":"5"' $RSYSLOG_OUT_LOG.json
content_check '"logontypename":"Service"' $RSYSLOG_OUT_LOG.json
content_check '"processname":"C:\\Windows\\System32\\services.exe"' $RSYSLOG_OUT_LOG.json
content_check '"newlogonaccountname":"SYSTEM"' $RSYSLOG_OUT_LOG.json
content_check '"newlogonaccountdomain":"NT AUTHORITY"' $RSYSLOG_OUT_LOG.json
content_check '"logonprocess":"Advapi"' $RSYSLOG_OUT_LOG.json
content_check '"authenticationpackage":"Negotiate"' $RSYSLOG_OUT_LOG.json
# Placeholder tokens such as "-" should now be dropped entirely by the parser.
# The JSON template still emits empty strings when a property is missing, so we
# assert that hyphen placeholders never surface in the flattened output.
check_not_present '"restrictedadminmode":"-"' "$RSYSLOG_OUT_LOG.json"
check_not_present '"networkaccountname":"-"' "$RSYSLOG_OUT_LOG.json"
check_not_present '"sourcenetworkaddress":"-"' "$RSYSLOG_OUT_LOG.json"
check_not_present '"sourceport":"-"' "$RSYSLOG_OUT_LOG.json"
check_not_present '"transitedservices":"-"' "$RSYSLOG_OUT_LOG.json"
check_not_present '"packagename":"-"' "$RSYSLOG_OUT_LOG.json"

# Validate structured JSON extraction from Windows 2025 data
content_check '"categorytext":"Audit Policy Change"' $RSYSLOG_OUT_LOG.json
content_check '"computer":"WIN-IKCCUTRJI52"' $RSYSLOG_OUT_LOG.json
content_check '"subjectaccountname":"WIN-IKCCUTRJI52$"' $RSYSLOG_OUT_LOG.json
content_check '"subjectaccountdomain":"WORKGROUP"' $RSYSLOG_OUT_LOG.json

# Validate privileges extraction for 4672 events
content_check '"privilegelist":"SeAssignPrimaryTokenPrivilege' $RSYSLOG_OUT_LOG.json

# Validate group membership and claims extraction
if ! python3 - "$RSYSLOG_OUT_LOG.raw.json" <<'PY'
import json
import sys
from pathlib import Path

raw_path = Path(sys.argv[1])
if not raw_path.exists():
    sys.stderr.write(f"raw JSON file not found: {raw_path}\n")
    sys.exit(1)

events = []
with raw_path.open('r', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        envelope = json.loads(line)
        if isinstance(envelope, dict) and 'win' in envelope:
            payload = envelope['win']
            if isinstance(payload, str):
                events.append(json.loads(payload))
            elif isinstance(payload, dict):
                events.append(payload)
        elif isinstance(envelope, dict):
            events.append(envelope)
        elif isinstance(envelope, str):
            events.append(json.loads(envelope))

def find_event(event_id, category=None):
    for evt in events:
        meta = evt.get('Event', {})
        if meta.get('EventID') == event_id and (category is None or meta.get('CategoryText') == category):
            return evt
    return None

gm_evt = find_event(4627, 'Group Membership')
if gm_evt is None:
    sys.stderr.write('Group Membership event not found in raw JSON output\n')
    sys.exit(1)
gm = gm_evt.get('GroupMembership')
if not isinstance(gm, list) or 'HOST-004\\None' not in gm:
    sys.stderr.write(f'GroupMembership array missing expected entry: {gm!r}\n')
    sys.exit(1)

claims_evt = find_event(4626, 'Logon')
if claims_evt is None:
    sys.stderr.write('Claims event not found in raw JSON output\n')
    sys.exit(1)
user_claims = claims_evt.get('UserClaims')
device_claims = claims_evt.get('DeviceClaims')
if not isinstance(user_claims, list) or not isinstance(device_claims, list):
    sys.stderr.write('Claims containers are not arrays\n')
    sys.exit(1)
if len(device_claims) == 0:
    sys.stderr.write('DeviceClaims array is empty\n')
    sys.exit(1)

PY
then
    echo "Membership and claims validation failed" >&2
    exit 1
fi

# Validate that DWM-1 account is extracted correctly for virtual accounts
content_check '"newlogonaccountname":"DWM-1"' $RSYSLOG_OUT_LOG.json
content_check '"newlogonaccountdomain":"Window Manager"' $RSYSLOG_OUT_LOG.json

# Validate that Administrator account is extracted correctly
content_check '"subjectaccountname":"Administrator"' $RSYSLOG_OUT_LOG.json
content_check '"subjectaccountdomain":"WIN-5SB1I3G0V7U"' $RSYSLOG_OUT_LOG.json

# Validate various logon types are present
content_check '"virtualaccount":"No"' $RSYSLOG_OUT_LOG.json
content_check '"elevatedtoken":"Yes"' $RSYSLOG_OUT_LOG.json


# Validate different event types have appropriate fields
content_check '"eventid":"4634"' $RSYSLOG_OUT_LOG.json
content_check '"eventid":"4647"' $RSYSLOG_OUT_LOG.json
content_check '"eventid":"4648"' $RSYSLOG_OUT_LOG.json
content_check '"eventid":"4672"' $RSYSLOG_OUT_LOG.json
content_check '"eventid":"4688"' $RSYSLOG_OUT_LOG.json


exit_test
