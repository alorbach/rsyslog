#!/bin/bash
# Test Account Management events (4720-4799) with enhanced field detection

unset RSYSLOG_DYNNAME
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmsnarewinsec/.libs/mmsnarewinsec")

template(name="account_mgmt_json" type="list" option.jsonf="on") {
    property(outname="eventid" name="$!win!Event!EventID" format="jsonf")
    property(outname="subject_securityid" name="$!win!Subject!SecurityID" format="jsonf")
    property(outname="subject_accountname" name="$!win!Subject!AccountName" format="jsonf")
    property(outname="subject_accountdomain" name="$!win!Subject!AccountDomain" format="jsonf")
    property(outname="subject_logonid" name="$!win!Subject!LogonID" format="jsonf")
    property(outname="newaccount_securityid" name="$!win!NewAccount!SecurityID" format="jsonf")
    property(outname="newaccount_accountname" name="$!win!NewAccount!AccountName" format="jsonf")
    property(outname="newaccount_accountdomain" name="$!win!NewAccount!AccountDomain" format="jsonf")
    property(outname="targetaccount_securityid" name="$!win!TargetAccount!SecurityID" format="jsonf")
    property(outname="targetaccount_accountname" name="$!win!TargetAccount!AccountName" format="jsonf")
    property(outname="targetaccount_accountdomain" name="$!win!TargetAccount!AccountDomain" format="jsonf")
    property(outname="changedattributes" name="$!win!ChangedAttributes" format="jsonf")
    property(outname="samaccountname" name="$!win!SAMAccountName" format="jsonf")
    property(outname="displayname" name="$!win!DisplayName" format="jsonf")
    property(outname="userprincipalname" name="$!win!UserPrincipalName" format="jsonf")
    property(outname="homedirectory" name="$!win!HomeDirectory" format="jsonf")
    property(outname="homedrive" name="$!win!HomeDrive" format="jsonf")
    property(outname="scriptpath" name="$!win!ScriptPath" format="jsonf")
    property(outname="profilepath" name="$!win!ProfilePath" format="jsonf")
    property(outname="userworkstations" name="$!win!UserWorkstations" format="jsonf")
    property(outname="passwordlastset" name="$!win!PasswordLastSet" format="jsonf")
    property(outname="accountexpires" name="$!win!AccountExpires" format="jsonf")
    property(outname="primarygroupid" name="$!win!PrimaryGroupID" format="jsonf")
    property(outname="allowedtodelegateto" name="$!win!AllowedToDelegateTo" format="jsonf")
    property(outname="olduacvalue" name="$!win!OldUACValue" format="jsonf")
    property(outname="newuacvalue" name="$!win!NewUACValue" format="jsonf")
    property(outname="useraccountcontrol" name="$!win!UserAccountControl" format="jsonf")
    property(outname="userparameters" name="$!win!UserParameters" format="jsonf")
    property(outname="sidhistory" name="$!win!SIDHistory" format="jsonf")
    property(outname="logonhours" name="$!win!LogonHours" format="jsonf")
    property(outname="dnshostname" name="$!win!DNSHostName" format="jsonf")
    property(outname="serviceprincipalnames" name="$!win!ServicePrincipalNames" format="jsonf")
    property(outname="generic_fields" name="$!win!EventData" format="jsonf")
}

input(type="imtcp" port="'$TCPFLOOD_PORT'")
action(type="mmsnarewinsec" 
       rootpath="!win"
       enablesections="all"
       debugjson="on"
       template="account_mgmt_json")
'

# Test Account Management events from samples-all-data/Account_Management.data
startup
tcpflood -m1 -i ${srcdir}/tests/testsuites/mmsnarewinsec/samples-all-data/Account_Management.data
shutdown_when_empty
wait_shutdown

# Validate Account Management field extraction for various event types
content_check '{"eventid":4783,"subject_securityid":"DOMAIN\\admin","subject_accountname":"admin","subject_accountdomain":"DOMAIN","subject_logonid":"0x30999"}'
content_check '{"eventid":4720,"newaccount_securityid":"DOMAIN-FR\\John.Locke","newaccount_accountname":"John.Locke","newaccount_accountdomain":"DOMAIN-FR"}'
content_check '{"eventid":4741,"newaccount_securityid":"S-1-5-21-1234567890-1234567890-1234567890-1109","newaccount_accountname":"WORKSTATION-001$","newaccount_accountdomain":"DOMAIN"}'
content_check '{"eventid":4722,"targetaccount_securityid":"DOMAIN-FR\\John.Locke","targetaccount_accountname":"John.Locke","targetaccount_accountdomain":"DOMAIN-FR"}'
exit_test