%package mmsnarewinsec
Summary: NXLog Snare Windows Security event parser support
Group: System Environment/Daemons
Requires: %name = %version-%release

%description mmsnarewinsec
The mmsnarewinsec module parses NXLog Snare-formatted Windows Security events
that are embedded in RFC3164/RFC5424 syslog envelopes or delivered as JSON
payloads. Incoming events are normalized and attached to the rsyslog message
as a JSON representation that mirrors the structure documented by NXLog and Snare.

