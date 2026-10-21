;// Message table for the CoreStationHXAgent Windows Event Log source.
;//
;// Compiled into the exe by CMake (mc.exe on MSVC, windmc on MinGW) so Event
;// Viewer can render entries; the registry value EventMessageFile points at the
;// exe. Each message is just its insertion string - the text is built by
;// core::Log (src/core/Logging.h).
;//
;// IDs are per subsystem, not per severity: the level travels separately as the
;// event type (Information/Warning/Error). Every message is declared
;// Severity=Success so the generated IDs are the plain numbers below, with no
;// severity bits - the same numbers syslog lines are tagged with on Linux.
;//
;// The IDs are mirrored in src/core/Logging.h (kMsgID*) so builds that skip the
;// message compiler still compile; EventMessagesCheck.cpp static_asserts that
;// the two stay in sync.

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

LanguageNames=(English=0x409:MSG00409)

MessageId=1000
Severity=Success
SymbolicName=MSG_GENERAL_INFO
Language=English
%1
.

MessageId=1001
Severity=Success
SymbolicName=MSG_GENERAL_WARNING
Language=English
%1
.

MessageId=1002
Severity=Success
SymbolicName=MSG_GENERAL_ERROR
Language=English
%1
.

MessageId=1100
Severity=Success
SymbolicName=MSG_SERIAL
Language=English
%1
.

MessageId=1200
Severity=Success
SymbolicName=MSG_SERIAL_BRIDGE
Language=English
%1
.

MessageId=1300
Severity=Success
SymbolicName=MSG_PLATFORM
Language=English
%1
.

MessageId=1400
Severity=Success
SymbolicName=MSG_METRICS
Language=English
%1
.

MessageId=1500
Severity=Success
SymbolicName=MSG_AMT
Language=English
%1
.

MessageId=1700
Severity=Success
SymbolicName=MSG_SESSION
Language=English
%1
.

MessageId=1900
Severity=Success
SymbolicName=MSG_UNHANDLED_EXCEPTION
Language=English
%1
.
