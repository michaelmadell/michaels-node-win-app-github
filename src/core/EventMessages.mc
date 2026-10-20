;// Message table for the CoreStationHXAgent Windows Event Log source.
;//
;// Compiled into the exe by CMake (mc.exe on MSVC, windmc on MinGW) so Event
;// Viewer can render entries; the registry value EventMessageFile points at the
;// exe. Each message is just its insertion string - the text is built by
;// core::EventLogger.
;//
;// The resulting IDs are mirrored in src/core/EventLogger.h (kEventId*) so
;// builds that skip the message compiler still compile; EventMessagesCheck.cpp
;// static_asserts that the two stay in sync.

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

LanguageNames=(English=0x409:MSG00409)

MessageId=0x1
Severity=Informational
SymbolicName=MSG_CORE_INFO
Language=English
%1
.

MessageId=0x2
Severity=Warning
SymbolicName=MSG_CORE_WARNING
Language=English
%1
.

MessageId=0x3
Severity=Error
SymbolicName=MSG_CORE_ERROR
Language=English
%1
.
