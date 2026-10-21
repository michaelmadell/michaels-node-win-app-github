# Cross-Platform Logging: Event Viewer + syslog

> **Status: implemented (2026-10-21).** This document was originally the task
> prompt; it has been updated to describe what was actually built, including
> the decisions taken where the original prompt conflicted with the codebase.
> See [Decisions and deviations](#decisions-and-deviations).

## Context

Before this work CoreStationHXAgent had two unrelated logging paths:

- **Windows**: `src/core/EventLogger.h` (header-only, added by the
  error-handling overhaul) wrote to the Windows Event Log via `ReportEventW`,
  with a message table compiled from `src/core/EventMessages.mc`. Its three
  event IDs were severity-encoded (`0x40000001` info, `0x80000002` warning,
  `0xC0000003` error), mirrored as `kEventId*` constants and checked by
  `EventMessagesCheck.cpp`. It also held the error helpers (`log`,
  `log_on_change`, `clear`) used by the migrated modules.
- **Linux**: raw `syslog()` calls in `LinuxPlatformDbus.cpp` (3) and
  `LinuxPlatformMetrics.cpp` (1); `LinuxPlatform::logMessage` called
  `syslog()` with a priority guessed from the text ("ERROR"/"WARNING");
  `LinuxPlatform::run()` called `openlog`/`closelog`. No message IDs.

The goal: a **single logging abstraction** that writes to Event Viewer on
Windows and syslog on Linux, with the same message IDs and severity model,
header-only and configured at compile time.

## What was built

### `src/core/Logging.h` (new) — the single entry point

```cpp
namespace core {
enum class LogLevel { Debug = 0, Info = 1, Warning = 2, Error = 3, Critical = 4 };

void Log(LogLevel level, std::uint32_t messageId, const char* message);
void Log(LogLevel level, std::uint32_t messageId, const std::string& message);

// Error helpers for core::Error values (src/core/Errors.h)
constexpr LogLevel LevelFor(CoreError::Code);            // NotFound/Timeout/Busy -> Warning, else Error
void LogError(std::uint32_t id, const std::string& context, const E& error);
void LogExpectedError(std::uint32_t id, const std::string& context, const std::expected<T, E>&);
bool LogErrorOnChange(const std::string& key, std::uint32_t id, const std::string& context, const E& error);
void ClearReportedError(const std::string& key, std::uint32_t id = kMsgIDInfo,
                        const std::string& recoveryMessage = {});
}
```

- **Windows**: `Log` maps the level to an event type and calls
  `EventLogger::instance().report(type, id, message)`.
- **Linux**: `Log` opens syslog once (`std::call_once` →
  `openlog("CoreStationHXAgent", LOG_PID, CORESTATION_LOG_FACILITY)`) and calls
  `syslog(priority, "[%u] %s", id, message)`.
- **Other platforms**: falls back to `stderr`.
- `LogErrorOnChange` / `ClearReportedError` rate-limit failures that are
  retried on a timer: one entry per distinct error per key, plus an optional
  Info "recovered" entry. These were previously Windows-only `EventLogger`
  members and now work on both platforms.

### Severity mapping

| `LogLevel` | Windows event type           | syslog priority |
|------------|------------------------------|-----------------|
| Debug      | `EVENTLOG_INFORMATION_TYPE`  | `LOG_DEBUG`     |
| Info       | `EVENTLOG_INFORMATION_TYPE`  | `LOG_INFO`      |
| Warning    | `EVENTLOG_WARNING_TYPE`      | `LOG_WARNING`   |
| Error      | `EVENTLOG_ERROR_TYPE`        | `LOG_ERR`       |
| Critical   | `EVENTLOG_ERROR_TYPE`        | `LOG_CRIT`      |

The Event Log has no debug or critical level, hence the folding on Windows.

### Message IDs — per subsystem, shared by both platforms

Defined in `Logging.h`; source of truth for the message table is
`EventMessages.mc`.

| Constant                   | ID   | Used for                                        |
|----------------------------|------|-------------------------------------------------|
| `kMsgIDInfo`               | 1000 | General info (incl. Linux `logMessage`)         |
| `kMsgIDWarning`            | 1001 | General warning                                 |
| `kMsgIDError`              | 1002 | General error                                   |
| `kMsgIDSerial`             | 1100 | `SerialManager`                                 |
| `kMsgIDSerialBridge`       | 1200 | IPC pipe/socket and client authentication       |
| `kMsgIDPlatform`           | 1300 | Service start, OS queries, power/session, tray  |
| `kMsgIDMetrics`            | 1400 | PDH/WMI/proc metrics and their set-up           |
| `kMsgIDAmt`                | 1500 | AMT SOL COM port management                     |
| `kMsgIDSession`            | 1700 | Session monitoring (Linux D-Bus thread)         |
| `kMsgIDUnhandledException` | 1900 | Top-level exception safety net in `main.cpp`    |

IDs identify the **subsystem**; the level travels separately as the event type
/ syslog priority. Every `.mc` entry is declared `Severity=Success`, so the
generated IDs are the plain numbers above with no severity bits — the same
numbers Linux syslog lines are prefixed with (`[1100] Serial: ...`).

### `src/core/EventLogger.h` — now only the Windows output code

- `instance()` — one process-wide instance; initialisation (self-registration
  of the event source when running as the service, then
  `RegisterEventSourceW`) runs once, thread-safely, on first use.
- `report(WORD type, DWORD id, const char* utf8)` — converts to UTF-16 into a
  **stack buffer** (`kMaxMessageChars = 4096`, truncated on a UTF-8 character
  boundary) and calls `ReportEventW`. No heap allocation.
- `register_event_source` / `unregister_event_source` /
  `current_module_path` — unchanged; used by `--register-event-source` /
  `--unregister-event-source` in `main.cpp` and mirrored by
  `installer/install.ps1` / `remove.ps1`.
- The error helpers and the `kEventId*` constants moved out (to `Logging.h`
  as `LogError*` / `kMsgID*`).

### `Platform::logMessage`

- **Windows**: unchanged — writes the rotating file log under ProgramData.
  It is deliberately **not** routed to Event Viewer (see decisions).
- **Linux**: `core::Log(level, id, message)`, with the level still inferred
  from the text (FATAL/ERROR → Error, WARNING → Warning, else Info) and the
  matching general ID (`kMsgIDError` / `kMsgIDWarning` / `kMsgIDInfo`).
- `Platform.h` documents this split.

### Call sites migrated

| File | Change |
|------|--------|
| `src/platform/LinuxPlatform.cpp` | Removed `openlog`/`closelog` (now lazy in `core::Log`) |
| `src/platform/LinuxPlatformInfo.cpp` | `logMessage` → `core::Log` |
| `src/platform/LinuxPlatformDbus.cpp` | 3× `syslog` → `core::Log(…, kMsgIDSession, …)` |
| `src/platform/LinuxPlatformMetrics.cpp` | `syslog` → `core::Log(Error, kMsgIDMetrics, …)` |
| `src/modules/serial/SerialManager.cpp` | `LogErrorOnChange` / `ClearReportedError` with `kMsgIDSerial` |
| `src/modules/serialpipe/SerialBridgePipe.cpp` | `kMsgIDSerialBridge` for pipe errors, auth rejections, dev-mode notice |
| `src/platform/WindowsPlatformSerialBridge.cpp` | Pipe start failure → `LogError(kMsgIDSerialBridge, …)` |
| `src/platform/WindowsPlatform.{h,cpp}` | `reportError` / `reportErrorOnChange` / `valueOrReport` take a message ID |
| `src/platform/WindowsPlatform{Info,Tray}.cpp` | `kMsgIDPlatform` |
| `src/platform/WindowsPlatformMetrics.cpp` | `kMsgIDMetrics` (PDH/COM set-up in the constructor too) |
| `src/main.cpp` | AMT errors → `kMsgIDAmt`; unhandled exceptions → `Critical`, `kMsgIDUnhandledException` |

No raw `syslog()` or direct `EventLogger` logging calls remain outside
`Logging.h` / `EventLogger.h`.

### Compile-time sync checks

- `EventMessagesCheck.cpp` (built by CMake on Windows, where the message
  table is generated): `static_assert` that each `kMsgID*` equals the
  generated `MSG_*` value, and that `Logging.h` defines exactly the ten IDs
  checked — adding an ID without a message-table entry fails the build.
- `Logging.h` (every platform, including Linux): `static_assert` that all IDs
  are unique, non-zero and fit in 16 bits (Event Viewer shows only the low
  16 bits).

### CMake

| Cache variable | Default | Effect |
|---|---|---|
| `CORESTATION_LOG_MIN_LEVEL` | `Info` | Lowest level written (`Debug`, `Info`, `Warning`, `Error`, `Critical`); validated at configure time, passed as `CORESTATION_LOG_MIN_LEVEL=0..4` |
| `CORESTATION_LOG_FACILITY` | `LOG_DAEMON` | Linux only; syslog facility macro, validated against `^LOG_[A-Z0-9]+$` |

Both are shown in the configure summary. `Logging.h` has the same defaults for
builds that bypass CMake (e.g. `build.sh`). `Errors.h` and `Logging.h` are in
`HEADER_FILES`; `EventLogger.h` is added on Windows only. No new link
libraries were needed (`advapi32` and libc already provide the APIs).

## Decisions and deviations

These differ from the original prompt; each was either a user decision or
forced by the codebase.

1. **Windows `logMessage` stays file-only** *(user decision)*. The prompt
   asked for it to go to Event Viewer, but ~120 call sites use it, including
   the 30-second "Metrics: …" heartbeat line and debug chatter (~3k
   events/day), and the errors an operator needs already reach Event Viewer
   through `LogError`. So the acceptance criterion "`core::Log` used
   everywhere" holds for the system-log channel; the Windows file log is a
   separate, intentional channel.
2. **Per-subsystem IDs instead of only 1000/1001/1002** *(user decision)*.
   The prompt's three constants are kept (as the general IDs) and seven
   subsystem IDs were added so Event Viewer / `journalctl` can filter by
   area. This renumbered the severity-encoded IDs from the previous
   (unreleased) commit.
3. **The prompt's "Current State" was inaccurate**: the IDs were not
   1000/1001/1002, `EventLogger` had no `LogEvent`/`Initialize`/
   `s_initialized`, and the quoted Linux calls ("Station started", "High
   memory usage…") don't exist. The real call sites (above) were migrated.
4. **No `--log-level` CLI flag.** A runtime flag would contradict "no runtime
   config"; the `CORESTATION_LOG_MIN_LEVEL` CMake option covers the need.
5. **Facility macro is `CORESTATION_LOG_FACILITY`**, not `LOG_FACILITY`, to
   avoid clashing with `<syslog.h>` names.
6. **"No heap allocation" applies to the output path only.** `core::Log` and
   `EventLogger::report` don't allocate (stack buffer on Windows, `syslog`
   formats internally). The error helpers build text with `std::format` /
   `describe()` and do allocate; callers already build `std::string`
   messages.
7. **Windows initialisation uses a function-local static** (C++11 "magic
   statics", equivalent to `std::call_once`); Linux uses `std::call_once`.

## Acceptance Criteria

- [x] Single `core::Log(LogLevel, uint32_t, const char*)` entry point for the
      system log (Windows `logMessage` file log intentionally separate — see
      decision 1)
- [ ] Windows: events appear in Event Viewer under the application source —
      *builds and links; not yet observed live (writing test events and
      registering the source need an elevated shell)*
- [x] Linux: messages appear in syslog/journalctl with correct severity —
      *verified in WSL: Critical→2, Error→3, Warning→4, Info→6, facility
      `LOG_DAEMON`, `[id]` prefix; Debug filtered by default and present with
      `CORESTATION_LOG_MIN_LEVEL=Debug`; `LogErrorOnChange` logs 1 of 3
      repeats plus the recovery line*
- [x] No raw `syslog()` calls remain in platform files
- [x] `EventMessagesCheck.cpp` passes (compile-time)
- [x] No runtime config files introduced
- [x] Builds on Windows (MSVC, MinGW GCC 16) and Linux (GCC 13) without
      errors or new warnings; unit tests pass (19 Windows, 18 Linux)
- [x] Header-only: no new `.cpp` files beyond `EventMessagesCheck.cpp`

## Adding a new message ID

1. Add `kMsgIDFoo` to `src/core/Logging.h` and to `detail::kAllMsgIDs`.
2. Add a `MessageId=…`, `Severity=Success`, `SymbolicName=MSG_FOO` entry to
   `src/core/EventMessages.mc`.
3. Add `CHECK_MSG_ID(kMsgIDFoo, MSG_FOO);` to `EventMessagesCheck.cpp` and
   bump the expected count there.
