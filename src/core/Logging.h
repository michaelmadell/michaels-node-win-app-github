#pragma once

// Unified system logging: core::Log(level, messageId, text) writes to the
// Windows Event Log (via EventLogger.h) or to syslog on Linux, with the same
// message IDs and severity model on both.
//
// This is the system-log channel for things an operator should see - errors,
// recoveries, security rejections. It is separate from Platform::logMessage,
// which on Windows is the verbose rotating file log (heartbeat/metrics
// chatter) and on Linux forwards to core::Log.
//
// On top of Log() sit error helpers for core::Error values (Errors.h):
// LogError() picks the level from the error code; LogErrorOnChange() and
// ClearReportedError() rate-limit failures that are retried on a timer.
//
// Compile-time configuration (CMake sets these; the defaults cover builds that
// don't go through CMake, e.g. build.sh):
//   CORESTATION_LOG_MIN_LEVEL  lowest LogLevel written (0=Debug .. 4=Critical), default 1 (Info)
//   CORESTATION_LOG_FACILITY   syslog facility (Linux), default LOG_DAEMON
//
// Header-only. Log() itself doesn't allocate (EventLogger converts into a
// stack buffer; syslog formats internally); the error helpers do, to build
// their text.

#include <cstdint>
#include <cstdio>
#include <expected>
#include <format>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include "Errors.h"

#ifdef _WIN32
#include "EventLogger.h"
#elif defined(__linux__)
#include <syslog.h>
#endif

#ifndef CORESTATION_LOG_MIN_LEVEL
#define CORESTATION_LOG_MIN_LEVEL 1
#endif

#if defined(__linux__) && !defined(CORESTATION_LOG_FACILITY)
#define CORESTATION_LOG_FACILITY LOG_DAEMON
#endif

namespace core {

enum class LogLevel { Debug = 0, Info = 1, Warning = 2, Error = 3, Critical = 4 };

inline constexpr LogLevel kMinLogLevel = static_cast<LogLevel>(CORESTATION_LOG_MIN_LEVEL);
static_assert(CORESTATION_LOG_MIN_LEVEL >= 0 && CORESTATION_LOG_MIN_LEVEL <= 4,
              "CORESTATION_LOG_MIN_LEVEL must be 0 (Debug) .. 4 (Critical)");

// ---------------------------------------------------------------------------
// Message IDs - one per subsystem; the level is carried separately. Source of
// truth is EventMessages.mc; EventMessagesCheck.cpp verifies these match it.
// On Linux each syslog line is prefixed "[<id>]".
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kMsgIDInfo = 1000;     // general, no specific subsystem
inline constexpr std::uint32_t kMsgIDWarning = 1001;
inline constexpr std::uint32_t kMsgIDError = 1002;
inline constexpr std::uint32_t kMsgIDSerial = 1100;           // SerialManager
inline constexpr std::uint32_t kMsgIDSerialBridge = 1200;     // IPC pipe/socket + client auth
inline constexpr std::uint32_t kMsgIDPlatform = 1300;         // service, OS queries, power/session, tray
inline constexpr std::uint32_t kMsgIDMetrics = 1400;          // PDH/WMI/proc metrics
inline constexpr std::uint32_t kMsgIDAmt = 1500;              // AMT SOL COM port management
inline constexpr std::uint32_t kMsgIDSession = 1700;          // session monitoring (Linux D-Bus)
inline constexpr std::uint32_t kMsgIDUnhandledException = 1900;

namespace detail {

inline constexpr std::uint32_t kAllMsgIDs[] = {
    kMsgIDInfo, kMsgIDWarning, kMsgIDError, kMsgIDSerial, kMsgIDSerialBridge,
    kMsgIDPlatform, kMsgIDMetrics, kMsgIDAmt, kMsgIDSession, kMsgIDUnhandledException,
};

// Event Viewer shows only the low 16 bits of an event ID, and IDs must be
// unique to be filterable - checked on every platform, not just where the
// message compiler runs.
consteval bool msgIDsValid() {
    for (std::size_t i = 0; i < std::size(kAllMsgIDs); ++i) {
        if (kAllMsgIDs[i] == 0 || kAllMsgIDs[i] > 0xFFFF) return false;
        for (std::size_t j = i + 1; j < std::size(kAllMsgIDs); ++j) {
            if (kAllMsgIDs[i] == kAllMsgIDs[j]) return false;
        }
    }
    return true;
}
static_assert(msgIDsValid(), "kMsgID* values must be unique, non-zero 16-bit IDs");

#ifdef __linux__
constexpr int syslogPriority(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::Debug:    return LOG_DEBUG;
    case LogLevel::Info:     return LOG_INFO;
    case LogLevel::Warning:  return LOG_WARNING;
    case LogLevel::Error:    return LOG_ERR;
    case LogLevel::Critical: return LOG_CRIT;
    }
    return LOG_INFO;
}
#endif

} // namespace detail

#ifdef CORESTATION_LOG_CAPTURE
// Unit-test builds only (tests/CMakeLists.txt defines CORESTATION_LOG_CAPTURE):
// every Log() call goes to this callback instead of the Event Log / syslog,
// so tests never write to the real system log and can assert on what was
// logged. An empty callback drops messages.
using LogCaptureFn = std::function<void(LogLevel, std::uint32_t, const std::string&)>;
inline LogCaptureFn& LogCapture() {
    static LogCaptureFn capture;
    return capture;
}
#endif

// The single entry point. `message` is UTF-8.
inline void Log(LogLevel level, std::uint32_t messageId, const char* message) {
    if (level < kMinLogLevel || message == nullptr) {
        return;
    }
#if defined(CORESTATION_LOG_CAPTURE)
    if (auto& capture = LogCapture()) {
        capture(level, messageId, message);
    }
#elif defined(_WIN32)
    // The Event Log has no debug/critical levels: Debug -> Information,
    // Critical -> Error.
    const WORD type = level >= LogLevel::Error   ? EVENTLOG_ERROR_TYPE
                    : level == LogLevel::Warning ? EVENTLOG_WARNING_TYPE
                                                 : EVENTLOG_INFORMATION_TYPE;
    EventLogger::instance().report(type, messageId, message);
#elif defined(__linux__)
    static std::once_flag opened;
    std::call_once(opened, [] { openlog("CoreStationHXAgent", LOG_PID, CORESTATION_LOG_FACILITY); });
    syslog(detail::syslogPriority(level), "[%u] %s", static_cast<unsigned>(messageId), message);
#else
    std::fprintf(stderr, "[%u] %s\n", static_cast<unsigned>(messageId), message);
#endif
}

inline void Log(LogLevel level, std::uint32_t messageId, const std::string& message) {
    Log(level, messageId, message.c_str());
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

// Missing/busy resources and timeouts are usually transient (port not plugged
// in yet, peer slow to respond) so they're warnings; everything else is an
// error.
constexpr LogLevel LevelFor(CoreError::Code code) noexcept {
    switch (code) {
    case CoreError::Code::NotFound:
    case CoreError::Code::Timeout:
    case CoreError::Code::Busy:
        return LogLevel::Warning;
    default:
        return LogLevel::Error;
    }
}

// Logs an error value at the level its code maps to, as
// "<context>: <message> (error N: <OS text>)".
template <Error E>
void LogError(std::uint32_t messageId, const std::string& context, const E& error) {
    std::string text = context.empty() ? describe(error) : std::format("{}: {}", context, describe(error));
    Log(LevelFor(error.code), messageId, text);
}

// Logs a std::expected's error, if it holds one.
template <typename T, Error E>
void LogExpectedError(std::uint32_t messageId, const std::string& context, const std::expected<T, E>& result) {
    if (!result) {
        LogError(messageId, context, result.error());
    }
}

namespace detail {

// Last error logged per key, for LogErrorOnChange().
class ErrorTracker {
public:
    // True if `code`/`platformError` differs from what was last recorded
    // under `key` (and records it).
    bool changed(const std::string& key, std::error_code code, std::uint32_t platformError) {
        const Entry current{ code, platformError };
        std::lock_guard<std::mutex> lock(mutex_);
        auto [it, inserted] = last_.try_emplace(key, current);
        if (inserted) {
            return true;
        }
        if (it->second == current) {
            return false;
        }
        it->second = current;
        return true;
    }

    // True if `key` had a recorded error (and forgets it).
    bool clear(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_.erase(key) > 0;
    }

private:
    struct Entry {
        std::error_code code;
        std::uint32_t platformError = 0;
        bool operator==(const Entry&) const = default;
    };
    std::mutex mutex_;
    std::map<std::string, Entry> last_;
};

inline ErrorTracker& errorTracker() {
    static ErrorTracker tracker;
    return tracker;
}

} // namespace detail

// For failures that are retried on a timer (port reconnects, pipe
// re-creation, metric polls): logs only when `error` differs from the last
// one logged under `key`, so a persistent fault produces one entry rather
// than one per retry. Pair with ClearReportedError() on success. Returns true
// if it logged, so callers can rate-limit their own output the same way.
template <Error E>
bool LogErrorOnChange(const std::string& key, std::uint32_t messageId, const std::string& context, const E& error) {
    if (!detail::errorTracker().changed(key, make_error_code(error), error.platform_error)) {
        return false;
    }
    LogError(messageId, context, error);
    return true;
}

// Forgets `key`'s last error. If one had been logged and recoveryMessage is
// non-empty, logs it as Info so the trail doesn't end on a stale error.
inline void ClearReportedError(const std::string& key, std::uint32_t messageId = kMsgIDInfo,
                               const std::string& recoveryMessage = {}) {
    if (detail::errorTracker().clear(key) && !recoveryMessage.empty()) {
        Log(LogLevel::Info, messageId, recoveryMessage);
    }
}

} // namespace core
