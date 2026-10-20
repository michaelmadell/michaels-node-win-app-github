#pragma once

// Windows Event Viewer sink for errors that reach a reporting boundary.
//
// Events go to the Application log under the "CoreStationHXAgent" source.
// Their text is rendered through the message table compiled into the exe from
// src/core/EventMessages.mc. Builds without that table (e.g. build.sh) still
// log, but Event Viewer prefixes each entry with "The description for Event
// ID N cannot be found".
//
// The source is registered by installer/install.ps1, or manually with
// `CoreStationHXAgent.exe --register-event-source` from an elevated prompt.
// The service (LocalSystem) also self-registers on first use if the key is
// missing; unprivileged processes (the tray helper) skip that silently.
//
// Header-only, Windows-only.

#ifdef _WIN32

#include <windows.h>
#include <cstdint>
#include <expected>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include "Errors.h"

namespace core {

// Must match EventMessages.mc - checked at compile time in CMake builds by
// EventMessagesCheck.cpp against the mc-generated header.
inline constexpr DWORD kEventIdInfo = 0x40000001L;
inline constexpr DWORD kEventIdWarning = 0x80000002L;
inline constexpr DWORD kEventIdError = 0xC0000003L;

inline constexpr wchar_t kEventSourceName[] = L"CoreStationHXAgent";
inline constexpr wchar_t kEventSourceRegistryKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\CoreStationHXAgent";

enum class EventSeverity { Information, Warning, Error };

// Missing/busy resources and timeouts are usually transient (port not plugged
// in yet, peer slow to respond) so they're warnings; everything else is an
// error.
constexpr EventSeverity severity_for(CoreError::Code code) noexcept {
    switch (code) {
    case CoreError::Code::NotFound:
    case CoreError::Code::Timeout:
    case CoreError::Code::Busy:
        return EventSeverity::Warning;
    default:
        return EventSeverity::Error;
    }
}

class EventLogger {
public:
    static EventLogger& instance() {
        static EventLogger logger;
        return logger;
    }

    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;

    void log_error(const std::string& message, DWORD event_id = kEventIdError) {
        report(EVENTLOG_ERROR_TYPE, event_id, message);
    }
    void log_warning(const std::string& message, DWORD event_id = kEventIdWarning) {
        report(EVENTLOG_WARNING_TYPE, event_id, message);
    }
    void log_info(const std::string& message, DWORD event_id = kEventIdInfo) {
        report(EVENTLOG_INFORMATION_TYPE, event_id, message);
    }

    // Logs an error value at the severity its code maps to, with the OS error
    // text appended (see core::describe).
    template <Error E>
    void log(const std::string& context, const E& error) {
        std::string text = context.empty() ? describe(error) : std::format("{}: {}", context, describe(error));
        if (severity_for(error.code) == EventSeverity::Warning) {
            log_warning(text);
        } else {
            log_error(text);
        }
    }

    // For failures that are retried on a timer (port reconnects, pipe
    // re-creation, metric polls): logs only when `error` differs from the last
    // one logged under `key`, so a persistent fault produces one event rather
    // than one per retry. Pair with clear() on success. Returns true if it
    // logged, so callers can rate-limit their own file logging the same way.
    template <Error E>
    bool log_on_change(const std::string& key, const std::string& context, const E& error) {
        const LastError current{ make_error_code(error), error.platform_error };
        {
            std::lock_guard<std::mutex> lock(last_errors_mutex_);
            auto [it, inserted] = last_errors_.try_emplace(key, current);
            if (!inserted) {
                if (it->second == current) {
                    return false;
                }
                it->second = current;
            }
        }
        log(context, error);
        return true;
    }

    // Forgets `key`'s last error. If one had been logged and recovery_message
    // is non-empty, logs it as Information so the trail doesn't end on a
    // stale error.
    void clear(const std::string& key, const std::string& recovery_message = {}) {
        bool hadError = false;
        {
            std::lock_guard<std::mutex> lock(last_errors_mutex_);
            hadError = last_errors_.erase(key) > 0;
        }
        if (hadError && !recovery_message.empty()) {
            log_info(recovery_message);
        }
    }

    // Convenience: log a std::expected's error, if it holds one.
    template <typename T, Error E>
    static void log_expected_error(const std::string& context, const std::expected<T, E>& result) {
        if (!result) {
            instance().log(context, result.error());
        }
    }

    // Creates/updates the source's registry key so Event Viewer can find the
    // message table in `message_file`. Needs administrator rights.
    static std::expected<void, PlatformError> register_event_source(const std::wstring& message_file) {
        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kEventSourceRegistryKey, 0, nullptr,
                                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (status != ERROR_SUCCESS) {
            return std::unexpected(registry_error("Failed to create event source registry key", status));
        }

        const DWORD typesSupported = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        status = RegSetValueExW(key, L"EventMessageFile", 0, REG_EXPAND_SZ,
                                reinterpret_cast<const BYTE*>(message_file.c_str()),
                                static_cast<DWORD>((message_file.size() + 1) * sizeof(wchar_t)));
        if (status == ERROR_SUCCESS) {
            status = RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD,
                                    reinterpret_cast<const BYTE*>(&typesSupported), sizeof(typesSupported));
        }
        RegCloseKey(key);

        if (status != ERROR_SUCCESS) {
            return std::unexpected(registry_error("Failed to write event source registry values", status));
        }
        return {};
    }

    // Removes the source's registry key. Succeeds if it was already absent.
    static std::expected<void, PlatformError> unregister_event_source() {
        LSTATUS status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, kEventSourceRegistryKey);
        if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
            return std::unexpected(registry_error("Failed to delete event source registry key", status));
        }
        return {};
    }

    static std::wstring current_module_path() {
        std::wstring path(MAX_PATH, L'\0');
        for (;;) {
            DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (len == 0) {
                return {};
            }
            if (len < path.size()) {
                path.resize(len);
                return path;
            }
            path.resize(path.size() * 2);
        }
    }

private:
    EventLogger() {
        ensure_registered();
        handle_ = RegisterEventSourceW(nullptr, kEventSourceName);
    }

    ~EventLogger() {
        if (handle_ != nullptr) {
            DeregisterEventSource(handle_);
        }
    }

    // Best effort: only succeeds with admin rights (i.e. when running as the
    // service). Without it events are still written, just without message text.
    static void ensure_registered() {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kEventSourceRegistryKey, 0, KEY_READ, &key) == ERROR_SUCCESS) {
            RegCloseKey(key);
            return;
        }
        std::wstring exePath = current_module_path();
        if (!exePath.empty()) {
            (void)register_event_source(exePath);
        }
    }

    static PlatformError registry_error(const char* what, LSTATUS status) {
        const bool denied = status == ERROR_ACCESS_DENIED;
        return PlatformError{
            .code = denied ? CoreError::Code::PermissionDenied : CoreError::Code::Internal,
            .sub_code = denied ? PlatformError::SubCode::RegistryAccessDenied
                               : PlatformError::SubCode::RegistryWriteFailed,
            .message = what,
            .platform_error = static_cast<std::uint32_t>(status),
        };
    }

    static std::wstring utf8_to_wide(const std::string& text) {
        if (text.empty()) {
            return {};
        }
        int len = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        std::wstring wide(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), len);
        return wide;
    }

    void report(WORD type, DWORD event_id, const std::string& message) {
        if (handle_ == nullptr) {
            return;
        }
        std::wstring wide = utf8_to_wide(message);
        LPCWSTR strings[] = { wide.c_str() };
        ReportEventW(handle_, type, 0, event_id, nullptr, 1, 0, strings, nullptr);
    }

    struct LastError {
        std::error_code code;
        std::uint32_t platform_error = 0;
        bool operator==(const LastError&) const = default;
    };

    HANDLE handle_ = nullptr;
    std::mutex last_errors_mutex_;
    std::map<std::string, LastError> last_errors_;
};

} // namespace core

#endif // _WIN32
