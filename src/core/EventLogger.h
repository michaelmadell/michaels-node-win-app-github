#pragma once

// Windows backend for core::Log (src/core/Logging.h): writes to the
// Application log under the "CoreStationHXAgent" event source. Code should log
// through core::Log / core::LogError rather than using this directly; the
// exceptions are the event-source registration commands.
//
// Event text is rendered through the message table compiled into the exe from
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
#include <cstring>
#include <expected>
#include <string>
#include "Errors.h"

namespace core {

inline constexpr wchar_t kEventSourceName[] = L"CoreStationHXAgent";
inline constexpr wchar_t kEventSourceRegistryKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\CoreStationHXAgent";

class EventLogger {
public:
    // Longest message written, in UTF-16 code units (including the
    // terminator). Longer messages are truncated. The Event Log's own limit
    // is ~31,839 characters; this keeps the conversion buffer on the stack.
    static constexpr int kMaxMessageChars = 4096;

    // The process-wide instance. Initialisation (source self-registration +
    // RegisterEventSource) runs exactly once, thread-safely, on first use.
    static EventLogger& instance() {
        static EventLogger logger;
        return logger;
    }

    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;

    // Writes one event. `type` is EVENTLOG_{INFORMATION,WARNING,ERROR}_TYPE,
    // `event_id` one of the kMsgID* IDs from Logging.h, `message` UTF-8.
    // No heap allocation: the UTF-16 conversion uses a stack buffer.
    void report(WORD type, DWORD event_id, const char* message) noexcept {
        if (handle_ == nullptr || message == nullptr) {
            return;
        }

        // Every UTF-8 byte becomes at most one UTF-16 unit, so capping the
        // input at kMaxMessageChars - 1 bytes guarantees the output fits.
        // Back off to a character boundary so a multi-byte sequence isn't cut.
        size_t len = std::strlen(message);
        if (len > static_cast<size_t>(kMaxMessageChars - 1)) {
            len = kMaxMessageChars - 1;
            while (len > 0 && (static_cast<unsigned char>(message[len]) & 0xC0) == 0x80) {
                --len;
            }
        }

        wchar_t wide[kMaxMessageChars];
        int converted = len == 0 ? 0
            : MultiByteToWideChar(CP_UTF8, 0, message, static_cast<int>(len), wide, kMaxMessageChars - 1);
        wide[converted > 0 ? converted : 0] = L'\0';

        LPCWSTR strings[] = { wide };
        ReportEventW(handle_, type, 0, event_id, nullptr, 1, 0, strings, nullptr);
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

    HANDLE handle_ = nullptr;
};

} // namespace core

#endif // _WIN32
