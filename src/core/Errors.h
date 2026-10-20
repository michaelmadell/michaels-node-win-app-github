#pragma once

// Structured error types for std::expected-based error handling.
//
// Each subsystem has its own error struct carrying a generic CoreError::Code,
// a subsystem-specific SubCode, a human-readable message and the OS error that
// triggered it (GetLastError() / errno, 0 if none). They are plain aggregates
// so call sites can use designated initializers:
//
//   return std::unexpected(core::SerialError{
//       .code = core::CoreError::Code::NotFound,
//       .sub_code = core::SerialError::SubCode::PortNotFound,
//       .message = "Failed to open port: " + portName,
//       .platform_error = GetLastError()});
//
// The subsystem structs deliberately don't inherit from CoreError: designated
// initializers can't name base-class members, so inheritance would force
// positional nested-brace construction at every call site. Code shared across
// error types is written against the core::Error concept instead.
//
// Every Code/SubCode enum is registered as a std::error_code enum with its own
// std::error_category, and each error struct converts via make_error_code().
//
// Header-only and platform-neutral: platform_error is a uint32_t so it holds
// either a Windows DWORD or a POSIX errno.

#include <concepts>
#include <cstdint>
#include <format>
#include <string>
#include <system_error>
#include <type_traits>

namespace core {

struct CoreError {
    enum class Code {
        Unknown = 0,
        InvalidArgument = 1,
        NotFound = 2,
        Timeout = 3,
        ResourceExhausted = 4,
        Internal = 5,
        IoError = 6,
        Busy = 7,
        PermissionDenied = 8,
    };
    Code code = Code::Unknown;
    std::string message;
    std::uint32_t platform_error = 0; // 0 if not applicable
};

struct SerialError {
    enum class SubCode {
        PortNotFound = 100,
        PortBusy = 101,
        ReadTimeout = 102,
        WriteError = 103,
        InvalidBaudRate = 104,
        ConfigureFailed = 105,
        ReadError = 106,
    };
    CoreError::Code code = CoreError::Code::Unknown;
    SubCode sub_code = SubCode::PortNotFound;
    std::string message;
    std::uint32_t platform_error = 0;
};

struct PlatformError {
    enum class SubCode {
        ServiceNotFound = 200,
        ServiceStartFailed = 201,
        ServiceStopFailed = 202,
        RegistryAccessDenied = 203,
        WmiQueryFailed = 204,
        RegistryWriteFailed = 205,
        PrivilegeAdjustFailed = 206,
        PowerActionFailed = 207,
        SessionActionFailed = 208,
        ProcessLaunchFailed = 209,
        VersionQueryFailed = 210,
        RegistryReadFailed = 211,
        DeviceNotFound = 212,
        DeviceControlFailed = 213,
    };
    CoreError::Code code = CoreError::Code::Unknown;
    SubCode sub_code = SubCode::ServiceNotFound;
    std::string message;
    std::uint32_t platform_error = 0;
};

struct AuthError {
    enum class SubCode {
        SignatureVerificationFailed = 300,
        CertificateExpired = 301,
        TrustedIdentityMismatch = 302,
        PipeAccessDenied = 303,
        ClientUnresolved = 304,
    };
    CoreError::Code code = CoreError::Code::Unknown;
    SubCode sub_code = SubCode::SignatureVerificationFailed;
    std::string message;
    std::uint32_t platform_error = 0;
};

struct PipeError {
    enum class SubCode {
        ConnectionFailed = 400,
        AuthRequired = 401,
        PipeBusy = 402,
        ClientDisconnected = 403,
        CreateFailed = 404,
        SetupFailed = 405,
    };
    CoreError::Code code = CoreError::Code::Unknown;
    SubCode sub_code = SubCode::ConnectionFailed;
    std::string message;
    std::uint32_t platform_error = 0;
};

// Anything shaped like the error structs above.
template <typename E>
concept Error = requires(const E& e) {
    { e.code } -> std::convertible_to<CoreError::Code>;
    { e.message } -> std::convertible_to<std::string>;
    { e.platform_error } -> std::convertible_to<std::uint32_t>;
};

// ---------------------------------------------------------------------------
// Code names
// ---------------------------------------------------------------------------

inline const char* to_string(CoreError::Code c) noexcept {
    switch (c) {
    case CoreError::Code::Unknown:           return "unknown";
    case CoreError::Code::InvalidArgument:   return "invalid argument";
    case CoreError::Code::NotFound:          return "not found";
    case CoreError::Code::Timeout:           return "timeout";
    case CoreError::Code::ResourceExhausted: return "resource exhausted";
    case CoreError::Code::Internal:          return "internal error";
    case CoreError::Code::IoError:           return "I/O error";
    case CoreError::Code::Busy:              return "busy";
    case CoreError::Code::PermissionDenied:  return "permission denied";
    }
    return "unrecognised core error";
}

inline const char* to_string(SerialError::SubCode c) noexcept {
    switch (c) {
    case SerialError::SubCode::PortNotFound:    return "serial port not found";
    case SerialError::SubCode::PortBusy:        return "serial port busy";
    case SerialError::SubCode::ReadTimeout:     return "serial read timeout";
    case SerialError::SubCode::WriteError:      return "serial write error";
    case SerialError::SubCode::InvalidBaudRate: return "invalid baud rate";
    case SerialError::SubCode::ConfigureFailed: return "serial port configuration failed";
    case SerialError::SubCode::ReadError:       return "serial read error";
    }
    return "unrecognised serial error";
}

inline const char* to_string(PlatformError::SubCode c) noexcept {
    switch (c) {
    case PlatformError::SubCode::ServiceNotFound:      return "service not found";
    case PlatformError::SubCode::ServiceStartFailed:   return "service start failed";
    case PlatformError::SubCode::ServiceStopFailed:    return "service stop failed";
    case PlatformError::SubCode::RegistryAccessDenied: return "registry access denied";
    case PlatformError::SubCode::WmiQueryFailed:       return "WMI/PDH query failed";
    case PlatformError::SubCode::RegistryWriteFailed:  return "registry write failed";
    case PlatformError::SubCode::PrivilegeAdjustFailed: return "privilege adjustment failed";
    case PlatformError::SubCode::PowerActionFailed:    return "shutdown/restart failed";
    case PlatformError::SubCode::SessionActionFailed:  return "session action failed";
    case PlatformError::SubCode::ProcessLaunchFailed:  return "process launch failed";
    case PlatformError::SubCode::VersionQueryFailed:   return "OS version query failed";
    case PlatformError::SubCode::RegistryReadFailed:   return "registry read failed";
    case PlatformError::SubCode::DeviceNotFound:       return "device not found";
    case PlatformError::SubCode::DeviceControlFailed:  return "device enable/disable failed";
    }
    return "unrecognised platform error";
}

inline const char* to_string(AuthError::SubCode c) noexcept {
    switch (c) {
    case AuthError::SubCode::SignatureVerificationFailed: return "signature verification failed";
    case AuthError::SubCode::CertificateExpired:          return "certificate expired";
    case AuthError::SubCode::TrustedIdentityMismatch:     return "trusted identity mismatch";
    case AuthError::SubCode::PipeAccessDenied:            return "pipe access denied";
    case AuthError::SubCode::ClientUnresolved:            return "client process could not be resolved";
    }
    return "unrecognised auth error";
}

inline const char* to_string(PipeError::SubCode c) noexcept {
    switch (c) {
    case PipeError::SubCode::ConnectionFailed:   return "pipe connection failed";
    case PipeError::SubCode::AuthRequired:       return "pipe authentication required";
    case PipeError::SubCode::PipeBusy:           return "pipe busy";
    case PipeError::SubCode::ClientDisconnected: return "pipe client disconnected";
    case PipeError::SubCode::CreateFailed:       return "pipe creation failed";
    case PipeError::SubCode::SetupFailed:        return "pipe listener setup failed";
    }
    return "unrecognised pipe error";
}

// ---------------------------------------------------------------------------
// std::error_category / std::error_code support
// ---------------------------------------------------------------------------

namespace detail {

template <typename Enum>
class EnumCategory final : public std::error_category {
public:
    explicit EnumCategory(const char* name) noexcept : name_(name) {}
    const char* name() const noexcept override { return name_; }
    std::string message(int value) const override { return to_string(static_cast<Enum>(value)); }

private:
    const char* name_;
};

} // namespace detail

inline const std::error_category& core_category() noexcept {
    static const detail::EnumCategory<CoreError::Code> category("core");
    return category;
}

inline const std::error_category& serial_category() noexcept {
    static const detail::EnumCategory<SerialError::SubCode> category("serial");
    return category;
}

inline const std::error_category& platform_category() noexcept {
    static const detail::EnumCategory<PlatformError::SubCode> category("platform");
    return category;
}

inline const std::error_category& auth_category() noexcept {
    static const detail::EnumCategory<AuthError::SubCode> category("auth");
    return category;
}

inline const std::error_category& pipe_category() noexcept {
    static const detail::EnumCategory<PipeError::SubCode> category("pipe");
    return category;
}

inline std::error_code make_error_code(CoreError::Code c) noexcept { return {static_cast<int>(c), core_category()}; }
inline std::error_code make_error_code(SerialError::SubCode c) noexcept { return {static_cast<int>(c), serial_category()}; }
inline std::error_code make_error_code(PlatformError::SubCode c) noexcept { return {static_cast<int>(c), platform_category()}; }
inline std::error_code make_error_code(AuthError::SubCode c) noexcept { return {static_cast<int>(c), auth_category()}; }
inline std::error_code make_error_code(PipeError::SubCode c) noexcept { return {static_cast<int>(c), pipe_category()}; }

// Error structs convert to their most specific code.
inline std::error_code make_error_code(const CoreError& e) noexcept { return make_error_code(e.code); }
inline std::error_code make_error_code(const SerialError& e) noexcept { return make_error_code(e.sub_code); }
inline std::error_code make_error_code(const PlatformError& e) noexcept { return make_error_code(e.sub_code); }
inline std::error_code make_error_code(const AuthError& e) noexcept { return make_error_code(e.sub_code); }
inline std::error_code make_error_code(const PipeError& e) noexcept { return make_error_code(e.sub_code); }

// "<message> (error 2: The system cannot find the file specified.)", or just
// the message when no OS error is attached.
template <Error E>
std::string describe(const E& e) {
    if (e.platform_error == 0) {
        return e.message;
    }
    std::string osText = std::system_category().message(static_cast<int>(e.platform_error));
    while (!osText.empty() && (osText.back() == '\n' || osText.back() == '\r' || osText.back() == ' ')) {
        osText.pop_back();
    }
    return std::format("{} (error {}: {})", e.message, e.platform_error, osText);
}

} // namespace core

template <> struct std::is_error_code_enum<core::CoreError::Code> : std::true_type {};
template <> struct std::is_error_code_enum<core::SerialError::SubCode> : std::true_type {};
template <> struct std::is_error_code_enum<core::PlatformError::SubCode> : std::true_type {};
template <> struct std::is_error_code_enum<core::AuthError::SubCode> : std::true_type {};
template <> struct std::is_error_code_enum<core::PipeError::SubCode> : std::true_type {};
