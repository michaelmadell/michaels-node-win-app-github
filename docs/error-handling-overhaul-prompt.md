# C++ Error Handling Overhaul: CoreStationHXAgent

## Context

You are working on the CoreStationHXAgent codebase — a Windows-native C++ agent that manages serial communication, IPC pipes, platform services, metrics collection, and remote command execution (C2A). The codebase is being upgraded from C++17 to C++23 as a prerequisite.

### Constraints
- **No runtime config files** for end users (features stay compile-time gated via CMake options)
- **Local dev config** is acceptable for build-time module selection
- **Linux parity** is not a current priority (focus on Windows code paths)
- **Telemetry** is scoped out for now
- **C2A command expansion** is deferred

### Current State
- MSVC `/EHsc` is already enabled (structured exceptions)
- Codebase uses `std::unique_ptr`, `std::make_unique`, move semantics — already modern C++ patterns
- Error signaling is fragmented: magic number returns, `bool` success flags, `std::stringstream` for error messages, hardcoded defaults on failure
- 5 files have `try/catch` blocks: `main.cpp` (2), `LinuxPlatformMetrics.cpp` (5), `LinuxPlatformInfo.cpp` (1), `CmcCommandHandler.cpp` (1)
- ~100 lines of `std::cout`/`std::stringstream` to replace with proper error handling

### Goal
Replace the current ad-hoc error handling with a structured, composable system centered on `std::expected` (C++23), with a clear error type hierarchy, systematic migration of existing patterns, and Windows Event Viewer integration for error reporting.

---

## Part 1: Error Type Hierarchy

Design a hierarchy of error types that map to each subsystem's failure domain. Each type should be a `struct` (not a class — no behavior needed) with a `std::string` message and a platform-specific error code.

### Requirements
- All error types inherit from a common `std::error_code`-compatible base
- Each type should support `std::error_category` for classification
- Error types must be constructible from a message string and optionally a Windows `DWORD` error code
- No exceptions in the types themselves — they are plain data carriers

### Suggested Structure

```cpp
// In src/core/Errors.h

namespace core {

// Base error category
class CoreErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override;
    std::string message(int condition) const override;
};

// Base error type
struct CoreError {
    enum class Code {
        Unknown = 0,
        InvalidArgument = 1,
        NotFound = 2,
        Timeout = 3,
        ResourceExhausted = 4,
        Internal = 5,
        // ...
    };
    Code code;
    std::string message;
    DWORD platform_error; // 0 if not applicable
};

// Subsystem-specific errors (each adds domain context)
struct SerialError : public CoreError {
    enum class SubCode {
        PortNotFound = 100,
        PortBusy = 101,
        ReadTimeout = 102,
        WriteError = 103,
        InvalidBaudRate = 104,
    };
    SubCode sub_code;
};

struct PlatformError : public CoreError {
    enum class SubCode {
        ServiceNotFound = 200,
        ServiceStartFailed = 201,
        ServiceStopFailed = 202,
        RegistryAccessDenied = 203,
        WmiQueryFailed = 204,
    };
    SubCode sub_code;
};

struct AuthError : public CoreError {
    enum class SubCode {
        SignatureVerificationFailed = 300,
        CertificateExpired = 301,
        TrustedIdentityMismatch = 302,
        PipeAccessDenied = 303,
    };
    SubCode sub_code;
};

struct PipeError : public CoreError {
    enum class SubCode {
        ConnectionFailed = 400,
        AuthRequired = 401,
        PipeBusy = 402,
        ClientDisconnected = 403,
    };
    SubCode sub_code;
};

} // namespace core
```

### Deliverable for Part 1
- Create `src/core/Errors.h` with the full hierarchy
- Implement `std::error_code` support (make `CoreError` convertible to `std::error_code`)
- Add a `make_error_code()` free function for each error type
- No `.cpp` file needed — everything is header-only

---

## Part 2: `std::expected` Adoption Strategy

`std::expected<E, T>` is the centerpiece. Every fallible operation returns `std::expected<T, E>` where `T` is the success value and `E` is one of the error types above.

### Adoption Rules
1. **Public API methods** always return `std::expected`
2. **Internal/private methods** may still return `bool` or throw if they are invariants (document which)
3. **Constructors** — keep throwing constructors for unrecoverable failures (e.g., "can't create event handle"), but use `std::expected` for fallible operations that callers can handle
4. **Event loop / main thread** — at the top level, convert `std::expected` to log messages and continue (don't crash)

### `std::expected` Usage Patterns to Enforce

```cpp
// Good: explicit error handling
auto result = serial_manager.OpenPort("COM3");
if (!result) {
    log_error("Failed to open COM3: ", result.error().message);
    return;
}
serial_manager.Write(result.value(), data);

// Good: early return with context
auto auth_result = verify_client_auth(pipe_handle);
if (!auth_result) {
    log_info("Auth failed for pipe client, disconnecting");
    DisconnectNamedPipe(pipe_handle);
    return;
}

// Bad: swallowing errors
auto result = serial_manager.OpenPort("COM3");
if (result) { /* ... */ } // what happens on failure?
```

### Phased Rollout
- **Phase A**: New code in existing modules uses `std::expected`
- **Phase B**: Migrate the serial module (highest impact, clearest win)
- **Phase C**: Migrate IPC/auth modules
- **Phase D**: Migrate platform modules
- **Phase E**: Migrate metrics and CMC command handler

---

## Part 3: Migration of Existing Error Patterns

### Pattern 1: Magic Number Returns

**Before** (SerialManager.cpp):
```cpp
bool SerialManager::OpenPort(const std::string& portName) {
    // ...
    if (!hSerial) return false;
    if (!SetCommMask(hSerial, EV_RXCHAR)) return false;
    // ...
    return true;
}
```

**After**:
```cpp
std::expected<void, SerialError> SerialManager::OpenPort(const std::string& portName) {
    auto hSerial = CreateFile(/* ... */);
    if (hSerial == INVALID_HANDLE_VALUE) {
        return std::unexpected(SerialError{
            .code = CoreError::Code::Internal,
            .sub_code = SerialError::SubCode::PortNotFound,
            .message = "Failed to open port: " + portName,
            .platform_error = GetLastError()
        });
    }
    // ...
    return {};
}
```

### Pattern 2: `bool` Success Flags + `std::stringstream` Error Messages

**Before** (WindowsPlatform.cpp):
```cpp
bool WindowsPlatform::StartService(const std::string& serviceName) {
    // ...
    if (!hService) {
        std::stringstream ss;
        ss << "Failed to start service: " << serviceName 
           << ", error=" << GetLastError();
        logMessage(ss.str());
        return false;
    }
    return true;
}
```

**After**:
```cpp
std::expected<void, PlatformError> WindowsPlatform::StartService(const std::string& serviceName) {
    // ...
    if (!hService) {
        DWORD err = GetLastError();
        logMessage(std::format("Failed to start service: {} (error={})", serviceName, err));
        return std::unexpected(PlatformError{
            .code = CoreError::Code::Internal,
            .sub_code = PlatformError::SubCode::ServiceStartFailed,
            .message = std::format("StartService failed for '{}'", serviceName),
            .platform_error = err
        });
    }
    return {};
}
```

### Pattern 3: Hardcoded Defaults on Failure

**Before** (metrics formatting):
```cpp
std::string WindowsPlatform::GetCpuUsage() {
    try {
        // ... PDH/WMI query
        return std::to_string(usage) + "%";
    } catch (...) {
        return "0%"; // silent failure
    }
}
```

**After**:
```cpp
std::expected<std::string, PlatformError> WindowsPlatform::GetCpuUsage() {
    // ... PDH/WMI query
    if (pdh_status != ERROR_SUCCESS) {
        return std::unexpected(PlatformError{
            .code = CoreError::Code::Internal,
            .sub_code = PlatformError::SubCode::WmiQueryFailed,
            .message = "PDH query failed for CPU usage",
            .platform_error = pdh_status
        });
    }
    return std::to_string(usage) + "%";
}
```

### Pattern 4: `try/catch` on Parsing

**Before** (CmcCommandHandler.cpp):
```cpp
try {
    time = std::stoul(token);
} catch (...) {
    time = 0; // default
}
```

**After**:
```cpp
auto result = std::stoul(token, &pos);
if (pos == 0 || token.empty()) {
    return std::unexpected(AuthError{
        .code = CoreError::Code::InvalidArgument,
        .sub_code = AuthError::SubCode::TrustedIdentityMismatch,
        .message = "Invalid time token: " + token
    });
}
```

### Files to Migrate (in priority order)

1. **`src/modules/serial/SerialManager.cpp` / `.h`** — Serial I/O, highest impact
2. **`src/modules/serialpipe/WindowsIpcClientAuth.cpp`** — IPC auth, returns `bool`
3. **`src/modules/serialpipe/SerialBridgePipe.cpp`** — Pipe lifecycle, `bool` returns
4. **`src/platform/WindowsPlatform.cpp`** — Service management, registry access
5. **`src/platform/WindowsPlatformMetrics.cpp`** — PDH/WMI metrics, `std::stringstream`
6. **`src/modules/cmc/CmcCommandHandler.cpp`** — Parsing, `try/catch` on `stoul`/`stod`
7. **`src/modules/amt/AMTPortManager.cpp`** — Registry enumeration, `bool` returns
8. **`src/main.cpp`** — Top-level `try/catch` at event loop boundary

---

## Part 4: Windows Event Viewer Integration

Errors need a destination. When `std::expected` carries an error up to the top level, it should be logged to Windows Event Viewer in addition to (or instead of) the in-process log.

### Requirements
- Create a lightweight `EventLogger` class in `src/core/EventLogger.h`
- Register the application as an event source on first use (one-time)
- Support three event types: `Information`, `Warning`, `Error`
- Map `CoreError::Code` to event severity
- No external dependencies — pure Win32 API

### Suggested API

```cpp
// In src/core/EventLogger.h
namespace core {

class EventLogger {
public:
    static EventLogger& instance();
    
    void log_error(const std::string& message, DWORD event_id = 0);
    void log_warning(const std::string& message, DWORD event_id = 0);
    void log_info(const std::string& message, DWORD event_id = 0);
    
    // Convenience: log a std::expected error to Event Viewer
    template<typename T, typename E>
    static void log_expected_error(const std::string& context, 
                                    const std::expected<T, E>& result) {
        if (!result) {
            auto& logger = instance();
            logger.log_error(context + ": " + result.error().message, 
                           static_cast<DWORD>(result.error().platform_error));
        }
    }
    
private:
    EventLogger();
    HKEY event_source_key_;
    bool registered_ = false;
    void ensure_registered();
};

} // namespace core
```

### Event Source Registration

The application must register its event source in the registry. This is a one-time admin operation, ideally done by an installer or setup script. For development, provide a `--register-event-source` flag.

Registry path: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\CoreStationHXAgent`

Key values:
- `EventMessageFile` → path to the application binary (it contains the message strings)
- `TypesSupported` → `7` (information, warning, error)

### Deliverable for Part 4
- `src/core/EventLogger.h` — header-only implementation
- `--register-event-source` flag in main.cpp
- Integration point: at the top of each event loop, call `EventLogger::log_expected_error()` when an `std::expected` is not ready

---

## Part 5: Exception Policy Decision

Currently, MSVC `/EHsc` is enabled. The question is whether to transition away from `try/catch` toward `std::expected` propagation.

### Recommendation: Hybrid Approach

1. **`std::expected`** for all fallible operations that callers can handle (serial I/O, auth, service management, metrics queries)
2. **`throw` / `try/catch`** preserved ONLY for:
   - Unrecoverable failures at the top level (e.g., "can't create main thread event")
   - External library calls that throw (e.g., COM, WMI)
   - Parsing errors in C2A commands (keep existing `try/catch` around `stoul`/`stod` for now — they're low-impact)
3. **Top-level boundary**: In `main.cpp`, wrap the main event loop in a single `try/catch` that logs to Event Viewer and continues. This is the "safety net" that catches anything that escapes `std::expected` handling.

### Code Changes for main.cpp

**Before**:
```cpp
try {
    // heartbeat loop
} catch (...) {
    std::cerr << "Heartbeat exception\n";
}
```

**After**:
```cpp
try {
    // heartbeat loop — all fallible ops return std::expected
} catch (const std::exception& e) {
    core::EventLogger::instance().log_error(
        std::format("Unhandled exception in heartbeat: {}", e.what()));
    // Don't crash — continue the main loop
} catch (...) {
    core::EventLogger::instance().log_error(
        "Unhandled unknown exception in heartbeat");
}
```

---

## Execution Plan

### Step 1: Create `src/core/Errors.h`
- Full error type hierarchy
- `std::error_code` support
- Header-only, no `.cpp` file

### Step 2: Create `src/core/EventLogger.h`
- Event Viewer integration
- `--register-event-source` support
- Template helper for `std::expected` error logging

### Step 3: Migrate SerialModule (SerialManager.cpp / .h)
- Convert `bool` returns to `std::expected<void, SerialError>`
- Replace `std::stringstream` error messages with structured error types
- Update all callers to handle `std::expected`

### Step 4: Migrate SerialBridgePipe / IPC Auth
- `verifyClientAuth()` → `std::expected<TrustedIdentity, AuthError>`
- `Start()` / `Stop()` → `std::expected<void, PipeError>`
- Update callers

### Step 5: Migrate WindowsPlatform
- Service management → `std::expected<void, PlatformError>`
- Registry access → `std::expected<std::string, PlatformError>`
- Replace `std::stringstream` with `std::format`

### Step 6: Migrate Metrics Modules
- `GetCpuUsage()`, `GetMemoryUsage()`, etc. → `std::expected<std::string, PlatformError>`
- Replace `try/catch` with `std::expected` returns
- Replace `std::stringstream` with `std::format`

### Step 7: Migrate CmcCommandHandler
- Parsing functions → `std::expected<T, AuthError>` where `T` is the parsed value
- Replace `try/catch` on `stoul`/`stod` with manual error checking

### Step 8: Migrate AMTPortManager
- Registry enumeration → `std::expected<std::vector<std::string>, PlatformError>`
- `bool` returns → `std::expected<void, PlatformError>`

### Step 9: Update main.cpp
- Replace top-level `try/catch` with `std::expected` handling
- Integrate `EventLogger` at event loop boundaries
- Add `--register-event-source` flag

### Step 10: Build Verification
- Compile with `/std:c++23 /permissive-`
- Verify no warnings on migrated code
- Test with invalid inputs (bad COM port, missing service, auth failure)
- Verify Event Viewer entries appear

---

## Quality Gates

1. **No `bool` return values for fallible operations** in public APIs
2. **No `std::stringstream` for error messages** — use `std::format` or structured error types
3. **No hardcoded defaults on failure** — errors must propagate
4. **Every `std::expected` must be handled** — no ignoring the `if (!result)` case
5. **Event Viewer entries for all top-level errors** — nothing silently swallowed
6. **No new `try/catch` blocks** — only existing ones preserved at boundaries
7. **Header-only error types** — no `.cpp` files for `Errors.h` or `EventLogger.h`

---

## Notes for the AI Agent

- When migrating a file, update both the `.h` declaration and the `.cpp` implementation
- When a method's return type changes, update ALL callers
- When adding `std::expected` to a method, add the `if (!result)` check at the call site
- Preserve existing logging format where possible — don't change log output style unless replacing `std::stringstream`
- Keep the existing `Log()` helper pattern — just change what it receives
- Do NOT modify Linux-specific code paths unless directly referenced from a Windows code path that IS being migrated
- Do NOT add tests — this is a production codebase, testing is out of scope
