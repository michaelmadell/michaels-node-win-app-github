# C++17 → C++23 Upgrade Guide

This guide walks you through upgrading CoreStationHXAgent from C++17 to C++23. Changes are broken into phases so you can build and test incrementally. Nothing in Phase 1 changes behavior — it's purely enabling the compiler.

---

## Prerequisites

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| MSVC (Visual Studio) | 17.8+ | Full C++23 library support. Check via `cl /version` |
| GCC (MinGW / Linux) | 13+ | C++23 libstdc++ support |
| CMake | 3.15+ | Already at 3.15 in this project |

Verify your compiler before starting:
```powershell
cl /version          # Should show 19.38+ for VS 2022 17.8+
g++ --version        # Should show 13.x+
```

---

## Phase 1: Enable C++23 (No Code Changes)

These changes only tell the compiler to accept C++23 syntax. The code compiles the same way it did before.

### Step 1.1 — Update CMakeLists.txt

**File:** `CMakeLists.txt`, lines 20–22

Change:
```cmake
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
```

To:
```cmake
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
```

### Step 1.2 — Add C++23 Standard Flag for MSVC

**File:** `CMakeLists.txt`, lines 321–331

Change:
```cmake
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W3
        /EHsc
        /MP
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/MTd>
        $<$<CONFIG:Debug>:/Zi>
    )
```

To:
```cmake
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W3
        /EHsc
        /MP
        /permissive-
        /std:c++23
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/MTd>
        $<$<CONFIG:Debug>:/Zi>
    )
```

**What these flags do:**
- `/permissive-` — Enables strict standards conformance. Turns off some Microsoft-specific extensions that violate the C++ standard. This is recommended for all modern C++ projects. **You may get new warnings here — see Phase 3.**
- `/std:c++23` — Explicitly requests the C++23 dialect. Without this, MSVC may default to an earlier standard even if CMake says 23.

### Step 1.3 — Add C++23 Standard Flag for GCC/Clang

**File:** `CMakeLists.txt`, lines 332–340

Change:
```cmake
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
    )
```

To:
```cmake
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -std=c++23
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
    )
```

### Step 1.4 — Verify It Compiles

```powershell
# Windows (MSVC)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Linux (GCC)
./build-linux.sh
# or manually:
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

**Expected result:** Builds exactly as before. No new errors. If you get errors, they're likely from `/permissive-` exposing non-standard code — defer those to Phase 3.

---

## Phase 2: Adopt New Features (Incremental, Safe Changes)

These changes use C++23 features to improve the code. Each is independent — do them in any order.

### Feature 2.1 — `std::print` / `std::format` (Replacement for `std::cout` + `std::stringstream`)

**Why:** `std::cout << "x: " << value << std::endl` is verbose and error-prone. `std::format` is type-safe and concise. `std::print` skips the string allocation entirely.

**What to change:** Throughout the codebase, replace debug logging patterns.

**Before:**
```cpp
#include <sstream>
std::cout << "[DEBUG] Serial Port opened successfully." << std::endl;

std::stringstream ss;
ss << "CPU Usage: " << cpu << "%";
std::cout << ss.str() << std::endl;
```

**After:**
```cpp
#include <print>
std::print("[DEBUG] Serial Port opened successfully.\n");

// Or if you need a formatted string (e.g., to pass to a function):
#include <format>
std::string msg = std::format("CPU Usage: {}%\n", cpu);
```

**Files affected** (based on grep results):
- `src/main.cpp` — ~25 occurrences of `std::cout <<` and `std::stringstream`
- `src/linux/main.cpp` — ~20 occurrences
- `src/platform/WindowsPlatform.cpp` — `std::ostringstream` on lines 160, 182, 188
- `src/platform/WindowsPlatformInfo.cpp` — `std::ostringstream` on lines 76, 174, 221, 301
- `src/platform/LinuxPlatformMetrics.cpp` — `std::stringstream` on lines 22, 43, 77, 134, 148
- `src/platform/WindowsPlatformMetrics.cpp` — `std::stringstream` on lines 98, 147, 409
- `src/modules/cmc/CmcCommandHandler.cpp` — `std::stringstream` line 28, `std::ostringstream` lines 38, 96
- `src/modules/metrics/MetricsCollector.cpp` — `std::stringstream` on lines 125-128
- `src/modules/session/SessionMonitor.cpp` — `std::stringstream`
- `src/platform/LinuxPlatformInfo.cpp` — `std::stringstream` on line 88

**Migration pattern:**
1. If the output goes directly to `std::cout`/`std::cerr` → use `std::print` / `std::println` (note: `std::println` adds a newline automatically)
2. If you need a `std::string` → use `std::format`
3. Delete the `#include <sstream>` if no other code in the file uses it

**Caveats:**
- `std::print` writes directly to the file handle — no `std::ios` state to worry about
- Custom types need a `std::formatter<T>` specialization. All standard types (string, int, float, bool) work out of the box
- On Windows, `std::print` to `stdout`/`stderr` works fine. It does NOT write to Event Viewer (that's a separate concern — see the error handling guide)

### Feature 2.2 — `std::to_underlying` (Replacement for `static_cast<int>` on enums)

**Why:** Converting enums to integers is common in Windows API and serial protocol code. `static_cast<int>` works but is noisy and doesn't protect you from casting the wrong type.

**Before:**
```cpp
macStream << std::hex << static_cast<int>(byteValue);
```

**After:**
```cpp
#include <utility>
macStream << std::hex << std::to_underlying(enumValue);
```

**Files affected:**
- `src/platform/LinuxPlatformMetrics.cpp` — lines 65, 92 (`static_cast<int>`)
- `src/platform/WindowsPlatform.cpp` — line 185 (`static_cast<int>`)
- `src/platform/WindowsPlatformInfo.cpp` — line 81 (`static_cast<int>` on byte value for MAC address)
- `src/modules/serialpipe/LinuxIpcClientAuth.cpp` — line 141, 149 (`static_cast<int>` on `size_t` → `int` for OpenSSL)

**Note:** For `size_t` → `int` conversions (OpenSSL BIO calls), `std::to_underlying` doesn't apply — that's a narrowing conversion that should stay as `static_cast<int>`. Only use `std::to_underlying` for enum types.

### Feature 2.3 — `std::source_location` (Better error reporting)

**Why:** When you create error types (Phase 3), you'll want to know where errors occurred. `std::source_location` captures file, line, and function name at the call site — zero runtime cost when not used.

**Example — adding to an error struct:**
```cpp
#include <source_location>

struct SerialError {
    int code;
    const char* message;
    std::source_location location;

    static SerialError fail(int code, const char* msg,
                            const std::source_location& loc = std::source_location::current()) {
        return {code, msg, loc};
    }
};

// Usage:
return SerialError::fail(EBADF, "Port not open");  // captures current file/line
```

**Format for logging:**
```cpp
#include <print>

void logError(const SerialError& err) {
    std::print("[ERROR] {} ({}:{} in {})\n",
        err.message,
        err.location.file_name(),
        err.location.line(),
        err.location.function_name());
}
```

**Note:** `std::source_location::current()` only works in default arguments. You can't call it mid-expression. This is by design — it captures the caller's location, not the callee's.

### Feature 2.4 — `std::is_constant_evaluated()` (Compile-time branching)

**Why:** Useful if you ever write utility functions that should work in `constexpr` contexts but also at runtime. Not urgently needed for this codebase, but good to know about.

```cpp
#include <utility>

constexpr const char* error_message(int code) {
    if (std::is_constant_evaluated()) {
        // Compile-time path: simple lookup
        switch (code) {
            case 1: return "Port not found";
            case 2: return "Permission denied";
            default: return "Unknown error";
        }
    } else {
        // Runtime path: could load from resources, do I/O, etc.
        return lookup_error_in_database(code);
    }
}
```

---

## Phase 3: Fix `/permissive-` Compliance Issues

If `/permissive-` (Step 1.2) introduced new errors or warnings, here's what to look for:

### Common `/permissive-` Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `error C2039: 'value_type': is not a member of 'std::...'` | Non-standard type alias assumption | Add the missing type alias or use the correct name |
| `error C3646: 'override' : unknown override specifier` | Missing `override` on virtual method override | Add `override` keyword |
| `error C2440: 'static_cast' : cannot convert from ... to ...` | Strict casting rules | Use proper cast or fix the type mismatch |
| `warning C4244: conversion from '...' to '...'` | Narrowing conversion | Use `static_cast` explicitly or fix the type |
| `error: narrowing conversion from 'int' to 'float'` | Initializer list narrowing | Use `static_cast` or change the type |

### Specific Things to Check in This Codebase

1. **`const_cast<LPWSTR>` usage** — Found in `WindowsPlatform.cpp`, `WindowsPlatformInfo.cpp`, `WindowsIpcClientAuth.cpp`. These cast away constness to satisfy WinAPI signatures. `/permissive-` may flag these. They're functionally necessary but technically undefined behavior. **Acceptable to keep** with a comment explaining why, but consider wrapping in a helper function.

2. **`reinterpret_cast` in window procedures** — Found in `TrayApp.cpp` and `SessionMonitor.cpp` (casting `lParam` to `LPCREATESTRUCT`, then to class pointers). These are the standard Windows pattern for `WM_CREATE` handler. **Safe to keep** — this is how Win32 GUI programming works.

3. **`std::ostringstream` with `std::hex << static_cast<int>(byte)`** — The MAC address formatting in `WindowsPlatformInfo.cpp` line 81. This works but is verbose. Could become:
   ```cpp
   #include <format>
   std::string mac = std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
   ```

---

## Phase 4: Preparation for `std::expected` (Next Step)

`std::expected` is the biggest win from this upgrade, but it requires designing error types first. Don't rush this — it's a separate migration effort.

### What to Do Now (Prep Work)

1. **Audit current error handling** — Go through each module and list:
   - What functions can fail
   - How they currently report failure (return value, bool, exception, void with side effects)
   - What the failure cases are

2. **Design error type hierarchy** — Plan your types before writing code:
   ```
   Error (base)
   ├── SerialError   (port open/close/read/write failures)
   ├── PlatformError (OS query failures)
   ├── AuthError     (IPC signature verification failures)
   └── PipeError     (named pipe / Unix socket failures)
   ```

3. **Decide exception policy** — C++23 + `std::expected` usually means "no exceptions." Currently the code uses `try/catch` in:
   - `src/main.cpp` — heartbeatThread and resendThread exception handlers
   - `src/platform/LinuxPlatformMetrics.cpp` — multiple catch blocks
   - `src/platform/LinuxPlatformInfo.cpp` — interface enumeration
   - `src/modules/cmc/CmcCommandHandler.cpp` — time parsing

   If you adopt `std::expected`, these `try/catch` blocks become unnecessary — errors propagate as `std::unexpected` values instead.

### What NOT to Do Yet

- Don't start replacing functions with `std::expected` returns yet. That's a large refactoring that depends on the error type design
- Don't remove `try/catch` blocks yet. They're still useful as safety nets during the transition
- Don't worry about `std::format` replacing every `std::cout` line. Do it module by module, not all at once

---

## Rollback Plan

If something breaks badly:

```powershell
# Revert CMakeLists.txt changes
git checkout CMakeLists.txt

# Clean and rebuild
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The source files (`*.cpp`, `*.h`) have no changes in Phases 1-2, so there's nothing to revert there. Phase 3 changes are file-specific and can be reverted individually.

---

## Verification Checklist

After completing each phase, verify:

- [ ] **Phase 1** — Project builds with no errors on Windows (MSVC)
- [ ] **Phase 1** — Project builds with no errors on Linux (GCC)
- [ ] **Phase 1** — Runtime behavior is identical (test serial communication, heartbeat, C2A commands)
- [ ] **Phase 2** — Each feature adoption compiles and passes existing tests
- [ ] **Phase 3** — All `/permissive-` warnings/errors are resolved or documented
- [ ] **Phase 4** — Error type hierarchy design is documented and reviewed

---

## Summary of Changes

| File | Lines to Change | What Changes |
|------|----------------|--------------|
| `CMakeLists.txt` | 20-22, 321-340 | Standard version, `/std:c++23`, `-std=c++23`, `/permissive-` |
| `src/main.cpp` | ~30 lines | `std::cout` → `std::print`, `std::stringstream` → `std::format` |
| `src/linux/main.cpp` | ~25 lines | Same pattern |
| `src/platform/*.cpp` | ~20 lines | Same pattern |
| `src/modules/*/*.cpp` | ~15 lines | Same pattern |
| `tests/*.cpp` | ~5 lines | Same pattern |

Total files affected by Phase 2: ~15 files, ~100 lines of cosmetic changes. No logic changes.
