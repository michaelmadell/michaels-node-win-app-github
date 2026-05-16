# Modular Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make file separation consistent, fix and unconditionally compile the Regedit module on Windows, structure the AMT COM port code cleanly in `main.cpp`, split `WindowsPlatform.cpp` into focused providers, and add comments/comment out dead code throughout.

**Architecture:** Regedit becomes a fixed, always-on utility class with a clean API. The AMT registry functions stay in `main.cpp` but are grouped and wired through Regedit. `WindowsPlatform.cpp` delegates network/OS discovery to `WindowsNetworkProvider` and serial I/O to `WindowsSerialProvider`, both new files under `src/platform/`.

**Tech Stack:** C++17, Win32 API (iphlpapi, wtsapi32, setupapi, advapi32), CMake 3.15+, MSVC

**Branch:** `20.26.5.1_rc4_prop`

**Spec:** `docs/superpowers/specs/2026-05-16-modular-refactor-design.md`

---

## File Map

| File | Action |
|------|--------|
| `src/modules/regedits/Regedit.h` | Rewrite — new signatures: HKEY root param, Binary methods, Logger-based constructor |
| `src/modules/regedits/Regedit.cpp` | Rewrite — fix error handling, implement all updated/new methods |
| `CMakeLists.txt` | Remove `BUILD_REGEDIT` option; add Regedit + providers unconditionally under `if(WIN32)` |
| `build.bat` | Remove `-DBUILD_REGEDIT=OFF` |
| `src/main.cpp` | Remove `ENABLE_REGEDIT` guards; wire Regedit; add AMT section delimiter + constants; comment out dead function |
| `src/platform/Windows_Addon.h` | Add `WideToUtf8()` inline helper |
| `src/platform/WindowsNetworkProvider.h` | New — declares `WindowsNetworkProvider` class |
| `src/platform/WindowsNetworkProvider.cpp` | New — implements getNetworkInterfaces, getHostname, getLoggedInUser, getOsVersion, getOsBuild |
| `src/platform/WindowsSerialProvider.h` | New — declares `WindowsSerialProvider` class |
| `src/platform/WindowsSerialProvider.cpp` | New — implements open, close, write, read; owns HANDLE lifetime |
| `src/platform/WindowsPlatform.h` | Add `networkProvider_` and `serialProvider_` members; remove serial private fields |
| `src/platform/WindowsPlatform.cpp` | Remove extracted methods; replace with one-line delegating stubs; update constructor |

---

## Task 1: Rewrite Regedit.h and Regedit.cpp

Fix the three issues in the Regedit module: duplicate error handling, hardcoded `HKEY_CURRENT_USER`, and missing binary read/write support. Also remove the `WindowsPlatform*` dependency — replace with a `Logger` function so Regedit has no circular dependency on the platform.

**Files:**
- Modify: `src/modules/regedits/Regedit.h`
- Modify: `src/modules/regedits/Regedit.cpp`

- [ ] **Step 1: Replace Regedit.h with new API**

```cpp
// src/modules/regedits/Regedit.h
#pragma once
#ifdef _WIN32
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

// Windows registry read/write helpers. Used by AMT port management and
// any other Windows-only code that needs clean open/check/use/close semantics.
class Regedit {
public:
    using Logger = std::function<void(const std::string&)>;
    explicit Regedit(Logger logger);
    ~Regedit() = default;

    // Read a REG_SZ value. outValue receives the string on success.
    bool Read(const std::string& path, std::string& outValue, HKEY root = HKEY_CURRENT_USER);
    // ReadBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
    bool ReadBinary(const std::string& path, std::vector<BYTE>& outData, HKEY root = HKEY_CURRENT_USER);
    bool Write(const std::string& path, const std::string& value, HKEY root = HKEY_CURRENT_USER);
    // WriteBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
    bool WriteBinary(const std::string& path, const std::vector<BYTE>& data, HKEY root = HKEY_CURRENT_USER);
    bool Create(const std::string& path, const std::string& value, HKEY root = HKEY_CURRENT_USER);
    bool Delete(const std::string& path, HKEY root = HKEY_CURRENT_USER);

    Regedit(const Regedit&) = delete;
    Regedit& operator=(const Regedit&) = delete;

private:
    Logger log_;
    // Split "Key\\SubKey\\ValueName" at the last backslash into (subKey, valueName).
    bool splitPath(const std::string& path, std::string& subKey, std::string& valueName) const;
};

#endif // _WIN32
```

- [ ] **Step 2: Replace Regedit.cpp with fixed implementation**

The original `Write()` called `RegCreateKeyExA` up to 9 times in a chain of else-if branches — one call per error code — instead of calling it once and branching on the result. The replacement calls it once, stores the `LSTATUS`, then switches on the error code.

```cpp
// src/modules/regedits/Regedit.cpp
#ifdef _WIN32
#include "Regedit.h"
#include <windows.h>

Regedit::Regedit(Logger logger) : log_(std::move(logger)) {}

bool Regedit::splitPath(const std::string& path, std::string& subKey, std::string& valueName) const {
    size_t last = path.find_last_of('\\');
    if (last == std::string::npos) {
        log_("ERROR: Invalid registry path (no backslash): " + path);
        return false;
    }
    subKey    = path.substr(0, last);
    valueName = path.substr(last + 1);
    return true;
}

bool Regedit::Read(const std::string& path, std::string& outValue, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key: " + subKey);
        return false;
    }

    char buffer[512] = {};
    DWORD bufferSize = sizeof(buffer);
    DWORD type = 0;
    LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, (LPBYTE)buffer, &bufferSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || type != REG_SZ) {
        log_("ERROR: Failed to read registry value or not REG_SZ: " + valueName);
        return false;
    }
    outValue = buffer;
    log_("Registry Read OK: " + subKey + "\\" + valueName + " = " + outValue);
    return true;
}

// ReadBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
bool Regedit::ReadBinary(const std::string& path, std::vector<BYTE>& outData, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key: " + subKey);
        return false;
    }

    DWORD dataSize = 0;
    DWORD type = 0;
    // First call: get required buffer size
    LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &dataSize);
    if (result != ERROR_SUCCESS || type != REG_BINARY || dataSize == 0) {
        RegCloseKey(hKey);
        log_("ERROR: Failed to query binary value size: " + valueName);
        return false;
    }

    outData.resize(dataSize);
    result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, outData.data(), &dataSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to read binary registry value: " + valueName);
        return false;
    }
    log_("Registry ReadBinary OK: " + subKey + "\\" + valueName);
    return true;
}

bool Regedit::Write(const std::string& path, const std::string& value, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    // REPLACED: original called RegCreateKeyExA once per error-code branch (9 calls total).
    // Call it once and switch on the result.
    LSTATUS status = RegCreateKeyExA(root, subKey.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) {
        switch (status) {
        case ERROR_INVALID_FUNCTION: log_("ERROR: Invalid function call opening: " + subKey); break;
        case ERROR_FILE_NOT_FOUND:   log_("ERROR: Key not found: "               + subKey); break;
        case ERROR_PATH_NOT_FOUND:   log_("ERROR: Path not found: "              + subKey); break;
        case ERROR_ACCESS_DENIED:    log_("ERROR: Access denied: "               + subKey); break;
        case ERROR_CANTWRITE:        log_("ERROR: Cannot write to: "             + subKey); break;
        case ERROR_KEY_DELETED:      log_("ERROR: Key marked for deletion: "     + subKey); break;
        case ERROR_NO_MORE_ITEMS:    log_("ERROR: Registry full, cannot add: "   + subKey); break;
        default:                     log_("ERROR: Failed to create/open: "       + subKey); break;
        }
        return false;
    }

    LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ,
        (const BYTE*)value.c_str(), (DWORD)(value.size() + 1));
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to write registry value: " + valueName);
        return false;
    }
    log_("Registry Write OK: " + subKey + "\\" + valueName + " = " + value);
    return true;
}

// WriteBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
bool Regedit::WriteBinary(const std::string& path, const std::vector<BYTE>& data, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    LSTATUS status = RegCreateKeyExA(root, subKey.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) {
        log_("ERROR: Failed to open/create key for binary write: " + subKey);
        return false;
    }

    LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_BINARY,
        data.data(), (DWORD)data.size());
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to write binary registry value: " + valueName);
        return false;
    }
    log_("Registry WriteBinary OK: " + subKey + "\\" + valueName);
    return true;
}

bool Regedit::Create(const std::string& path, const std::string& value, HKEY root) {
    return Write(path, value, root);
}

bool Regedit::Delete(const std::string& path, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key for delete: " + subKey);
        return false;
    }
    LONG result = RegDeleteValueA(hKey, valueName.c_str());
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to delete registry value: " + valueName);
        return false;
    }
    log_("Registry Delete OK: " + valueName);
    return true;
}

#endif // _WIN32
```

- [ ] **Step 3: Commit**

```bash
git add src/modules/regedits/Regedit.h src/modules/regedits/Regedit.cpp
git commit -m "fix: rewrite Regedit module with clean error handling, HKEY root param, and binary support"
```

---

## Task 2: Remove BUILD_REGEDIT from Build System and main.cpp

Registry support on Windows is now unconditional. Remove the `BUILD_REGEDIT` option from CMakeLists.txt, the `-DBUILD_REGEDIT=OFF` flag from build.bat, and the `ENABLE_REGEDIT` guards in main.cpp.

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `build.bat`
- Modify: `src/main.cpp`

- [ ] **Step 1: Update CMakeLists.txt**

Find and replace the `BUILD_REGEDIT` option line (line 14) with a comment:
```cmake
# REMOVED: registry module is now unconditional on Windows (_WIN32); BUILD_REGEDIT option eliminated.
# option(BUILD_REGEDIT "Build with registry editing components (Windows only)" ON)
```

Find the `if(BUILD_REGEDIT)` block inside the `if(WIN32)` section (around lines 172-176) and replace with an unconditional append:
```cmake
    # Registry module always compiled on Windows — no flag needed.
    list(APPEND MODULE_SOURCES
        src/modules/regedits/Regedit.cpp
    )
```

Find the second `if(BUILD_REGEDIT)` block in the HEADER_FILES section (around lines 206-208) and replace with:
```cmake
    # Registry module header always included on Windows.
    list(APPEND HEADER_FILES src/modules/regedits/Regedit.h)
```

Find the `if(BUILD_REGEDIT AND WIN32)` compile-definitions block (around lines 251-253) and replace with:
```cmake
# REMOVED: ENABLE_REGEDIT define eliminated; Regedit.h is included directly under #ifdef _WIN32.
# if(BUILD_REGEDIT AND WIN32)
#     target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_REGEDIT)
# endif()
```

Find the status print line `message(STATUS "  Registry Edit:   ${BUILD_REGEDIT}")` and replace with:
```cmake
message(STATUS "  Registry Edit:   Windows (always)")
```

- [ ] **Step 2: Update build.bat**

Find line 37:
```bat
cmake -S . -B "%BUILD_DIR%" -A x64 -DBUILD_REGEDIT=OFF
```
Replace with:
```bat
cmake -S . -B "%BUILD_DIR%" -A x64
```

- [ ] **Step 3: Update main.cpp — remove ENABLE_REGEDIT guards**

Find (around lines 25-27):
```cpp
#ifdef ENABLE_REGEDIT
#include "modules/regedits/Regedit.h"
#endif
```
Replace with:
```cpp
#ifdef _WIN32
#include "modules/regedits/Regedit.h"
#endif
```

Find (around lines 44-46):
```cpp
#ifdef ENABLE_REGEDIT
std::unique_ptr<Regedit> regedit;
#endif
```
Replace with:
```cpp
#ifdef _WIN32
std::unique_ptr<Regedit> regedit;
#endif
```

- [ ] **Step 4: Instantiate regedit in main() immediately after platform creation**

In `main()`, find the line:
```cpp
    platform = createPlatform();
```
Add directly after it:
```cpp
#ifdef _WIN32
    // Regedit is always initialized on Windows — used by AMT COM port management below.
    regedit = std::make_unique<Regedit>([](const std::string& msg) {
        platform->logMessage(msg);
    });
#endif
```

- [ ] **Step 5: Commit**

```bash
git add CMakeLists.txt build.bat src/main.cpp
git commit -m "build: make Regedit unconditional on Windows, remove BUILD_REGEDIT flag"
```

---

## Task 3: Restructure AMT Section in main.cpp

Add section delimiters, extract magic literals to named constants, wire Regedit for non-enumeration registry operations, and comment out the dead `readSerialPortWorker()` function.

**Files:**
- Modify: `src/main.cpp`

- [ ] **Step 1: Add AMT section opener and extract constants**

Find the `struct AMTPortInfo` definition (line 152) and insert before it:

```cpp
// =============================================================================
// === AMT COM Port Management =================================================
// =============================================================================
// Intel AMT Serial-over-LAN (SOL) uses a virtual COM port managed by the
// Windows PnP driver. On HX2000 hardware, AMT defaults to COM3, which
// conflicts with the CoreStation BMC serial connection. The functions below
// detect, disable, and reassign the AMT COM port at startup.
```

Immediately after the section opener comment, before `struct AMTPortInfo`, add the constants:

```cpp
// Target COM port for the CoreStation BMC serial link.
static constexpr char kBmcComPort[]    = "COM3";
// COM port AMT SOL is reassigned to when it conflicts with kBmcComPort.
static constexpr char kAmtTargetPort[] = "COM4";
// kAmtTargetPort in wide-string form for Win32 registry calls.
static constexpr wchar_t kAmtTargetPortW[] = L"COM4";
// AMT SOL device display name written to the registry after reassignment.
static constexpr wchar_t kAmtFriendlyName[] = L"Intel(R) Active Management Technology - SOL (COM4)";
// COM Name Arbiter ComDB bitmask for COM4.
// ComDB is a binary array; COM N occupies bit (N-1) in byte floor((N-1)/8).
// COM4 = bit index 3 → byte[0] bit 3 → 0x08.
static constexpr BYTE kComDbCom4Bit = 0x08;
// Registry path for the COM Name Arbiter database (includes value name).
static constexpr char kComArbiterPath[] =
    "SYSTEM\\CurrentControlSet\\Control\\COM Name Arbiter\\ComDB";
```

- [ ] **Step 2: Wire Regedit in `reassignComPort()` — Step 1 (COM Name Arbiter)**

In `reassignComPort()`, find the `// --- Step 1: COM Name Arbiter` block. The current implementation opens the key with `RegOpenKeyExW`, calls `RegQueryValueExW` for ComDB, and `RegSetValueExW` to write it back. Replace with:

```cpp
    // --- Step 1: COM Name Arbiter — reserve COM4 ---
    // ComDB is a binary bitmask. COM N occupies bit (N-1) in byte floor((N-1)/8).
    // COM4 = bit index 3 → byte[0] bit 3 → kComDbCom4Bit (0x08)
    {
        std::vector<BYTE> comDb;
        if (regedit->ReadBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE)) {
            if (comDb.size() < 1) comDb.resize(8, 0);
            if (!(comDb[0] & kComDbCom4Bit)) {
                comDb[0] |= kComDbCom4Bit;
                regedit->WriteBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE);
                platform->logMessage("COM Name Arbiter: COM4 reserved.");
            } else {
                platform->logMessage("COM Name Arbiter: COM4 was already reserved.");
            }
        } else {
            platform->logMessage("WARNING: Could not read COM Name Arbiter — continuing anyway.");
        }
    }
```

- [ ] **Step 3: Wire Regedit in `reassignComPort()` — Step 2 (PortName + FriendlyName writes)**

In `reassignComPort()`, find the loop body inside `// --- Step 2: Write PortName and FriendlyName`. Locate the two block sections that set FriendlyName and PortName with `RegSetValueExW` / `RegCreateKeyExW`. Replace those two blocks with:

```cpp
            // Build narrow key paths (HWID and instance IDs are ASCII-safe)
            std::string narrowDevKey(devKeyPath.begin(), devKeyPath.end());
            std::string narrowInstance(instanceName, instanceName + wcslen(instanceName));
            std::string friendlyPath = narrowDevKey + "\\" + narrowInstance + "\\FriendlyName";
            std::string portPath     = narrowDevKey + "\\" + narrowInstance + "\\Device Parameters\\PortName";

            // Write FriendlyName and PortName via Regedit (creates Device Parameters if absent)
            regedit->Write(friendlyPath, "Intel(R) Active Management Technology - SOL (COM4)", HKEY_LOCAL_MACHINE);
            if (regedit->Write(portPath, kAmtTargetPort, HKEY_LOCAL_MACHINE)) {
                platform->logMessage("Set PortName=COM4 for: " + std::string(instancePath.begin(), instancePath.end()));
            } else {
                platform->logMessage("ERROR: Failed to write PortName for: " + std::string(instancePath.begin(), instancePath.end()));
            }
```

Also remove the now-unused `const wchar_t* targetPort` and `const wchar_t* friendlyName` local variables since they are replaced by `kAmtTargetPort` / `kAmtFriendlyName` constants (though `kAmtFriendlyName` is now unused too — leave it as a named constant for documentation).

- [ ] **Step 4: Wire Regedit in `GetAMTComPort()` — PortName read**

In `GetAMTComPort()`, find the inner `if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramPath.c_str()...` block that reads `PortName`. Replace it with:

```cpp
                std::string narrowDevKey(devKeyPath.begin(), devKeyPath.end());
                std::string narrowInstance(instanceName, instanceName + wcslen(instanceName));
                std::string portPath = narrowDevKey + "\\" + narrowInstance + "\\Device Parameters\\PortName";

                std::string portNameA;
                if (regedit->Read(portPath, portNameA, HKEY_LOCAL_MACHINE)) {
                    RegCloseKey(hDevKey);
                    std::wstring portNameW(portNameA.begin(), portNameA.end());
                    std::wstring fullId = std::wstring(L"PCI\\") + kAMTDeviceHwids[i] + L"\\" + instanceName;
                    return {portNameW, fullId};
                }
```

- [ ] **Step 5: Add AMT section closer**

Find the end of `reassignComPort()` (the closing `#endif` + `}`) and add after it:

```cpp
// =============================================================================
// === End AMT COM Port Management =============================================
// =============================================================================
```

- [ ] **Step 6: Comment out `readSerialPortWorker()`**

Find the function definition starting at `void readSerialPortWorker() {` (around line 462). Wrap the entire function body:

```cpp
/* NOT CALLED: serialThread() reads incoming data via serialManager->ProcessIncomingData()
   and platform->readSerial() directly. This worker stub was never wired into any thread.
void readSerialPortWorker() {
    ... (original body preserved verbatim) ...
}
*/
```

- [ ] **Step 7: Replace magic COM port literals in `main()` with constants**

In `main()`, find:
```cpp
    if (AMTInfo.comPort == L"COM3") {
```
This references the hardcoded `L"COM3"`. Replace with a wide-string version of the constant. Add at the top of the AMT constants block (Step 1):
```cpp
// kBmcComPort in wide-string form for comparison with Win32 registry values.
static constexpr wchar_t kBmcComPortW[] = L"COM3";
```

Then replace in `main()`:
```cpp
    if (AMTInfo.comPort == kBmcComPortW) {
```

Also replace the second occurrence in `reassignComPort()` Step 4 (Verify):
```cpp
    if (newInfo.comPort == kBmcComPortW) {
```

- [ ] **Step 8: Commit**

```bash
git add src/main.cpp
git commit -m "refactor: structure AMT section in main.cpp with delimiters, constants, and Regedit wiring"
```

---

## Task 4: Add WideToUtf8 Inline Helper to Windows_Addon.h

`WideToUtf8()` is currently a static free function in `WindowsPlatform.cpp`. After splitting that file, both `WindowsNetworkProvider.cpp` and `WindowsPlatform.cpp` need it. Moving it to `Windows_Addon.h` (the shared Windows utility header) makes it available to all platform files.

**Files:**
- Modify: `src/platform/Windows_Addon.h`

- [ ] **Step 1: Add include and helper to Windows_Addon.h**

Find the `#pragma once` at the top of `Windows_Addon.h` and add after the existing includes:

```cpp
#include <string>
```

At the end of the file (before or after `ComInitializer`), add:

```cpp
// UTF-16 to UTF-8 conversion used across Windows platform files.
inline std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
                                   nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
                        &result[0], size, nullptr, nullptr);
    return result;
}
```

- [ ] **Step 2: Remove duplicate definition from WindowsPlatform.cpp**

In `WindowsPlatform.cpp`, find the `std::string WideToUtf8(...)` free function definition (around lines 66-74) and delete it. The inline version in `Windows_Addon.h` replaces it — `WindowsPlatform.cpp` already includes `Windows_Addon.h`.

- [ ] **Step 3: Commit**

```bash
git add src/platform/Windows_Addon.h src/platform/WindowsPlatform.cpp
git commit -m "refactor: move WideToUtf8 to Windows_Addon.h so all platform files can share it"
```

---

## Task 5: Create WindowsNetworkProvider

Extract the five read-only discovery methods from `WindowsPlatform.cpp` into a new `WindowsNetworkProvider` class. `WindowsPlatform` adds a member of this type and its interface methods become one-line delegating stubs.

**Files:**
- Create: `src/platform/WindowsNetworkProvider.h`
- Create: `src/platform/WindowsNetworkProvider.cpp`
- Modify: `src/platform/WindowsPlatform.h`
- Modify: `src/platform/WindowsPlatform.cpp`
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Create WindowsNetworkProvider.h**

```cpp
// src/platform/WindowsNetworkProvider.h
#pragma once
// Windows network interface and OS version discovery (read-only, no retained handles).
#ifdef _WIN32
#include "core/SystemState.h"
#include <string>
#include <vector>

class WindowsNetworkProvider {
public:
    std::vector<NetworkInterface> getNetworkInterfaces();
    std::string getHostname();
    std::string getLoggedInUser();
    std::string getOsVersion();
    std::string getOsBuild();
};

#endif // _WIN32
```

- [ ] **Step 2: Create WindowsNetworkProvider.cpp**

Cut the following method implementations from `WindowsPlatform.cpp` verbatim and place them here. Add the file-level comment and required includes at the top:

```cpp
// src/platform/WindowsNetworkProvider.cpp
// Windows network interface and OS version discovery (read-only, no retained handles).
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "WindowsNetworkProvider.h"
#include "Windows_Addon.h"
#include <wtsapi32.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

// RtlGetVersion is used instead of GetVersionEx (deprecated in Windows 8.1+)
// because GetVersionEx lies about the version when there is no manifest.
typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static std::string Trim(const std::string& input) {
    if (input.empty()) return {};
    const char* ws = " \t\r\n";
    size_t start = input.find_first_not_of(ws);
    if (start == std::string::npos) return {};
    size_t end = input.find_last_not_of(ws);
    return input.substr(start, end - start + 1);
}
```

Then paste the five method bodies from `WindowsPlatform.cpp` with the class name changed to `WindowsNetworkProvider::`:

- `std::vector<NetworkInterface> WindowsNetworkProvider::getNetworkInterfaces()` — copy from WindowsPlatform.cpp lines 362–435 verbatim, change `WindowsPlatform::` to `WindowsNetworkProvider::`
- `std::string WindowsNetworkProvider::getHostname()` — copy from lines 437–446
- `std::string WindowsNetworkProvider::getLoggedInUser()` — copy from lines 448–473
- `std::string WindowsNetworkProvider::getOsVersion()` — copy from lines 475–523
- `std::string WindowsNetworkProvider::getOsBuild()` — copy from lines 525–543

Close with:
```cpp
#endif // _WIN32
```

- [ ] **Step 3: Add networkProvider_ to WindowsPlatform.h**

In `WindowsPlatform.h`, add the include after the existing platform includes:
```cpp
#include "WindowsNetworkProvider.h"
```

In the `private:` section of `WindowsPlatform`, add:
```cpp
    WindowsNetworkProvider networkProvider_;
```

- [ ] **Step 4: Replace network/OS methods in WindowsPlatform.cpp with delegating stubs**

In `WindowsPlatform.cpp`, remove the five method bodies that were moved to `WindowsNetworkProvider.cpp` and replace each with a one-line delegating stub:

```cpp
std::vector<NetworkInterface> WindowsPlatform::getNetworkInterfaces() {
    return networkProvider_.getNetworkInterfaces();
}

std::string WindowsPlatform::getHostname() {
    return networkProvider_.getHostname();
}

std::string WindowsPlatform::getLoggedInUser() {
    return networkProvider_.getLoggedInUser();
}

std::string WindowsPlatform::getOsVersion() {
    return networkProvider_.getOsVersion();
}

std::string WindowsPlatform::getOsBuild() {
    return networkProvider_.getOsBuild();
}
```

Also remove the `RtlGetVersionPtr` typedef and `Trim()` / `WideToUtf8()` functions from `WindowsPlatform.cpp` — `WideToUtf8` is now in `Windows_Addon.h`, `RtlGetVersionPtr` and `Trim` now live in `WindowsNetworkProvider.cpp`.

- [ ] **Step 5: Add WindowsNetworkProvider.cpp to CMakeLists.txt**

In `CMakeLists.txt`, find the `if(WIN32)` block where `WindowsPlatform.cpp` is listed (around line 146):
```cmake
    list(APPEND CORE_SOURCES
        src/platform/WindowsPlatform.cpp
    )
```
Add the new file:
```cmake
    list(APPEND CORE_SOURCES
        src/platform/WindowsPlatform.cpp
        src/platform/WindowsNetworkProvider.cpp
    )
```

- [ ] **Step 6: Commit**

```bash
git add src/platform/WindowsNetworkProvider.h src/platform/WindowsNetworkProvider.cpp src/platform/WindowsPlatform.h src/platform/WindowsPlatform.cpp CMakeLists.txt
git commit -m "refactor: extract WindowsNetworkProvider from WindowsPlatform"
```

---

## Task 6: Create WindowsSerialProvider

Extract the four serial I/O methods from `WindowsPlatform.cpp` into a new `WindowsSerialProvider` class that owns the COM handle lifetime. Also fix the hardcoded `"COM3"` reconnect string in `writeSerial` by storing the last-used port name.

**Files:**
- Create: `src/platform/WindowsSerialProvider.h`
- Create: `src/platform/WindowsSerialProvider.cpp`
- Modify: `src/platform/WindowsPlatform.h`
- Modify: `src/platform/WindowsPlatform.cpp`
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Create WindowsSerialProvider.h**

```cpp
// src/platform/WindowsSerialProvider.h
#pragma once
// Windows COM port serial I/O — owns the HANDLE lifetime for one port at a time.
#ifdef _WIN32
#include "Windows_Addon.h"
#include <string>
#include <functional>
#include <chrono>

class WindowsSerialProvider {
public:
    using Logger = std::function<void(const std::string&)>;
    explicit WindowsSerialProvider(Logger logger);

    bool open(const std::string& portName, int baudrate);
    void close();
    bool write(const std::string& data);
    bool read(std::string& outData);
    bool isOpen() const;

private:
    Logger log_;
    UniqueHandle hSerial_{INVALID_HANDLE_VALUE};
    std::string lastPortName_;
    int lastBaudrate_ = 115200;
    std::chrono::steady_clock::time_point lastAttempt_;
    // Minimum milliseconds between reconnect attempts in write() when port is closed.
    static constexpr int RETRY_DELAY_MS = 5000;
};

#endif // _WIN32
```

- [ ] **Step 2: Create WindowsSerialProvider.cpp**

```cpp
// src/platform/WindowsSerialProvider.cpp
// Windows COM port serial I/O — owns the HANDLE lifetime for one port at a time.
#ifdef _WIN32
#include "WindowsSerialProvider.h"
#include <windows.h>
#include <string>
#include <sstream>

WindowsSerialProvider::WindowsSerialProvider(Logger logger)
    : log_(std::move(logger))
    , hSerial_(INVALID_HANDLE_VALUE)
{}

bool WindowsSerialProvider::isOpen() const {
    return hSerial_.get() != INVALID_HANDLE_VALUE && hSerial_.get() != nullptr;
}
```

Now paste the four method bodies from `WindowsPlatform.cpp` with the class name changed to `WindowsSerialProvider::` and member names updated:

For `open()` — copy `WindowsPlatform::openSerialPort()` (lines 545–608), rename to `WindowsSerialProvider::open()`, change `hSerial` to `hSerial_`, `logMessage(...)` to `log_(...)`, and add at the start of the function body:
```cpp
    lastPortName_ = portName;
    lastBaudrate_ = baudrate;
```

For `close()` — copy `WindowsPlatform::closeSerialPort()` (lines 610–613), rename to `WindowsSerialProvider::close()`, change `hSerial` to `hSerial_`.

For `write()` — copy `WindowsPlatform::writeSerial()` (lines 615–645), rename to `WindowsSerialProvider::write()`. Change `hSerial` to `hSerial_`, `logMessage(...)` to `log_(...)`. In the reconnect block, replace the hardcoded `"COM3"` with `lastPortName_`:
```cpp
            // Reconnect using last known port — avoids hardcoded port name here.
            if (open(lastPortName_, lastBaudrate_)) {
```

For `read()` — copy `WindowsPlatform::readSerial()` (lines 647–668), rename to `WindowsSerialProvider::read()`. Change `hSerial` to `hSerial_`, `logMessage(...)` to `log_(...)`.

Close with:
```cpp
#endif // _WIN32
```

- [ ] **Step 3: Update WindowsPlatform.h — add serialProvider_, remove serial private fields**

Add the include after `WindowsNetworkProvider.h`:
```cpp
#include "WindowsSerialProvider.h"
```

In the `private:` section, remove:
```cpp
    UniqueHandle hSerial = UniqueHandle(INVALID_HANDLE_VALUE);
    std::chrono::steady_clock::time_point lastSerialAttempt_;
    static constexpr int SERIAL_RETRY_DELAY_MS = 5000;
```

Replace with:
```cpp
    WindowsSerialProvider serialProvider_;
```

- [ ] **Step 4: Update WindowsPlatform.cpp — constructor + delegating serial stubs**

In the constructor initializer list, add `serialProvider_` initialization. The provider takes a Logger so it can call `logMessage()`. Update the constructor to:

```cpp
WindowsPlatform::WindowsPlatform()
    : serialProvider_([this](const std::string& msg) { logMessage(msg); })
{
    g_platform_instance = this;
    // ... rest of constructor body unchanged
```

Remove the four serial method bodies from `WindowsPlatform.cpp` and replace with delegating stubs:

```cpp
bool WindowsPlatform::openSerialPort(const std::string& portName, int baudrate) {
    return serialProvider_.open(portName, baudrate);
}

void WindowsPlatform::closeSerialPort() {
    serialProvider_.close();
}

bool WindowsPlatform::writeSerial(const std::string& data) {
    return serialProvider_.write(data);
}

bool WindowsPlatform::readSerial(std::string& data) {
    return serialProvider_.read(data);
}
```

- [ ] **Step 5: Add WindowsSerialProvider.cpp to CMakeLists.txt**

Find the `CORE_SOURCES` append block updated in Task 5 and add the new file:
```cmake
    list(APPEND CORE_SOURCES
        src/platform/WindowsPlatform.cpp
        src/platform/WindowsNetworkProvider.cpp
        src/platform/WindowsSerialProvider.cpp
    )
```

- [ ] **Step 6: Commit**

```bash
git add src/platform/WindowsSerialProvider.h src/platform/WindowsSerialProvider.cpp src/platform/WindowsPlatform.h src/platform/WindowsPlatform.cpp CMakeLists.txt
git commit -m "refactor: extract WindowsSerialProvider from WindowsPlatform"
```

---

## Task 7: Build, Verify, and Add File-Level Comments

Run the build to confirm all files compile and link correctly. Then add the remaining file-purpose comments and the CMake `if(WIN32)` comment.

**Files:**
- Run: `build.bat`
- Modify: `src/platform/WindowsPlatform.cpp` (file header)
- Modify: `CMakeLists.txt` (WIN32 block comment)

- [ ] **Step 1: Build and check for errors**

Run from the repo root:
```bat
build.bat
```

Expected output ends with:
```
BUILD SUCCESSFUL (completed in N seconds)
```

If there are compile errors, the most likely causes are:
- Missing `#include` in a provider file — check what symbols are undefined and add the appropriate header
- `WideToUtf8` redefinition — ensure the static definition in `WindowsPlatform.cpp` was fully removed in Task 4 Step 4
- `hSerial` reference remaining in `WindowsPlatform.cpp` — ensure all four serial method bodies were removed
- `RtlGetVersionPtr` typedef missing from a file — it should now only be in `WindowsNetworkProvider.cpp`

- [ ] **Step 2: Add file-level purpose comments to new and modified platform files**

Add a one-line purpose comment at the top of `WindowsPlatform.cpp` (after the `#ifdef _WIN32` guard):
```cpp
// Windows platform implementation — service lifecycle, session monitoring, logging, and metrics.
// Network discovery delegated to WindowsNetworkProvider; serial I/O delegated to WindowsSerialProvider.
```

Add a comment to the `if(WIN32)` block in `CMakeLists.txt` above the Regedit source append:
```cmake
    # Registry module is unconditional on Windows — required for AMT COM port management at runtime.
```

- [ ] **Step 3: Commit**

```bash
git add src/platform/WindowsPlatform.cpp CMakeLists.txt
git commit -m "docs: add file-level comments to platform files and CMakeLists"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Section 1 (Regedit fix + always-on): Task 1 (rewrite), Task 2 (build system)
- [x] Section 2 (AMT restructuring): Task 3 (delimiter, constants, Regedit wiring, dead function commented out)
- [x] Section 3 (WindowsPlatform split): Tasks 5 and 6
- [x] Section 4 (comments + dead code): Task 3 Step 6 (`readSerialPortWorker` commented, not deleted), Task 7 Step 2 (file headers), Task 2 Step 1 (BUILD_REGEDIT lines commented, not deleted in cmake)

**Constraints verified:**
- [x] No changes to `Platform.h` or `SystemState.h`
- [x] No changes to `main()` startup sequence (Regedit instantiation is additive, not a change)
- [x] No new CMake targets or flags (registry is always-on via `if(WIN32)`)
- [x] Dead code commented out with explanations, not deleted
- [x] Linux build files untouched

**Type consistency:**
- `Regedit::Read(path, outValue, root)` — used in Task 3 as `regedit->Read(portPath, portNameA, HKEY_LOCAL_MACHINE)` ✓
- `Regedit::ReadBinary(path, outData, root)` — used in Task 3 as `regedit->ReadBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE)` ✓
- `Regedit::Write(path, value, root)` — used in Task 3 as `regedit->Write(friendlyPath, "...", HKEY_LOCAL_MACHINE)` ✓
- `Regedit::WriteBinary(path, data, root)` — used in Task 3 as `regedit->WriteBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE)` ✓
- `WindowsNetworkProvider::getNetworkInterfaces()` — delegated in WindowsPlatform ✓
- `WindowsSerialProvider::open/close/write/read()` — delegated in WindowsPlatform ✓
