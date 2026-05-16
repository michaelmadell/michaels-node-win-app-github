# Modular Refactor Design — CoreStationHXAgent

**Date:** 2026-05-16
**Branch:** 20.26.5.1_rc4
**Approach:** Incremental Refactor (Approach A)

---

## Overview

The goal of this refactor is to make file separation more consistent, ensure Windows Registry support is always compiled into Windows builds, add explanatory comments where non-obvious, and comment out (not delete) unnecessary code with clear explanations. No interfaces change, no build targets change, and the app must compile and run correctly throughout.

---

## Section 1: Regedit Module Fix + Always-On Windows Build

### Problem

`src/modules/regedits/Regedit.cpp` has three issues:
1. **Duplicated error handling** — `RegCreateKeyExA` is called 9 separate times inside each function (once per error branch) instead of being called once and branching on the result.
2. **Hardcoded `HKEY_CURRENT_USER`** — useless for system-level operations (AMT COM Name Arbiter, COM port device parameters) which live under `HKEY_LOCAL_MACHINE`.
3. **Conditionally disabled** — `BUILD_REGEDIT=OFF` in `build.bat` means the module is never compiled, and the `Regedit` instance created in `main.cpp:45` is never used.

### Changes

- **Fix error handling** — call the registry API once per function, store the `LSTATUS` result, check it once, branch accordingly. The 9-duplicate pattern becomes a single open/check/use/close.
- **Add `HKEY` root parameter** — update `Read()`, `Write()`, `Create()`, `Delete()` to accept a root hive as a parameter (`HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, etc.).
- **Add `ReadBinary()` / `WriteBinary()`** — the COM Name Arbiter `ComDB` entry is `REG_BINARY`; the current module only supports `REG_SZ`. Two new methods handle binary values.
- **Remove `BUILD_REGEDIT` flag** — replaced with `if(WIN32)` guard in `CMakeLists.txt`. Registry support is unconditional on Windows. Old cmake lines kept as comments with explanation.
- **Remove `-DBUILD_REGEDIT=OFF`** from `build.bat`.

### Files Affected

- `src/modules/regedits/Regedit.cpp` — rewritten internals
- `src/modules/regedits/Regedit.h` — updated signatures
- `CMakeLists.txt` — remove `BUILD_REGEDIT` option, add unconditional `if(WIN32)` source inclusion
- `build.bat` — remove `-DBUILD_REGEDIT=OFF`

---

## Section 2: `main.cpp` Restructuring — AMT Registry Functions

### Problem

230 lines of AMT COM port detection and reassignment logic (`GetAMTInstanceId`, `GetAMTComPort`, `disableAMTComPort`, `enableAMTComPort`, `reassignComPort`) sit inline in `main.cpp` between includes and `main()` with no grouping or boundaries. They call Win32 registry APIs directly, bypassing the `Regedit` helper. COM port numbers and hardware IDs are hardcoded as magic literals in 6+ locations. `readSerialPortWorker()` is defined but never called.

### Changes

- **Add section delimiter comment** — `// === AMT COM Port Management ===` header and footer block wrapping all AMT functions, making the section immediately identifiable.
- **Extract constants** — `COM3`, `COM4`, AMT hardware IDs (`VEN_8086&DEV_7773...`, `VEN_8086&DEV_7E73...`), and the ComDB bitmask (`0x08` = COM4 bit in byte 0) become named `constexpr` values at the top of the AMT section. Each gets a one-line comment explaining the hardware constraint it encodes.
- **Wire through `Regedit`** — replace direct `RegOpenKeyExW` / `RegQueryValueExW` / `RegSetValueExW` calls inside AMT functions with calls to `Regedit::Read()`, `Regedit::ReadBinary()`, `Regedit::Write()`, `Regedit::WriteBinary()`. The `Regedit` instance at `main.cpp:45` becomes the live utility it was always intended to be.
- **Comment out `readSerialPortWorker()`** — wrapped with `/* NOT CALLED: serialThread() reads via platform->readSerial() directly */`. Not deleted.
- **`main()` itself unchanged** — the startup sequence calling AMT functions stays exactly as-is.

### Files Affected

- `src/main.cpp` — AMT section delimited, constants extracted, Regedit wired in, dead function commented out

---

## Section 3: `WindowsPlatform.cpp` Split

### Problem

`WindowsPlatform.cpp` is 1,190 lines mixing five distinct concerns: network interface enumeration, OS version detection, serial I/O, system metrics, and Windows Service Control Manager registration. No internal boundaries make it hard to navigate or reason about individual concerns.

### Changes

Split into three focused files, all under `src/platform/`:

**`WindowsNetworkProvider.cpp` / `WindowsNetworkProvider.h`** (new)
- Contains: `getNetworkInterfaces()`, `getOsVersion()`
- Dependencies: `iphlpapi`, Windows Registry (via `Regedit`)
- Characteristics: read-only discovery, no threads, no handles to manage

**`WindowsSerialProvider.cpp` / `WindowsSerialProvider.h`** (new)
- Contains: `openSerialPort()`, `closeSerialPort()`, `writeSerial()`, `readSerial()`
- Dependencies: Win32 `CreateFile`, `WriteFile`, `ReadFile`
- Characteristics: all COM handle lifecycle in one place

**`WindowsPlatform.cpp`** (slimmed down, keeps existing file)
- Keeps: `run()` with power/session callback wiring, Windows SCM registration, `logMessage()`
- Delegates: network and serial calls to the two new providers via `#include`
- Remains: the single implementation of `Platform.h` — nothing in `main.cpp` changes

**`Windows_Addon.h`** — unchanged. All three files include it.

**`CMakeLists.txt`** — two new `.cpp` files added to the `if(WIN32)` source list. No new targets or flags.

Each new file gets a one-line purpose comment at the top.

### Files Affected

- `src/platform/WindowsNetworkProvider.cpp` — new
- `src/platform/WindowsNetworkProvider.h` — new
- `src/platform/WindowsSerialProvider.cpp` — new
- `src/platform/WindowsSerialProvider.h` — new
- `src/platform/WindowsPlatform.cpp` — reduced, delegates to providers
- `src/platform/WindowsPlatform.h` — updated includes
- `CMakeLists.txt` — new sources added

---

## Section 4: Comments and Dead Code Strategy

### Comment Placement Rules

Comments are added only where the **WHY** is non-obvious. No comments on self-explanatory code.

| Location | Comment type |
|----------|-------------|
| Top of each new/modified file | One-line purpose statement |
| Each AMT `constexpr` constant | Explains the hardware constraint encoded (e.g. COM4 bit position in ComDB) |
| `ReadBinary`/`WriteBinary` in Regedit | Notes these exist for `REG_BINARY` entries like COM Name Arbiter `ComDB` |
| Non-obvious Win32 flag combinations | One line explaining the flag choice |
| `#ifdef _WIN32` registry block in CMake | Notes registry support is unconditional on Windows |

### Dead Code Commented Out (Not Deleted)

| Code | Comment |
|------|---------|
| `readSerialPortWorker()` in `main.cpp` | `// NOT CALLED: serialThread() reads via platform->readSerial() directly` |
| `BUILD_REGEDIT` cmake option lines | `# REMOVED: registry module is now unconditional on Windows (_WIN32)` |
| Duplicate `RegCreateKeyExA` error blocks in `Regedit.cpp` | `// REPLACED: each branch was re-calling RegCreateKeyExA instead of reusing the result` |

---

## File Change Summary

| File | Action |
|------|--------|
| `src/modules/regedits/Regedit.cpp` | Rewrite internals — fix error handling, add HKEY param, add Binary methods |
| `src/modules/regedits/Regedit.h` | Update signatures |
| `src/main.cpp` | Add AMT section delimiters, extract constants, wire Regedit, comment out dead function |
| `src/platform/WindowsNetworkProvider.cpp` | New — extracted from WindowsPlatform |
| `src/platform/WindowsNetworkProvider.h` | New |
| `src/platform/WindowsSerialProvider.cpp` | New — extracted from WindowsPlatform |
| `src/platform/WindowsSerialProvider.h` | New |
| `src/platform/WindowsPlatform.cpp` | Slim down — delegates to providers |
| `src/platform/WindowsPlatform.h` | Update includes |
| `CMakeLists.txt` | Remove BUILD_REGEDIT, add new provider sources under if(WIN32) |
| `build.bat` | Remove -DBUILD_REGEDIT=OFF |

---

## Constraints

- No interface changes to `Platform.h` or `SystemState.h`
- No changes to `main()` startup sequence
- No new CMake targets or build flags (registry is always-on via `if(WIN32)`, not a new flag)
- Unnecessary code commented out, never deleted
- Linux build (`LinuxPlatform.cpp`, `debian/`) untouched
