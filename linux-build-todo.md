# Linux (Debian) Build Parity TODO

The Linux build uses `debuild` → `dh --with cmake` → `CMakeLists.txt`.
`build.sh` is a separate cross-compile script for producing the Windows exe on a Linux
build machine — it is intentionally different and excluded from this list.

Changes are ordered: file/packaging restructuring first, then code fixes.

---

## SECTION 1 — DEBIAN PACKAGING FIXES

### 1.1 CRITICAL — Add missing build dependencies to `debian/control`

File: `debian/control`

`CMakeLists.txt` calls `find_package(PkgConfig REQUIRED)` and
`pkg_check_modules(DBUS REQUIRED dbus-1)` on Linux. Neither `pkg-config` nor
`libdbus-1-dev` are in `Build-Depends`, so `debuild` will fail to configure CMake.

**Old:**
```
Build-Depends: debhelper (>= 11), cmake, dh-cmake
```

**New:**
```
Build-Depends: debhelper (>= 11), cmake, dh-cmake, pkg-config, libdbus-1-dev
```

### 1.2 Update `debian/changelog` version

File: `debian/changelog`

The changelog version `2025.9.1` is stale and doesn't reflect the current software
version (`20.26.5.1`). Each release needs a new changelog entry. The version scheme used
in the package (`YYYY.M.PATCH`) should stay consistent; update it to match the release.

**Current:**
```
corestationhxagent (2025.9.1) jammy; urgency=medium

  * Initial Linux Release.

 -- Michael Madell <michael.madell@amulethotkey.com>  Wed, 24 Sep 2025 14:20:00 +0100
```

**Add a new entry at the top (do not edit the existing one):**
```
corestationhxagent (2026.5.1) jammy; urgency=medium

  * Sync with Windows build 20.26.5.1_rc3.
  * Added robust HX2K/HX3K CPU detection.
  * Improved MAC address filtering for AAEON devices.

 -- Michael Madell <michael.madell@amulethotkey.com>  Mon, 12 May 2026 00:00:00 +0000
```

### 1.3 Remove `debian/files` from source control

File: `debian/files`

`debian/files` is generated automatically by `dpkg-buildpackage` and should not be
committed. Its presence in the repo will cause `debuild` to fail or produce warnings
about stale package lists.

**Action:** Delete `debian/files` and add it to `.gitignore`:
```
debian/files
```

### 1.4 Fix `postinst` to use `deb-systemd-helper` consistently

File: `debian/postinst`

`prerm` and `postrm` both use `deb-systemd-helper` correctly. `postinst` calls
`systemctl enable/restart` directly, which will fail on systems where systemd is not PID 1
(e.g. chroot, container builds). Match the pattern used in the other maintainer scripts.

**Old:**
```sh
systemctl enable CoreStationHXAgent.service
echo "Starting CoreStationHXAgent Service..."
systemctl restart CoreStationHXAgent.service
```

**New:**
```sh
if [ -x "/usr/bin/deb-systemd-helper" ]; then
    deb-systemd-helper enable CoreStationHXAgent.service >/dev/null || true
fi
if [ -x "/bin/systemctl" ] || [ -x "/usr/bin/systemctl" ]; then
    systemctl daemon-reload >/dev/null || true
    systemctl restart CoreStationHXAgent.service >/dev/null || true
fi
```

---

## SECTION 2 — `CMakeLists.txt` FIXES

File: `CMakeLists.txt`

### 2.1 CRITICAL — Move `3kcheck.cpp` into the `WIN32` source block

`3kcheck.cpp` is in the unconditional `MODULE_SOURCES` set and is compiled on Linux, but
the entire file is wrapped in `#ifdef _WIN32`. This compiles as an empty translation unit
on Linux. More importantly, `3kcheck.h` only declares `GetCpuInfo()`/`IsHX2KCPU()` inside
`#ifdef _WIN32`, so any future reference outside that guard would silently be missing.
Move the file into the WIN32 block.

**Old (lines ~140–143):**
```cmake
set(MODULE_SOURCES
    src/modules/serial/SerialManager.cpp
    src/modules/3kcheck/3kcheck.cpp
)
```

**New:**
```cmake
set(MODULE_SOURCES
    src/modules/serial/SerialManager.cpp
)
```

Then inside the `if(WIN32)` block, add alongside the other WIN32 modules:
```cmake
list(APPEND MODULE_SOURCES
    src/modules/3kcheck/3kcheck.cpp
)
```

### 2.2 Restrict `ENABLE_SESSION_MONITOR` define to WIN32 only

`ENABLE_SESSION_MONITOR` is currently set for both platforms, but `SessionMonitor.cpp` is
only compiled on Windows. On Linux this define is unused, but it creates a mismatch
between the symbol being defined and any future `#ifdef ENABLE_SESSION_MONITOR` guard
in shared code.

**Old:**
```cmake
if(BUILD_SESSION_MONITOR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_SESSION_MONITOR)
endif()
```

**New:**
```cmake
if(BUILD_SESSION_MONITOR AND WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_SESSION_MONITOR)
endif()
```

### 2.3 Fix unclosed parenthesis in `BUILD_REGEDIT` option string

**Old (line ~14):**
```cmake
option(BUILD_REGEDIT "Build with registry editing components (Windows only" ON)
```

**New:**
```cmake
option(BUILD_REGEDIT "Build with registry editing components (Windows only)" ON)
```

---

## SECTION 3 — `src/platform/LinuxPlatform.cpp` FIXES

File: `src/platform/LinuxPlatform.cpp`

### 3.1 CRITICAL — Add missing `getCurrentSessionState()` implementation

`Platform.h` declares `getCurrentSessionState()` as a pure virtual method (line 20).
`LinuxPlatform` does not implement it — this is a **link error** that prevents the
Linux binary from building entirely. It needs to be added to both the class declaration
and the implementation.

**Add to the `LinuxPlatform` class declaration (in the public methods block):**
```cpp
std::string getCurrentSessionState() override;
```

**Add the implementation (e.g. near `getLoggedInUser`):**
```cpp
std::string LinuxPlatform::getCurrentSessionState() {
    // Get the first active session ID from loginctl
    std::string sessionId = executeCommand(
        "loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $1}'"
    );
    if (sessionId.empty()) {
        return "6"; // No session — equivalent to logoff
    }

    // Check if the session is locked
    std::string locked = executeCommand(
        "loginctl show-session " + sessionId + " -p LockedHint --value 2>/dev/null"
    );
    locked.erase(locked.find_last_not_of("\n\r \t") + 1);

    if (locked == "yes") {
        return "7"; // Locked — matches WTS_SESSION_LOCK
    }
    return "5"; // Active — matches WTSActive / WTS_SESSION_LOGON
}
```

### 3.2 Fix `dbusThread()` — blocks forever on shutdown

`dbusThread()` uses `dbus_connection_read_write_dispatch(conn, -1)` (infinite timeout).
When `g_terminate` becomes true the D-Bus thread never unblocks, causing the process to
hang on SIGTERM/SIGINT instead of shutting down cleanly.

**Old (lines ~159–173):**
```cpp
while (true) {
    dbus_connection_read_write_dispatch(conn, -1);
    DBusMessage* msg = dbus_connection_pop_message(conn);
    if (msg == NULL) continue;
    ...
    dbus_message_unref(msg);
}
```

**New — poll with a short timeout so `g_terminate` is checked regularly:**
```cpp
while (!g_terminate.load()) {
    dbus_connection_read_write_dispatch(conn, 200); // 200ms timeout
    DBusMessage* msg = dbus_connection_pop_message(conn);
    if (msg == NULL) continue;

    if (dbus_message_is_signal(msg, "org.freedesktop.login1.Session", "Lock")) {
        if (g_session_callback) g_session_callback("7");
    } else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Session", "Unlock")) {
        if (g_session_callback) g_session_callback("8");
    }
    dbus_message_unref(msg);
}
syslog(LOG_INFO, "D-Bus thread exiting.");
dbus_connection_unref(conn);
```

### 3.3 Extend D-Bus monitoring to detect login/logout (parity with Windows)

Windows `SessionMonitor` fires callbacks for logon (5) and logoff (6). Linux only detects
lock/unlock. Subscribe to `org.freedesktop.login1.Manager` signals to cover login/logout.

**Add these match rules in `dbusThread()` after the existing two:**
```cpp
const char* match_rule3 =
    "type='signal',interface='org.freedesktop.login1.Manager',member='SessionNew'";
const char* match_rule4 =
    "type='signal',interface='org.freedesktop.login1.Manager',member='SessionRemoved'";
dbus_bus_add_match(conn, match_rule3, &err);
dbus_bus_add_match(conn, match_rule4, &err);
```

**And in the dispatch loop (alongside the Lock/Unlock handlers):**
```cpp
} else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Manager", "SessionNew")) {
    if (g_session_callback) g_session_callback("5"); // Logon
} else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Manager", "SessionRemoved")) {
    if (g_session_callback) g_session_callback("6"); // Logoff
}
```

---

## Summary Table

| Priority | File | Section | Change |
|----------|------|---------|--------|
| CRITICAL | `debian/control` | §1.1 | Add `pkg-config`, `libdbus-1-dev` to Build-Depends — debuild will fail without these |
| CRITICAL | `src/platform/LinuxPlatform.cpp` | §3.1 | Implement `getCurrentSessionState()` — pure virtual not implemented, link error |
| HIGH | `debian/changelog` | §1.2 | Add new changelog entry for current version |
| HIGH | `debian/files` | §1.3 | Delete from repo and add to `.gitignore` |
| HIGH | `CMakeLists.txt` | §2.1 | Move `3kcheck.cpp` into WIN32 source block |
| HIGH | `src/platform/LinuxPlatform.cpp` | §3.2 | Fix `dbusThread()` infinite timeout — process hangs on shutdown |
| MEDIUM | `debian/postinst` | §1.4 | Use `deb-systemd-helper` consistently with prerm/postrm |
| MEDIUM | `CMakeLists.txt` | §2.2 | Restrict `ENABLE_SESSION_MONITOR` define to WIN32 |
| MEDIUM | `src/platform/LinuxPlatform.cpp` | §3.3 | Add login/logout D-Bus signals for session parity |
| LOW | `CMakeLists.txt` | §2.3 | Fix unclosed paren in BUILD_REGEDIT option string |