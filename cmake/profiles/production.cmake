# production: the shipping feature set - the same flags build-production.bat
# has always passed (TrayApp=OFF C2A=OFF SerialBridgePipe=OFF
# SessionMonitor=ON Metrics=OFF), no tests, IPC auth never compiled out.
# CMakeLists.txt refuses to configure if IPC_AUTH_DEV_DISABLE ends up ON with
# this profile (e.g. via local.cmake).
set(BUILD_SESSION_MONITOR    ON  CACHE BOOL "" FORCE)
set(BUILD_TRAY_APP           OFF CACHE BOOL "" FORCE)
set(BUILD_METRICS            OFF CACHE BOOL "" FORCE)
set(BUILD_SERIAL_BRIDGE_PIPE OFF CACHE BOOL "" FORCE)
set(BUILD_C2A                OFF CACHE BOOL "" FORCE)
set(IPC_AUTH_DEV_DISABLE     OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING           OFF CACHE BOOL "" FORCE)
