# dev-minimal: core + serial only - every optional module off - with unit
# tests on. Fastest build for work on the core loop.
# IPC_AUTH_DEV_DISABLE is moot here (no serial bridge) but kept ON so turning
# the bridge on in local.cmake gives a dev-friendly build.
set(BUILD_SESSION_MONITOR    OFF CACHE BOOL "" FORCE)
set(BUILD_TRAY_APP           OFF CACHE BOOL "" FORCE)
set(BUILD_METRICS            OFF CACHE BOOL "" FORCE)
set(BUILD_SERIAL_BRIDGE_PIPE OFF CACHE BOOL "" FORCE)
set(BUILD_C2A                OFF CACHE BOOL "" FORCE)
set(IPC_AUTH_DEV_DISABLE     ON  CACHE BOOL "" FORCE)
set(ENABLE_TESTING           ON  CACHE BOOL "" FORCE)
