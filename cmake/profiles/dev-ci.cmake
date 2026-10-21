# dev-ci: what a thorough CI run should compile - every module, unit tests on,
# IPC client auth ENABLED (the real verification code path is built and
# tested). Use it locally to reproduce a CI-style build.
set(BUILD_SESSION_MONITOR    ON  CACHE BOOL "" FORCE)
set(BUILD_TRAY_APP           ON  CACHE BOOL "" FORCE)  # Windows only; ignored elsewhere
set(BUILD_METRICS            ON  CACHE BOOL "" FORCE)
set(BUILD_SERIAL_BRIDGE_PIPE ON  CACHE BOOL "" FORCE)
set(BUILD_C2A                ON  CACHE BOOL "" FORCE)
set(IPC_AUTH_DEV_DISABLE     OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING           ON  CACHE BOOL "" FORCE)
