# dev-full: every module, unit tests on, IPC client auth compiled out so
# unsigned dev clients can use the serial bridge. Never ship this build -
# build.bat/build.sh don't copy dev-* builds into installer/.
set(BUILD_SESSION_MONITOR    ON  CACHE BOOL "" FORCE)
set(BUILD_TRAY_APP           ON  CACHE BOOL "" FORCE)  # Windows only; ignored elsewhere
set(BUILD_METRICS            ON  CACHE BOOL "" FORCE)
set(BUILD_SERIAL_BRIDGE_PIPE ON  CACHE BOOL "" FORCE)
set(BUILD_C2A                ON  CACHE BOOL "" FORCE)
set(IPC_AUTH_DEV_DISABLE     ON  CACHE BOOL "" FORCE)
set(ENABLE_TESTING           ON  CACHE BOOL "" FORCE)
