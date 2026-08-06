# Cross-compilation toolchain for producing the Windows build from a Linux CI
# runner, using the mingw-w64 posix-threads variant (required for std::thread,
# same variant build.sh already invokes directly as x86_64-w64-mingw32-g++-posix).
#
# Usage:
#   cmake -S . -B build-win -DCMAKE_TOOLCHAIN_FILE=mingw-w64-toolchain.cmake

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(MINGW_PREFIX x86_64-w64-mingw32)
set(CMAKE_C_COMPILER ${MINGW_PREFIX}-gcc-posix)
set(CMAKE_CXX_COMPILER ${MINGW_PREFIX}-g++-posix)
set(CMAKE_RC_COMPILER ${MINGW_PREFIX}-windres)

set(CMAKE_FIND_ROOT_PATH /usr/${MINGW_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Static-link the mingw runtime so the .exe runs on machines with no MinGW
# DLLs installed (mirrors the -static flag build.sh already uses).
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
