# Unit tests (googletest + gmock). Enabled via -DENABLE_TESTING=ON (see root
# CMakeLists.txt, or any dev-* build profile). See README "Running tests".
#
# No OS/hardware mocking: tests cover pure logic, code that only talks to the
# Platform interface (via tests/mock_platform.h), and real OS paths that need
# no hardware (missing serial ports, an in-process named pipe/socketpair).
# Tests for feature-gated modules are compiled only when that module is.

include(FetchContent)

# Match the main target's static CRT (/MT) on MSVC so gtest/gtest_main don't
# link-mismatch against it (CMP0091, already NEW via cmake_minimum_required).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)

# --- test run configuration ---------------------------------------------------------

set(UNIT_TEST_TIMEOUT 30 CACHE STRING
    "Per-test timeout in seconds (ctest TIMEOUT) - stops a hung test blocking CI")
set(UNIT_TEST_ARGS "" CACHE STRING
    "Extra googletest arguments for every test run via ctest, e.g. --gtest_brief=1;--gtest_break_on_failure")

# --- sources ---------------------------------------------------------------------------

set(UNIT_TEST_SOURCES
    test_metric_cache.cpp
    test_system_state.cpp
    test_errors.cpp
    test_serialization.cpp
    test_metrics.cpp
    test_serial_manager.cpp
    # Production code under test that isn't header-only:
    ${CMAKE_SOURCE_DIR}/src/modules/serial/SerialManager.cpp
)

if(BUILD_C2A)
    list(APPEND UNIT_TEST_SOURCES
        test_command_handler.cpp
        ${CMAKE_SOURCE_DIR}/src/modules/cmc/CmcCommandHandler.cpp
    )
endif()

if(BUILD_METRICS)
    list(APPEND UNIT_TEST_SOURCES
        ${CMAKE_SOURCE_DIR}/src/modules/metrics/MetricsCollector.cpp
    )
endif()

# Authenticated serial IPC bridge (specs/001-secure-serial-ipc): pure
# Subject-matching tests plus an in-process pipe/socketpair test, each pulled
# in alongside the production file it tests and gated behind
# BUILD_SERIAL_BRIDGE_PIPE like that production code, so building tests
# without the bridge doesn't newly require OpenSSL/wintrust.
if(BUILD_SERIAL_BRIDGE_PIPE)
    list(APPEND UNIT_TEST_SOURCES test_ipc_bridge.cpp)
    if(WIN32)
        list(APPEND UNIT_TEST_SOURCES
            test_ipc_client_auth.cpp
            ${CMAKE_SOURCE_DIR}/src/modules/serialpipe/WindowsIpcClientAuth.cpp
        )
    elseif(UNIX AND NOT APPLE)
        list(APPEND UNIT_TEST_SOURCES
            test_linux_ipc_client_auth.cpp
            ${CMAKE_SOURCE_DIR}/src/modules/serialpipe/LinuxIpcClientAuth.cpp
        )
    endif()
endif()

add_executable(unit_tests ${UNIT_TEST_SOURCES})

target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Same feature/platform defines as the app (ENABLE_*, UNICODE, ...): Platform.h
# and SystemState.h change shape with them, and the production sources
# compiled in above must agree with the tests on class layouts and vtables.
# CORESTATION_LOG_CAPTURE routes core::Log to test::LogCapture instead of the
# real Event Log / syslog.
target_compile_definitions(unit_tests PRIVATE
    $<TARGET_PROPERTY:CoreStationHXAgent,COMPILE_DEFINITIONS>
    CORESTATION_LOG_CAPTURE
)

target_link_libraries(unit_tests PRIVATE gtest_main gmock)

if(BUILD_SERIAL_BRIDGE_PIPE)
    if(WIN32)
        target_link_libraries(unit_tests PRIVATE wintrust crypt32)
    elseif(UNIX AND NOT APPLE)
        find_package(OpenSSL REQUIRED)
        target_link_libraries(unit_tests PRIVATE OpenSSL::Crypto)
    endif()
endif()

# libstdc++ keeps the Windows console backend for std::print in a separate
# library (same as the main target).
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(unit_tests PRIVATE stdc++exp)
endif()

if(COMMAND corestation_enable_coverage)
    corestation_enable_coverage(unit_tests)
endif()

# --- registration with ctest -----------------------------------------------------------

include(GoogleTest)

# Discovery runs the test binary. When cross-compiling without an emulator
# (e.g. mingw-w64 on Linux with no Wine) it can't run at build time, so defer
# discovery to test time instead of failing the build.
set(_discovery_mode POST_BUILD)
if(CMAKE_CROSSCOMPILING AND NOT CMAKE_CROSSCOMPILING_EMULATOR)
    set(_discovery_mode PRE_TEST)
endif()

gtest_discover_tests(unit_tests
    EXTRA_ARGS ${UNIT_TEST_ARGS}
    PROPERTIES TIMEOUT ${UNIT_TEST_TIMEOUT}
    DISCOVERY_TIMEOUT 120
    DISCOVERY_MODE ${_discovery_mode}
)
