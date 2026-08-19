# Unit tests for the pure-logic pieces of CoreStationHXAgent that don't need
# OS/hardware mocking: MetricCache's TTL semantics and SystemState/
# NetworkInterface equality. Enabled via -DENABLE_TESTING=ON (see root
# CMakeLists.txt).

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

set(UNIT_TEST_SOURCES
    test_metric_cache.cpp
    test_system_state.cpp
)

# Pure-logic Subject-matching tests for the authenticated serial IPC bridge
# (specs/001-secure-serial-ipc) -- each pulled in alongside the production
# file it tests, gated behind BUILD_SERIAL_BRIDGE_PIPE the same way that
# production code is, so building tests WITHOUT the bridge enabled doesn't
# newly require OpenSSL/wintrust just to compile the test binary.
if(BUILD_SERIAL_BRIDGE_PIPE)
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
)

target_link_libraries(unit_tests PRIVATE gtest_main)

if(BUILD_SERIAL_BRIDGE_PIPE)
    if(WIN32)
        target_link_libraries(unit_tests PRIVATE wintrust crypt32)
    elseif(UNIX AND NOT APPLE)
        find_package(OpenSSL REQUIRED)
        target_link_libraries(unit_tests PRIVATE OpenSSL::Crypto)
    endif()
endif()

include(GoogleTest)
gtest_discover_tests(unit_tests)
