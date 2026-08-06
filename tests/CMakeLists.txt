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

add_executable(unit_tests
    test_metric_cache.cpp
    test_system_state.cpp
)

target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(unit_tests PRIVATE gtest_main)

include(GoogleTest)
gtest_discover_tests(unit_tests)
