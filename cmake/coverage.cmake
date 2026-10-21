# Unit-test line coverage with gcov + gcovr (GCC/Clang only).
#
#   cmake -S . -B build-cov -DDEVELOPMENT_PROFILE=dev-ci -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build-cov
#   ctest --test-dir build-cov
#   cmake --build build-cov --target coverage     # report + gate
#
# Reports cover the platform-independent code the unit tests compile in
# (src/core/, src/modules/); the Windows/Linux platform layers and main.cpp
# aren't unit-testable without OS mocking and aren't compiled into the test
# binary, so gcovr never sees them. Output: <build>/coverage/index.html
# (browsable) and coverage.xml (Cobertura, for CI dashboards). The target
# fails if line coverage is below COVERAGE_MIN_LINE.
#
# MSVC has no gcov-style instrumentation flag (coverage there needs VS
# Enterprise or OpenCppCoverage), so ENABLE_COVERAGE is GCC/Clang-only.

option(ENABLE_COVERAGE "Instrument unit tests for gcov line coverage (GCC/Clang; needs ENABLE_TESTING)" OFF)
set(COVERAGE_MIN_LINE "75" CACHE STRING
    "Minimum line coverage (percent) the 'coverage' target accepts for src/core + src/modules")

if(NOT ENABLE_COVERAGE)
    return()
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    message(WARNING "ENABLE_COVERAGE: '${CMAKE_CXX_COMPILER_ID}' isn't supported (GCC/Clang only) - ignored")
    return()
endif()
if(NOT ENABLE_TESTING)
    message(WARNING "ENABLE_COVERAGE needs ENABLE_TESTING=ON - ignored")
    return()
endif()

# Adds coverage instrumentation to a target (tests/CMakeLists.txt calls this
# for unit_tests). -O0 keeps line attribution exact.
function(corestation_enable_coverage target)
    target_compile_options(${target} PRIVATE --coverage -O0 -g)
    target_link_options(${target} PRIVATE --coverage)
endfunction()

find_program(GCOVR_EXECUTABLE gcovr)
if(NOT GCOVR_EXECUTABLE)
    message(WARNING "ENABLE_COVERAGE: gcovr not found (pip install gcovr / apt install gcovr) - "
                    "tests are instrumented but there is no 'coverage' target")
    return()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(_gcov_tool "gcov")
else()
    set(_gcov_tool "llvm-cov gcov")
endif()

set(COVERAGE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/coverage")
add_custom_target(coverage
    COMMAND ${CMAKE_COMMAND} -E make_directory "${COVERAGE_OUTPUT_DIR}"
    COMMAND "${GCOVR_EXECUTABLE}"
        --root "${CMAKE_SOURCE_DIR}"
        --object-directory "${CMAKE_BINARY_DIR}"
        --gcov-executable "${_gcov_tool}"
        --filter "src/core/"
        --filter "src/modules/"
        --exclude-unreachable-branches
        --html-details "${COVERAGE_OUTPUT_DIR}/index.html"
        --cobertura "${COVERAGE_OUTPUT_DIR}/coverage.xml"
        --print-summary
        --fail-under-line "${COVERAGE_MIN_LINE}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Unit-test coverage for src/core + src/modules (minimum ${COVERAGE_MIN_LINE}% lines)"
    VERBATIM
)
message(STATUS "Coverage: ON (gcovr target 'coverage', minimum ${COVERAGE_MIN_LINE}% lines)")
