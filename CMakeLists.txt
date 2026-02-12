cmake_minimum_required(VERSION 3.15)

# Project copnfiguration
project(CoreStationHXAgent
    VERSION 20.26.2.1
    DESCRIPTION "CoreStation Host Agent for serial monitoring"
    LANGUAGES CXX
)

# Build options
option(BUILD_METRIC_CACHE "Build with metric caching support" ON)
option(BUILD_SESSION_MONITOR "Build with session state monitoring" ON)
option(ENABLE_TESTING "Build tests" OFF)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type default
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build Type" FORCE)
endif()

message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

# Parse version information from version.h
if(EXISTS "${CMAKE_SOURCE_DIR}/src/version.h")
    file(STRINGS "src/version.h" VERSION_HEADER_CONTENTS)
    foreach(LINE ${VERSION_HEADER_CONTENTS})
        if(LINE MATCHES "^#define[ \t]+VERSION_YEAR[ \t]+([0-9]+)")
            set(VERSION_YEAR ${CMAKE_MATCH_1})
        endif()
        if(LINE MATCHES "^#define[ \t]+VERSION_MONTH[ \t]+([0-9]+)")
            set(VERSION_MONTH ${CMAKE_MATCH_1})
        endif()
        if(LINE MATCHES "^#define[ \t]+VERSION_RELEASE[ \t]+([0-9]+)")
            set(VERSION_RELEASE ${CMAKE_MATCH_1})
        endif()
        if(LINE MATCHES "^#define[ \t]+VERSION_EXTRAVERSION[ \t]+\"([a-z]+)\"")
            set(VERSION_EXTRAVERSION ${CMAKE_MATCH_1})
        endif()
        if(LINE MATCHES "^#define[ \t]+VERSION_RC_NO[ \t]+([0-9]+)")
            set(VERSION_RC_NO ${CMAKE_MATCH_1})
        endif()
    endforeach()
    
    if(VERSION_EXTRAVERSION STREQUAL "rc")
        set(APP_VERSION_STRING "${VERSION_YEAR}.${VERSION_MONTH}.${VERSION_RELEASE}_${VERSION_EXTRAVERSION}${VERSION_RC_NO}")
    else()
        set(APP_VERSION_STRING "${VERSION_YEAR}.${VERSION_MONTH}.${VERSION_RELEASE}_${VERSION_EXTRAVERSION}")
    endif()
    
    message(STATUS "Application version: ${APP_VERSION_STRING}")
endif()

# Git Information
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    execute_process(
        COMMAND ${GIT_EXECUTABLE} diff-index --quiet HEAD --
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_MODIFIED
        ERROR_QUIET
    )
    
    if(GIT_MODIFIED)
        set(GIT_HASH "${GIT_HASH}-mods")
    endif()
    
    string(TIMESTAMP BUILD_TIME "%Y-%m-%d_%H:%M:%S")
    
    # Generate git_info.h
    file(WRITE "${CMAKE_SOURCE_DIR}/git_info.h"
"#pragma once
#include <string>

namespace GitInfo {
    const std::string BRANCH = \"${GIT_BRANCH}\";
    const std::string HASH = \"${GIT_HASH}\";
    const std::string BUILD_TIME = \"${BUILD_TIME}\";
}
")
    
    message(STATUS "Git branch: ${GIT_BRANCH}")
    message(STATUS "Git hash: ${GIT_HASH}")
else()
    # Create a default git_info.h if Git is not available
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/git_info.h")
        file(WRITE "${CMAKE_SOURCE_DIR}/git_info.h"
"#pragma once
#include <string>

namespace GitInfo {
    const std::string BRANCH = \"unknown\";
    const std::string HASH = \"unknown\";
    const std::string BUILD_TIME = \"unknown\";
}
")
    endif()
    message(STATUS "Git not found - using default git_info.h")
endif()

# Platform-specific build files

# Core Sources
set(CORE_SOURCES
    src/main.cpp
)

# Platform-specific sources
if(WIN32)
    list(APPEND CORE_SOURCES
        src/WindowsPlatform.cpp
    )
    
elseif(UNIX AND NOT APPLE)
    list(APPEND CORE_SOURCES
        src/LinuxPlatform.cpp
    )
endif()

# Header files (for IDE organization)
set(HEADER_FILES
    src/Platform.h
    src/SystemState.h
    src/version.h
)

if(BUILD_METRIC_CACHE)
    list(APPEND HEADER_FILES src/MetricCache.h)
endif()

if(WIN32 AND BUILD_TRAYAPP AND EXISTS "${CMAKE_SOURCE_DIR}/src/TrayApp.h")
    list(APPEND HEADER_FILES src/TrayApp.h)
endif()

## Create Executable
add_executable(${PROJECT_NAME} ${CORE_SOURCES} ${HEADER_FILES})

#windows resources
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/app.rc")
    target_sources(${PROJECT_NAME} PRIVATE app.rc)
endif()

## Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)

## Compiler Definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<PLATFORM_ID:Windows>:_WIN32>
    $<$<PLATFORM_ID:Windows>:UNICODE>
    $<$<PLATFORM_ID:Windows>:_UNICODE>
    $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
    $<$<PLATFORM_ID:Windows>:NOMINMAX>
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
)    

if(BUILD_METRIC_CACHE)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_METRIC_CACHE)
endif()

if(BUILD_SESSION_MONITOR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_SESSION_MONITOR)
endif()

## Compiler Flags
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W3                     # Warning level 3
        /EHsc                   # Exception handling
        /MP                     # Multi-processor compilation
        $<$<CONFIG:Release>:/O2>    # Optimize for speed
        $<$<CONFIG:Release>:/MT>    # Static runtime
        $<$<CONFIG:Debug>:/Od>      # No optimization
        $<$<CONFIG:Debug>:/MTd>     # Static runtime (debug)
        $<$<CONFIG:Debug>:/Zi>      # Debug info
    )
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
    )
endif()

## Platform-specific libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        iphlpapi        # IP Helper API
        ws2_32          # WinSock 2
        wtsapi32        # Windows Terminal Services
        setupapi        # Setup API
        user32          # User interface
        gdi32           # Graphics Device Interface
        shell32         # Shell API
        advapi32        # Advanced Windows API
        comctl32        # Common Controls
        winmm           # Windows Multimedia
        pdh             # Performance Data Helper
    )
elseif(UNIX AND NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DBUS REQUIRED dbus-1)
    target_include_directories(${PROJECT_NAME} PRIVATE ${DBUS_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${DBUS_LIBRARIES})
endif()

## Output Directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    OUTPUT_NAME "CoreStationHXAgent"
)

## Installation rules
if(WIN32)
    install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin
    )
elseif(UNIX AND NOT APPLE)
    install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION /usr/sbin
    )
    
    if(EXISTS "${CMAKE_SOURCE_DIR}/CoreStationHXAgent.service")
        install(FILES CoreStationHXAgent.service
            DESTINATION /lib/systemd/system
        )
    endif()
endif()

## Packaging (CPACK)
set(CPACK_PACKAGE_NAME "corestationhxagent")
set(CPACK_PACKAGE_VENDOR "Amulet Hotkey Ltd")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CoreStation Host Agent for serial monitoring")
set(CPACK_PACKAGE_VERSION ${APP_VERSION_STRING})

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_UPGRADE_GUID "6c85b236-3029-4744-a467-2b56b128c6b1")
else()
    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Your Name <youremail@example.com>")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "network-manager, libdbus-1-3")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()

include(CPack)

## Testing (OPTIONAL)
if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

## Print configuration summary
message(STATUS "")
message(STATUS "================================================")
message(STATUS "CoreStationHXAgent Build Configuration")
message(STATUS "================================================")
message(STATUS "Version:           ${APP_VERSION_STRING}")
message(STATUS "Build Type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard:      C++${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler:          ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Platform:          ${CMAKE_SYSTEM_NAME}")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  TrayApp:         ${BUILD_TRAYAPP}")
message(STATUS "  Metric Cache:    ${BUILD_METRIC_CACHE}")
message(STATUS "  Session Monitor: ${BUILD_SESSION_MONITOR}")
message(STATUS "  Testing:         ${ENABLE_TESTING}")
message(STATUS "")
message(STATUS "Source Files:")
foreach(src ${CORE_SOURCES})
    message(STATUS "  - ${src}")
endforeach()
message(STATUS "================================================")
message(STATUS "")

## Build Instructions
#
# To build with CMake:
#
# Windows:
#   mkdir build
#   cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64
#   cmake --build . --config Release
#
# Linux:
#   mkdir build
#   cd build
#   cmake ..
#   make -j$(nproc)
#
# To change options:
#   cmake .. -DBUILD_TRAYAPP=OFF
#   cmake .. -DCMAKE_BUILD_TYPE=Debug
#
# To clean:
#   cmake --build . --target clean
#
# To install:
#   cmake --install . --prefix /usr/local