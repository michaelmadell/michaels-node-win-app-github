cmake_minimum_required(VERSION 3.10)

project(CoreStationHXAgent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VERSION_YEAR 2025)
set(VERSION_MONTH 9)

add_definitions(
    -DVERSION_YEAR=${VERSION_YEAR}
    -DVERSION_MONTH=${VERSION_MONTH}
)

set(CORE_SOURCES
    src/main.cpp
)

if(WIN32)
    list(APPEND CORE_SOURCES src/WindowsPlatform.cpp)
elseif(UNIX AND NOT APPLE)
    list(APPEND CORE_SOURCES src/LinuxPlatform.cpp)
endif()

add_executable(CoreStationHXAgent ${CORE_SOURCES})

if(WIN32)
    # For standard Windows libraries, we can link them directly by name.
    # The MSVC linker knows where to find them.
    target_link_libraries(CoreStationHXAgent PRIVATE
        iphlpapi
        ws2_32
        wtsapi32
        setupapi
        user32
        shell32
    )
elseif(UNIX AND NOT APPLE)
endif()

include(InstallRequiredSystemLibraries)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION "2025.9.1")

install(TARGETS CoreStationHXAgent DESTINATION bin)

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_PACKAGE_NAME "CoreStationHXAgent")
    set(CPACK_PACKAGE_VERSION "2025.9.1")
    set(CPACK_PACKAGE_VENDOR "Amulet Hotkey Ltd")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CoreStation HX Agent")
    set(CPACK_WIX_UPGRADE_GUID "6c85b236-3029-4744-a467-2b56b128c6b1")
elseif(UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_PACKAGE_MAINTAINER "Michael Madell <michael.madell@amulethotkey.com>")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/control")

    install(FILES src/CoreStationHXAgent.service DESTINATION /lib/systemd/system)
endif()

include(CPack)