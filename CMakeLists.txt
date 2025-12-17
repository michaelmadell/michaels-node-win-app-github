cmake_minimum_required(VERSION 3.10)

project(CoreStationHXAgent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Create a Debian-compliant version string (no underscores)
if(VERSION_EXTRAVERSION STREQUAL "rc")
    set(DEB_VERSION_STRING "${VERSION_YEAR}.${VERSION_MONTH}.${VERSION_RELEASE}-${VERSION_RC_NO}")
else()
    set(DEB_VERSION_STRING "${VERSION_YEAR}.${VERSION_MONTH}.${VERSION_RELEASE}")
endif()

message(STATUS "Building CoreStationHXAgent version: ${APP_VERSION_STRING}")

set(CORE_SOURCES src/main.cpp)
if(WIN32)
    list(APPEND CORE_SOURCES src/WindowsPlatform.cpp)
elseif(UNIX AND NOT APPLE)
    list(APPEND CORE_SOURCES src/LinuxPlatform.cpp)
endif()

# The Windows-specific resource files (like resource.h) should only be compiled 
# when WIN32 is true. We remove them here and rely only on the C++ source list.
add_executable(CoreStationHXAgent ${CORE_SOURCES}) 

# OPTIONAL: If you need to include the Windows resource files again 
# for the Windows build, you'd add them conditionally like this:
if(WIN32)
    target_sources(CoreStationHXAgent PRIVATE "src\\version.h")
    # You would also typically need the .rc file for the resource compiler
    # target_sources(CoreStationHXAgent PRIVATE "app.rc")
endif()

if(WIN32)
    target_link_libraries(CoreStationHXAgent PRIVATE iphlpapi ws2_32 wtsapi32 setupapi user32 shell32)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DBUS REQUIRED dbus-1)
    include_directories(${DBUS_INCLUDE_DIRS})
    target_link_libraries(CoreStationHXAgent PRIVATE ${DBUS_LIBRARIES})
endif()

include(InstallRequiredSystemLibraries)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION "2025.11.1")


set(CPACK_PACKAGE_NAME "corestationhxagent") # Debian prefers lowercase package names
set(CPACK_PACKAGE_VENDOR "Amulet Hotkey Ltd")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CoreStation Host Agent for serial monitoring")

if(WIN32)
    set(CPACK_PACKAGE_VERSION ${APP_VERSION_STRING})
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_UPGRADE_GUID "6c85b236-3029-4744-a467-2b56b128c6b1")
else() 
    set(CPACK_PACKAGE_VERSION ${DEB_VERSION_STRING})
    set(CPACK_GENERATOR "DEB")
    set(CPACK_SET_DESTDIR TRUE)
    set(CPACK_PACKAGE_CONTACT "Your Name <youremail@example.com>")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Your Name <youremail@example.com>")
    include(GNUInstallDirs)
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "network-manager, libdbus-1-3")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_PACKAGE_CONTROL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/debian")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst")
endif()

if(UNIX AND NOT APPLE)
    install(TARGETS CoreStationHXAgent DESTINATION /usr/sbin)
    install(FILES CoreStationHXAgent.service DESTINATION /lib/systemd/system)
endif()

include(CPack)
