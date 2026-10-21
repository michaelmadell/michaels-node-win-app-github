# Build profiles: named sets of module options for local development.
#
#   cmake -S . -B build-dev-full -DDEVELOPMENT_PROFILE=dev-full
#   build.bat --profile dev-full        (Windows)
#   ./build.sh --profile dev-full       (Linux)
#
# A profile is a cmake/profiles/<name>.cmake file that FORCE-sets option cache
# variables, so selecting a profile wins over whatever an existing build tree
# had cached (and over -D flags for the same options - use local.cmake for
# personal overrides). After the profile, cmake/profiles/local.cmake
# (git-ignored) is applied if it exists.
#
# Nothing happens unless DEVELOPMENT_PROFILE is set: plain `cmake` invocations
# (CI, IDEs) keep using the option() defaults, exactly as before profiles
# existed. Profiles are build-time only; the binary doesn't know which was used.

set(CORESTATION_PROFILE_DIR "${CMAKE_CURRENT_LIST_DIR}/profiles")

# The module options a profile controls, in summary order.
set(CORESTATION_PROFILE_OPTIONS
    BUILD_SESSION_MONITOR
    BUILD_TRAY_APP
    BUILD_METRICS
    BUILD_SERIAL_BRIDGE_PIPE
    BUILD_C2A
    IPC_AUTH_DEV_DISABLE
    ENABLE_TESTING
)

# Lists the profile names available in cmake/profiles/ (excluding local.cmake).
function(list_profiles out_var)
    file(GLOB _profile_files RELATIVE "${CORESTATION_PROFILE_DIR}" "${CORESTATION_PROFILE_DIR}/*.cmake")
    set(_names "")
    foreach(_file IN LISTS _profile_files)
        get_filename_component(_name "${_file}" NAME_WE)
        if(NOT _name STREQUAL "local")
            list(APPEND _names "${_name}")
        endif()
    endforeach()
    list(SORT _names)
    set(${out_var} "${_names}" PARENT_SCOPE)
endfunction()

# Applies cmake/profiles/<name>.cmake, then local.cmake if present, and prints
# which modules ended up enabled/disabled.
function(load_profile name)
    set(_profile_file "${CORESTATION_PROFILE_DIR}/${name}.cmake")
    if(name STREQUAL "local" OR NOT EXISTS "${_profile_file}")
        list_profiles(_available)
        list(JOIN _available ", " _available_text)
        message(FATAL_ERROR
            "Unknown DEVELOPMENT_PROFILE '${name}'. Available profiles: ${_available_text}")
    endif()

    include("${_profile_file}")

    set(_local_file "${CORESTATION_PROFILE_DIR}/local.cmake")
    set(_local_note "")
    if(EXISTS "${_local_file}")
        include("${_local_file}")
        set(_local_note " (+ local.cmake overrides)")
    endif()

    set(_on "")
    set(_off "")
    foreach(_opt IN LISTS CORESTATION_PROFILE_OPTIONS)
        if(${_opt})
            list(APPEND _on "${_opt}")
        else()
            list(APPEND _off "${_opt}")
        endif()
    endforeach()
    list(JOIN _on ", " _on_text)
    list(JOIN _off ", " _off_text)
    if(NOT _on_text)
        set(_on_text "(none)")
    endif()
    if(NOT _off_text)
        set(_off_text "(none)")
    endif()

    message(STATUS "Build profile: ${name}${_local_note}")
    message(STATUS "  enabled:  ${_on_text}")
    message(STATUS "  disabled: ${_off_text}")
endfunction()
