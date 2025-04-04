cmake_minimum_required(VERSION 3.16)
project(NodeWinApp)

set(CMAKE_CXX_STANDARD 17)

add_executable(NodeWinApp WIN32 main.cpp)

target_link_libraries(NodeWinApp PRIVATE ws2_32 iphlpapi)

if (MSVC)
    foreach(flag_var
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE)
        string(REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endforeach()
endif()
