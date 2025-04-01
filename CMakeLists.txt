cmake_minimum_required(VERSION 3.16)
project(NodeWinApp)

set(CMAKE_CXX_STANDARD 17)

add_executable(NodeWinApp WIN32 main.cpp)

target_link_libraries(NodeWinApp PRIVATE ws2_32 iphlpapi)
