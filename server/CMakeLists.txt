cmake_minimum_required(VERSION 3.31)
project(server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_executable(server
        main.cpp
        state.cpp
        state.h
        host.cpp
        host.h
)

target_include_directories(server PRIVATE ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ../pack/include
)
target_link_libraries(server PRIVATE net crypto serial pack)
target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)