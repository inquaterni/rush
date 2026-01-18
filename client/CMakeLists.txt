cmake_minimum_required(VERSION 3.31)
project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_executable(client main.cpp
                      client.cpp
                      client.h
        guard.cpp
        guard.h
)

target_include_directories(client PRIVATE ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ../pack/include
)
target_link_libraries(client PRIVATE net crypto serial pack)
target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)