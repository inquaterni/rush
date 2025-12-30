cmake_minimum_required(VERSION 3.31)
project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_executable(client main.cpp)

target_include_directories(client PRIVATE ../3rdparty)
target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)