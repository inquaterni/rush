cmake_minimum_required(VERSION 3.31)
project(core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

set(RUSH_CORE_INCLUDES include/host_deleter.h
                       include/context.h
)
set(RUSH_CORE_SRCS src/context.cpp)

add_library(core ${RUSH_CORE_INCLUDES} ${RUSH_CORE_SRCS})

target_include_directories(core PRIVATE ../3rdparty)
target_link_libraries(core PRIVATE fmt::fmt)
target_compile_options(core PRIVATE -Wall -Wextra -Wpedantic)