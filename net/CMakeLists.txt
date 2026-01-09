cmake_minimum_required(VERSION 3.31)
project(net LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

set(RUSH_CORE_INCLUDES include/host_deleter.h
                       include/guard.h
                       include/packet.h
                       include/packet_deleter.h
                       include/peer_deleter.h
                       include/types.h
)
set(RUSH_CORE_SRCS src/guard.cpp
                   src/packet.cpp
)

add_library(net ${RUSH_CORE_INCLUDES} ${RUSH_CORE_SRCS})

target_include_directories(net PRIVATE ../3rdparty ../crypto/include ../serial/include)
target_link_libraries(net PRIVATE fmt::fmt crypto serial)
target_compile_options(net PRIVATE -Wall -Wextra -Wpedantic)