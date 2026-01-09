cmake_minimum_required(VERSION 3.31)
project(serial LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

set(RUSH_SERIAL_INCLUDES include/packet.capnp.h include/packet_serializer.h)
set(RUSH_SERIAL_SRCS src/packet.capnp.c++ src/packet_serializer.cpp)

include(FetchContent)
FetchContent_Declare(
        capnproto
        GIT_REPOSITORY https://github.com/capnproto/capnproto.git
        GIT_TAG        v1.2.0
        SOURCE_SUBDIR  c++
)
FetchContent_MakeAvailable(capnproto)

add_library(serial ${RUSH_SERIAL_INCLUDES} ${RUSH_SERIAL_SRCS})

target_include_directories(serial PRIVATE ../3rdparty)
target_link_libraries(serial PRIVATE
        fmt::fmt
        CapnProto::capnp
        CapnProto::kj-async
)
target_compile_options(serial PRIVATE -Wall -Wextra -Wpedantic)