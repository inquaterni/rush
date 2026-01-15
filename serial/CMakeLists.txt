cmake_minimum_required(VERSION 3.31)
project(serial LANGUAGES CXX)

include(FetchContent)
FetchContent_Declare(
        capnproto
        GIT_REPOSITORY https://github.com/capnproto/capnproto.git
        GIT_TAG        v1.2.0
        SOURCE_SUBDIR  c++
        OVERRIDE_FIND_PACKAGE
)

set(UNITY_BUILD_V ${CMAKE_UNITY_BUILD})
set(CMAKE_UNITY_BUILD OFF)

FetchContent_MakeAvailable(capnproto)

set(CMAKE_UNITY_BUILD ${UNITY_BUILD_V})

CAPNP_GENERATE_CPP(CAPNP_SRCS CAPNP_HDRS schemas/packet.capnp)

set(RUSH_SERIAL_INCLUDES include/packet_serializer.h)
set(RUSH_SERIAL_SRCS src/packet_serializer.cpp)

add_library(serial
        ${RUSH_SERIAL_INCLUDES}
        ${RUSH_SERIAL_SRCS}
        ${CAPNP_HDRS}
        ${CAPNP_SRCS}
)

target_include_directories(serial PUBLIC
        ../3rdparty
        include
        ../net/include
        ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(serial PRIVATE
        net
        CapnProto::kj-async
)
target_compile_options(serial PRIVATE -Wall -Wextra -Wpedantic)