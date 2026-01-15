cmake_minimum_required(VERSION 3.31)
project(net LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

set(RUSH_NET_INCLUDES
        include/host_deleter.h
        include/guard.h
        include/packet.h
        include/packet_deleter.h
        include/peer_deleter.h
        include/types.h
        include/event.h
)
set(RUSH_NET_SRCS
        src/guard.cpp
        src/packet.cpp
)

add_library(net ${RUSH_NET_INCLUDES} ${RUSH_NET_SRCS})

target_include_directories(net PRIVATE ../3rdparty ../crypto/include)
target_link_libraries(net PRIVATE fmt::fmt
        CapnProto::capnp
        crypto
)
target_compile_options(net PRIVATE -Wall -Wextra -Wpedantic)