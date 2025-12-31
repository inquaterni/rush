cmake_minimum_required(VERSION 3.31)
project(core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

include(FetchContent)
FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/jedisct1/libsodium
        GIT_TAG stable
)
FetchContent_MakeAvailable(Sodium)

set(RUSH_CORE_INCLUDES include/host_deleter.h
                       include/guard.h
                       include/packet.h
                       include/packet_deleter.h
                       include/peer_deleter.h
                       include/secure_session.h
)
set(RUSH_CORE_SRCS src/guard.cpp
                   src/packet.cpp
                   src/secure_session.cpp
)

add_library(core ${RUSH_CORE_INCLUDES} ${RUSH_CORE_SRCS})

target_include_directories(core PRIVATE ../3rdparty)
target_link_libraries(core PRIVATE fmt::fmt
                                   sodium
)
target_compile_options(core PRIVATE -Wall -Wextra -Wpedantic)