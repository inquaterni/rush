cmake_minimum_required(VERSION 3.31)
project(pack LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

include(FetchContent)

FetchContent_Declare(
        zstd
        URL https://github.com/facebook/zstd/archive/refs/tags/v1.5.6.zip
        OVERRIDE_FIND_PACKAGE
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(zstd)

set(RUSH_PACK_INCLUDES include/compressor.h)
set(RUSH_PACK_SRCS src/compressor.cpp)

add_library(pack ${RUSH_PACK_INCLUDES} ${RUSH_PACK_SRCS})

target_include_directories(pack PRIVATE
        ../3rdparty
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(pack PRIVATE zstd)
target_compile_options(pack PRIVATE -Wall -Wextra -Wpedantic)