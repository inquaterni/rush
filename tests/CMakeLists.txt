cmake_minimum_required(VERSION 3.31)
project(tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

enable_testing()

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
        OVERRIDE_FIND_PACKAGE
)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

add_executable(tests main.cpp)

target_include_directories(tests PRIVATE
        ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
)
target_link_libraries(tests PRIVATE
        net
        crypto
        serial
        GTest::gtest_main
)
target_include_directories(tests SYSTEM PRIVATE
        ${gtest_SOURCE_DIR}/include
)
target_compile_options(tests PRIVATE -Wall -Wextra -Wpedantic)

include(GoogleTest)
gtest_discover_tests(tests)