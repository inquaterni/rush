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

add_executable(tests main.cpp
        pty_pumper_tests.cpp)

target_include_directories(tests PRIVATE
        ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ../term/include
)
target_link_libraries(tests PRIVATE
        net
        crypto
        serial
        term
        GTest::gtest_main
        GTest::gmock
)
target_include_directories(tests SYSTEM PRIVATE
        ${gtest_SOURCE_DIR}/include
)

target_compile_options(tests PRIVATE
        -Wall -Wextra -Wpedantic
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -DTESTING
)

target_link_options(tests PRIVATE -fsanitize=address,undefined)

include(GoogleTest)
gtest_discover_tests(tests)