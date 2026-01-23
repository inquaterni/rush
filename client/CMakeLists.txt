cmake_minimum_required(VERSION 3.31)
project(client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

include(FetchContent)

FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG        asio-1-36-0
        OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(asio)

if(NOT TARGET asio::asio)
    add_library(asio_lib INTERFACE)
    add_library(asio::asio ALIAS asio_lib)
    target_include_directories(asio_lib INTERFACE ${asio_SOURCE_DIR}/asio/include)
    target_compile_definitions(asio_lib INTERFACE ASIO_STANDALONE)

    find_package(Threads REQUIRED)
    target_link_libraries(asio_lib INTERFACE Threads::Threads)
endif()


add_executable(client
        main.cpp
        client.cpp
        client.h
        guard.cpp
        guard.h
        state.cpp
        state.h
        state.cpp
        state.h
        session.cpp
        session.h
)

target_include_directories(client PRIVATE ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ../pack/include
)
target_link_libraries(client PRIVATE
        net
        crypto
        serial
        pack
        asio::asio
)
target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)