cmake_minimum_required(VERSION 3.31)
project(term LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

find_library(PAM_LIBRARY NAMES pam DOC "The PAM library")

find_path(PAM_INCLUDE_DIR NAMES security/pam_appl.h DOC "The PAM include directory")

if (NOT PAM_LIBRARY OR NOT PAM_INCLUDE_DIR)
    message(FATAL_ERROR "PAM library or headers not found. Try: sudo apt install libpam0g-dev")
endif()

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

set(RUSH_TERM_INCLUDES
        include/pty_pumper.h
        include/session.h
        include/tunnel_session.h
)
set(RUSH_TERM_SRCS
        src/pty_pumper.cpp
        src/session.cpp
        src/tunnel_session.cpp
)

add_library(term ${RUSH_TERM_INCLUDES} ${RUSH_TERM_SRCS})

target_include_directories(term PRIVATE
        ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ${PAM_INCLUDE_DIR}
)
target_link_libraries(term PRIVATE
        fmt::fmt
        crypto
        serial
        net
        ${PAM_LIBRARY}
        asio::asio
)
target_compile_options(term PRIVATE -Wall -Wextra -Wpedantic)