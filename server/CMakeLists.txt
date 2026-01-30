cmake_minimum_required(VERSION 3.31)
project(server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

find_library(PAM_LIBRARY NAMES pam DOC "The PAM library")

find_path(PAM_INCLUDE_DIR NAMES security/pam_appl.h DOC "The PAM include directory")

if (NOT PAM_LIBRARY OR NOT PAM_INCLUDE_DIR)
    message(FATAL_ERROR "PAM library or headers not found. Try: sudo apt install libpam0g-dev")
endif()

add_executable(server
        main.cpp
        state.cpp
        state.h
        host.cpp
)

target_include_directories(server PRIVATE ../3rdparty
        ../net/include
        ../crypto/include
        ../serial/include
        ../pack/include
        ../term/include
        ${PAM_INCLUDE_DIR}
)
target_link_libraries(server PRIVATE
        net
        crypto
        serial
        pack
        term
)
target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)