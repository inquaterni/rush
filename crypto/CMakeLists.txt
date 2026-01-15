cmake_minimum_required(VERSION 3.31)
project(crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

# TODO: remove from system-wise dependencies
find_package(fmt REQUIRED)

include(FetchContent)
FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/jedisct1/libsodium
        GIT_TAG stable
        OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(Sodium)

set(RUSH_CRYPTO_INCLUDES
        include/guard.h
        include/key_pair.h
        include/types.h
        include/session_keys.h
        include/cipher.h
        include/keys_factory.h
        include/encryption.h
        include/xchacha20poly1305.h
)
set(RUSH_CRYPTO_SRCS
        src/guard.cpp
        src/cipher.cpp
        src/session_keys.cpp
)

add_library(crypto ${RUSH_CRYPTO_INCLUDES} ${RUSH_CRYPTO_SRCS})

target_include_directories(crypto PRIVATE ../3rdparty)
target_link_libraries(crypto PRIVATE
        fmt::fmt
        sodium
)
target_compile_options(crypto PRIVATE -Wall -Wextra -Wpedantic)