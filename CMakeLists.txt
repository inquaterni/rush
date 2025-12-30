cmake_minimum_required(VERSION 3.31)
project(rush LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(./core)
add_subdirectory(./server)
add_subdirectory(./client)
