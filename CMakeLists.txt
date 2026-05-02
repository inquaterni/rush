cmake_minimum_required(VERSION 3.31)
project(rush LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_UNITY_BUILD ON)

option(RUSH_ENABLE_PIC            "Enable position independent code"       ON)
option(RUSH_ENABLE_HARDENING      "Enable security hardening flags"        ON)
option(RUSH_ENABLE_LTO            "Enable LTO"                             ON)
option(RUSH_BUILD_NATIVE          "Enable native build"                    ON)
option(RUSH_ENABLE_CX16           "Enable 128-bit atomics"                 ON)
option(RUSH_ENABLE_AVX10          "Enable AVX10.1 instructions"            ON)
option(RUSH_ENABLE_AVX2           "Enable AVX2 instructions"               ON)
option(RUSH_STRIP_DEAD            "Enable dead code stripping"             ON)
option(RUSH_HIDDEN_VISIBILITY     "Hide symbols"                           ON)
option(RUSH_ENABLE_NO_EXCEPT      "Enable -fno-exceptions"                 ON)
option(RUSH_ENABLE_NO_RTTI        "Enable -fno-rtti"                       ON)
option(RUSH_USE_JEMALLOC          "Replace system allocator with jemalloc" OFF)
option(RUSH_USE_MIMALLOC          "Replace system allocator with mimalloc" OFF)
option(RUSH_ENABLE_FAST_MATH      "Enable -ffast-math (not recommended)"   OFF)

set(ALLOCATOR_LIB)
set(CMAKE_POSITION_INDEPENDENT_CODE ${RUSH_ENABLE_PIC})

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Using CCache: ${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
else()
    message(STATUS "No ccache found.")
endif()

if(UNIX AND NOT APPLE)
    if(CMAKE_BUILD_TYPE MATCHES Debug)
        add_compile_options("-gsplit-dwarf")
    endif()
    find_program(MOLD_LINKER mold)
    if(MOLD_LINKER)
        message(STATUS "Using Mold linker")
        add_link_options("-fuse-ld=mold")
    else()
        find_program(LLD_LINKER lld)
        if(LLD_LINKER)
            message(STATUS "Using LLD linker")
            add_link_options("-fuse-ld=lld")
        endif()
    endif()
endif()

include(CheckCXXCompilerFlag)
include(CheckIPOSupported)

if(CMAKE_BUILD_TYPE MATCHES Release)

    add_compile_options("-O3" "-fno-math-errno" "-fomit-frame-pointer")
    if(RUSH_ENABLE_PIC)
        add_compile_options("-fPIE")
        add_link_options("-pie")
    endif()

    if(RUSH_ENABLE_HARDENING)
        check_cxx_compiler_flag("-fstack-protector-strong" HAS_STACK_PROTECTOR)
        if(HAS_STACK_PROTECTOR)
            add_compile_options("-fstack-protector-strong" "--param=ssp-buffer-size=4")
        endif()

        check_cxx_compiler_flag("-fstack-clash-protection" HAS_STACK_CLASH)
        if(HAS_STACK_CLASH)
            add_compile_options("-fstack-clash-protection")
        endif()

        check_cxx_compiler_flag("-fcf-protection=full" HAS_CF_PROTECTION)
        if(HAS_CF_PROTECTION)
            add_compile_options("-fcf-protection=full")
        endif()

        add_compile_options("-Wformat" "-Wformat-security" "-Werror=format-security")

        add_compile_definitions(_FORTIFY_SOURCE=3)

        if(UNIX AND NOT APPLE)
            add_link_options(
                    "-Wl,-z,relro"
                    "-Wl,-z,now"
                    "-Wl,-z,noexecstack"
                    "-Wl,-z,separate-code"
            )
        endif()

        message(STATUS "Security hardening enabled.")
    endif()

    if(RUSH_ENABLE_NO_EXCEPT)
        check_cxx_compiler_flag("-fno-exceptions" HAS_NO_EXCEPTIONS)
        if(HAS_NO_EXCEPTIONS)
            add_compile_definitions(ASIO_NO_EXCEPTIONS SPDLOG_NO_EXCEPTIONS KJ_USE_FIBERS=0)
            add_compile_options("-fno-exceptions")
        endif()
    endif()

    if(RUSH_ENABLE_NO_RTTI)
        check_cxx_compiler_flag("-fno-rtti" HAS_NO_RTTI)
        if(HAS_NO_RTTI)
            add_compile_definitions(ASIO_NO_TYPEID)
            add_compile_options("-fno-rtti")
        endif()
    endif()

    if(RUSH_HIDDEN_VISIBILITY)
        set(CMAKE_CXX_VISIBILITY_PRESET hidden)
        set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
        message(STATUS "Hidden symbol visibility enabled.")
    endif()

    if(RUSH_STRIP_DEAD AND UNIX AND NOT APPLE)
        check_cxx_compiler_flag("-ffunction-sections" HAS_FUNCTION_SECTIONS)
        if(HAS_FUNCTION_SECTIONS)
            add_compile_options("-ffunction-sections" "-fdata-sections")
            add_link_options("-Wl,--gc-sections")
            message(STATUS "Dead code stripping enabled.")
        endif()
    endif()

    if(RUSH_ENABLE_LTO)
        check_ipo_supported(RESULT lto_supported OUTPUT lto_error)
        if(lto_supported)
            set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
        else()
            message(WARNING "LTO requested but not supported: ${lto_error}")
        endif()
    endif()

    if(RUSH_BUILD_NATIVE)
        check_cxx_compiler_flag("-march=native" HAS_MARCH_NATIVE)
        if(HAS_MARCH_NATIVE)
            add_compile_options("-march=native")
        endif()
    else()
        if(RUSH_ENABLE_AVX10)
            check_cxx_compiler_flag("-mavx10.1" HAS_AVX10)
            if(HAS_AVX10)
                add_compile_options("-mavx10.1")
            endif()
        elseif(RUSH_ENABLE_AVX2)
            check_cxx_compiler_flag("-mavx2" HAS_AVX2)
            if(HAS_AVX2)
                add_compile_options("-mavx2")
            endif()
        endif()
        if(RUSH_ENABLE_CX16)
            check_cxx_compiler_flag("-mcx16" HAS_CX16)
            if(HAS_CX16)
                add_compile_options("-mcx16")
                message(STATUS "Enabled 128-bit atomics (-mcx16) for lock-free operations.")
            else()
                message(WARNING "-mcx16 was requested, but the compiler/architecture does not support it.")
            endif()
        endif()
    endif()

    if(RUSH_ENABLE_FAST_MATH)
        check_cxx_compiler_flag("-ffast-math" HAS_FAST_MATH)
        if(HAS_FAST_MATH)
            message(WARNING "-ffast-math is set — floating-point semantics may break")
            add_compile_options("-ffast-math")
        endif()
    endif()
endif()

if(RUSH_USE_JEMALLOC AND NOT RUSH_USE_MIMALLOC)
    include(ExternalProject)

    set(JEMALLOC_VERSION "5.3.1")
    set(JEMALLOC_EP_DIR  "${CMAKE_CURRENT_BINARY_DIR}/jemalloc_ep")
    set(JEMALLOC_LIB     "${JEMALLOC_EP_DIR}/src/jemalloc_project/lib/libjemalloc_pic.a")
    set(JEMALLOC_INC     "${JEMALLOC_EP_DIR}/src/jemalloc_project/include")
    set(JEMALLOC_STAMP   "${CMAKE_CURRENT_BINARY_DIR}/jemalloc-${JEMALLOC_VERSION}.stamp")

    if(NOT EXISTS "${JEMALLOC_STAMP}" OR NOT EXISTS "${JEMALLOC_LIB}")
        file(REMOVE_RECURSE "${JEMALLOC_EP_DIR}")

        ExternalProject_Add(jemalloc_project
                PREFIX              "${JEMALLOC_EP_DIR}"
                GIT_REPOSITORY      https://github.com/jemalloc/jemalloc.git
                GIT_TAG             "${JEMALLOC_VERSION}"
                GIT_SHALLOW         ON
                UPDATE_DISCONNECTED ON
                BUILD_IN_SOURCE     ON
                CONFIGURE_COMMAND
                <SOURCE_DIR>/autogen.sh
                COMMAND <SOURCE_DIR>/configure
                --with-jemalloc-prefix=
                --disable-shared
                --disable-stats
                BUILD_COMMAND   make -j${nproc}
                INSTALL_COMMAND ""
                BUILD_BYPRODUCTS "${JEMALLOC_LIB}"
        )

        ExternalProject_Add_Step(jemalloc_project write_stamp
                COMMAND   ${CMAKE_COMMAND} -E echo "${JEMALLOC_VERSION}" > "${JEMALLOC_STAMP}"
                DEPENDEES build
                ALWAYS    OFF
        )
    else()
        add_custom_target(jemalloc_project)
    endif()

    file(MAKE_DIRECTORY "${JEMALLOC_INC}")

    add_library(jemalloc STATIC IMPORTED GLOBAL)
    set_target_properties(jemalloc PROPERTIES IMPORTED_LOCATION "${JEMALLOC_LIB}")
    target_include_directories(jemalloc INTERFACE "${JEMALLOC_INC}")
    add_dependencies(jemalloc jemalloc_project)
    message(STATUS "Using jemalloc ${JEMALLOC_VERSION}")
    set(ALLOCATOR_LIB jemalloc)
endif()
if(RUSH_USE_MIMALLOC AND NOT RUSH_USE_JEMALLOC)
    include(FetchContent)

    set(MIMALLOC_VERSION "v3.3.2")
    FetchContent_Declare(
            mimalloc
            GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
            GIT_TAG        ${MIMALLOC_VERSION}
    )
    set(MI_BUILD_TESTS OFF FORCE "")
    set(MI_BUILD_SHARED OFF FORCE "")
    set(MI_BUILD_OBJECT OFF FORCE "")
    FetchContent_MakeAvailable(mimalloc)
    
    set(ALLOCATOR_LIB mimalloc-static)
    message(STATUS "Using mimalloc ${MIMALLOC_VERSION}")
    add_compile_definitions(-DUSE_MIMALLOC)
endif()
if (RUSH_USE_JEMALLOC AND RUSH_USE_MIMALLOC)
    message(FATAL_ERROR "You can use either jemalloc or mimalloc, not both")
endif()
if(ALLOCATOR_LIB)
    add_compile_options(
            "-fno-builtin-malloc"
            "-fno-builtin-calloc"
            "-fno-builtin-realloc"
            "-fno-builtin-free"
    )
    message(STATUS "Disabled compiler built-in allocations to enforce ${ALLOCATOR_LIB}")
endif()

link_libraries(atomic)

add_subdirectory(net)
add_subdirectory(crypto)
add_subdirectory(serial)
add_subdirectory(pack)
add_subdirectory(term)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tests)