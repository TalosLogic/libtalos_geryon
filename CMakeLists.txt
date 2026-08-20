# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.22)

project(libtalos_geryon
    VERSION 1.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------

option(GERYON_BUILD_TESTS "Build the test suite" ON)

# The end-to-end example (examples/): a multi-process demo that
# doubles as a deterministic pass/fail smoke test.  On by default; it links
# only the public geryon.h surface.
option(GERYON_BUILD_EXAMPLES "Build the end-to-end example" ON)

# The dudect-style timing-validation harness (tests/timing) is a manual /
# nightly tool, never part of the merge gate; keep it off by default.
option(GERYON_BUILD_TIMING "Build the timing-leak validation harness" OFF)

# liboqs backend dispatch (D-PQ-2): ON builds with runtime CPU dispatch
# (OQS_DIST_BUILD); OFF selects the pure-C _ref backends on every arch. Default
# tracks the build type - ON for Release, OFF for Debug - so day-to-day builds
# and CI exercise BOTH code paths. Independently overridable; the timing
# configuration is Release + OFF (D-PQ-4).
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(GERYON_OQS_DIST_DEFAULT OFF)
else()
    set(GERYON_OQS_DIST_DEFAULT ON)
endif()
option(GERYON_OQS_DIST "Build liboqs with runtime CPU dispatch (OQS_DIST_BUILD)"
    ${GERYON_OQS_DIST_DEFAULT})

# Comma-separated sanitizer list, e.g. -DGERYON_SANITIZE=address,undefined.
# Appended to both the library and the tests.
set(GERYON_SANITIZE "" CACHE STRING
    "Comma-separated sanitizers to enable (e.g. address,undefined)")

# Warning flags applied to library and test code (not third_party).
set(GERYON_WARNINGS
    -Wall -Wextra -Werror
    -Wshadow -Wvla -Wwrite-strings -Wstrict-prototypes
)

if(GERYON_SANITIZE)
    add_compile_options(-fsanitize=${GERYON_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${GERYON_SANITIZE})
endif()

# -----------------------------------------------------------------------------
# libsodium (pinned 1.0.22) built from source via ExternalProject
# (static, PIC, installed into the build tree).
# -----------------------------------------------------------------------------

include(ExternalProject)
include(ProcessorCount)

ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 1)
endif()

set(LIBSODIUM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium")
set(LIBSODIUM_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/libsodium-install")
set(LIBSODIUM_INCLUDE_DIR "${LIBSODIUM_INSTALL_DIR}/include")
set(LIBSODIUM_LIB "${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a")

ExternalProject_Add(libsodium_build
    SOURCE_DIR  "${LIBSODIUM_SOURCE_DIR}"
    INSTALL_DIR "${LIBSODIUM_INSTALL_DIR}"

    UPDATE_COMMAND ""
    PATCH_COMMAND  ""

    # Run autogen.sh only when the tracked submodule lacks a configure script.
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env sh -c
            "test -x '${LIBSODIUM_SOURCE_DIR}/configure' || \
             (cd '${LIBSODIUM_SOURCE_DIR}' && ./autogen.sh -s)"
        COMMAND
        "${LIBSODIUM_SOURCE_DIR}/configure"
            "--prefix=<INSTALL_DIR>"
            "--disable-shared"
            "--enable-static"
            "--with-pic"
            "CFLAGS=-O2"

    BUILD_COMMAND   ${CMAKE_MAKE_PROGRAM} "-j${NPROC}"
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install

    BUILD_BYPRODUCTS "${LIBSODIUM_LIB}"
    BUILD_IN_SOURCE OFF
)

# INTERFACE_INCLUDE_DIRECTORIES is validated at configure time; the install
# tree does not exist yet, so create the include dir up front.
file(MAKE_DIRECTORY "${LIBSODIUM_INCLUDE_DIR}")

add_library(sodium STATIC IMPORTED GLOBAL)
add_dependencies(sodium libsodium_build)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION             "${LIBSODIUM_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBSODIUM_INCLUDE_DIR}"
)

# -----------------------------------------------------------------------------
# monocypher (pinned 4.0.3): one .c/.h pair, compiled directly.
# geryon uses ONLY crypto_x25519_to_eddsa from the core unit; the optional
# SHA-512 and ed25519 units are deliberately NOT enabled.
# -----------------------------------------------------------------------------

add_library(monocypher STATIC
    third_party/monocypher/src/monocypher.c
)
target_include_directories(monocypher PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher/src"
)
# third_party code is not held to geryon's warning bar.
target_compile_options(monocypher PRIVATE -w)

# -----------------------------------------------------------------------------
# liboqs (pinned 0.16.0) built from source via ExternalProject (static, PIC,
# installed into the build tree). Only the four closed-suite algorithms are
# compiled (ML-KEM-512/1024 + ML-DSA-44/87, D-GEN-7); OpenSSL is OFF so
# libsodium stays the only symmetric provider (liboqs falls back to its
# internal SHAKE). Linked PRIVATE into geryon_core, deliberately NOT
# add_subdirectory, so liboqs's option namespace and CMake policies stay
# isolated (D-PQ-2, the same pattern as libsodium above).
# -----------------------------------------------------------------------------

set(LIBOQS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/liboqs")
set(LIBOQS_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/liboqs-install")
set(LIBOQS_INCLUDE_DIR "${LIBOQS_INSTALL_DIR}/include")
set(LIBOQS_LIB "${LIBOQS_INSTALL_DIR}/lib/liboqs.a")

# Dispatch selection (D-PQ-2). When dispatch is OFF, force every mlkem-native
# backend to the pure-C _ref path on both arches; when ON, OQS_DIST_BUILD picks
# per-CPU at runtime.
if(GERYON_OQS_DIST)
    set(LIBOQS_BACKEND_ARGS -DOQS_DIST_BUILD:BOOL=ON)
else()
    set(LIBOQS_BACKEND_ARGS
        -DOQS_DIST_BUILD:BOOL=OFF
        -DOQS_ENABLE_KEM_ml_kem_512_x86_64:BOOL=OFF
        -DOQS_ENABLE_KEM_ml_kem_512_aarch64:BOOL=OFF
        -DOQS_ENABLE_KEM_ml_kem_1024_x86_64:BOOL=OFF
        -DOQS_ENABLE_KEM_ml_kem_1024_aarch64:BOOL=OFF
        -DOQS_ENABLE_SIG_ml_dsa_44_x86_64:BOOL=OFF
        -DOQS_ENABLE_SIG_ml_dsa_44_aarch64:BOOL=OFF
        -DOQS_ENABLE_SIG_ml_dsa_87_x86_64:BOOL=OFF
        -DOQS_ENABLE_SIG_ml_dsa_87_aarch64:BOOL=OFF
    )
endif()

ExternalProject_Add(liboqs_build
    SOURCE_DIR  "${LIBOQS_SOURCE_DIR}"
    INSTALL_DIR "${LIBOQS_INSTALL_DIR}"

    UPDATE_COMMAND ""
    PATCH_COMMAND  ""

    # OQS_MINIMAL_BUILD is a semicolon list; LIST_SEPARATOR lets us write it
    # with '|' so ExternalProject does not eat the separators as its own
    # argument boundaries.
    LIST_SEPARATOR |
    CMAKE_CACHE_ARGS
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
        -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
        -DBUILD_SHARED_LIBS:BOOL=OFF
        -DOQS_USE_OPENSSL:BOOL=OFF
        -DOQS_BUILD_ONLY_LIB:BOOL=ON
        -DOQS_MINIMAL_BUILD:STRING=KEM_ml_kem_512|KEM_ml_kem_1024|SIG_ml_dsa_44|SIG_ml_dsa_87
    CMAKE_ARGS ${LIBOQS_BACKEND_ARGS}

    BUILD_BYPRODUCTS "${LIBOQS_LIB}"
)

# INTERFACE_INCLUDE_DIRECTORIES is validated at configure time; the install
# tree does not exist yet, so create the include dir up front.
file(MAKE_DIRECTORY "${LIBOQS_INCLUDE_DIR}")

add_library(oqs STATIC IMPORTED GLOBAL)
add_dependencies(oqs liboqs_build)
set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION             "${LIBOQS_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INCLUDE_DIR}"
)

# -----------------------------------------------------------------------------
# geryon_core static library (Layer 1).
# -----------------------------------------------------------------------------

file(GLOB GERYON_CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.c")

add_library(geryon_core STATIC ${GERYON_CORE_SOURCES})
target_include_directories(geryon_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
)
target_compile_options(geryon_core PRIVATE ${GERYON_WARNINGS})
# Production interlock (src/core/error.h): PRIVATE so it marks only the shipped
# library objects, never propagating to test targets that recompile sources
# with GY_TEST_HOOKS. The two macros together are a hard #error.
target_compile_definitions(geryon_core PRIVATE GY_PRODUCTION_BUILD)
# PUBLIC: core's public headers include these deps' headers (hash.h -> sodium.h,
# mlkem.h/mldsa.h -> oqs/oqs.h), so their include dirs must propagate up the
# layer chain to any source that transitively includes a core header. Linking is
# also propagated, which is harmless for static archives (final executables link
# them anyway). PRIVATE only appeared to work where a system libsodium/liboqs
# was installed on the compiler's default include path.
target_link_libraries(geryon_core PUBLIC sodium monocypher oqs)
add_dependencies(geryon_core libsodium_build liboqs_build)

# -----------------------------------------------------------------------------
# geryon_kex static library (Layer 2). Includes core/ headers only; ratchet/
# will include kex/ headers only. Sources land per-module.
# -----------------------------------------------------------------------------

file(GLOB GERYON_KEX_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/kex/*.c")

add_library(geryon_kex STATIC ${GERYON_KEX_SOURCES})
target_include_directories(geryon_kex PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/kex"
)
target_compile_options(geryon_kex PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_kex PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_kex PUBLIC geryon_core)

# -----------------------------------------------------------------------------
# geryon_ratchet static library (Layer 3). Includes kex/ headers only. Sources
# land per-module.
# -----------------------------------------------------------------------------

file(GLOB GERYON_RATCHET_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ratchet/*.c")

add_library(geryon_ratchet STATIC ${GERYON_RATCHET_SOURCES})
target_include_directories(geryon_ratchet PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ratchet"
)
target_compile_options(geryon_ratchet PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_ratchet PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_ratchet PUBLIC geryon_kex)

# -----------------------------------------------------------------------------
# geryon_session static library (Layer 4). Includes ratchet/ headers only
# (ratchet.h re-exports the kex interfaces session/ needs). Sources land
# per-module.
# -----------------------------------------------------------------------------

file(GLOB GERYON_SESSION_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/session/*.c")

add_library(geryon_session STATIC ${GERYON_SESSION_SOURCES})
target_include_directories(geryon_session PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/session"
)
target_compile_options(geryon_session PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_session PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_session PUBLIC geryon_ratchet)

# -----------------------------------------------------------------------------
# geryon_proto static library (Layer 5). Includes session/ headers ONLY; its
# objects must reference no ratchet/ or core/ symbol (nm audit). It
# does its own byte/endian work and takes the suite descriptor as a parameter.
# -----------------------------------------------------------------------------

file(GLOB GERYON_PROTO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/proto/*.c")

add_library(geryon_proto STATIC ${GERYON_PROTO_SOURCES})
target_include_directories(geryon_proto PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_options(geryon_proto PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_proto PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_proto PUBLIC geryon_session)

# Aggregate: linking `geryon` brings the whole stack and the public header.
# include/geryon.h is the ONLY installed header.
add_library(geryon INTERFACE)
target_link_libraries(geryon INTERFACE geryon_proto)
target_include_directories(geryon INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/geryon.h" DESTINATION include)

# -----------------------------------------------------------------------------
# Tests: driven by tests/CMakeLists.txt, which builds each tests/core/test_*.c
# into build/tests/ and registers it with CTest. Slow/iterated vectors carry
# the `slow` label; exclude them with `ctest -LE slow` (see README.md).
# -----------------------------------------------------------------------------

if(GERYON_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# -----------------------------------------------------------------------------
# Example: the end-to-end multi-process demo.  Registers its own
# `demo` CTest case (exit 0 = pass), so it can serve as a regression smoke
# test; wiring it into the pipeline is a later decision.
# -----------------------------------------------------------------------------

if(GERYON_BUILD_EXAMPLES)
    enable_testing()
    add_subdirectory(examples)
endif()

# Timing harness: separate opt-in so it never enters the default build or the
# merge gate. Registers only the bounded `timing`-labelled self-check.
if(GERYON_BUILD_TIMING)
    enable_testing()
    add_subdirectory(tests/timing)
endif()

# -----------------------------------------------------------------------------
# format-check: clang-format --dry-run --Werror over first-party sources.
# `cmake --build build --target format-check`
# -----------------------------------------------------------------------------

find_program(CLANG_FORMAT_BIN NAMES clang-format)
if(CLANG_FORMAT_BIN)
    file(GLOB_RECURSE GERYON_FORMAT_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
    list(FILTER GERYON_FORMAT_FILES EXCLUDE REGEX "/third_party/")
    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_BIN} --dry-run --Werror ${GERYON_FORMAT_FILES}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Checking formatting with clang-format"
        VERBATIM)
else()
    message(STATUS "clang-format not found; format-check target unavailable")
endif()
