# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.22)

project(libtalos_geryon
    VERSION 1.5.0
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
# libdecaf / ed448goldilocks (pinned v1.0.3, e5cc624; git submodule).
# DIRECT-compile integration of the 448 slice (D-XED-12 Build, amended
# 2026-08-20): geryon compiles libdecaf's C sources for the 448 path
# under its OWN static archive and runs libdecaf's Python generator via custom
# commands. Deliberately NOT add_subdirectory and NOT ExternalProject, because
# libdecaf's top-level project(... C CXX) forces a C++ toolchain (even though
# zero C++ compiles into the static lib) and would leak its install()/CTest/
# option namespace into geryon. The hard constraint is NO libstdc++ at runtime;
# compiling only the C sources honors it. geryon owns a small enumerable copy of
# libdecaf's 448 build graph (source list + generator commands + arch map),
# re-diffed against upstream at each geryon-controlled pin bump.
# -----------------------------------------------------------------------------

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(DECAF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed448goldilocks-code")
set(DECAF_GEN "${CMAKE_CURRENT_BINARY_DIR}/decaf448-generated")
set(DECAF_TEMPLATE "${DECAF_SRC}/src/generator/template.py")

# p448 arch selection: mirror third_party/.../src/CMakeLists.txt
# (TARGET_ARCH_DIR_P448). Only arch_x86_64 and arch_ref64 are validated targets
# for geryon; the pure-C arch_ref64 is the portable fallback (never arch_32,
# which is the generic 32-bit path).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(DECAF_ARCH arch_x86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arch64")
    set(DECAF_ARCH arch_ref64)
else()
    set(DECAF_ARCH arch_ref64)
endif()
message(STATUS "libdecaf448: p448 target arch = ${DECAF_ARCH}")

file(MAKE_DIRECTORY
    "${DECAF_GEN}/include/decaf"
    "${DECAF_GEN}/c/p448"
    "${DECAF_GEN}/c/ed448goldilocks"
    "${DECAF_GEN}/c/p25519"
    "${DECAF_GEN}/c/curve25519")

set(DECAF_GENERATED "")

# Run template.py --per=<PER> [--item=<ITEM>] --guard=<GUARD> -o <OUT> <TMPL>.
# Re-encodes libdecaf's src/generator/{,ed448goldilocks/}CMakeLists.txt for the
# 448 path only. A macro (not a function) so DECAF_GENERATED accumulates in this
# scope.
macro(decaf_generate out per item guard tmpl)
    if("${item}" STREQUAL "")
        set(_decaf_itemarg "")
    else()
        set(_decaf_itemarg "--item=${item}")
    endif()
    add_custom_command(
        OUTPUT "${DECAF_GEN}/${out}"
        COMMAND "${Python3_EXECUTABLE}" "${DECAF_TEMPLATE}"
            "--per=${per}" ${_decaf_itemarg} "--guard=${guard}"
            -o "${DECAF_GEN}/${out}" "${DECAF_SRC}/src/${tmpl}"
        DEPENDS "${DECAF_TEMPLATE}" "${DECAF_SRC}/src/${tmpl}"
        COMMENT "libdecaf448: generating ${out}"
        VERBATIM)
    list(APPEND DECAF_GENERATED "${DECAF_GEN}/${out}")
endmacro()

macro(decaf_copy_header out src)
    add_custom_command(
        OUTPUT "${DECAF_GEN}/${out}"
        COMMAND "${CMAKE_COMMAND}" -E copy
            "${DECAF_SRC}/src/${src}" "${DECAF_GEN}/${out}"
        DEPENDS "${DECAF_SRC}/src/${src}"
        VERBATIM)
    list(APPEND DECAF_GENERATED "${DECAF_GEN}/${out}")
endmacro()

# Public headers the 448 sources include (via <decaf.h>, which itself pulls in
# BOTH curves' point_*.h, so curve25519's point header is generated too -
# header only, no curve25519 code is compiled).
decaf_generate("include/decaf.h"           global ""               "decaf.h"
    "public_include/decaf.tmpl.h")
decaf_generate("include/decaf/point_255.h" curve  curve25519       "decaf/point_255.h"
    "per_curve/point.tmpl.h")
decaf_generate("include/decaf/point_448.h" curve  ed448goldilocks  "decaf/point_448.h"
    "per_curve/point.tmpl.h")
decaf_generate("include/decaf/ed448.h"     curve  ed448goldilocks  "decaf/ed448.h"
    "per_curve/eddsa.tmpl.h")
decaf_copy_header("include/decaf/common.h"    "public_include/decaf/common.h")
decaf_copy_header("include/decaf/shake.h"     "public_include/decaf/shake.h")
decaf_copy_header("include/decaf/sha512.h"    "public_include/decaf/sha512.h")
decaf_copy_header("include/decaf/spongerng.h" "public_include/decaf/spongerng.h")

# Generated internal p448 field header + sources.
decaf_generate("c/p448/f_field.h"  field p448 "p448/f_field.h"
    "per_field/f_field.tmpl.h")
decaf_generate("c/p448/f_generic.c" field p448 "p448/f_generic.c"
    "per_field/f_generic.tmpl.c")

# Generated ed448goldilocks curve sources.
decaf_generate("c/ed448goldilocks/scalar.c"    curve ed448goldilocks "ed448goldilocks/scalar.c"
    "per_curve/scalar.tmpl.c")
decaf_generate("c/ed448goldilocks/decaf.c"     curve ed448goldilocks "ed448goldilocks/decaf.c"
    "per_curve/decaf.tmpl.c")
decaf_generate("c/ed448goldilocks/elligator.c" curve ed448goldilocks "ed448goldilocks/elligator.c"
    "per_curve/elligator.tmpl.c")
decaf_generate("c/ed448goldilocks/eddsa.c"     curve ed448goldilocks "ed448goldilocks/eddsa.c"
    "per_curve/eddsa.tmpl.c")

# curve25519 / p25519 slice. Required because the embedded libtalos_schnorr
# reaches raw decaf_255 group ops for EncodeToG-255 (the Elligator inverse;
# libsodium's ristretto255 exposes only the one-way from_hash). With
# USE_EXTERNAL_DECAF, geryon owns the whole decaf schnorr links, so the parent's
# 448 target must carry curve25519 too (schnorr reuses it for the 255 tier).
# Generated internal p25519 field header + generic source:
decaf_generate("c/p25519/f_field.h"   field p25519 "p25519/f_field.h"
    "per_field/f_field.tmpl.h")
decaf_generate("c/p25519/f_generic.c" field p25519 "p25519/f_generic.c"
    "per_field/f_generic.tmpl.c")

# The generated curve25519/decaf.c #includes <decaf/ed255.h>, so it is generated
# even though geryon uses libsodium for Ed25519 (the decaf ed255 code links only
# as referenced).
decaf_generate("include/decaf/ed255.h" curve curve25519 "decaf/ed255.h"
    "per_curve/eddsa.tmpl.h")

# Generated curve25519 curve sources.
decaf_generate("c/curve25519/scalar.c"    curve curve25519 "curve25519/scalar.c"
    "per_curve/scalar.tmpl.c")
decaf_generate("c/curve25519/decaf.c"     curve curve25519 "curve25519/decaf.c"
    "per_curve/decaf.tmpl.c")
decaf_generate("c/curve25519/elligator.c" curve curve25519 "curve25519/elligator.c"
    "per_curve/elligator.tmpl.c")
decaf_generate("c/curve25519/eddsa.c"     curve curve25519 "curve25519/eddsa.c"
    "per_curve/eddsa.tmpl.c")

add_custom_target(decaf448_generate DEPENDS ${DECAF_GENERATED})

# The 448 source slice. Static (checked-in) sources come from the submodule
# tree; generated .c come from DECAF_GEN. NOTE: eddsa.c defines
# decaf_ed448_sign/verify (RFC 8032), used ONLY by the 448 validation gate
# (D-XED-12 scope): they are archived here but geryon's own code never
# references them, so production consumers drop eddsa.o at final link.
set(DECAF_448_SOURCES
    "${DECAF_SRC}/src/utils.c"
    "${DECAF_SRC}/src/shake.c"
    "${DECAF_SRC}/src/sha512.c"
    "${DECAF_SRC}/src/spongerng.c"
    "${DECAF_SRC}/src/p448/${DECAF_ARCH}/f_impl.c"
    "${DECAF_SRC}/src/p448/f_arithmetic.c"
    "${DECAF_SRC}/src/ed448goldilocks/decaf_tables.c"
    "${DECAF_GEN}/c/p448/f_generic.c"
    "${DECAF_GEN}/c/ed448goldilocks/scalar.c"
    "${DECAF_GEN}/c/ed448goldilocks/decaf.c"
    "${DECAF_GEN}/c/ed448goldilocks/elligator.c"
    "${DECAF_GEN}/c/ed448goldilocks/eddsa.c"
)
set_source_files_properties(
    "${DECAF_GEN}/c/p448/f_generic.c"
    "${DECAF_GEN}/c/ed448goldilocks/scalar.c"
    "${DECAF_GEN}/c/ed448goldilocks/decaf.c"
    "${DECAF_GEN}/c/ed448goldilocks/elligator.c"
    "${DECAF_GEN}/c/ed448goldilocks/eddsa.c"
    PROPERTIES GENERATED 1)

# curve25519 / p25519 object slices, folded into the decaf448 archive below so
# the single geryon decaf target carries BOTH curves (see the schnorr var block
# after add_subdirectory: USE_EXTERNAL_DECAF, no separate 255 target). These are
# SEPARATE object libraries with their own include path because p448/f_field.h
# and p25519/f_field.h share a name and cannot coexist on one target's includes;
# upstream libdecaf and schnorr's cmake/decaf_slice.cmake mirror this.
set(DECAF_255_FIELD_INC
    "${DECAF_SRC}/src/include"
    "${DECAF_SRC}/src/include/${DECAF_ARCH}"
    "${DECAF_SRC}/src/p25519"
    "${DECAF_SRC}/src/p25519/${DECAF_ARCH}"
    "${DECAF_GEN}/c/p25519"
    "${DECAF_GEN}/c/curve25519"
    "${DECAF_GEN}/include"
)
set_source_files_properties(
    "${DECAF_GEN}/c/p25519/f_generic.c"
    "${DECAF_GEN}/c/curve25519/scalar.c"
    "${DECAF_GEN}/c/curve25519/decaf.c"
    "${DECAF_GEN}/c/curve25519/elligator.c"
    "${DECAF_GEN}/c/curve25519/eddsa.c"
    PROPERTIES GENERATED 1)

add_library(decaf_p25519 OBJECT
    "${DECAF_SRC}/src/p25519/${DECAF_ARCH}/f_impl.c"
    "${DECAF_SRC}/src/p25519/f_arithmetic.c"
    "${DECAF_GEN}/c/p25519/f_generic.c")
add_dependencies(decaf_p25519 decaf448_generate)
set_target_properties(decaf_p25519 PROPERTIES POSITION_INDEPENDENT_CODE True)
target_compile_options(decaf_p25519 PRIVATE -w)
target_include_directories(decaf_p25519 PRIVATE ${DECAF_255_FIELD_INC})

add_library(decaf_curve25519 OBJECT
    "${DECAF_SRC}/src/curve25519/decaf_tables.c"
    "${DECAF_GEN}/c/curve25519/scalar.c"
    "${DECAF_GEN}/c/curve25519/decaf.c"
    "${DECAF_GEN}/c/curve25519/elligator.c"
    "${DECAF_GEN}/c/curve25519/eddsa.c")
add_dependencies(decaf_curve25519 decaf448_generate)
set_target_properties(decaf_curve25519 PROPERTIES POSITION_INDEPENDENT_CODE True)
target_compile_options(decaf_curve25519 PRIVATE -w)
target_include_directories(decaf_curve25519 PRIVATE ${DECAF_255_FIELD_INC})

add_library(decaf448 STATIC ${DECAF_448_SOURCES}
    $<TARGET_OBJECTS:decaf_p25519>
    $<TARGET_OBJECTS:decaf_curve25519>)
add_dependencies(decaf448 decaf448_generate)
set_target_properties(decaf448 PROPERTIES POSITION_INDEPENDENT_CODE True)
# third_party code is not held to geryon's warning bar (same as monocypher).
target_compile_options(decaf448 PRIVATE -w)
# PUBLIC: the generated decaf.h API dir is needed both by decaf448's OWN
# sources (they #include <decaf.h>) and by geryon's x448.c when decaf448 is
# linked in; it is the only libdecaf interface geryon code consumes.
target_include_directories(decaf448 PUBLIC "${DECAF_GEN}/include")
# PRIVATE: the internal field/arch + generated per-field headers are the
# archive's own compile concern and must NOT propagate to geryon_core. The
# generated per-field header (f_field.h) lives under DECAF_GEN/c/p448.
target_include_directories(decaf448 PRIVATE
    "${DECAF_SRC}/src/include"
    "${DECAF_SRC}/src/include/${DECAF_ARCH}"
    "${DECAF_SRC}/src/p448"
    "${DECAF_SRC}/src/p448/${DECAF_ARCH}"
    "${DECAF_GEN}/c/p448"
    "${DECAF_GEN}/c/ed448goldilocks"
)

# The INTERNAL gf field headers are NOT part of decaf448's interface (they must
# not reach the rest of geryon_core). ed448.c is the ONE geryon
# translation unit that borrows them, applied PRIVATE to that source alone.
# Exposed here as a variable for that ticket (approach #3 shim, D-XED-13).
set(GERYON_DECAF448_INTERNAL_INCLUDES
    "${DECAF_SRC}/src/include"
    "${DECAF_SRC}/src/include/${DECAF_ARCH}"
    "${DECAF_SRC}/src/p448"
    "${DECAF_SRC}/src/p448/${DECAF_ARCH}"
    "${DECAF_GEN}/c/p448"
    "${DECAF_GEN}/include"
    CACHE INTERNAL "Internal libdecaf gf field include dirs for src/core/ed448.c only")

# -----------------------------------------------------------------------------
# geryon_core static library (Layer 1).
# -----------------------------------------------------------------------------

file(GLOB GERYON_CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.c")

# KR-ML-DSA (QSPGS): per-backend objects compiled against liboqs' mldsa-native
# internals; the glob above deliberately does not descend into src/core/krmldsa.
include(cmake/krmldsa.cmake)

add_library(geryon_core STATIC ${GERYON_CORE_SOURCES} ${GERYON_KRMLDSA_OBJECTS})
target_include_directories(geryon_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
)
# PRIVATE: x448.c needs libdecaf's PUBLIC decaf.h (RFC 7748 X448) and ed448.c
# additionally needs the INTERNAL gf field headers (D-XED-13 R2 approach-#3
# shim). GERYON_DECAF448_INTERNAL_INCLUDES carries both (src/include has
# word.h/field.h; DECAF_GEN/include has decaf.h). Applied PRIVATE at the target
# level for robustness (a per-source property did not reliably apply): the
# internal-header PATH is available to all core objects, but only ed448.c
# #includes field.h, so the layering rule (only ed448.c uses internal gf) still
# holds in code. These dirs are PRIVATE, so nothing propagates above Layer 1.
target_include_directories(geryon_core PRIVATE ${GERYON_DECAF448_INTERNAL_INCLUDES})
target_compile_options(geryon_core PRIVATE ${GERYON_WARNINGS})
# Production interlock (src/core/error.h): PRIVATE so it marks only the shipped
# library objects, never propagating to test targets that recompile sources
# with GY_TEST_HOOKS. The two macros together are a hard #error.
target_compile_definitions(geryon_core PRIVATE GY_PRODUCTION_BUILD)
# PUBLIC: core's public headers include these deps' headers (hash.h -> sodium.h,
# mlkem*/mldsa*.h -> oqs/oqs.h), so their include dirs must propagate up the
# layer chain to any source that transitively includes a core header. Linking is
# also propagated, which is harmless for static archives (final executables link
# them anyway). PRIVATE only appeared to work where a system libsodium/liboqs
# was installed on the compiler's default include path.
target_link_libraries(geryon_core PUBLIC sodium monocypher oqs)
# libdecaf 448 archive: PRIVATE (D-XED-12) - only core/x448.c and core/ed448.c
# call into it; its public decaf.h include propagates to geryon_core
# sources via the INTERFACE include, but the archive itself does not propagate
# to higher layers. The internal gf headers reach ONLY ed448.c,
# via GERYON_DECAF448_INTERNAL_INCLUDES.
target_link_libraries(geryon_core PRIVATE decaf448)
# ed448.c includes libdecaf's generated headers (decaf.h + the internal gf
# field headers), so the generator must run before geryon_core's objects
# compile, not merely before it links.
add_dependencies(geryon_core libsodium_build liboqs_build decaf448_generate)

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
# libtalos_schnorr: the mandatory group-element provider for the classical group
# vertical (D-GRP-1), so it is a normal part of the build, not an option. It
# consumes geryon's C-only decaf slice (decaf448) and libsodium (sodium)
# instead of building its own, so there is no second copy of either (the
# libsodium target even shares the name `sodium`) and no libstdc++ from
# ed448goldilocks's C++-bearing decaf-static. Both sides pin the same
# ed448goldilocks (v1.0.3). Cache vars set with FORCE before add_subdirectory so
# schnorr's option()/set() pick them up. EXCLUDE_FROM_ALL: configured now,
# compiled once the group layer links talos_schnorr (no consumer exists yet).
#
# decaf448 now carries BOTH curves (p448/ed448goldilocks AND p25519/curve25519,
# folded in above), so schnorr reuses this one target for both tiers: the 448
# tier and, for EncodeToG-255, the raw decaf_255 group ops. That is why
# USE_EXTERNAL_DECAF255 is left OFF (schnorr defaults its 255 provider to the
# 448 target) and no separate decaf255 target is provided.
# -----------------------------------------------------------------------------
set(TALOS_SCHNORR_USE_EXTERNAL_SODIUM ON       CACHE BOOL   "" FORCE)
set(TALOS_SCHNORR_SODIUM_TARGET       sodium   CACHE STRING "" FORCE)
set(TALOS_SCHNORR_USE_EXTERNAL_DECAF  ON       CACHE BOOL   "" FORCE)
set(TALOS_SCHNORR_DECAF_TARGET        decaf448 CACHE STRING "" FORCE)
set(TALOS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(TALOS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/libtalos_schnorr EXCLUDE_FROM_ALL)

# -----------------------------------------------------------------------------
# geryon_group static library: the classical private-group vertical (M8,
# GROUP_SPEC), a PARALLEL VERTICAL (D-GRP-2), NOT part of the Layer 1-5 messaging
# stack. It composes the [CPZ] protocol clean-room over the libtalos_schnorr
# group-element provider (D-GRP-1) and reuses geryon_core for HKDF/HMAC/rng and
# the suite descriptor (GROUP_SPEC section 2.3). EXCLUDE_FROM_ALL: opt-in by
# linking it, never a compile-time flag (groups-separate-target, D-QGS-1); it is
# compiled when a consumer or its tests link it.
# -----------------------------------------------------------------------------
# Client / server / common role split (GROUP_SPEC section 8.3): the
# group vertical ships as TWO facades over shared internals so a client binary
# contains no issuance code or any path consuming ServerSecretParams. The split
# is STRUCTURAL (separate translation units, verified by tests/audit/
# nm_scope_server.sh), not documentary:
#   - COMMON (geryon_group_internal): the sk-free shared layer - proof-statement
#     assembly (group_stmt), the object wire encode/decode, and the section 2
#     parameter/hash/tier/attribute/verifiable-encryption foundation. One static
#     archive both facades link, so a binary linking both (e.g. the tests) gets a
#     single copy and no duplicate symbols.
#   - CLIENT (geryon_group): the member-side operations and credential/
#     presentation proving. Never consumes ServerSecretParams.
#   - SERVER (geryon_groups_server): the five section 8.1 ServerSecretParams
#     operations (KeyGen/iparams, issuance, blind issuance, and the two
#     presentation verifications). A separate target, never linked into a client.
set(GERYON_GROUP_COMMON_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_stmt.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_wire.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_params.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_hash.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_tier.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_attr.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_venc.c")
set(GERYON_GROUP_CLIENT_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_ops.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_state.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_cred_client.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_pres_client.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_issue_client.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_facade_client.c")
set(GERYON_GROUP_SERVER_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_cred_server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_pres_server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_issue_server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_mac_server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group/group_facade_server.c")

# Common internals. geryon_core: HKDF/HMAC/rng/util plus gy_info / gy_suite_desc
# (GROUP_SPEC section 2.3). talos_schnorr: the group-element provider (D-GRP-1).
# PUBLIC linkage propagates the include dirs to both facades.
add_library(geryon_group_internal STATIC EXCLUDE_FROM_ALL
    ${GERYON_GROUP_COMMON_SOURCES})
target_include_directories(geryon_group_internal PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/group"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(geryon_group_internal PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_group_internal PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_group_internal PUBLIC geryon_core talos_schnorr)

add_library(geryon_group STATIC EXCLUDE_FROM_ALL ${GERYON_GROUP_CLIENT_SOURCES})
target_compile_options(geryon_group PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_group PRIVATE GY_PRODUCTION_BUILD)
# geryon_proto: the client facade extends the custodian (custodian.h + its
# transitive proto/session/core include dirs). A group client is a messaging
# client, so this coupling is by design; the SERVER target links neither.
target_link_libraries(geryon_group PUBLIC geryon_group_internal geryon_proto)

add_library(geryon_groups_server STATIC EXCLUDE_FROM_ALL
    ${GERYON_GROUP_SERVER_SOURCES})
target_compile_options(geryon_groups_server PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_groups_server PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_groups_server PUBLIC geryon_group_internal)

# -----------------------------------------------------------------------------
# geryon_qspgs vertical: the quantum-safe private-group system (M9, QSPGS_SPEC),
# a SECOND parallel group vertical (two-group-types, D-QGS-11) that ships beside
# the classical geryon_group. It serves the HYBRID suites only and is built ON
# the KR-ML-DSA base pair (folded into geryon_core) plus geryon_core's
# HKDF / suite descriptor. EXCLUDE_FROM_ALL: opt-in by linking it, never a
# compile-time flag (groups-separate-target).
#
# Client / server / common role split (QSPGS_SPEC section 7.1;
# mirrors the M8 group split, GROUP_SPEC section 8.3). The split is STRUCTURAL
# (separate translation units, verified by tests/audit/nm_scope_qspgs_server.sh),
# not documentary:
#   - COMMON (geryon_qspgs_internal): the sk-free shared layer - the section 4
#     wire encode/decode, the frozen tier-hash helpers (C_UID, H(vkpsdn)), and
#     the PUBLIC-verifier core / appendix signature checks (qspgs_wire.c). It
#     carries no rerandomization secret; both facades link it.
#   - CLIENT (geryon_qspgs): the section 5 member operations plus the key
#     hierarchy, skpers, join PKE, and ek-field layer - everything that touches
#     rrs / rho / skpsdn / ek / gk. Never linked into the server.
#   - SERVER (geryon_qsgroups_server): the section 7.3 stateless checks over the
#     common layer's public verifiers. A separate target, never linked into a
#     client, holding no core secret parameter and no KR-ML-DSA internal.

# Common internals: the sk-free wire + verify layer, over geryon_core (HKDF /
# suite descriptor / util plus the KR-ML-DSA public verifiers folded
# into it). PUBLIC linkage propagates the include dirs to both facades.
add_library(geryon_qspgs_internal STATIC EXCLUDE_FROM_ALL
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_sizes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_wire.c")
target_include_directories(geryon_qspgs_internal PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(geryon_qspgs_internal PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_qspgs_internal PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_qspgs_internal PUBLIC geryon_core)

# Client facade: the section 5 operations and the key hierarchy. Links the
# common layer for the wire codecs and public verifiers.
add_library(geryon_qspgs STATIC EXCLUDE_FROM_ALL
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_keys.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_pers.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_join.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_field.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_ops.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_store.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_facade_client.c")
target_compile_options(geryon_qspgs PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_qspgs PRIVATE GY_PRODUCTION_BUILD)
# geryon_proto: the public client facade (geryon_qspgs.h) extends a borrowed
# custodian for identity signing (custodian.h + its transitive proto/session/
# core include dirs), exactly as the classical geryon_group client does.  A
# QSPGS client is a messaging client, so this coupling is by design; the SERVER
# target (geryon_qsgroups_server) links neither the client nor proto.
target_link_libraries(geryon_qspgs PUBLIC geryon_qspgs_internal geryon_proto)

# Server facade: the section 7.3 stateless checks (qspgs_server.c) and the
# handle-free public surface over them, which decodes the opaque wire objects
# internally (qspgs_facade_server.c, geryon_qsgroups_server.h). Links ONLY the
# common layer; never the client target. Its only optional secret state is
# send/fetch token check state, held by the deployer, not here.
add_library(geryon_qsgroups_server STATIC EXCLUDE_FROM_ALL
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_server.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/qspgs/qspgs_facade_server.c")
target_compile_options(geryon_qsgroups_server PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(geryon_qsgroups_server PRIVATE GY_PRODUCTION_BUILD)
target_link_libraries(geryon_qsgroups_server PUBLIC geryon_qspgs_internal)

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
