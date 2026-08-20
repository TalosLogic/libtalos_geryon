# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

# Test executables build into their own directory under the build tree.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

# Helper: create one test executable linked against geryon_core and register
# it with CTest. The shared harness header lives in this directory; vector
# files are located at runtime via GERYON_TEST_SOURCE_DIR. Any extra label
# arguments (e.g. slow) are attached as CTest labels.
function(geryon_add_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    # Link sodium and monocypher explicitly: some core headers (hash.h) expose
    # libsodium types, and a few tests use libsodium point ops or monocypher's
    # crypto_x25519_to_eddsa directly for cross-checks. geryon_core links both
    # PRIVATE, so tests need their own.
    target_link_libraries(${TEST_NAME} PRIVATE geryon_core sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

# One executable + one CTest per tests/core/test_*.c.
file(GLOB GERYON_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/core/test_*.c")

foreach(test_src ${GERYON_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    # test_*_slow.c sources carry iterated/expensive vectors: tag them `slow`
    # so `ctest -LE slow` skips them on the default/merge path.
    if(test_name MATCHES "_slow$")
        geryon_add_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_test(${test_name} "${test_src}")
    endif()
endforeach()

# Core tests that need GY_TEST_HOOKS-only seams (the D-PQ-3 ML-KEM/ML-DSA
# _derand entry points and the pqinit RNG draw-count / fault-injection hooks).
# The production geryon_core is built WITHOUT hooks, so these recompile the core
# sources into the test with -DGY_TEST_HOOKS and link the primitive providers
# directly (sodium, monocypher, oqs) instead of geryon_core, avoiding duplicate
# symbols - the same shape as the kex/ratchet hooked harnesses below.
file(GLOB GERYON_CORE_HOOKS_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/core_hooks/test_*.c")
file(GLOB GERYON_CORE_LIB_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/core/*.c")

function(geryon_add_core_hooks_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_CORE_LIB_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/core")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    # oqs carries its include dir + archive as usage requirements; sodium and
    # monocypher back the rest of core.
    target_link_libraries(${TEST_NAME} PRIVATE sodium monocypher oqs)
    add_dependencies(${TEST_NAME} liboqs_build)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_CORE_HOOKS_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_core_hooks_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_core_hooks_test(${test_name} "${test_src}")
    endif()
endforeach()

# Layer 2 (kex/) tests. These recompile the kex sources directly INTO the test
# executable with -DGY_TEST_HOOKS so the D-X3DH-14 ordering counters are live
# (the production geryon_kex library is built without hooks). They therefore
# link geryon_core, not geryon_kex, to avoid duplicate symbols.
file(GLOB GERYON_KEX_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/kex/test_*.c")
file(GLOB GERYON_KEX_LIB_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/kex/*.c")

function(geryon_add_kex_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_KEX_LIB_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/kex")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    target_link_libraries(${TEST_NAME} PRIVATE geryon_core sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_KEX_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_kex_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_kex_test(${test_name} "${test_src}")
    endif()
endforeach()

# Layer 3 (ratchet/) tests. Recompile the ratchet sources into the test with
# -DGY_TEST_HOOKS (for the KDF exposures and the ratchet-keypair seam) and link
# geryon_kex for the Layer 2 handshake helpers.
file(GLOB GERYON_RATCHET_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/ratchet/test_*.c")
file(GLOB GERYON_RATCHET_LIB_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/ratchet/*.c")
# Test-only two-party harness, compiled into every ratchet test.
file(GLOB GERYON_HARNESS_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/harness/*.c")

function(geryon_add_ratchet_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_RATCHET_LIB_SOURCES}
        ${GERYON_HARNESS_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/harness"
        "${CMAKE_SOURCE_DIR}/src/ratchet"
        "${CMAKE_SOURCE_DIR}/src/kex")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_kex geryon_core sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_RATCHET_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_ratchet_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_ratchet_test(${test_name} "${test_src}")
    endif()
endforeach()

# Ratchet tests that ALSO need core GY_TEST_HOOKS seams (the ML-KEM _derand
# entry points, for cross-run-deterministic hybrid frame KATs).  Like the
# core_hooks harness, these recompile the core + kex + ratchet sources into the
# test with -DGY_TEST_HOOKS and link the providers directly, NEVER the prebuilt
# geryon_* libraries (which are built without hooks and with GY_PRODUCTION_BUILD,
# so no test-only symbol can enter the shipped library - src/core/error.h
# enforces that these two macros never coexist).  GY_PRODUCTION_BUILD is
# deliberately not set here.
file(GLOB GERYON_RATCHET_HOOKS_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/ratchet_hooks/test_*.c")

function(geryon_add_ratchet_hooks_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE}
        ${GERYON_CORE_LIB_SOURCES} ${GERYON_KEX_LIB_SOURCES}
        ${GERYON_RATCHET_LIB_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/core"
        "${CMAKE_SOURCE_DIR}/src/kex"
        "${CMAKE_SOURCE_DIR}/src/ratchet")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    target_link_libraries(${TEST_NAME} PRIVATE sodium monocypher oqs)
    add_dependencies(${TEST_NAME} liboqs_build)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_RATCHET_HOOKS_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_ratchet_hooks_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_ratchet_hooks_test(${test_name} "${test_src}")
    endif()
endforeach()

# Layer 4 (session/) tests. Link the session library (no test hooks needed);
# geryon_session re-exports the ratchet/kex/core includes transitively.
file(GLOB GERYON_SESSION_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/session/test_*.c")

function(geryon_add_session_test TEST_NAME TEST_SOURCE)
    # The two-party harness (gy_sim) is compiled in so send/receive tests can
    # drive a real peer; it uses only the public ratchet API.
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_HARNESS_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/harness"
        "${CMAKE_SOURCE_DIR}/src/ratchet"
        "${CMAKE_SOURCE_DIR}/src/kex")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_session geryon_ratchet geryon_kex geryon_core sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_SESSION_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_session_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_session_test(${test_name} "${test_src}")
    endif()
endforeach()

# Layer 5 (proto/) tests. Link geryon_proto plus the harness (gy_sim) for a
# real bundle source; the seam test reaches gy_bundle_validate through kex/.
file(GLOB GERYON_PROTO_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/proto/test_*.c")

function(geryon_add_proto_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_HARNESS_SOURCES})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/harness"
        "${CMAKE_SOURCE_DIR}/src/ratchet"
        "${CMAKE_SOURCE_DIR}/src/kex")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_proto geryon_session geryon_ratchet geryon_kex geryon_core
        sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_PROTO_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    # test_*_slow.c sources carry iterated/expensive vectors (e.g. real
    # Argon2id derivations): tag them `slow` so `ctest -LE slow`
    # skips them on the default/merge path, matching every other layer above.
    if(test_name MATCHES "_slow$")
        geryon_add_proto_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_proto_test(${test_name} "${test_src}")
    endif()
endforeach()

# Public-API integration tests: driven through include/geryon.h
# ONLY, over the reference apistore. The _slow soaks carry the slow label.
file(GLOB GERYON_API_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/api/test_*.c")

function(geryon_add_api_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE}
        "${CMAKE_CURRENT_SOURCE_DIR}/api/apistore.c")
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/api"
        "${CMAKE_SOURCE_DIR}/include")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_proto geryon_session geryon_ratchet geryon_kex geryon_core
        sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_API_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_api_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_api_test(${test_name} "${test_src}")
    endif()
endforeach()

# Descriptor-discipline audit (D-GEN-7): a scripted grep over kex/
# and ratchet/, no build artifact.  Runs on the default path (it is fast and
# has no dependencies).
add_test(NAME descriptor_discipline
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/audit/descriptor_discipline.sh"
        "${CMAKE_SOURCE_DIR}/src")
set_tests_properties(descriptor_discipline PROPERTIES LABELS "audit")
