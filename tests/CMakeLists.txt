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
# The 448 validation-gate tests link libdecaf directly, not just geryon_core;
# registered separately below.
list(FILTER GERYON_TEST_SOURCES EXCLUDE REGEX "/test_gate_448")

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

# Classical group vertical tests: link geryon_group, which pulls geryon_core and
# talos_schnorr. The group system is a parallel vertical, so these get their own
# helper rather than geryon_add_test (which links only geryon_core). sodium is
# needed for the same reason as above (core headers expose libsodium types).
function(geryon_add_group_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    # Group tests exercise BOTH roles (client operations and the server-side
    # issue/verify), so they link both facades over the shared internal. A
    # production client links only geryon_group; the nm_scope_server audit checks
    # that client archive carries no server symbol.
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_group geryon_groups_server sodium monocypher)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

file(GLOB GERYON_GROUP_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/group/test_*.c")
# test_group_server.c deliberately links ONLY the server facade (no client), to
# prove the server target is self-contained; register it separately.
list(FILTER GERYON_GROUP_TEST_SOURCES EXCLUDE REGEX "/test_group_server\\.c$")
foreach(test_src ${GERYON_GROUP_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    geryon_add_group_test(${test_name} "${test_src}")
endforeach()

# Standalone server-target test: geryon_groups_server + its shared internal only,
# NOT geryon_group. The link itself proves no server symbol reaches client code.
add_executable(test_group_server "${CMAKE_CURRENT_SOURCE_DIR}/group/test_group_server.c")
target_include_directories(test_group_server PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(test_group_server PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(test_group_server PRIVATE
    GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_group_server PRIVATE
    geryon_groups_server sodium monocypher)
add_test(NAME test_group_server COMMAND $<TARGET_FILE:test_group_server>)

# QSPGS vertical tests: link geryon_qspgs, which pulls geryon_core (and the
# KR-ML-DSA primitives folded into it). The quantum-safe group system is its own
# parallel vertical, so it gets its own helper, mirroring geryon_add_group_test.
function(geryon_add_qspgs_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    # QSPGS tests exercise BOTH roles (the section 5 client operations and the
    # section 7.3 server checks), so they link both facades over the shared
    # internal. A production client links only geryon_qspgs; the
    # nm_scope_qspgs_server audit checks the server archive carries no client
    # symbol.
    target_link_libraries(${TEST_NAME} PRIVATE
        geryon_qspgs geryon_qsgroups_server sodium monocypher)
    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

file(GLOB GERYON_QSPGS_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/qspgs/test_*.c")
# test_qspgs_server.c deliberately links ONLY the server facade (no client), to
# prove the server target is self-contained and stateless; register
# it separately, mirroring test_group_server.
list(FILTER GERYON_QSPGS_TEST_SOURCES EXCLUDE REGEX "/test_qspgs_server\\.c$")
foreach(test_src ${GERYON_QSPGS_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    geryon_add_qspgs_test(${test_name} "${test_src}")
endforeach()

# Standalone server-target test: geryon_qsgroups_server + its shared internal
# only, NOT geryon_qspgs. The link itself proves no client symbol reaches the
# server target (QSPGS_SPEC section 7.1; the nm_scope_qspgs_server audit checks
# the archive statically).
add_executable(test_qspgs_server
    "${CMAKE_CURRENT_SOURCE_DIR}/qspgs/test_qspgs_server.c")
target_include_directories(test_qspgs_server PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(test_qspgs_server PRIVATE ${GERYON_WARNINGS})
target_compile_definitions(test_qspgs_server PRIVATE
    GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_qspgs_server PRIVATE
    geryon_qsgroups_server sodium monocypher)
add_test(NAME test_qspgs_server COMMAND $<TARGET_FILE:test_qspgs_server>)

# The frozen-vector KATs SKIP (exit 77) until captured (QSPGS_KEYS_KAT_POPULATED
# 0), so a fresh checkout reports them "Skipped", not failed.
if(TARGET test_qspgs_vectors)
    set_tests_properties(test_qspgs_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()
if(TARGET test_qspgs_wire_vectors)
    set_tests_properties(test_qspgs_wire_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()

# The frozen-vector KATs SKIP (exit 77) until their vectors are captured
# (GROUP_*_VECTORS_POPULATED 0), so CTest reports them as "Skipped", not failed,
# on a fresh checkout.
if(TARGET test_group_vectors)
    set_tests_properties(test_group_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()
if(TARGET test_group_mac_vectors)
    set_tests_properties(test_group_mac_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()
if(TARGET test_group_stmt_vectors)
    set_tests_properties(test_group_stmt_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()
# Emitter for the independent 255-tier [CPZ] oracle: SKIPs unless run with
# --dump (it produces tests/vectors/group_kvac_255.vec for verify.py, it is not
# a self-checking test). See tools/oracles/group_kvac/.
if(TARGET test_group_kvac_emit)
    set_tests_properties(test_group_kvac_emit PROPERTIES SKIP_RETURN_CODE 77)

    # Shared shim exposing geryon's vendored decaf448 to the Python oracle for
    # the 448 tier (byte-array ops; every decaf struct stays inside C). Built
    # with the test suite so the ctest below can load it; the 255 tier needs
    # only libsodium. Guarded on the decaf448 target, present whenever the group
    # vertical builds.
    set(GK_SHIM_ARG "")
    if(TARGET decaf448)
        add_library(decaf448_shim SHARED
            "${CMAKE_SOURCE_DIR}/tools/oracles/group_kvac/decaf448_shim.c")
        # Pin the output to a stable, documentable path (<build>/decaf448_shim.*)
        # so the manual verify.py command references a literal path, not a
        # find(1) glob. The ctest uses $<TARGET_FILE:...> and needs no path.
        set_target_properties(decaf448_shim PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
        target_link_libraries(decaf448_shim PRIVATE decaf448)
        set(GK_SHIM_ARG "$<TARGET_FILE:decaf448_shim>")
    endif()

    # Optional: regenerate a fresh vector file (both tiers) and verify it with
    # the clean-room Python oracle. Skips (exit 77) when python3 is absent, or
    # per-tier when a backend (libsodium / the decaf shim) is unavailable, so it
    # runs opportunistically and never blocks a toolchain-less CI box.
    add_test(NAME test_group_kvac_oracle
        COMMAND sh
            "${CMAKE_SOURCE_DIR}/tools/oracles/group_kvac/run_ctest.sh"
            "$<TARGET_FILE:test_group_kvac_emit>"
            "${CMAKE_SOURCE_DIR}/tools/oracles/group_kvac/verify.py"
            "${GK_SHIM_ARG}")
    set_tests_properties(test_group_kvac_oracle PROPERTIES
        SKIP_RETURN_CODE 77 LABELS "oracle")
endif()

# 448 validation-gate tests (D-XED-12): exercise libdecaf's RFC 7748
# X448 and RFC 8032 Ed448 primitives DIRECTLY, so they link the decaf448
# archive (and see its public decaf.h via the INTERFACE include). These TUs are
# the ONLY references to decaf_ed448_sign/verify in the tree. Compiled with a
# relaxed warning set (no -Werror): they include external libdecaf headers,
# which are not held to geryon's warning bar. They need no geryon library (the
# harness is header-only), only decaf448.
function(geryon_add_gate448_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_options(${TEST_NAME} PRIVATE -Wall -Wextra)
    target_link_libraries(${TEST_NAME} PRIVATE decaf448)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

geryon_add_gate448_test(test_gate_448
    "${CMAKE_CURRENT_SOURCE_DIR}/core/test_gate_448.c")
geryon_add_gate448_test(test_gate_448_slow
    "${CMAKE_CURRENT_SOURCE_DIR}/core/test_gate_448_slow.c" slow)

# 448 gf-smoke unit: unlike the gate tests above (which use only the
# public decaf.h), this geryon-side TU borrows libdecaf's INTERNAL gf field
# headers via GERYON_DECAF448_INTERNAL_INCLUDES - the exact approach #3 wiring
# src/core/ed448.c uses. Proves the include path + a gf_mul link
# from decaf448. Internal headers are relaxed to -Wall -Wextra (not -Werror).
add_executable(test_gate_448_gf_smoke
    "${CMAKE_CURRENT_SOURCE_DIR}/core/test_gate_448_gf_smoke.c")
target_include_directories(test_gate_448_gf_smoke PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    ${GERYON_DECAF448_INTERNAL_INCLUDES})
target_compile_options(test_gate_448_gf_smoke PRIVATE -Wall -Wextra)
target_link_libraries(test_gate_448_gf_smoke PRIVATE decaf448)
add_test(NAME test_gate_448_gf_smoke
    COMMAND $<TARGET_FILE:test_gate_448_gf_smoke>)

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
    # The recompiled core slice includes the KR-ML-DSA dispatchers
    # (src/core/krmldsa{44,87}.c), which reference the per-backend tables
    # gy_kr<set>_<backend>_backend. Those tables are the krmldsa OBJECT
    # libraries (production geryon_core folds them in); a harness that rebuilds
    # the core slice must link them too, or the dispatchers are undefined.
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${GERYON_CORE_LIB_SOURCES}
        ${GERYON_KRMLDSA_OBJECTS})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/core")
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    # ed448.c (recompiled into this harness via the core glob) borrows
    # libdecaf's internal gf field headers; applied at target level here since
    # the whole core slice is rebuilt into the test (the production geryon_core
    # restricts them to ed448.c alone via set_source_files_properties).
    target_include_directories(${TEST_NAME} PRIVATE
        ${GERYON_DECAF448_INTERNAL_INCLUDES})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    # oqs carries its include dir + archive as usage requirements; sodium and
    # monocypher back the rest of core; decaf448 backs x448.c/ed448.c (its
    # public decaf.h propagates via the INTERFACE include).
    target_link_libraries(${TEST_NAME} PRIVATE sodium monocypher oqs decaf448)
    # ed448.c (in the recompiled core slice) needs libdecaf's generated headers
    # present before it compiles.
    add_dependencies(${TEST_NAME} liboqs_build decaf448_generate)

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

# The KR-ML-DSA frozen self-KATs (D-QGS-10) SKIP (exit 77) until
# their vectors are captured (krmldsa_kat.h KRMLDSA_KAT_POPULATED == 0), same
# mechanism as the tests/group frozen-vector KATs above.  Capture with:
#   ./tests/test_krmldsa_vectors --dump > tests/core_hooks/krmldsa_kat.h
if(TARGET test_krmldsa_vectors)
    set_tests_properties(test_krmldsa_vectors PROPERTIES SKIP_RETURN_CODE 77)
endif()

# KR-ML-DSA sign/verify benchmark (the D-QGS-7 wire-freeze
# gate).  A standalone, manually-run report (the libtalos_voleith examples/
# model, same bench_util.h methodology), NOT a CTest case: timings are advisory
# and machine-specific.  Links geryon_core to reach the internal gy_kr<set>_*
# primitive (no public QSPGS API yet).  Run: ./tests/bench_krmldsa [iters].
add_executable(bench_krmldsa bench/bench_krmldsa.c)
target_include_directories(bench_krmldsa PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/bench")
target_compile_options(bench_krmldsa PRIVATE ${GERYON_WARNINGS})
target_link_libraries(bench_krmldsa PRIVATE geryon_core sodium monocypher)

# QSPGS [CFG+] section 7 operation-cost benchmark: AddMember
# and RemoveMember at representative group sizes, cross-checked against
# the design cost model.  Same standalone / advisory model as
# bench_krmldsa; links the CLIENT facade geryon_qspgs for the section-5
# composition primitives.  Run: ./tests/bench_qspgs_ops [iters].
if(TARGET geryon_qspgs)
    add_executable(bench_qspgs_ops bench/bench_qspgs_ops.c)
    target_include_directories(bench_qspgs_ops PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/bench")
    target_compile_options(bench_qspgs_ops PRIVATE ${GERYON_WARNINGS})
    target_link_libraries(bench_qspgs_ops PRIVATE geryon_qspgs sodium monocypher)
endif()

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
    # As with the core_hooks harness: the recompiled core slice pulls in the
    # KR-ML-DSA dispatchers, so link the per-backend krmldsa OBJECT tables too.
    add_executable(${TEST_NAME} ${TEST_SOURCE}
        ${GERYON_CORE_LIB_SOURCES} ${GERYON_KEX_LIB_SOURCES}
        ${GERYON_RATCHET_LIB_SOURCES} ${GERYON_KRMLDSA_OBJECTS})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/core"
        "${CMAKE_SOURCE_DIR}/src/kex"
        "${CMAKE_SOURCE_DIR}/src/ratchet"
        # ed448.c/x448.c are in the recompiled core slice and need libdecaf's
        # generated headers (word.h/field.h + decaf.h), same as the core_hooks
        # and geryon_core builds.
        ${GERYON_DECAF448_INTERNAL_INCLUDES})
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    target_link_libraries(${TEST_NAME} PRIVATE sodium monocypher oqs decaf448)
    add_dependencies(${TEST_NAME} liboqs_build decaf448_generate)

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

# QSPGS tests that need the client GY_TEST_HOOKS forging seam (qspgs_hooks.h): the
# malicious-admin E5 negative (D-QGS-13 E5)
# needs a validly-signed-but-inconsistent core, which no public API can produce.
# The QSPGS client facade EXTENDS the custodian, so this harness recompiles the
# whole client stack (core + kex + ratchet + session + proto + the QSPGS client
# slice) with -DGY_TEST_HOOKS and links the providers directly, NEVER the prebuilt
# geryon_* libraries (built with GY_PRODUCTION_BUILD, which src/core/error.h makes
# mutually exclusive with GY_TEST_HOOKS).  GY_PRODUCTION_BUILD is not set here.
file(GLOB GERYON_SESSION_LIB_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/session/*.c")
file(GLOB GERYON_PROTO_LIB_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/proto/*.c")
# The QSPGS client slice (the common sk-free codec + the client operations and
# facade); the server sources are not needed by the fetch-side negative.
set(GERYON_QSPGS_CLIENT_SLICE
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_sizes.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_wire.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_keys.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_pers.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_join.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_field.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_ops.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_store.c"
    "${CMAKE_SOURCE_DIR}/src/qspgs/qspgs_facade_client.c")
file(GLOB GERYON_QSPGS_HOOKS_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/qspgs_hooks/test_*.c")

function(geryon_add_qspgs_hooks_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE}
        ${GERYON_CORE_LIB_SOURCES} ${GERYON_KEX_LIB_SOURCES}
        ${GERYON_RATCHET_LIB_SOURCES} ${GERYON_SESSION_LIB_SOURCES}
        ${GERYON_PROTO_LIB_SOURCES} ${GERYON_QSPGS_CLIENT_SLICE}
        ${GERYON_KRMLDSA_OBJECTS})
    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src/core"
        "${CMAKE_SOURCE_DIR}/src/kex"
        "${CMAKE_SOURCE_DIR}/src/ratchet"
        "${CMAKE_SOURCE_DIR}/src/session"
        "${CMAKE_SOURCE_DIR}/src/proto"
        "${CMAKE_SOURCE_DIR}/src/qspgs"
        "${CMAKE_SOURCE_DIR}/include"
        ${GERYON_DECAF448_INTERNAL_INCLUDES})
    target_compile_options(${TEST_NAME} PRIVATE ${GERYON_WARNINGS})
    target_compile_definitions(${TEST_NAME} PRIVATE
        GERYON_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        GY_TEST_HOOKS)
    target_link_libraries(${TEST_NAME} PRIVATE sodium monocypher oqs decaf448)
    add_dependencies(${TEST_NAME} liboqs_build decaf448_generate)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    if(ARGN)
        set_tests_properties(${TEST_NAME} PROPERTIES LABELS "${ARGN}")
    endif()
endfunction()

foreach(test_src ${GERYON_QSPGS_HOOKS_TEST_SOURCES})
    get_filename_component(test_name "${test_src}" NAME_WE)
    if(test_name MATCHES "_slow$")
        geryon_add_qspgs_hooks_test(${test_name} "${test_src}" slow)
    else()
        geryon_add_qspgs_hooks_test(${test_name} "${test_src}")
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

# 448 scope audit (D-XED-12): geryon's own archives must carry no
# reference to the RFC 8032 Ed448 scheme (decaf_ed448_sign/verify); only XEd448
# is production. Build-artifact based, so it takes the geryon library targets as
# generator-expression paths and runs after they build.
add_test(NAME nm_scope_448
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/audit/nm_scope_448.sh"
        "$<TARGET_FILE:geryon_core>"
        "$<TARGET_FILE:geryon_kex>"
        "$<TARGET_FILE:geryon_ratchet>"
        "$<TARGET_FILE:geryon_session>"
        "$<TARGET_FILE:geryon_proto>")
set_tests_properties(nm_scope_448 PROPERTIES LABELS "audit")

# Client/server scope audit (GROUP_SPEC section 8.3): the CLIENT group
# archive must contain no ServerSecretParams-consuming operation. Build-artifact
# based; guarded on the group vertical being configured.
if(TARGET geryon_group)
    add_test(NAME nm_scope_server
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/audit/nm_scope_server.sh"
            "$<TARGET_FILE:geryon_group>")
    set_tests_properties(nm_scope_server PROPERTIES LABELS "audit")
endif()

# QSPGS client/server scope audit (QSPGS_SPEC section 7.1): the
# stateless server archive must carry no client-only symbol and no
# rerandomization internal. Build-artifact based; guarded on the QSPGS server
# target being configured.
if(TARGET geryon_qsgroups_server)
    add_test(NAME nm_scope_qspgs_server
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/audit/nm_scope_qspgs_server.sh"
            "$<TARGET_FILE:geryon_qsgroups_server>")
    set_tests_properties(nm_scope_qspgs_server PROPERTIES LABELS "audit")
endif()

# Dependency-surface audit: geryon's own archives reference no C++
# runtime and no OpenSSL, and a fully linked binary pulls no forbidden shared
# object. Build-artifact based; test_api links the whole stack (all layers +
# sodium + liboqs + libdecaf + monocypher) so its ldd is the runtime link set.
add_test(NAME dependency_surface
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/audit/dependency_surface.sh"
        "$<TARGET_FILE:geryon_core>"
        "$<TARGET_FILE:geryon_kex>"
        "$<TARGET_FILE:geryon_ratchet>"
        "$<TARGET_FILE:geryon_session>"
        "$<TARGET_FILE:geryon_proto>"
        "$<TARGET_FILE:test_api>")
set_tests_properties(dependency_surface PROPERTIES LABELS "audit")
