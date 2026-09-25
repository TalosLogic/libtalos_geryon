# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# dudect-style timing-validation harness.  Built only when
# -DGERYON_BUILD_TIMING=ON, so it stays out of the default build and the merge
# gate entirely.  The nightly/manual CI job configures with that option and
# runs `ctest -L timing`, which drives the bounded --selftest.

add_executable(geryon_dudect
    dudect_timer.c
    dudect_platform.c
    dudect_runner.c
    targets_core.c
    targets_ratchet.c
    targets_he.c
    targets_gate448.c
    targets_c448.c
    targets_group.c
    targets_group_server.c
    targets_qspgs.c
    dudect_main.c
)
target_include_directories(geryon_dudect PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/src/group")
target_compile_options(geryon_dudect PRIVATE ${GERYON_WARNINGS})
# targets_gate448.c includes external libdecaf headers (via decaf448), which are
# not held to geryon's -Werror bar; relax just that one TU.
set_source_files_properties(targets_gate448.c PROPERTIES
    COMPILE_OPTIONS "-Wno-error")
# geryon_ratchet resolves the DR/X3DH targets and re-exports geryon_kex +
# geryon_core (the gy_* wrappers); sodium/monocypher back them, and libm
# supplies sqrt() for the t-statistic (Linux needs -lm explicitly).  oqs backs
# the ML-KEM/ML-DSA the hybrid X3DH responder target reaches (it does not
# propagate transitively through geryon_ratchet, same as the test harnesses).
target_link_libraries(geryon_dudect PRIVATE geryon_ratchet sodium monocypher oqs)
# decaf448 backs the raw-primitive X448 timing target (targets_gate448.c);
# it does not propagate through geryon_ratchet (linked PRIVATE into geryon_core).
target_link_libraries(geryon_dudect PRIVATE decaf448)
# geryon_group backs the section 6 ProfileKey-decrypt CT target
# (targets_group.c); it is a separate vertical (EXCLUDE_FROM_ALL) and pulls in
# talos_schnorr, so link it explicitly. geryon_groups_server backs the section
# 8.4 secret-keyed server targets (targets_group_server.c: issuance, blind
# issuance, presentation-verify Z-recompute).
target_link_libraries(geryon_dudect PRIVATE geryon_group geryon_groups_server)
# The QSPGS / KR-ML-DSA secret-handling targets (targets_qspgs.c, SEC-v1.5.0
# LOW-5): geryon_qspgs resolves the client field read path
# (gy_qspgs_member_ct_open) and the KR-ML-DSA glue (via geryon_core), and
# geryon_qsgroups_server resolves the section 7.3 bearer-token check.  Both are
# EXCLUDE_FROM_ALL verticals, so link them explicitly (mirroring the group
# targets above); they carry the src/qspgs include dir transitively.
target_link_libraries(geryon_dudect PRIVATE geryon_qspgs geryon_qsgroups_server)
add_dependencies(geryon_dudect liboqs_build)
if(NOT APPLE)
    target_link_libraries(geryon_dudect PRIVATE m)
endif()

set_target_properties(geryon_dudect PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/timing")

# The only CTest-registered path: the bounded self-check that proves the
# harness detects a leak.  Labelled `timing` so the merge job (ctest -LE slow)
# skips it unless the harness was built in.
add_test(NAME timing_selftest
    COMMAND geryon_dudect --selftest --no-pin)
set_tests_properties(timing_selftest PROPERTIES LABELS "timing")
