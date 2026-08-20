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
    dudect_main.c
)
target_include_directories(geryon_dudect PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(geryon_dudect PRIVATE ${GERYON_WARNINGS})
# geryon_ratchet resolves the DR/X3DH targets and re-exports geryon_kex +
# geryon_core (the gy_* wrappers); sodium/monocypher back them, and libm
# supplies sqrt() for the t-statistic (Linux needs -lm explicitly).  oqs backs
# the ML-KEM/ML-DSA the hybrid X3DH responder target reaches (it does not
# propagate transitively through geryon_ratchet, same as the test harnesses).
target_link_libraries(geryon_dudect PRIVATE geryon_ratchet sodium monocypher oqs)
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
