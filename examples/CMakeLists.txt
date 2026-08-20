# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# The geryon end-to-end example.  One executable, linking ONLY the
# public `geryon` interface target (which carries include/geryon.h); the demo
# includes no internal header.  The coordinator holds no custodian by
# construction.  The example builds the fork/IPC skeleton; later stages add
# the custodian, publish/fetch, and messaging flows.

# Shared demo sources: everything except the thin, suite-selecting main.  The
# classical (geryon_demo) and hybrid (geryon_hybrid_demo) binaries differ only
# in their main; the driver, client walkthrough, coordinator, store, and IPC are
# identical, mirroring the library's suite-agnostic messaging path (D-GEN-9).
set(GERYON_DEMO_COMMON_SRC
    demo_driver.c
    coordinator.c
    client.c
    filestore.c
    demo_ipc.c
)

add_executable(geryon_demo main.c ${GERYON_DEMO_COMMON_SRC})

# The example may use plain memcmp and its own logging, but it links only the
# public library surface.
target_link_libraries(geryon_demo PRIVATE geryon)
target_compile_options(geryon_demo PRIVATE ${GERYON_WARNINGS})

# The hybrid twin: same sources, hybrid suite selected in hybrid_main.c.
add_executable(geryon_hybrid_demo hybrid_main.c ${GERYON_DEMO_COMMON_SRC})
target_link_libraries(geryon_hybrid_demo PRIVATE geryon)
target_compile_options(geryon_hybrid_demo PRIVATE ${GERYON_WARNINGS})

# Deterministic pass/fail: exit 0 is a pass, nonzero a fail.  Non-interactive,
# network-free, bounded runtime, so it can be dropped into CI unchanged.
add_test(NAME demo COMMAND geryon_demo)
add_test(NAME hybrid_demo COMMAND geryon_hybrid_demo)

# Fail-closed check: with GERYON_DEMO_FAULT set, an injected corruption must make
# the demo exit nonzero.  A passing run here is a FAILED test (the demo did not
# fail closed), so the expectation is inverted.
add_test(NAME hybrid_demo_fault COMMAND geryon_hybrid_demo)
set_tests_properties(hybrid_demo_fault PROPERTIES
    ENVIRONMENT "GERYON_DEMO_FAULT=1" WILL_FAIL TRUE)

# Build hygiene: the examples must include only the public geryon.h and their
# own demo-local headers, never an internal library header.  One check covers
# every examples/ source, classical and hybrid alike.
add_test(NAME demo_include_check
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/demo_headers_check.sh"
               "${CMAKE_CURRENT_SOURCE_DIR}")
