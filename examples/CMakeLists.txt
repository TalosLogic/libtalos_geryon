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

# The classical 448 twin: same sources, geryon_c448 selected in c448_main.c.
# Being classical, it exercises the same path as
# geryon_demo, one tier up (X448 + XEd448, SHA-512).
add_executable(geryon_c448_demo c448_main.c ${GERYON_DEMO_COMMON_SRC})
target_link_libraries(geryon_c448_demo PRIVATE geryon)
target_compile_options(geryon_c448_demo PRIVATE ${GERYON_WARNINGS})

# The highest-strength hybrid twin: same sources, geryon_h448_1024 selected in
# h448_1024_main.c (X448 + ML-KEM-1024, XEd448 + ML-DSA-87, SHA-512).  Runs the
# same hybrid walkthrough as geryon_hybrid_demo, one tier up.
add_executable(geryon_h448_1024_demo h448_1024_main.c ${GERYON_DEMO_COMMON_SRC})
target_link_libraries(geryon_h448_1024_demo PRIVATE geryon)
target_compile_options(geryon_h448_1024_demo PRIVATE ${GERYON_WARNINGS})

# Deterministic pass/fail: exit 0 is a pass, nonzero a fail.  Non-interactive,
# network-free, bounded runtime, so it can be dropped into CI unchanged.
add_test(NAME demo COMMAND geryon_demo)
add_test(NAME hybrid_demo COMMAND geryon_hybrid_demo)
add_test(NAME c448_demo COMMAND geryon_c448_demo)
add_test(NAME h448_1024_demo COMMAND geryon_h448_1024_demo)

# Fail-closed check: with GERYON_DEMO_FAULT set, an injected corruption must make
# the demo exit nonzero.  A passing run here is a FAILED test (the demo did not
# fail closed), so the expectation is inverted.
add_test(NAME hybrid_demo_fault COMMAND geryon_hybrid_demo)
set_tests_properties(hybrid_demo_fault PROPERTIES
    ENVIRONMENT "GERYON_DEMO_FAULT=1" WILL_FAIL TRUE)
add_test(NAME c448_demo_fault COMMAND geryon_c448_demo)
set_tests_properties(c448_demo_fault PROPERTIES
    ENVIRONMENT "GERYON_DEMO_FAULT=1" WILL_FAIL TRUE)
add_test(NAME h448_1024_demo_fault COMMAND geryon_h448_1024_demo)
set_tests_properties(h448_1024_demo_fault PROPERTIES
    ENVIRONMENT "GERYON_DEMO_FAULT=1" WILL_FAIL TRUE)

# Build hygiene: the examples must include only the public geryon.h and their
# own demo-local headers, never an internal library header.  One check covers
# every examples/ source, classical and hybrid alike.
add_test(NAME demo_include_check
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/demo_headers_check.sh"
               "${CMAKE_CURRENT_SOURCE_DIR}")

# -----------------------------------------------------------------------------
# The GROUP worked example: a multi-process (GRP_NMEMBERS members + an untrusted
# coordinator-server) lifecycle over the PUBLIC group API (geryon_group.h /
# geryon_group_server.h) with real pairwise M0-M7 sessions.  Reuses the pure
# infra (demo_ipc.c, filestore.c) from the messaging demo; all group-specific
# code lives in its own sources.  One binary per classical tier.
set(GERYON_GROUP_DEMO_COMMON_SRC
    group_demo_driver.c
    group_coordinator.c
    group_client.c
    demo_ipc.c
    filestore.c)

add_executable(geryon_group_demo group_demo_main.c ${GERYON_GROUP_DEMO_COMMON_SRC})
target_link_libraries(geryon_group_demo PRIVATE
    geryon geryon_group geryon_groups_server)
target_compile_options(geryon_group_demo PRIVATE ${GERYON_WARNINGS})

add_executable(geryon_group_c448_demo group_demo_c448_main.c
    ${GERYON_GROUP_DEMO_COMMON_SRC})
target_link_libraries(geryon_group_c448_demo PRIVATE
    geryon geryon_group geryon_groups_server)
target_compile_options(geryon_group_c448_demo PRIVATE ${GERYON_WARNINGS})

add_test(NAME group_demo COMMAND geryon_group_demo)
add_test(NAME group_c448_demo COMMAND geryon_group_c448_demo)
