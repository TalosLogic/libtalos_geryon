# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# The geryon end-to-end example.  One executable, linking ONLY the
# public `geryon` interface target (which carries include/geryon.h); the demo
# includes no internal header.  The coordinator holds no custodian by
# construction.  The example builds the fork/IPC skeleton; later stages add
# the custodian, publish/fetch, and messaging flows.

add_executable(geryon_demo
    main.c
    coordinator.c
    client.c
    filestore.c
    demo_ipc.c
)

# The example may use plain memcmp and its own logging, but it links only the
# public library surface.
target_link_libraries(geryon_demo PRIVATE geryon)
target_compile_options(geryon_demo PRIVATE ${GERYON_WARNINGS})

# Deterministic pass/fail: exit 0 is a pass, nonzero a fail.  Non-interactive,
# network-free, bounded runtime, so it can be dropped into CI unchanged.
add_test(NAME demo COMMAND geryon_demo)

# Build hygiene: the example must include only the public
# geryon.h and its own demo-local headers, never an internal library header.
add_test(NAME demo_include_check
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/demo_headers_check.sh"
               "${CMAKE_CURRENT_SOURCE_DIR}")
