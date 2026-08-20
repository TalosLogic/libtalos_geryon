/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon classical end-to-end example (geryon_demo).  A thin main over the
 * shared demo driver: it selects the classical suite and a per-run temp base;
 * all topology, fork/IPC, and the messaging walkthrough live in demo_driver.c
 * and client.c, unchanged across suites.
 */

#include "geryon.h"

#include "demo_driver.h"

int
main(void)
{
    return demo_run(GY_SUITE_C25519, "/tmp/geryon_demo_XXXXXX");
}
