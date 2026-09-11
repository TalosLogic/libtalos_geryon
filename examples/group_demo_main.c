/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon classical group example (geryon_group_demo), 25519 tier.  A thin main
 * over the shared group demo driver: it selects the classical geryon_c25519
 * suite; all topology, fork/IPC, the group server, and the lifecycle live in
 * the driver / coordinator / client, unchanged across the two classical tiers.
 */

#include "geryon.h"

#include "group_demo_driver.h"

int
main(void)
{
    return group_demo_run(GY_SUITE_C25519, "/tmp/geryon_group_demo_XXXXXX");
}
