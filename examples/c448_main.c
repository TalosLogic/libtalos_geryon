/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon classical 448 end-to-end example (geryon_c448_demo).  A thin main over
 * the shared demo driver, identical to the classical geryon_demo except that it
 * pins the higher-strength classical suite geryon_c448 (X448 + XEd448, SHA-512).
 * That single change is all a consumer makes to run the entire messaging
 * walkthrough at the 448 tier: the suite is pinned at identity creation and
 * every call above it is suite-agnostic (D-GEN-9).  Being classical, c448 takes
 * the same path as geryon_c25519 - it carries no ML-KEM refresh and reports
 * gy_pq_pending as GY_PQ_NOT_APPLICABLE.
 */

#include "geryon.h"

#include "demo_driver.h"

int
main(void)
{
    return demo_run(GY_SUITE_C448, "/tmp/geryon_c448_demo_XXXXXX");
}
