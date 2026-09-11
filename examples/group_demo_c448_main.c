/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon classical group example (geryon_group_c448_demo), 448 tier.  Same
 * shared group driver as geryon_group_demo, one tier up (Decaf448, SHAKE256
 * Fiat-Shamir), selecting the classical geryon_c448 suite.
 */

#include "geryon.h"

#include "group_demo_driver.h"

int
main(void)
{
    return group_demo_run(GY_SUITE_C448, "/tmp/geryon_group_c448_demo_XXXXXX");
}
