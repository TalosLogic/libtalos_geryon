/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon quantum-safe group example (geryon_qsgroup_demo), 25519 hybrid tier.
 * A thin main over the shared QSPGS demo driver: it selects the hybrid
 * geryon_h25519_512 suite (X25519 + ML-KEM-512, XEdDSA + ML-DSA-44); all
 * topology, fork/IPC, the coordinator, and the lifecycle live in the driver /
 * coordinator / client, unchanged across the two hybrid tiers.
 */

#include "geryon.h"

#include "qsgroup_demo_driver.h"

int
main(void)
{
    return qsgroup_demo_run(GY_SUITE_H25519_512,
                            "/tmp/geryon_qsgroup_demo_XXXXXX");
}
