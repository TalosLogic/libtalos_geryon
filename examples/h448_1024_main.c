/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon highest-strength hybrid end-to-end example (geryon_h448_1024_demo).  A
 * thin main over the shared demo driver, identical to the classical geryon_demo
 * except that it pins the top hybrid suite geryon_h448_1024 (X448 +
 * ML-KEM-1024, XEd448 + ML-DSA-87, SHA-512).  That single change is all a
 * consumer makes to run the entire messaging walkthrough at the highest tier:
 * the suite is pinned at identity creation and every call above it is
 * suite-agnostic (D-GEN-9).  The hybrid-only surfaces (gy_pq_pending advancing
 * PENDING -> CONFIRMED, the dual XEd448 + ML-DSA-87 signed bundle, and a Double
 * Ratchet run crossing an ML-KEM refresh boundary) are exercised inside
 * client.c under this suite, exactly as for geryon_h25519_512 one tier down.
 */

#include "geryon.h"

#include "demo_driver.h"

int
main(void)
{
    return demo_run(GY_SUITE_H448_1024, "/tmp/geryon_h448_1024_demo_XXXXXX");
}
