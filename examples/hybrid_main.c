/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon hybrid end-to-end example (geryon_hybrid_demo).  A thin main over the
 * shared demo driver, identical to the classical geryon_demo except that it
 * pins the post-quantum-hybrid suite geryon_h25519_512 (X25519 + ML-KEM-512,
 * XEdDSA + ML-DSA-44).  That single change is all a consumer makes to run the
 * entire messaging walkthrough under hybrid: the suite is pinned at identity
 * creation and every call above it is suite-agnostic (D-GEN-9).  The hybrid-only
 * surfaces (gy_pq_pending advancing PENDING -> CONFIRMED, the dual XEdDSA +
 * ML-DSA signed bundle, and a Double Ratchet run crossing an ML-KEM refresh
 * boundary) are exercised inside client.c under this suite.
 */

#include "geryon.h"

#include "demo_driver.h"

int
main(void)
{
    return demo_run(GY_SUITE_H25519_512, "/tmp/geryon_hybrid_demo_XXXXXX");
}
