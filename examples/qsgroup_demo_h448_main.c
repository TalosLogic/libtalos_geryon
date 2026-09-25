/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon quantum-safe group example (geryon_qsgroup_h448_demo), 448 hybrid
 * tier.  Same shared QSPGS driver as geryon_qsgroup_demo, one tier up: the
 * hybrid geryon_h448_1024 suite (X448 + ML-KEM-1024, XEd448 + ML-DSA-87).
 */

#include "geryon.h"

#include "qsgroup_demo_driver.h"

int
main(void)
{
    return qsgroup_demo_run(GY_SUITE_H448_1024,
                            "/tmp/geryon_qsgroup_h448_demo_XXXXXX");
}
