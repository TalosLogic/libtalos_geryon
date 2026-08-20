/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Shared end-to-end demo driver: the process topology and fork/IPC plumbing,
 * parameterized by cipher suite.  The classical (geryon_demo) and hybrid
 * (geryon_hybrid_demo) binaries are thin mains that differ ONLY in the suite
 * they pass here and their per-run temp base, mirroring the library's design:
 * the suite is pinned at identity creation and the whole messaging path above
 * it is suite-agnostic (D-GEN-9).
 */

#ifndef GERYON_DEMO_DRIVER_H
#define GERYON_DEMO_DRIVER_H

#include <stdint.h>

/*
 * Run the demo under the given GY_SUITE_* value.  base_template is an mkdtemp
 * template ending in "XXXXXX", naming the per-run sealed-store base.  Returns a
 * process exit code: 0 on a clean pass, nonzero on any failure.
 */
int demo_run(uint8_t suite, const char *base_template);

#endif /* GERYON_DEMO_DRIVER_H */
