/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_QSGROUP_DEMO_DRIVER_H
#define GERYON_QSGROUP_DEMO_DRIVER_H

#include <stdint.h>

/*
 * Run the quantum-safe group worked example for one HYBRID suite
 * (GY_SUITE_H25519_512 or GY_SUITE_H448_1024).  Forks QSG_NMEMBERS members
 * under an untrusted coordinator (relay + opaque object store).  Deterministic:
 * returns 0 on a full clean run, nonzero on any failure.  base_template is an
 * mkdtemp template for the per-run sealed-store area.
 */
int qsgroup_demo_run(uint8_t suite, const char *base_template);

#endif /* GERYON_QSGROUP_DEMO_DRIVER_H */
