/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_GROUP_DEMO_DRIVER_H
#define GERYON_GROUP_DEMO_DRIVER_H

#include <stdint.h>

/*
 * Run the group worked example for one classical suite (GY_SUITE_C25519 or
 * GY_SUITE_C448).  Forks GRP_NMEMBERS members under an untrusted coordinator
 * that also plays the group server.  Deterministic: returns 0 on a full clean
 * run, nonzero on any failure.  base_template is an mkdtemp template for the
 * per-run sealed-store area.
 */
int group_demo_run(uint8_t suite, const char *base_template);

#endif /* GERYON_GROUP_DEMO_DRIVER_H */
