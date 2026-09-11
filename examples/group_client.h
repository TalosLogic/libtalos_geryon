/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_GROUP_CLIENT_H
#define GERYON_GROUP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

/* One group member: a gy_custodian plus the gy_group client, over a sealed
 * file store, talking to the coordinator across one pipe pair. */
struct grp_client_cfg {
    const char *name; /* logical relay name, "m1".."m5", or "m2b" (companion) */
    int index;        /* member index 0..GRP_NMEMBERS-1 (the UID this process
                         * speaks for; a companion shares its member's index) */
    int role;         /* GRP_ROLE_FOUNDER / GRP_ROLE_MEMBER */
    const char *dir;  /* sealed-store directory */
    const char *secret;       /* custodian credential */
    uint8_t suite;            /* GY_SUITE_C25519 / GY_SUITE_C448 */
    const uint8_t *device_id; /* THIS process's own device id (GRP_DEV_A/B) */
    size_t device_id_len;
    int companion; /* 1 = a member's SECOND device: joins the messaging mesh and
                    * receives, but performs no KVAC credential/roster ops */
};

int grp_client_run(const struct grp_client_cfg *cfg, int rfd, int wfd);

#endif /* GERYON_GROUP_CLIENT_H */
