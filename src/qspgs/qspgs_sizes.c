/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * QSPGS suite-size helpers (QSPGS_SPEC.md section 2.2 sizes, D-QGS-11 item 6):
 * pure suite_id -> byte-length lookups over the frozen tier constants.  They
 * carry no secret and no rerandomization, so they live in the sk-free common
 * layer (geryon_qspgs_internal): the section 4 wire codecs (qspgs_wire.c, e.g.
 * the ACCT record) size their fields with these, and both the client and server
 * facades reach them through the common layer.  Declared in qspgs_keys.h.
 */

#include "qspgs_keys.h"

#include "encode.h" /* GY_SUITE_* */
#include "suite.h"

size_t
gy_qspgs_master_key_len(uint8_t suite_id)
{
    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return GY_QSPGS_MASTER_KEY_255;
    case GY_SUITE_H448_1024:
        return GY_QSPGS_MASTER_KEY_448;
    default:
        return 0;
    }
}

size_t
gy_qspgs_base_vkb_len(uint8_t suite_id)
{
    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return GY_KR44_VKB;
    case GY_SUITE_H448_1024:
        return GY_KR87_VKB;
    default:
        return 0;
    }
}

size_t
gy_qspgs_base_skb_len(uint8_t suite_id)
{
    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return GY_KR44_SKB;
    case GY_SUITE_H448_1024:
        return GY_KR87_SKB;
    default:
        return 0;
    }
}
