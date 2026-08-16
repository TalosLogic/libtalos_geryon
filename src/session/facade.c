/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Session-layer facade: thin re-exports of the suite table, key
 * generation, and secure-zero for the public API, so proto/ reaches them
 * through session/ rather than referencing core/ or kex/ directly.
 */

#include "facade.h"

int
gy_runtime_init(void)
{
    return gy_core_init();
}

const struct gy_suite_desc *
gy_suite_lookup(uint8_t suite_id)
{
    return gy_suite_desc(suite_id);
}

int
gy_identity_generate(const struct gy_suite_desc *desc, struct gy_keypair *ik)
{
    if (desc == NULL || ik == NULL)
        return GY_ERR_ARG;
    return gy_keypair_generate(desc, ik);
}

int
gy_signed_prekey_generate(const struct gy_suite_desc *desc,
                          struct gy_signed_prekey *spk,
                          const uint8_t *identity_sk, uint64_t timestamp)
{
    if (desc == NULL || spk == NULL || identity_sk == NULL)
        return GY_ERR_ARG;
    return gy_spk_create(desc, spk, identity_sk, timestamp);
}

int
gy_opk_generate(const struct gy_suite_desc *desc, struct gy_keypair *out,
                size_t n, const uint32_t *existing, size_t n_existing)
{
    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    return gy_opk_batch(desc, out, n, existing, n_existing);
}

void
gy_wipe(void *p, size_t n)
{
    if (p != NULL)
        gy_secure_zero(p, n);
}

void *
gy_guarded_alloc(size_t n)
{
    return gy_secure_alloc(n);
}

void
gy_guarded_free(void *p)
{
    gy_secure_free(p);
}

uint8_t
gy_default_aead(const struct gy_suite_desc *desc)
{
    (void)desc;
    return GY_AEAD_CHACHA20POLY1305;
}

int
gy_suite_info(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
              const char *purpose)
{
    return gy_info(out, cap, outlen, suite_id, purpose);
}
