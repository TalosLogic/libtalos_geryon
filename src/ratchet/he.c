/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "he.h"

#define GY_INFO_MAX 48

#ifdef GY_TEST_HOOKS
int (*gy_he_test_salt)(uint8_t *out, size_t n);
#endif

/* Fill the 16-byte header salt, honoring the test seam when present. */
static int
gen_salt(uint8_t out[GY_HE_SALT_LEN])
{
#ifdef GY_TEST_HOOKS
    if (gy_he_test_salt != NULL)
        return gy_he_test_salt(out, GY_HE_SALT_LEN);
#endif
    return gy_random_bytes(out, GY_HE_SALT_LEN);
}

/*
 * Header AEAD key/nonce (D-DR-15):
 *   key || nonce = KDF-CTR(hk, Label = INFO("he.aead"),
 *                          Context = aead_id || hdr_salt, L = 32 + nonce_len)
 * split into key || nonce.  hk is the KDF key only, never the AEAD key.
 */
static int
he_derive(const struct gy_suite_desc *desc, uint8_t aead_id,
          const uint8_t hk[32], const uint8_t salt[GY_HE_SALT_LEN],
          uint8_t *key, uint8_t *nonce, size_t *nonce_len)
{
    uint8_t info[GY_INFO_MAX];
    uint8_t ctx[1 + GY_HE_SALT_LEN];
    uint8_t buf[32 + GY_AEAD_MAX_NONCE];
    size_t infolen, nl;
    int rc;

    nl = gy_aead_nonce_len(aead_id);
    if (nl == 0)
        return GY_ERR_UNSUPPORTED;

    ctx[0] = aead_id;
    memcpy(ctx + 1, salt, GY_HE_SALT_LEN);

    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, "he.aead");
    if (rc != GY_OK)
        return rc;
    rc =
        gy_kdf_ctr(desc, buf, 32 + nl, hk, 32, info, infolen, ctx, sizeof(ctx));
    if (rc != GY_OK) {
        gy_secure_zero(buf, sizeof(buf));
        return rc;
    }

    memcpy(key, buf, 32);
    memcpy(nonce, buf + 32, nl);
    *nonce_len = nl;
    gy_secure_zero(buf, sizeof(buf));
    return GY_OK;
}

int
gy_he_encrypt(const struct gy_suite_desc *desc, uint8_t aead_id,
              const uint8_t hk[32], const uint8_t *header, size_t hlen,
              const uint8_t ad2[2], uint8_t out_salt[16], uint8_t *out_enc,
              size_t cap, size_t *out_len)
{
    uint8_t key[32], nonce[GY_AEAD_MAX_NONCE], salt[GY_HE_SALT_LEN];
    size_t nl, enclen, taglen;
    int rc;

    if (desc == NULL || hk == NULL || (header == NULL && hlen) || ad2 == NULL ||
        out_salt == NULL || out_enc == NULL || out_len == NULL)
        return GY_ERR_ARG;

    taglen = gy_aead_tag_len(aead_id);
    if (taglen == 0)
        return GY_ERR_UNSUPPORTED;
    if (cap < hlen + taglen)
        return GY_ERR_ARG;

    rc = gen_salt(salt);
    if (rc != GY_OK)
        return rc;

    rc = he_derive(desc, aead_id, hk, salt, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;

    enclen = cap;
    rc = gy_aead_encrypt(aead_id, out_enc, &enclen, key, nonce, nl, ad2, 2,
                         header, hlen);
    if (rc != GY_OK)
        goto out;

    memcpy(out_salt, salt, GY_HE_SALT_LEN);
    *out_len = enclen;

out:
    gy_secure_zero(key, sizeof(key));
    gy_secure_zero(nonce, sizeof(nonce));
    gy_secure_zero(salt, sizeof(salt));
    return rc;
}

int
gy_he_decrypt(const struct gy_suite_desc *desc, uint8_t aead_id,
              const uint8_t hk[32], const uint8_t salt[16], const uint8_t *enc,
              size_t elen, const uint8_t ad2[2], uint8_t *out_header,
              size_t cap, size_t *out_len)
{
    uint8_t key[32], nonce[GY_AEAD_MAX_NONCE];
    size_t nl, hlen, taglen;
    int rc;

    if (desc == NULL || hk == NULL || salt == NULL || (enc == NULL && elen) ||
        ad2 == NULL || out_header == NULL || out_len == NULL)
        return GY_ERR_ARG;

    taglen = gy_aead_tag_len(aead_id);
    if (taglen == 0)
        return GY_ERR_UNSUPPORTED;
    if (elen < taglen)
        return GY_ERR_VERIFY;

    rc = he_derive(desc, aead_id, hk, salt, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;

    hlen = cap;
    rc = gy_aead_decrypt(aead_id, out_header, &hlen, key, nonce, nl, ad2, 2,
                         enc, elen);
    if (rc != GY_OK)
        goto out;

    *out_len = hlen;

out:
    gy_secure_zero(key, sizeof(key));
    gy_secure_zero(nonce, sizeof(nonce));
    return rc;
}

#ifdef GY_TEST_HOOKS
int
gy_he_derive(const struct gy_suite_desc *desc, uint8_t aead_id,
             const uint8_t hk[32], const uint8_t salt[16], uint8_t *key,
             uint8_t *nonce, size_t *nonce_len)
{
    return he_derive(desc, aead_id, hk, salt, key, nonce, nonce_len);
}
#endif
