/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_keys.h"

#include "qspgs_labels.h"

#include "encode.h" /* gy_info */
#include "error.h"
#include "suite.h" /* gy_suite_desc, struct gy_iov, GY_HASH_MAX */
#include "util.h"

/*
 * The QSPGS key-hierarchy derivations.  Every step is the
 * extract-then-expand HKDF frozen in qspgs_keys.h; the KR-ML-DSA base-pair
 * primitives provide the pseudonym keys.  No polynomial or curve
 * arithmetic lives here: symmetric derivations go through the suite descriptor's
 * tier HKDF, pseudonym keys through gy_kr<set>_randvk / randsk.
 */

/* Longest gy_info domain: "geryon.1." (9) + "geryon_h448_1024" (16) + "." (1)
 * + "qspgs-rerand" (12) = 38; rounded up. */
#define QSPGS_DOMAIN_MAX 48

/* domain || var, where var is at most a 1-byte length prefix plus UID_MAX. */
#define QSPGS_INFO_MAX (QSPGS_DOMAIN_MAX + 1 + GY_QSPGS_UID_MAX)

static void
put_be64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

/*
 * gy_qspgs_master_key_len and gy_qspgs_base_vkb_len (pure suite-size lookups)
 * live in the sk-free common layer (qspgs_sizes.c) so the section 4 wire codecs
 * can size ACCT fields without linking the client; the client reaches them
 * through geryon_qspgs_internal.  Declared in qspgs_keys.h.
 */

int
gy_qspgs_base_keygen(uint8_t suite_id, uint8_t *vkb, uint8_t *skb)
{
    if (vkb == NULL || skb == NULL)
        return GY_ERR_ARG;

    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return gy_kr44_keygen_base(vkb, skb);
    case GY_SUITE_H448_1024:
        return gy_kr87_keygen_base(vkb, skb);
    default:
        return GY_ERR_ARG;
    }
}

int
gy_qspgs_base_keygen_seed(uint8_t suite_id, uint8_t *vkb, uint8_t *skb,
                          const uint8_t *seed)
{
    if (vkb == NULL || skb == NULL || seed == NULL)
        return GY_ERR_ARG;

    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return gy_kr44_keygen_base_seed(vkb, skb, seed);
    case GY_SUITE_H448_1024:
        return gy_kr87_keygen_base_seed(vkb, skb, seed);
    default:
        return GY_ERR_ARG;
    }
}

/*
 * One [CFG+] KDF(key, label[|| var]) step: PRK = Extract(salt = domain,
 * ikm = key); out = Expand(PRK, info = domain || var).  info == domain when
 * varlen is 0.  domain must be the first dlen bytes of info.
 */
static int
qspgs_kdf(const struct gy_suite_desc *desc, const uint8_t *domain, size_t dlen,
          const uint8_t *key, size_t keylen, const uint8_t *info,
          size_t infolen, uint8_t *out, size_t outlen)
{
    uint8_t prk[GY_HASH_MAX];
    struct gy_iov ikm;
    int rc;

    ikm.p = key;
    ikm.len = keylen;

    rc = desc->hkdf_extract(prk, domain, dlen, &ikm, 1);
    if (rc != GY_OK)
        goto out;
    rc = desc->hkdf_expand(out, outlen, prk, info, infolen);

out:
    gy_secure_zero(prk, sizeof(prk));
    return rc;
}

/*
 * Resolve suite_id to (desc, master_key_len) for a hybrid suite, building the
 * gy_info domain for purpose into domain / *dlen.  Returns GY_ERR_ARG for a
 * non-hybrid suite.
 */
static int
qspgs_prepare(uint8_t suite_id, const char *purpose,
              const struct gy_suite_desc **descp, size_t *mklen,
              uint8_t domain[QSPGS_DOMAIN_MAX], size_t *dlen)
{
    const struct gy_suite_desc *desc;
    size_t n;

    n = gy_qspgs_master_key_len(suite_id);
    if (n == 0)
        return GY_ERR_ARG;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    *descp = desc;
    *mklen = n;
    return gy_info(domain, QSPGS_DOMAIN_MAX, dlen, suite_id, purpose);
}

int
gy_qspgs_derive_uk(uint8_t suite_id, const uint8_t *muk, uint64_t ep,
                   uint8_t *uk)
{
    const struct gy_suite_desc *desc;
    uint8_t info[QSPGS_INFO_MAX];
    size_t mklen, dlen;
    int rc;

    if (muk == NULL || uk == NULL)
        return GY_ERR_ARG;
    rc = qspgs_prepare(suite_id, GY_QSPGS_LBL_UK, &desc, &mklen, info, &dlen);
    if (rc != GY_OK)
        return rc;

    /* info = domain || be64(ep). */
    put_be64(info + dlen, ep);
    rc = qspgs_kdf(desc, info, dlen, muk, mklen, info, dlen + 8, uk, mklen);

    gy_secure_zero(info, sizeof(info));
    return rc;
}

int
gy_qspgs_derive_acq(uint8_t suite_id, const uint8_t *uk, uint8_t *acq)
{
    const struct gy_suite_desc *desc;
    uint8_t domain[QSPGS_DOMAIN_MAX];
    size_t mklen, dlen;
    int rc;

    if (uk == NULL || acq == NULL)
        return GY_ERR_ARG;
    rc =
        qspgs_prepare(suite_id, GY_QSPGS_LBL_ACQ, &desc, &mklen, domain, &dlen);
    if (rc != GY_OK)
        return rc;

    rc = qspgs_kdf(desc, domain, dlen, uk, mklen, domain, dlen, acq, mklen);

    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

int
gy_qspgs_derive_exp_key(uint8_t suite_id, const uint8_t *uk,
                        uint8_t out[GY_QSPGS_EXPKEY_BYTES])
{
    const struct gy_suite_desc *desc;
    uint8_t domain[QSPGS_DOMAIN_MAX];
    size_t mklen, dlen;
    int rc;

    if (uk == NULL || out == NULL)
        return GY_ERR_ARG;
    rc =
        qspgs_prepare(suite_id, GY_QSPGS_LBL_EXP, &desc, &mklen, domain, &dlen);
    if (rc != GY_OK)
        return rc;

    rc = qspgs_kdf(desc, domain, dlen, uk, mklen, domain, dlen, out,
                   GY_QSPGS_EXPKEY_BYTES);

    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

int
gy_qspgs_derive_sub_key(uint8_t suite_id, const uint8_t *gk,
                        uint8_t ek[GY_QSPGS_EK_BYTES],
                        uint8_t rrs[GY_QSPGS_RRS_BYTES])
{
    const struct gy_suite_desc *desc;
    uint8_t domain[QSPGS_DOMAIN_MAX];
    uint8_t sub[GY_QSPGS_EK_BYTES + GY_QSPGS_RRS_BYTES];
    size_t mklen, dlen;
    int rc;

    if (gk == NULL || ek == NULL || rrs == NULL)
        return GY_ERR_ARG;
    rc =
        qspgs_prepare(suite_id, GY_QSPGS_LBL_SUB, &desc, &mklen, domain, &dlen);
    if (rc != GY_OK)
        return rc;

    /* One expand yields ek || rrs; split without a re-derivation. */
    rc = qspgs_kdf(desc, domain, dlen, gk, mklen, domain, dlen, sub,
                   sizeof(sub));
    if (rc == GY_OK) {
        memcpy(ek, sub, GY_QSPGS_EK_BYTES);
        memcpy(rrs, sub + GY_QSPGS_EK_BYTES, GY_QSPGS_RRS_BYTES);
    }

    gy_secure_zero(sub, sizeof(sub));
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

/* One-branch token off gk: KDF(gk, label) -> out[outlen] (section 6.5). */
static int
qspgs_token(uint8_t suite_id, const char *label, const uint8_t *gk,
            uint8_t *out, size_t outlen)
{
    const struct gy_suite_desc *desc;
    uint8_t domain[QSPGS_DOMAIN_MAX];
    size_t mklen, dlen;
    int rc;

    if (gk == NULL || out == NULL)
        return GY_ERR_ARG;
    rc = qspgs_prepare(suite_id, label, &desc, &mklen, domain, &dlen);
    if (rc != GY_OK)
        return rc;

    rc = qspgs_kdf(desc, domain, dlen, gk, mklen, domain, dlen, out, outlen);
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

int
gy_qspgs_derive_fet(uint8_t suite_id, const uint8_t *gk,
                    uint8_t fet[GY_QSPGS_FET_BYTES])
{
    return qspgs_token(suite_id, GY_QSPGS_LBL_FET, gk, fet, GY_QSPGS_FET_BYTES);
}

int
gy_qspgs_derive_send(uint8_t suite_id, const uint8_t *gk,
                     uint8_t send[GY_QSPGS_SEND_BYTES])
{
    return qspgs_token(suite_id, GY_QSPGS_LBL_SEND, gk, send,
                       GY_QSPGS_SEND_BYTES);
}

int
gy_qspgs_derive_rho(uint8_t suite_id, const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                    const uint8_t *uid, size_t uidlen,
                    uint8_t rho[GY_QSPGS_RHO_BYTES])
{
    const struct gy_suite_desc *desc;
    uint8_t info[QSPGS_INFO_MAX];
    size_t mklen, dlen;
    int rc;

    if (rrs == NULL || uid == NULL || rho == NULL)
        return GY_ERR_ARG;
    if (uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    rc = qspgs_prepare(suite_id, GY_QSPGS_LBL_RERAND, &desc, &mklen, info,
                       &dlen);
    if (rc != GY_OK)
        return rc;

    /* info = domain || len(UID) || UID (one-byte length prefix, D-GEN-3). */
    info[dlen] = (uint8_t)uidlen;
    memcpy(info + dlen + 1, uid, uidlen);
    rc = qspgs_kdf(desc, info, dlen, rrs, GY_QSPGS_RRS_BYTES, info,
                   dlen + 1 + uidlen, rho, GY_QSPGS_RHO_BYTES);

    gy_secure_zero(info, sizeof(info));
    return rc;
}

int
gy_qspgs_derive_vk_psdn(uint8_t suite_id, uint8_t *vkr, const uint8_t *vkb,
                        const uint8_t rho[GY_QSPGS_RHO_BYTES])
{
    if (vkr == NULL || vkb == NULL || rho == NULL)
        return GY_ERR_ARG;

    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return gy_kr44_randvk(vkr, vkb, rho);
    case GY_SUITE_H448_1024:
        return gy_kr87_randvk(vkr, vkb, rho);
    default:
        return GY_ERR_ARG;
    }
}

int
gy_qspgs_derive_sk_psdn(uint8_t suite_id, gy_qspgs_psdn_sk_t *out,
                        const uint8_t *skb, const uint8_t *vkb,
                        const uint8_t rho[GY_QSPGS_RHO_BYTES])
{
    int rc;

    if (out == NULL || skb == NULL || vkb == NULL || rho == NULL)
        return GY_ERR_ARG;

    switch (suite_id) {
    case GY_SUITE_H25519_512:
        rc = gy_kr44_randsk(&out->rsk.k44, skb, vkb, rho);
        break;
    case GY_SUITE_H448_1024:
        rc = gy_kr87_randsk(&out->rsk.k87, skb, vkb, rho);
        break;
    default:
        return GY_ERR_ARG;
    }
    /* Tag the slot only on success; a failed randsk leaves nothing to clear. */
    out->suite_id = (rc == GY_OK) ? suite_id : 0;
    return rc;
}

void
gy_qspgs_psdn_sk_clear(gy_qspgs_psdn_sk_t *sk)
{
    if (sk == NULL)
        return;

    switch (sk->suite_id) {
    case GY_SUITE_H25519_512:
        gy_kr44_rsk_clear(&sk->rsk.k44);
        break;
    case GY_SUITE_H448_1024:
        gy_kr87_rsk_clear(&sk->rsk.k87);
        break;
    default:
        /* Untagged or already cleared: wipe the whole union defensively. */
        gy_secure_zero(&sk->rsk, sizeof(sk->rsk));
        break;
    }
    sk->suite_id = 0;
}
