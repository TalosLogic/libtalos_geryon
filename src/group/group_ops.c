/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_ops.h"

#include "group_hash.h" /* gy_group_domain, GY_GROUP_DOMAIN_MAX */

#include "error.h"
#include "suite.h" /* gy_suite_desc, struct gy_iov, GY_HASH_MAX */
#include "util.h"

/*
 * The ten client-side group operations, pure composition over the
 * algebraic-MAC, credential, and presentation units.  The only
 * non-trivial cryptography introduced here is the ProfileKeyVersion
 * HKDF (Split B); everything else forwards to the existing
 * credential / presentation / verifiable-encryption calls, adding the operation
 * framing (GROUP_SPEC section 7) and the transactional zeroization those calls
 * do not own.
 */

/* GROUP_SPEC section 2.2 item 5: the frozen ProfileKeyVersion domain label. */
#define GY_GROUP_PKV_PURPOSE "grp-pkv"

int
gy_group_profile_key_version(const struct gy_group_tier *tier,
                             const uint8_t uid[GY_GROUP_UID_BYTES],
                             const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                             uint8_t out[GY_GROUP_PK_VERSION_BYTES])
{
    const struct gy_suite_desc *desc;
    struct gy_iov ikm;
    uint8_t ikmbuf[GY_GROUP_PROFILEKEY_BYTES + GY_GROUP_UID_BYTES];
    uint8_t domain[GY_GROUP_DOMAIN_MAX];
    uint8_t prk[GY_HASH_MAX];
    size_t dlen;
    int rc;

    if (tier == NULL || uid == NULL || pk == NULL || out == NULL)
        return GY_ERR_ARG;
    desc = gy_suite_desc(tier->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PKV_PURPOSE, domain,
                         sizeof(domain), &dlen);
    if (rc != GY_OK)
        return rc;

    /* IKM = ProfileKey || UID (section 3.3: bind the UID so equal ProfileKeys
     * across users do not yield equal versions). */
    memcpy(ikmbuf, pk, GY_GROUP_PROFILEKEY_BYTES);
    memcpy(ikmbuf + GY_GROUP_PROFILEKEY_BYTES, uid, GY_GROUP_UID_BYTES);
    ikm.p = ikmbuf;
    ikm.len = sizeof(ikmbuf);

    rc = desc->hkdf_extract(prk, domain, dlen, &ikm, 1);
    if (rc != GY_OK)
        goto out;
    rc = desc->hkdf_expand(out, GY_GROUP_PK_VERSION_BYTES, prk, domain, dlen);

out:
    gy_secure_zero(ikmbuf, sizeof(ikmbuf));
    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

int
gy_group_get_auth_credential(const struct gy_group_tier *tier,
                             const struct gy_group_generators *gens,
                             const struct gy_group_server_public *pp_A,
                             const uint8_t uid[GY_GROUP_UID_BYTES],
                             uint64_t date,
                             const struct gy_group_auth_response *resp,
                             struct gy_group_mac_tag *out_cred)
{
    int rc;

    if (out_cred == NULL || resp == NULL)
        return GY_ERR_ARG;

    /* The pi_I check IS the credential check: verify before storing anything
     * (D-GRP-7 - nothing is stored on failure). */
    rc = gy_group_auth_verify(tier, gens, pp_A, uid, date, resp);
    if (rc != GY_OK)
        return rc;

    *out_cred = resp->mac; /* store the AuthCredential (t, U, V) */
    return GY_OK;
}

int
gy_group_commit_to_profile_key(const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               const uint8_t uid[GY_GROUP_UID_BYTES],
                               const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                               uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
                               struct gy_group_pk_commitment *out_commit)
{
    int rc;

    rc = gy_group_profile_key_version(tier, uid, pk, out_version);
    if (rc != GY_OK)
        return rc;
    return gy_group_pk_commit(tier, gens, uid, pk, out_commit);
}

int
gy_group_get_pk_credential_request(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
    struct gy_group_pk_request *out_req, uint8_t y_out[GY_GROUP_SCALAR_MAX])
{
    int rc;

    rc = gy_group_profile_key_version(tier, uid, pk, out_version);
    if (rc != GY_OK)
        return rc;
    return gy_group_pk_request(tier, gens, uid, pk, out_req, y_out);
}

int
gy_group_get_pk_credential_finish(const struct gy_group_tier *tier,
                                  const struct gy_group_generators *gens,
                                  const struct gy_group_server_public *pp_P,
                                  const uint8_t uid[GY_GROUP_UID_BYTES],
                                  const struct gy_group_pk_request *req,
                                  const uint8_t y[GY_GROUP_SCALAR_MAX],
                                  const struct gy_group_pk_blind_response *resp,
                                  struct gy_group_mac_tag *out_cred)
{
    /* pi_BI verification, blind decryption, and the (t,U,V) output are the
     * provider's; this is the operation-framing name for section 7.3 step 5. */
    return gy_group_pk_blind_receive(tier, gens, pp_P, uid, req, y, resp,
                                     out_cred);
}

int
gy_group_auth_as_member(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const struct gy_group_secret_params *sp,
                        const struct gy_group_public_params *pp_pub,
                        const struct gy_group_server_public *pp_srv_A,
                        const struct gy_group_mac_tag *cred,
                        const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                        struct gy_group_auth_presentation *out_pres)
{
    /* The presentation recomputes and embeds the deterministic UidCiphertext
     * (E_A1,E_A2) internally (section 6.3), so no separate ciphertext output. */
    return gy_group_auth_present(tier, gens, sp, pp_pub, pp_srv_A, cred, uid,
                                 date, out_pres);
}

int
gy_group_add_member(const struct gy_group_tier *tier,
                    const struct gy_group_generators *gens,
                    const struct gy_group_secret_params *sp,
                    const struct gy_group_public_params *pp_pub,
                    const struct gy_group_server_public *pp_srv_P,
                    const struct gy_group_mac_tag *new_cred,
                    const uint8_t new_uid[GY_GROUP_UID_BYTES],
                    const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                    struct gy_group_pk_presentation *out_pres)
{
    /* The presentation binds and embeds the new member's Uid/ProfileKey
     * ciphertexts; the server extracts them as the stored entry. */
    return gy_group_pk_present(tier, gens, sp, pp_pub, pp_srv_P, new_cred,
                               new_uid, new_pk, out_pres);
}

int
gy_group_create(const struct gy_group_tier *tier,
                const struct gy_group_generators *gens, uint8_t *out_gmk,
                struct gy_group_secret_params *out_sp,
                struct gy_group_public_params *out_pp)
{
    int rc;

    if (tier == NULL || out_gmk == NULL)
        return GY_ERR_ARG;

    rc = gy_group_master_key(tier, out_gmk);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_secret_derive(tier, out_gmk, tier->master_key_len, out_sp);
    if (rc != GY_OK)
        goto err_gmk;
    rc = gy_group_public_derive(tier, gens, out_sp, out_pp);
    if (rc != GY_OK)
        goto err_sp;
    return GY_OK;

err_sp:
    gy_group_secret_clear(out_sp);
err_gmk:
    gy_secure_zero(out_gmk, tier->master_key_len);
    return rc;
}

int
gy_group_fetch_members(const struct gy_group_tier *tier,
                       const struct gy_group_secret_params *sp,
                       const struct gy_group_member_ct *in, size_t n_in,
                       struct gy_group_member *out, size_t out_cap,
                       size_t *out_count)
{
    size_t i;
    int rc;

    if (tier == NULL || sp == NULL || out == NULL || out_count == NULL)
        return GY_ERR_ARG;
    if (n_in != 0 && in == NULL)
        return GY_ERR_ARG;
    /* Compile-time input bound (section 10, D-SES-4): never process more than
     * the cap, and never overrun the caller's view buffer. */
    if (n_in > GY_GROUP_MAX_ENTRIES || n_in > out_cap)
        return GY_ERR_ARG;

    *out_count = 0;
    memset(out, 0, n_in * sizeof(*out));

    for (i = 0; i < n_in; i++) {
        rc = gy_group_uid_decrypt(tier, sp, &in[i].uid_ct, out[i].uid);
        if (rc != GY_OK)
            goto fail;
        out[i].role = in[i].role;
        out[i].has_profile_key = in[i].has_profile_key ? 1u : 0u;
        if (out[i].has_profile_key) {
            rc = gy_group_pk_decrypt(tier, sp, &in[i].pk_ct, out[i].uid,
                                     out[i].profile_key);
            if (rc != GY_OK)
                goto fail;
        }
    }

    *out_count = n_in;
    return GY_OK;

fail:
    /* Transactional (section 10): a single malformed entry fails the whole
     * fetch; zeroize the partially decrypted plaintext (profile keys are
     * secret) and report a uniform structured error. */
    gy_secure_zero(out, n_in * sizeof(*out));
    *out_count = 0;
    return rc;
}

int
gy_group_delete_member(const struct gy_group_tier *tier,
                       const struct gy_group_secret_params *sp,
                       const uint8_t target_uid[GY_GROUP_UID_BYTES],
                       struct gy_group_uid_ct *out_uid_ct)
{
    /* The deterministic UidCiphertext is the server's delete key; the Role
     * check and removal are server-side (section 7.8). */
    return gy_group_uid_encrypt(tier, sp, target_uid, out_uid_ct);
}

int
gy_group_add_invited_member(const struct gy_group_tier *tier,
                            const struct gy_group_secret_params *sp,
                            const uint8_t invited_uid[GY_GROUP_UID_BYTES],
                            struct gy_group_uid_ct *out_uid_ct)
{
    /* Invited entry: UID only, no ProfileKeyCiphertext and no pi_P (section
     * 7.9); completed later by AddGroupMember / UpdateProfileKey. */
    return gy_group_uid_encrypt(tier, sp, invited_uid, out_uid_ct);
}

int
gy_group_update_profile_key(const struct gy_group_tier *tier,
                            const struct gy_group_generators *gens,
                            const struct gy_group_secret_params *sp,
                            const struct gy_group_public_params *pp_pub,
                            const struct gy_group_server_public *pp_srv_P,
                            const struct gy_group_mac_tag *own_cred,
                            const uint8_t own_uid[GY_GROUP_UID_BYTES],
                            const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                            struct gy_group_pk_presentation *out_pres)
{
    /* Cryptographically identical to AddGroupMember over the caller's own
     * (uid, new_pk); the server enforces the self-match that prevents rollback
     * of other members' profile data (section 7.10). */
    return gy_group_pk_present(tier, gens, sp, pp_pub, pp_srv_P, own_cred,
                               own_uid, new_pk, out_pres);
}
