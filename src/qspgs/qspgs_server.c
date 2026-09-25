/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * QSPGS server side (QSPGS_SPEC.md section 7.3): the stateless server-side
 * checks, each a pure function of its inputs.  This translation unit is the
 * geryon_qsgroups_server facade; it links ONLY the sk-free common layer
 * (geryon_qspgs_internal, qspgs_wire.c) and geryon_core, never the client
 * target.  It carries no rerandomization internal (rrs / rho / skpsdn) and no
 * KR-ML-DSA glue: signature verification is the public liboqs verifier reached
 * through the common layer.  See qspgs_server.h.
 */

#include "qspgs_server.h"

#include "aead.h" /* GY_AEAD_* (group AEAD policy, SEC-v1.5.0 INFO-6) */
#include "error.h"
#include "qspgs_wire.h" /* gy_qspgs_core_verify / _apx_line_verify / _vkpsdn_hash_check */
#include "suite.h" /* gy_suite_desc */
#include "util.h"  /* gy_const_memcmp */

/*
 * Group-approved field AEADs (SEC-v1.5.0 INFO-6).  Duplicated inline (not the
 * gy_qspgs_group_aead_ok predicate) so the server target stays free of the
 * client-only field layer: this TU links no seal / open symbols
 * (tests/audit/nm_scope_qspgs_server.sh).  Keep the set in sync with
 * qspgs_field.c: ChaCha20-Poly1305 (MTI) and AEGIS-256, both always available.
 */
static int
server_group_aead_ok(uint8_t aead_id)
{
    return aead_id == GY_AEAD_CHACHA20POLY1305 || aead_id == GY_AEAD_AEGIS256;
}

/* Resolve a hybrid descriptor (QSPGS serves the hybrid tiers only), or NULL. */
static const struct gy_suite_desc *
server_hybrid_desc(uint8_t suite_id)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);

    if (desc == NULL || !desc->is_hybrid)
        return (NULL);
    return (desc);
}

int
gy_qspgs_server_token_check(const uint8_t *presented, const uint8_t *stored,
                            size_t token_len)
{
    if (presented == NULL || stored == NULL || token_len == 0)
        return (GY_ERR_ARG);

    /*
	 * Bearer-token equality is over server-held bytes; use the const-time
	 * compare so a timing side channel cannot leak how much of a guessed
	 * token is correct.
	 */
    if (gy_const_memcmp(presented, stored, token_len) != 0)
        return (GY_ERR_VERIFY);

    return (GY_OK);
}

int
gy_qspgs_server_core_check(const struct gy_qspgs_core *prior, uint8_t op_kind,
                           const struct gy_qspgs_core *next,
                           uint32_t signer_index, const uint8_t *signer_vkr,
                           const uint8_t *sig, size_t sig_len, uint8_t *scratch,
                           size_t scratch_cap)
{
    const struct gy_suite_desc *desc;
    size_t hlen;
    int rc;

    if (next == NULL || signer_vkr == NULL || sig == NULL || scratch == NULL)
        return (GY_ERR_ARG);

    desc = server_hybrid_desc(next->suite_id);
    if (desc == NULL)
        return (GY_ERR_ARG);
    hlen = desc->hash_len;

    /* An unknown operation kind is a caller error, decided before any prior /
     * admn logic so it never masquerades as a verification failure. */
    if (op_kind != GY_QSPGS_OP_CREATE && op_kind != GY_QSPGS_OP_UNCHANGED &&
        op_kind != GY_QSPGS_OP_APPEND_ONE && op_kind != GY_QSPGS_OP_REPLACE)
        return (GY_ERR_ARG);

    /*
     * CREATE (section 7.3 item 1, category CREATE): no prior version.  The
     * sole member is the creating admin; vMaj is 1 and there is exactly one
     * vk-lst entry (Fig. 9).  The signer resolves against the SUBMITTED
     * vk-lst[0].
     */
    if (op_kind == GY_QSPGS_OP_CREATE) {
        if (prior != NULL)
            return (GY_ERR_ARG);
        if (next->n_members != 1 || next->n_vk != 1 || next->vmaj != 1)
            return (GY_ERR_VERIFY);
        /* The founding header pins the group's field AEAD (SEC-v1.5.0 INFO-6):
         * reject a core that names one outside the group-approved set before it
         * is signed into the lineage as immutable. */
        if (!server_group_aead_ok(next->aead_id))
            return (GY_ERR_VERIFY);
        if (signer_index != 0)
            return (GY_ERR_ARG);
        if (next->members[0].admn == 0)
            return (GY_ERR_VERIFY);
        rc = gy_qspgs_vkpsdn_hash_check(next->suite_id, signer_vkr,
                                        next->vkhash);
        if (rc != GY_OK)
            return (rc);
        return (gy_qspgs_core_verify(next, signer_index, signer_vkr, sig,
                                     sig_len, scratch, scratch_cap));
    }

    /* Every non-CREATE edit is checked against the STORED prior version. */
    if (prior == NULL)
        return (GY_ERR_ARG);
    if (prior->suite_id != next->suite_id)
        return (GY_ERR_ARG);
    /*
     * Field-AEAD immutability (SEC-v1.5.0 INFO-6): the pinned aead_id is set at
     * Create and never changes, so no admin edit may swap the group onto a
     * different (or unapproved) AEAD.  Checked against the STORED prior, like
     * the admn and vMaj lineage below.
     */
    if (next->aead_id != prior->aead_id)
        return (GY_ERR_VERIFY);
    /*
     * Capability-epoch and identity immutability (SEC-v1.5.0 INFO-2, D-QGS-12):
     * format_version and the GID are set at Create and immutable for the group's
     * life.  Both are admin-signed, so only a misbehaving admin could change
     * them; machine-enforcing equality against the stored prior refuses such a
     * core before it enters the lineage (defense in depth, alongside aead_id).
     * The GID is public; the const-time compare is the library-wide policy.
     */
    if (next->format_version != prior->format_version)
        return (GY_ERR_VERIFY);
    if (gy_const_memcmp(next->gid, prior->gid, GY_QSPGS_GID_LEN) != 0)
        return (GY_ERR_VERIFY);

    /*
     * Admin lineage (D-QGS-13 E2): the admn gate ALWAYS reads the PRIOR
     * mem-lst, so a non-admin cannot sign a next core that flips its own admn
     * bit.  The signer must be an existing member of the prior version.
     */
    if (signer_index >= prior->n_members || signer_index >= prior->n_vk)
        return (GY_ERR_ARG);
    if (prior->members[signer_index].admn == 0)
        return (GY_ERR_VERIFY);

    /*
     * Version lineage (D-QGS-14 E13, spec section 7.3 item 4): every [CFG+]
     * admin protocol sets hdr <- (GID, vMaj + 1, ...), so a submitted non-Create
     * core must advance vMaj by exactly one over the stored prior.  This is the
     * server half of the anti-rollback property, alongside the prior-version
     * admn gate above and the client-side Fig. 15 lineage (D-QGS-14 E11).
     */
    if (next->vmaj != prior->vmaj + 1)
        return (GY_ERR_VERIFY);

    /*
     * vk-lst transition by operation (D-QGS-13 E2, the four categories).  The
     * hashes are public H(vkpsdn); the const-time compare is the library-wide
     * byte-comparison policy, not a secrecy requirement.
     */
    switch (op_kind) {
    case GY_QSPGS_OP_UNCHANGED:
        if (next->n_vk != prior->n_vk)
            return (GY_ERR_VERIFY);
        if (gy_const_memcmp(next->vkhash, prior->vkhash,
                            (size_t)prior->n_vk * hlen) != 0)
            return (GY_ERR_VERIFY);
        break;
    case GY_QSPGS_OP_APPEND_ONE:
        if (next->n_vk != prior->n_vk + 1)
            return (GY_ERR_VERIFY);
        if (gy_const_memcmp(next->vkhash, prior->vkhash,
                            (size_t)prior->n_vk * hlen) != 0)
            return (GY_ERR_VERIFY);
        break;
    case GY_QSPGS_OP_REPLACE:
        /* Rotation rerandomized every key; the server holds no gk and accepts
         * the submitted vk-lst wholesale (Fig. 17 / 20). */
        break;
    default:
        return (GY_ERR_ARG);
    }

    /*
     * Resolve the signer's supplied vkpsdn against the SUBMITTED vk-lst[signer]
     * (equal to the prior hash for UNCHANGED / APPEND_ONE by the checks above;
     * the rotated key for REPLACE, Fig. 20 vkpsdn <- (vk-lst)_i), then verify
     * the core signature over the NEXT objects under it.
     */
    if (signer_index >= next->n_members || signer_index >= next->n_vk)
        return (GY_ERR_ARG);
    rc = gy_qspgs_vkpsdn_hash_check(next->suite_id, signer_vkr,
                                    next->vkhash + (size_t)signer_index * hlen);
    if (rc != GY_OK)
        return (rc);
    return (gy_qspgs_core_verify(next, signer_index, signer_vkr, sig, sig_len,
                                 scratch, scratch_cap));
}

int
gy_qspgs_server_apx_check(uint8_t suite_id, const uint8_t gid[GY_QSPGS_GID_LEN],
                          uint32_t vmaj, uint32_t vmin,
                          const struct gy_qspgs_apx_line *line,
                          const uint8_t *author_vkr,
                          const uint8_t *stored_vkhash, uint8_t *scratch,
                          size_t scratch_cap)
{
    int rc;

    if (gid == NULL || line == NULL || author_vkr == NULL || scratch == NULL)
        return (GY_ERR_ARG);
    if (server_hybrid_desc(suite_id) == NULL)
        return (GY_ERR_ARG);

    /* Item 3 (existing author only): resolve the supplied key against the
     * stored vk-lst hash.  A newcomer's vkpsdn is not yet in the vk-lst, so the
     * caller passes NULL and appends H(author_vkr) on acceptance. */
    if (stored_vkhash != NULL) {
        rc = gy_qspgs_vkpsdn_hash_check(suite_id, author_vkr, stored_vkhash);
        if (rc != GY_OK)
            return (rc);
    }

    /* Item 2: the line signature verifies under the author's vkpsdn, over the
     * apx-hdr (gid, vmaj, vmin) and the line (D-QGS-13 E1). */
    return (gy_qspgs_apx_line_verify(suite_id, gid, vmaj, vmin, line,
                                     author_vkr, scratch, scratch_cap));
}

/* True iff (a_maj, a_min) > (b_maj, b_min) lexicographically. */
static int
version_gt(uint32_t a_maj, uint32_t a_min, uint32_t b_maj, uint32_t b_min)
{
    if (a_maj != b_maj)
        return (a_maj > b_maj);
    return (a_min > b_min);
}

int
gy_qspgs_server_version_check(uint32_t cur_vmaj, uint32_t cur_vmin,
                              uint32_t ext_vmaj, uint32_t ext_vmin,
                              uint32_t new_vmaj, uint32_t new_vmin)
{
    /* Compare-and-swap: the write must extend the current head, else a
     * concurrent write moved it and this is a conflict (never merged). */
    if (ext_vmaj != cur_vmaj || ext_vmin != cur_vmin)
        return (GY_ERR_STATE);

    /* Version discipline: strictly increasing (vMaj, vMin). */
    if (!version_gt(new_vmaj, new_vmin, cur_vmaj, cur_vmin))
        return (GY_ERR_STATE);

    return (GY_OK);
}

int
gy_qspgs_server_fetch_check(const uint8_t *fet, const uint8_t *presented)
{
    if (fet == NULL || presented == NULL)
        return (GY_ERR_ARG);

    return (gy_qspgs_server_token_check(presented, fet, GY_QSPGS_FET_LEN));
}
