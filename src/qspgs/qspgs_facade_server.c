/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS public server facade (geryon_qsgroups_server.h).
 * The handle-free, stateless public surface over the section-7.3 acceptance
 * checks: it DECODES the opaque wire objects a member submits (the signed core,
 * the core-signature object, appendix lines) against the frozen section-4
 * grammar and forwards to the internal pure checks in qspgs_server.c.  No wire
 * struct crosses the public boundary.
 *
 * This translation unit is part of the geryon_qsgroups_server target; it links
 * ONLY the sk-free common layer (geryon_qspgs_internal: qspgs_wire.c) and
 * geryon_core (suite descriptor), never the client target.  It holds no core
 * secret parameter and no KR-ML-DSA rerandomization internal (rrs / rho /
 * skpsdn): signature verification is the public verifier reached through the
 * common layer, and the tests/audit/nm_scope_qspgs_server.sh scan enforces that
 * no client-only symbol appears here.
 *
 * The transient decode buffers (the member / vk-lst / appendix-line arrays and
 * the TBS scratch) are heap-allocated per call and freed before return: these
 * are server admin-edit paths, not a hot loop, and the entry bound
 * (GY_QSPGS_MAX_ENTRIES) makes a fixed on-stack array impractical.  Nothing
 * decoded is secret (the core, its signature, and the presented vkr are all
 * public), so no zeroization is needed.
 */

#include "geryon_qsgroups_server.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "qspgs_server.h" /* the internal pure section-7.3 checks. */
#include "qspgs_wire.h"   /* the section-4 decoders and wire structs. */
#include "suite.h"        /* gy_suite_desc (hybrid gate, tier sizes). */
#include "util.h"         /* gy_const_memcmp (byte-comparison policy). */

/* Resolve a hybrid descriptor (QSPGS serves the hybrid tiers only), or NULL. */
static const struct gy_suite_desc *
hybrid_desc(uint8_t suite_id)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);

    if (desc == NULL || !desc->is_hybrid)
        return (NULL);
    return (desc);
}

/*
 * Decode a core from its three independently framed, exact-length objects (the
 * header, the member-list, and the vk-lst) into *core, whose list pointers then
 * reference into those buffers.  members[0..GY_QSPGS_MAX_ENTRIES) backs the
 * decoded member list.  Each decoder is strict (it consumes its whole object or
 * fails), so no cross-object length arithmetic is needed here.
 */
static int
decode_core(struct gy_qspgs_core *core, uint8_t suite_id,
            struct gy_qspgs_member *members, const uint8_t *header_obj,
            size_t header_obj_len, const uint8_t *member_list_obj,
            size_t member_list_obj_len, const uint8_t *vk_lst_obj,
            size_t vk_lst_obj_len)
{
    size_t consumed;
    int rc;

    memset(core, 0, sizeof(*core));
    core->suite_id = suite_id;

    rc = gy_qspgs_header_decode(core, header_obj, header_obj_len, &consumed);
    if (rc != GY_OK)
        return (rc);
    rc = gy_qspgs_member_list_decode(core, members, GY_QSPGS_MAX_ENTRIES,
                                     member_list_obj, member_list_obj_len,
                                     &consumed);
    if (rc != GY_OK)
        return (rc);
    return (
        gy_qspgs_vk_lst_decode(core, vk_lst_obj, vk_lst_obj_len, &consumed));
}

/* ---- pure token / version checks (thin pass-throughs) ------------------- */

int
gy_qsgroups_server_token_check(const uint8_t *presented, const uint8_t *stored,
                               size_t token_len)
{
    return (gy_qspgs_server_token_check(presented, stored, token_len));
}

int
gy_qsgroups_server_version_check(uint32_t cur_vmaj, uint32_t cur_vmin,
                                 uint32_t ext_vmaj, uint32_t ext_vmin,
                                 uint32_t new_vmaj, uint32_t new_vmin)
{
    return (gy_qspgs_server_version_check(cur_vmaj, cur_vmin, ext_vmaj,
                                          ext_vmin, new_vmaj, new_vmin));
}

/* ---- checks over opaque wire (decoded internally) ----------------------- */

int
gy_qsgroups_server_fetch_check(uint8_t suite_id, const uint8_t *fet,
                               const uint8_t *presented)
{
    if (fet == NULL || presented == NULL)
        return (GY_ERR_ARG);
    if (hybrid_desc(suite_id) == NULL)
        return (GY_ERR_UNSUPPORTED);

    /* SEC-v1.5.0 LOW-1: fet is the separate server record the admin emitted in
     * the core bundle, NOT decoded from the served header. */
    return (gy_qspgs_server_fetch_check(fet, presented));
}

int
gy_qsgroups_server_core_check(
    uint8_t suite_id, uint8_t op_kind, const uint8_t *prior_header_obj,
    size_t prior_header_obj_len, const uint8_t *prior_member_list_obj,
    size_t prior_member_list_obj_len, const uint8_t *prior_vk_lst_obj,
    size_t prior_vk_lst_obj_len, const uint8_t *header_obj,
    size_t header_obj_len, const uint8_t *member_list_obj,
    size_t member_list_obj_len, const uint8_t *vk_lst_obj,
    size_t vk_lst_obj_len, const uint8_t *sig_obj, size_t sig_obj_len,
    const uint8_t *signer_vkr, size_t signer_vkr_len)
{
    const struct gy_suite_desc *desc;
    struct gy_qspgs_core core, prior;
    struct gy_qspgs_member *members = NULL, *prior_members = NULL;
    const struct gy_qspgs_core *prior_p = NULL;
    uint8_t *scratch = NULL;
    const uint8_t *sig;
    size_t consumed, sig_len, scratch_cap;
    uint32_t signer_index, last_vmin;
    int have_prior;
    int rc;

    if (header_obj == NULL || member_list_obj == NULL || vk_lst_obj == NULL ||
        sig_obj == NULL || signer_vkr == NULL)
        return (GY_ERR_ARG);
    desc = hybrid_desc(suite_id);
    if (desc == NULL)
        return (GY_ERR_UNSUPPORTED);
    if (signer_vkr_len != desc->dsa_pk_len)
        return (GY_ERR_ARG);

    /*
     * A prior version is present iff its three objects are supplied; it is
     * absent only for a CREATE.  Either all three or none: a partial prior is a
     * caller error.
     */
    have_prior = (prior_header_obj != NULL || prior_member_list_obj != NULL ||
                  prior_vk_lst_obj != NULL);
    if (have_prior &&
        (prior_header_obj == NULL || prior_member_list_obj == NULL ||
         prior_vk_lst_obj == NULL))
        return (GY_ERR_ARG);

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    /* TBS = signer_index(4) || header || member-list || vk-lst || 8. */
    scratch_cap = header_obj_len + member_list_obj_len + vk_lst_obj_len + 16;
    scratch = calloc(1, scratch_cap);
    if (have_prior)
        prior_members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*prior_members));
    if (members == NULL || scratch == NULL ||
        (have_prior && prior_members == NULL)) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    rc = decode_core(&core, suite_id, members, header_obj, header_obj_len,
                     member_list_obj, member_list_obj_len, vk_lst_obj,
                     vk_lst_obj_len);
    if (rc != GY_OK)
        goto out;

    if (have_prior) {
        rc = decode_core(&prior, suite_id, prior_members, prior_header_obj,
                         prior_header_obj_len, prior_member_list_obj,
                         prior_member_list_obj_len, prior_vk_lst_obj,
                         prior_vk_lst_obj_len);
        if (rc != GY_OK)
            goto out;
        prior_p = &prior;
    }

    rc = gy_qspgs_core_sig_decode(suite_id, sig_obj, sig_obj_len, &signer_index,
                                  &last_vmin, &sig, &sig_len, &consumed);
    if (rc != GY_OK)
        goto out;
    if (consumed != sig_obj_len) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    core.last_vmin = last_vmin; /* covered by the TBS the verifier rebuilds. */

    rc = gy_qspgs_server_core_check(prior_p, op_kind, &core, signer_index,
                                    signer_vkr, sig, sig_len, scratch,
                                    scratch_cap);
out:
    free(members);
    free(prior_members);
    free(scratch);
    return (rc);
}

int
gy_qsgroups_server_apx_check(uint8_t suite_id, const uint8_t *vk_lst_obj,
                             size_t vk_lst_obj_len, const uint8_t *apx_obj,
                             size_t apx_obj_len, size_t line_index,
                             const uint8_t *author_vkr, size_t author_vkr_len,
                             int newcomer)
{
    const struct gy_suite_desc *desc;
    struct gy_qspgs_appendix apx;
    struct gy_qspgs_apx_line *lines = NULL;
    const struct gy_qspgs_apx_line *line;
    const uint8_t *stored_vkhash = NULL;
    uint8_t *scratch = NULL;
    size_t consumed, scratch_cap;
    int is_newcomer, rc;

    if (apx_obj == NULL || author_vkr == NULL)
        return (GY_ERR_ARG);
    desc = hybrid_desc(suite_id);
    if (desc == NULL)
        return (GY_ERR_UNSUPPORTED);
    if (author_vkr_len != desc->dsa_pk_len)
        return (GY_ERR_ARG);

    lines = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*lines));
    scratch_cap = apx_obj_len + 16; /* line TBS = type(1) || author(4) || pl. */
    scratch = calloc(1, scratch_cap);
    if (lines == NULL || scratch == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    memset(&apx, 0, sizeof(apx));
    apx.suite_id = suite_id;
    rc = gy_qspgs_appendix_decode(&apx, lines, GY_QSPGS_MAX_ENTRIES, apx_obj,
                                  apx_obj_len, &consumed);
    if (rc != GY_OK)
        goto out;
    if (line_index >= apx.n_lines) {
        rc = GY_ERR_ARG;
        goto out;
    }
    line = &lines[line_index];

    /* Newcomer status is a property of the line, not a caller assertion: only a
     * JOIN is authored under a key not yet in the vk-lst, so ONLY a JOIN may
     * skip the stored-H(vkpsdn) resolution (SEC-v1.5.0 LOW-3).  Derive it from
     * the decoded line, reject a caller whose flag disagrees, and require the
     * vk-lst for every other line kind. */
    is_newcomer = (line->line_type == GY_QAPX_JOIN);
    if (!!newcomer != is_newcomer) {
        rc = GY_ERR_ARG;
        goto out;
    }
    if (!is_newcomer && vk_lst_obj == NULL) {
        rc = GY_ERR_ARG;
        goto out;
    }

    /* An existing author's vkpsdn resolves against the stored H(vkpsdn) at its
     * vk-lst index; a newcomer's is not yet listed (stored_vkhash stays NULL). */
    if (!is_newcomer) {
        struct gy_qspgs_core core;

        memset(&core, 0, sizeof(core));
        core.suite_id = suite_id;
        rc = gy_qspgs_vk_lst_decode(&core, vk_lst_obj, vk_lst_obj_len,
                                    &consumed);
        if (rc != GY_OK)
            goto out;
        if (line->author_index >= core.n_vk) {
            rc = GY_ERR_ARG;
            goto out;
        }
        stored_vkhash =
            core.vkhash + (size_t)line->author_index * desc->hash_len;
    }

    rc = gy_qspgs_server_apx_check(suite_id, apx.gid, apx.vmaj, apx.vmin, line,
                                   author_vkr, stored_vkhash, scratch,
                                   scratch_cap);
out:
    free(lines);
    free(scratch);
    return (rc);
}

int
gy_qsgroups_server_leave_fetch_check(uint8_t suite_id,
                                     const uint8_t *vk_lst_obj,
                                     size_t vk_lst_obj_len, const uint8_t *gid,
                                     uint32_t k, const uint8_t *sig,
                                     size_t sig_len, const uint8_t *leaver_vkr,
                                     size_t leaver_vkr_len)
{
    const struct gy_suite_desc *desc;
    struct gy_qspgs_core core;
    size_t consumed;
    int rc;

    if (vk_lst_obj == NULL || gid == NULL || sig == NULL || leaver_vkr == NULL)
        return (GY_ERR_ARG);
    desc = hybrid_desc(suite_id);
    if (desc == NULL)
        return (GY_ERR_UNSUPPORTED);
    if (leaver_vkr_len != desc->dsa_pk_len)
        return (GY_ERR_ARG);

    /* Resolve leaver_vkr against the stored H(vkpsdn) at index k (item 3). */
    memset(&core, 0, sizeof(core));
    core.suite_id = suite_id;
    rc = gy_qspgs_vk_lst_decode(&core, vk_lst_obj, vk_lst_obj_len, &consumed);
    if (rc != GY_OK)
        return (rc);
    if (k >= core.n_vk)
        return (GY_ERR_ARG);
    rc = gy_qspgs_vkpsdn_hash_check(suite_id, leaver_vkr,
                                    core.vkhash + (size_t)k * desc->hash_len);
    if (rc != GY_OK)
        return (rc);

    return (gy_qspgs_leave_token_verify(suite_id, gid, k, sig, sig_len,
                                        leaver_vkr));
}

int
gy_qsgroups_server_appendix_append(uint8_t suite_id, const uint8_t *cur_apx,
                                   size_t cur_apx_len, const uint8_t *line_obj,
                                   size_t line_obj_len, uint8_t *out,
                                   size_t *out_len)
{
    struct gy_qspgs_appendix acur, aline, amerged;
    struct gy_qspgs_apx_line *lines = NULL;
    size_t consumed, na = 0, nb, need;
    int rc;

    if (line_obj == NULL || out_len == NULL)
        return (GY_ERR_ARG);
    if (hybrid_desc(suite_id) == NULL)
        return (GY_ERR_UNSUPPORTED);

    lines = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*lines));
    if (lines == NULL)
        return (GY_ERR_CRYPTO);

    memset(&amerged, 0, sizeof(amerged));

    /* Decode the accumulated appendix (if any) into the front of lines[]. */
    if (cur_apx != NULL && cur_apx_len > 0) {
        memset(&acur, 0, sizeof(acur));
        acur.suite_id = suite_id;
        rc = gy_qspgs_appendix_decode(&acur, lines, GY_QSPGS_MAX_ENTRIES,
                                      cur_apx, cur_apx_len, &consumed);
        if (rc != GY_OK)
            goto out;
        na = acur.n_lines;
        memcpy(amerged.gid, acur.gid, GY_QSPGS_GID_LEN);
        amerged.vmaj = acur.vmaj;
        amerged.vmin = acur.vmin;
    }

    /* Decode the submitted line object into lines[na..]. */
    memset(&aline, 0, sizeof(aline));
    aline.suite_id = suite_id;
    rc = gy_qspgs_appendix_decode(&aline, lines + na, GY_QSPGS_MAX_ENTRIES - na,
                                  line_obj, line_obj_len, &consumed);
    if (rc != GY_OK)
        goto out;
    nb = aline.n_lines;

    if (na == 0) {
        memcpy(amerged.gid, aline.gid, GY_QSPGS_GID_LEN);
        amerged.vmaj = aline.vmaj;
        amerged.vmin = aline.vmin;
    } else if (aline.vmaj != amerged.vmaj || aline.vmin != amerged.vmin ||
               gy_const_memcmp(aline.gid, amerged.gid, GY_QSPGS_GID_LEN) != 0) {
        rc = GY_ERR_VERIFY; /* a line for a different group / version. */
        goto out;
    }

    amerged.suite_id = suite_id;
    amerged.lines = lines;
    amerged.n_lines = na + nb;

    /* Size query / short buffer follow the buffer convention. */
    if (out == NULL) {
        need = cur_apx_len + line_obj_len;
        *out_len = need;
        rc = GY_OK;
        goto out;
    }
    rc = gy_qspgs_appendix_encode(&amerged, out, *out_len, out_len);
out:
    free(lines);
    return (rc);
}
