/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_wire.h"

#include "qspgs_labels.h"

#include "encode.h" /* gy_be*, gy_info, GY_SUITE_* */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "suite.h" /* gy_suite_desc, GY_HASH_MAX */
#include "util.h"

/*
 * The QSPGS group data structure wire (section 4).  The
 * core list (header + member list + vk-lst) and the admin core signature, plus
 * the two frozen tier-hash helpers (C_UID commitment, H(vkpsdn)).  Framing
 * mirrors group_wire.c; no crypto arithmetic lives here (the tier hash and the
 * KR-ML-DSA verifier are reached through the descriptor / the primitives).
 */

/* Longest gy_info domain here: "geryon.1." (9) + "geryon_h448_1024" (16) +
 * "." (1) + "qspgs-vkhash" (12) = 38; rounded up. */
#define QSPGS_WIRE_DOMAIN_MAX 48

/* Resolve a hybrid descriptor, or NULL. */
static const struct gy_suite_desc *
wire_hybrid_desc(uint8_t suite_id)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);

    if (desc == NULL || !desc->is_hybrid)
        return NULL;
    return desc;
}

/* Object header: obj_type || wire_version || suite_id. */
static int
obj_put_header(uint8_t obj_type, uint8_t suite_id, uint8_t *out, size_t cap)
{
    if (cap < GY_QSPGS_OBJ_HDR_LEN)
        return GY_ERR_TOOLONG;
    out[0] = obj_type;
    out[1] = GY_QSPGS_WIRE_VERSION;
    out[2] = suite_id;
    return GY_OK;
}

static int
obj_check_header(uint8_t obj_type, uint8_t suite_id, const uint8_t *in,
                 size_t len)
{
    if (len < GY_QSPGS_OBJ_HDR_LEN)
        return GY_ERR_VERIFY;
    if (in[0] != obj_type || in[1] != GY_QSPGS_WIRE_VERSION ||
        in[2] != suite_id)
        return GY_ERR_VERIFY;
    return GY_OK;
}

/*
 * Tier hash of gy_info(suite_id, purpose) || data, into out (desc->hash_len
 * bytes).  The domain-separating prefix keeps the commitment / list hash from
 * colliding across suites (D-GEN-3).  data may be split into two parts (part
 * a then part b); either length may be 0.
 */
static int
wire_domain_hash(const struct gy_suite_desc *desc, uint8_t suite_id,
                 const char *purpose, const uint8_t *a, size_t alen,
                 const uint8_t *b, size_t blen, uint8_t *out)
{
    uint8_t buf[QSPGS_WIRE_DOMAIN_MAX + GY_QSPGS_RC_LEN + GY_QSPGS_UID_MAX];
    uint8_t big[QSPGS_WIRE_DOMAIN_MAX + GY_QSPGS_VKR_MAX];
    uint8_t *work;
    size_t dlen, need, cap;
    int rc;

    /* Pick the buffer that fits the larger input (vkr for the vk hash). */
    if (alen + blen <= sizeof(buf) - QSPGS_WIRE_DOMAIN_MAX) {
        work = buf;
        cap = sizeof(buf);
    } else {
        work = big;
        cap = sizeof(big);
    }

    rc = gy_info(work, QSPGS_WIRE_DOMAIN_MAX, &dlen, suite_id, purpose);
    if (rc != GY_OK)
        goto out;
    need = dlen + alen + blen;
    if (need > cap) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    if (alen != 0)
        memcpy(work + dlen, a, alen);
    if (blen != 0)
        memcpy(work + dlen + alen, b, blen);
    rc = desc->hash(out, work, need);

out:
    gy_secure_zero(buf, sizeof(buf));
    gy_secure_zero(big, sizeof(big));
    return rc;
}

int
gy_qspgs_cuid_commit(uint8_t suite_id, const uint8_t *uid, size_t uidlen,
                     const uint8_t rc_open[GY_QSPGS_RC_LEN], uint8_t *out)
{
    const struct gy_suite_desc *desc = wire_hybrid_desc(suite_id);

    if (desc == NULL || uid == NULL || rc_open == NULL || out == NULL)
        return GY_ERR_ARG;
    if (uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;

    /* C_UID = H(domain || r_c || UID). */
    return wire_domain_hash(desc, suite_id, GY_QSPGS_LBL_CUID, rc_open,
                            GY_QSPGS_RC_LEN, uid, uidlen, out);
}

int
gy_qspgs_vkpsdn_hash(uint8_t suite_id, const uint8_t *vkr, uint8_t *out)
{
    const struct gy_suite_desc *desc = wire_hybrid_desc(suite_id);

    if (desc == NULL || vkr == NULL || out == NULL)
        return GY_ERR_ARG;

    /* H(vkpsdn) = H(domain || vkr). */
    return wire_domain_hash(desc, suite_id, GY_QSPGS_LBL_VKHASH, vkr,
                            desc->dsa_pk_len, NULL, 0, out);
}

int
gy_qspgs_vkpsdn_hash_check(uint8_t suite_id, const uint8_t *vkr,
                           const uint8_t *stored_hash)
{
    const struct gy_suite_desc *desc = wire_hybrid_desc(suite_id);
    uint8_t h[GY_QSPGS_HASH_MAX];
    int rc;

    if (desc == NULL || vkr == NULL || stored_hash == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_vkpsdn_hash(suite_id, vkr, h);
    if (rc != GY_OK)
        return rc;
    rc = gy_const_memcmp(h, stored_hash, desc->hash_len) == 0 ? GY_OK
                                                              : GY_ERR_VERIFY;
    gy_secure_zero(h, sizeof(h));
    return rc;
}

/* ---- header (item 1) ---------------------------------------------------- */

int
gy_qspgs_header_encode(const struct gy_qspgs_core *core, uint8_t *out,
                       size_t cap, size_t *outlen)
{
    size_t off, need;
    int rc;

    if (core == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(core->suite_id) == NULL)
        return GY_ERR_ARG;
    if (core->sa_ct == NULL && core->sa_ct_len != 0)
        return GY_ERR_ARG;
    if (core->join_ct == NULL && core->join_ct_len != 0)
        return GY_ERR_ARG;

    need = GY_QSPGS_OBJ_HDR_LEN + GY_QSPGS_GID_LEN + 2 + 1 + 4 + 4 +
           core->sa_ct_len + 1;
    if (core->join_ct_len != 0)
        need += 4 + core->join_ct_len;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_HEADER, core->suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    memcpy(out + off, core->gid, GY_QSPGS_GID_LEN);
    off += GY_QSPGS_GID_LEN;
    /* Format epoch (D-QGS-12): after GID, before the state version vMaj.  Being
     * inside the header, it is covered by the core signature. */
    gy_be16_put(out + off, core->format_version);
    off += 2;
    /* Field-AEAD epoch (SEC-v1.5.0 INFO-6): after the format epoch, before the
     * state version vMaj.  Admin-pinned at Create, immutable for the group's
     * life; inside the header, so covered by the core signature and enforced by
     * gy_qspgs_server_core_check. */
    out[off++] = core->aead_id;
    gy_be32_put(out + off, core->vmaj);
    off += 4;
    /* SEC-v1.5.0 LOW-1: fet is NOT carried here.  It is a gk-derived bearer
     * token the server enforces; keeping it inside the signed, byte-exact
     * served header disclosed it to any fetcher (including a leaver's
     * post-removal confirmation fetch).  It now rides the emit bundle's fet
     * field as a separate server record, never served back (QSPGS_SPEC 10.2
     * item 5). */
    gy_be32_put(out + off, (uint32_t)core->sa_ct_len);
    off += 4;
    if (core->sa_ct_len != 0) {
        memcpy(out + off, core->sa_ct, core->sa_ct_len);
        off += core->sa_ct_len;
    }
    /* join slot: present flag, then (only if present) length-prefixed blob. */
    out[off++] = core->join_ct_len != 0 ? 1 : 0;
    if (core->join_ct_len != 0) {
        gy_be32_put(out + off, (uint32_t)core->join_ct_len);
        off += 4;
        memcpy(out + off, core->join_ct, core->join_ct_len);
        off += core->join_ct_len;
    }
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_header_decode(struct gy_qspgs_core *core, const uint8_t *in,
                       size_t len, size_t *consumed)
{
    size_t off;
    uint32_t sal, jl;
    int rc;

    if (core == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(core->suite_id) == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_HEADER, core->suite_id, in, len);
    if (rc != GY_OK)
        return rc;

    off = GY_QSPGS_OBJ_HDR_LEN;
    /* Fixed prefix: gid || format_version || aead_id || vMaj || sa_ct_len.  fet
     * is no longer part of the header (SEC-v1.5.0 LOW-1); see the encoder. */
    if (len < off + GY_QSPGS_GID_LEN + 2 + 1 + 4 + 4)
        return GY_ERR_VERIFY;
    memcpy(core->gid, in + off, GY_QSPGS_GID_LEN);
    off += GY_QSPGS_GID_LEN;
    /* Format epoch (D-QGS-12): refuse a group whose capability epoch this build
     * does not implement, before consuming any of its state. */
    core->format_version = gy_be16_get(in + off);
    off += 2;
    if (core->format_version < GY_QSPGS_MIN_SUPPORTED_FORMAT_VERSION ||
        core->format_version > GY_QSPGS_MAX_SUPPORTED_FORMAT_VERSION)
        return GY_ERR_UNSUPPORTED;
    /* Field-AEAD epoch (SEC-v1.5.0 INFO-6): read here so members can open the
     * fields with the group's pinned AEAD.  The allowed-set and cross-version
     * immutability are enforced above the codec (gy_qspgs_server_core_check /
     * gy_custodian_qsgroup_create); the field layer rejects a non-group id. */
    core->aead_id = in[off];
    off += 1;
    core->vmaj = gy_be32_get(in + off);
    off += 4;
    sal = gy_be32_get(in + off);
    off += 4;
    if (sal > len - off)
        return GY_ERR_VERIFY;
    core->sa_ct = sal != 0 ? in + off : NULL;
    core->sa_ct_len = sal;
    off += sal;

    /* join present flag, then optional length-prefixed blob. */
    if (off + 1 > len)
        return GY_ERR_VERIFY;
    if (in[off] == 0) {
        off += 1;
        core->join_ct = NULL;
        core->join_ct_len = 0;
    } else if (in[off] == 1) {
        off += 1;
        if (off + 4 > len)
            return GY_ERR_VERIFY;
        jl = gy_be32_get(in + off);
        off += 4;
        if (jl == 0 || jl > len - off)
            return GY_ERR_VERIFY; /* present flag with an empty blob is invalid */
        core->join_ct = in + off;
        core->join_ct_len = jl;
        off += jl;
    } else {
        return GY_ERR_VERIFY; /* the flag is boolean. */
    }

    if (off != len)
        return GY_ERR_VERIFY; /* strict: no trailing bytes. */
    *consumed = off;
    return GY_OK;
}

/* ---- member list (item 2) ----------------------------------------------- */

int
gy_qspgs_member_list_encode(const struct gy_qspgs_core *core, uint8_t *out,
                            size_t cap, size_t *outlen)
{
    const struct gy_suite_desc *desc;
    size_t off, need, i, hlen;
    int rc;

    if (core == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(core->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    if (core->n_members > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_ARG;
    if (core->n_members != 0 && core->members == NULL)
        return GY_ERR_ARG;
    hlen = desc->hash_len;

    need = GY_QSPGS_OBJ_HDR_LEN + 1 + 2;
    for (i = 0; i < core->n_members; i++) {
        const struct gy_qspgs_member *m = &core->members[i];
        if (m->mct == NULL && m->mct_len != 0)
            return GY_ERR_ARG;
        if (m->admn > 1)
            return GY_ERR_ARG;
        if (m->mct_len > 0xffff)
            return GY_ERR_ARG;
        need += hlen + 1 + 2 + m->mct_len;
    }
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_MEMBER_LIST, core->suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    out[off++] = (uint8_t)hlen;
    gy_be16_put(out + off, (uint16_t)core->n_members);
    off += 2;
    for (i = 0; i < core->n_members; i++) {
        const struct gy_qspgs_member *m = &core->members[i];
        memcpy(out + off, m->cuid, hlen);
        off += hlen;
        out[off++] = m->admn;
        gy_be16_put(out + off, (uint16_t)m->mct_len);
        off += 2;
        if (m->mct_len != 0) {
            memcpy(out + off, m->mct, m->mct_len);
            off += m->mct_len;
        }
    }
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_member_list_decode(struct gy_qspgs_core *core,
                            struct gy_qspgs_member *out, size_t out_cap,
                            const uint8_t *in, size_t len, size_t *consumed)
{
    const struct gy_suite_desc *desc;
    size_t off, i, hlen, n;
    int rc;

    if (core == NULL || out == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(core->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_MEMBER_LIST, core->suite_id, in, len);
    if (rc != GY_OK)
        return rc;
    hlen = desc->hash_len;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + 1 + 2 > len)
        return GY_ERR_VERIFY;
    if (in[off] != (uint8_t)hlen)
        return GY_ERR_VERIFY; /* the inline hash length must match the tier. */
    off += 1;
    n = gy_be16_get(in + off);
    off += 2;
    if (n > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_VERIFY;
    if (n > out_cap)
        return GY_ERR_TOOLONG;

    memset(out, 0, out_cap * sizeof(*out));
    for (i = 0; i < n; i++) {
        struct gy_qspgs_member *m = &out[i];
        uint32_t mlen;

        if (off + hlen + 1 + 2 > len)
            goto malformed;
        memcpy(m->cuid, in + off, hlen);
        off += hlen;
        if (in[off] > 1)
            goto malformed; /* admn is boolean. */
        m->admn = in[off];
        off += 1;
        mlen = gy_be16_get(in + off);
        off += 2;
        if (mlen > len - off)
            goto malformed;
        m->mct = mlen != 0 ? in + off : NULL;
        m->mct_len = mlen;
        off += mlen;
    }
    if (off != len)
        goto malformed; /* strict: exact length. */

    core->members = out;
    core->n_members = n;
    *consumed = off;
    return GY_OK;

malformed:
    memset(out, 0, out_cap * sizeof(*out));
    return GY_ERR_VERIFY;
}

/* ---- vk-lst (item 3) ---------------------------------------------------- */

int
gy_qspgs_vk_lst_encode(const struct gy_qspgs_core *core, uint8_t *out,
                       size_t cap, size_t *outlen)
{
    const struct gy_suite_desc *desc;
    size_t off, need, hlen;
    int rc;

    if (core == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(core->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    if (core->n_vk > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_ARG;
    if (core->n_vk != 0 && core->vkhash == NULL)
        return GY_ERR_ARG;
    hlen = desc->hash_len;

    need = GY_QSPGS_OBJ_HDR_LEN + 1 + 2 + core->n_vk * hlen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_VK_LST, core->suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    out[off++] = (uint8_t)hlen;
    gy_be16_put(out + off, (uint16_t)core->n_vk);
    off += 2;
    if (core->n_vk != 0) {
        memcpy(out + off, core->vkhash, core->n_vk * hlen);
        off += core->n_vk * hlen;
    }
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_vk_lst_decode(struct gy_qspgs_core *core, const uint8_t *in,
                       size_t len, size_t *consumed)
{
    const struct gy_suite_desc *desc;
    size_t off, hlen, n;
    int rc;

    if (core == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(core->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_VK_LST, core->suite_id, in, len);
    if (rc != GY_OK)
        return rc;
    hlen = desc->hash_len;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + 1 + 2 > len)
        return GY_ERR_VERIFY;
    if (in[off] != (uint8_t)hlen)
        return GY_ERR_VERIFY;
    off += 1;
    n = gy_be16_get(in + off);
    off += 2;
    if (n > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_VERIFY;
    if (len != off + n * hlen)
        return GY_ERR_VERIFY; /* strict: exact length. */

    core->vkhash = n != 0 ? in + off : NULL;
    core->n_vk = n;
    *consumed = len;
    return GY_OK;
}

/* ---- core signature (item 4) -------------------------------------------- */

int
gy_qspgs_core_tbs(const struct gy_qspgs_core *core, uint32_t signer_index,
                  uint8_t *out, size_t cap, size_t *outlen)
{
    size_t off, w;
    int rc;

    if (core == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(core->suite_id) == NULL)
        return GY_ERR_ARG;

    /* signer_index. */
    if (cap < 4)
        return GY_ERR_TOOLONG;
    gy_be32_put(out, signer_index);
    off = 4;

    /* header || member-list || vk-lst, each a full tagged object. */
    rc = gy_qspgs_header_encode(core, out + off, cap - off, &w);
    if (rc != GY_OK)
        return rc;
    off += w;
    rc = gy_qspgs_member_list_encode(core, out + off, cap - off, &w);
    if (rc != GY_OK)
        return rc;
    off += w;
    rc = gy_qspgs_vk_lst_encode(core, out + off, cap - off, &w);
    if (rc != GY_OK)
        return rc;
    off += w;

    /* vMaj || last_vMin (vMaj is also inside the header; the spec item lists
     * it explicitly, so it is bound here as well). */
    if (cap - off < 8)
        return GY_ERR_TOOLONG;
    gy_be32_put(out + off, core->vmaj);
    off += 4;
    gy_be32_put(out + off, core->last_vmin);
    off += 4;

    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_core_sig_encode(uint8_t suite_id, uint32_t signer_index,
                         uint32_t last_vmin, const uint8_t *sig, size_t sig_len,
                         uint8_t *out, size_t cap, size_t *outlen)
{
    size_t off, need;
    int rc;

    if (sig == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(suite_id) == NULL)
        return GY_ERR_ARG;
    if (sig_len == 0 || sig_len > 0xffff)
        return GY_ERR_ARG;

    need = GY_QSPGS_OBJ_HDR_LEN + 4 + 4 + 2 + sig_len;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_CORE_SIG, suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    gy_be32_put(out + off, signer_index);
    off += 4;
    gy_be32_put(out + off, last_vmin);
    off += 4;
    gy_be16_put(out + off, (uint16_t)sig_len);
    off += 2;
    memcpy(out + off, sig, sig_len);
    off += sig_len;
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_core_sig_decode(uint8_t suite_id, const uint8_t *in, size_t len,
                         uint32_t *signer_index, uint32_t *last_vmin,
                         const uint8_t **sig, size_t *sig_len, size_t *consumed)
{
    const struct gy_suite_desc *desc;
    size_t off;
    uint32_t sl;
    int rc;

    if (in == NULL || signer_index == NULL || last_vmin == NULL ||
        sig == NULL || sig_len == NULL || consumed == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_CORE_SIG, suite_id, in, len);
    if (rc != GY_OK)
        return rc;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + 4 + 4 + 2 > len)
        return GY_ERR_VERIFY;
    *signer_index = gy_be32_get(in + off);
    off += 4;
    *last_vmin = gy_be32_get(in + off);
    off += 4;
    sl = gy_be16_get(in + off);
    off += 2;
    /* strict: exact length, and the signature width is the fixed tier width
     * (canonical encoding; the verifier hands this length to liboqs). */
    if (sl != desc->dsa_sig_len || len != off + sl)
        return GY_ERR_VERIFY;
    *sig = in + off;
    *sig_len = sl;
    *consumed = len;
    return GY_OK;
}

int
gy_qspgs_core_verify(const struct gy_qspgs_core *core, uint32_t signer_index,
                     const uint8_t *vkr, const uint8_t *sig, size_t sig_len,
                     uint8_t *scratch, size_t scratch_cap)
{
    static const uint8_t ctx[] = GY_QSPGS_CTX_CORE;
    size_t tbslen;
    int rc;

    if (core == NULL || vkr == NULL || sig == NULL || scratch == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_core_tbs(core, signer_index, scratch, scratch_cap, &tbslen);
    if (rc != GY_OK)
        return rc;

    /* The KR verifier passes the FIXED tier signature length to liboqs, so the
     * declared width MUST equal it or liboqs reads past the wire buffer. */
    switch (core->suite_id) {
    case GY_SUITE_H25519_512:
        if (sig_len != GY_KR44_SIG)
            return GY_ERR_VERIFY;
        rc = gy_kr44_verify(sig, vkr, scratch, tbslen, ctx, sizeof(ctx) - 1);
        break;
    case GY_SUITE_H448_1024:
        if (sig_len != GY_KR87_SIG)
            return GY_ERR_VERIFY;
        rc = gy_kr87_verify(sig, vkr, scratch, tbslen, ctx, sizeof(ctx) - 1);
        break;
    default:
        rc = GY_ERR_ARG;
        break;
    }
    return rc == GY_OK ? GY_OK : GY_ERR_VERIFY;
}

/* ---- appendix (item 5) -------------------------------------------------- */

static int
apx_line_type_ok(uint8_t t)
{
    return t >= GY_QAPX_LEAVE && t <= GY_QAPX_JOIN;
}

int
gy_qspgs_apx_line_tbs(const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
                      uint32_t vmin, uint8_t line_type, uint32_t author_index,
                      const uint8_t *payload, size_t payload_len, uint8_t *out,
                      size_t cap, size_t *outlen)
{
    size_t off;

    if (gid == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (payload == NULL && payload_len != 0)
        return GY_ERR_ARG;
    if (!apx_line_type_ok(line_type))
        return GY_ERR_ARG;
    if (cap < GY_QSPGS_GID_LEN + 4 + 4 + 1 + 4 + payload_len)
        return GY_ERR_TOOLONG;

    /* apx-hdr = GID || vMaj || vMin, then the line (D-QGS-13 E1: bind the
     * appendix header so an old signed line cannot be replayed at a later
     * version; [CFG+] Fig. 12/16 sign Sgn(apx-hdr, line)). */
    memcpy(out, gid, GY_QSPGS_GID_LEN);
    off = GY_QSPGS_GID_LEN;
    gy_be32_put(out + off, vmaj);
    off += 4;
    gy_be32_put(out + off, vmin);
    off += 4;
    out[off] = line_type;
    off += 1;
    gy_be32_put(out + off, author_index);
    off += 4;
    if (payload_len != 0)
        memcpy(out + off, payload, payload_len);
    off += payload_len;
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_apx_line_verify(uint8_t suite_id, const uint8_t gid[GY_QSPGS_GID_LEN],
                         uint32_t vmaj, uint32_t vmin,
                         const struct gy_qspgs_apx_line *line,
                         const uint8_t *vkr, uint8_t *scratch,
                         size_t scratch_cap)
{
    static const uint8_t ctx[] = GY_QSPGS_CTX_APPENDIX;
    size_t tbslen;
    int rc;

    if (gid == NULL || line == NULL || vkr == NULL || scratch == NULL ||
        line->sig == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(suite_id) == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_apx_line_tbs(
        gid, vmaj, vmin, line->line_type, line->author_index, line->payload,
        line->payload_len, scratch, scratch_cap, &tbslen);
    if (rc != GY_OK)
        return rc;

    /* As in gy_qspgs_core_verify: the declared signature width MUST equal the
     * fixed tier length the KR verifier hands to liboqs. */
    switch (suite_id) {
    case GY_SUITE_H25519_512:
        if (line->sig_len != GY_KR44_SIG)
            return GY_ERR_VERIFY;
        rc = gy_kr44_verify(line->sig, vkr, scratch, tbslen, ctx,
                            sizeof(ctx) - 1);
        break;
    case GY_SUITE_H448_1024:
        if (line->sig_len != GY_KR87_SIG)
            return GY_ERR_VERIFY;
        rc = gy_kr87_verify(line->sig, vkr, scratch, tbslen, ctx,
                            sizeof(ctx) - 1);
        break;
    default:
        return GY_ERR_ARG;
    }
    return rc == GY_OK ? GY_OK : GY_ERR_VERIFY;
}

int
gy_qspgs_leave_token_tbs(const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                         uint8_t *out, size_t cap, size_t *outlen)
{
    if (gid == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (cap < GY_QSPGS_GID_LEN + 4)
        return GY_ERR_TOOLONG;
    memcpy(out, gid, GY_QSPGS_GID_LEN);
    gy_be32_put(out + GY_QSPGS_GID_LEN, k);
    *outlen = GY_QSPGS_GID_LEN + 4;
    return GY_OK;
}

int
gy_qspgs_leave_token_verify(uint8_t suite_id,
                            const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                            const uint8_t *sig, size_t sig_len,
                            const uint8_t *vkr)
{
    static const uint8_t ctx[] = GY_QSPGS_CTX_LEAVEFETCH;
    uint8_t tbs[GY_QSPGS_GID_LEN + 4];
    size_t tbslen;
    int rc;

    if (gid == NULL || sig == NULL || vkr == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(suite_id) == NULL)
        return GY_ERR_ARG;
    rc = gy_qspgs_leave_token_tbs(gid, k, tbs, sizeof(tbs), &tbslen);
    if (rc != GY_OK)
        return rc;

    switch (suite_id) {
    case GY_SUITE_H25519_512:
        if (sig_len != GY_KR44_SIG)
            return GY_ERR_ARG;
        rc = gy_kr44_verify(sig, vkr, tbs, tbslen, ctx, sizeof(ctx) - 1);
        break;
    case GY_SUITE_H448_1024:
        if (sig_len != GY_KR87_SIG)
            return GY_ERR_ARG;
        rc = gy_kr87_verify(sig, vkr, tbs, tbslen, ctx, sizeof(ctx) - 1);
        break;
    default:
        return GY_ERR_ARG;
    }
    return rc == GY_OK ? GY_OK : GY_ERR_VERIFY;
}

int
gy_qspgs_appendix_encode(const struct gy_qspgs_appendix *apx, uint8_t *out,
                         size_t cap, size_t *outlen)
{
    size_t off, need, i;
    int rc;

    if (apx == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(apx->suite_id) == NULL)
        return GY_ERR_ARG;
    if (apx->n_lines > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_ARG;
    if (apx->n_lines != 0 && apx->lines == NULL)
        return GY_ERR_ARG;

    need = GY_QSPGS_OBJ_HDR_LEN + GY_QSPGS_GID_LEN + 4 + 4 + 2;
    for (i = 0; i < apx->n_lines; i++) {
        const struct gy_qspgs_apx_line *l = &apx->lines[i];
        if (!apx_line_type_ok(l->line_type))
            return GY_ERR_ARG;
        if (l->payload == NULL && l->payload_len != 0)
            return GY_ERR_ARG;
        if (l->sig == NULL || l->sig_len == 0)
            return GY_ERR_ARG;
        if (l->payload_len > 0xffff || l->sig_len > 0xffff)
            return GY_ERR_ARG;
        need += 1 + 4 + 2 + l->payload_len + 2 + l->sig_len;
    }
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_APPENDIX, apx->suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    memcpy(out + off, apx->gid, GY_QSPGS_GID_LEN);
    off += GY_QSPGS_GID_LEN;
    gy_be32_put(out + off, apx->vmaj);
    off += 4;
    gy_be32_put(out + off, apx->vmin);
    off += 4;
    gy_be16_put(out + off, (uint16_t)apx->n_lines);
    off += 2;
    for (i = 0; i < apx->n_lines; i++) {
        const struct gy_qspgs_apx_line *l = &apx->lines[i];
        out[off++] = l->line_type;
        gy_be32_put(out + off, l->author_index);
        off += 4;
        gy_be16_put(out + off, (uint16_t)l->payload_len);
        off += 2;
        if (l->payload_len != 0) {
            memcpy(out + off, l->payload, l->payload_len);
            off += l->payload_len;
        }
        gy_be16_put(out + off, (uint16_t)l->sig_len);
        off += 2;
        memcpy(out + off, l->sig, l->sig_len);
        off += l->sig_len;
    }
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_appendix_decode(struct gy_qspgs_appendix *apx,
                         struct gy_qspgs_apx_line *out, size_t out_cap,
                         const uint8_t *in, size_t len, size_t *consumed)
{
    const struct gy_suite_desc *desc;
    size_t off, i, n;
    int rc;

    if (apx == NULL || out == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;
    desc = wire_hybrid_desc(apx->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_APPENDIX, apx->suite_id, in, len);
    if (rc != GY_OK)
        return rc;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + GY_QSPGS_GID_LEN + 4 + 4 + 2 > len)
        return GY_ERR_VERIFY;
    memcpy(apx->gid, in + off, GY_QSPGS_GID_LEN);
    off += GY_QSPGS_GID_LEN;
    apx->vmaj = gy_be32_get(in + off);
    off += 4;
    apx->vmin = gy_be32_get(in + off);
    off += 4;
    n = gy_be16_get(in + off);
    off += 2;
    if (n > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_VERIFY;
    if (n > out_cap)
        return GY_ERR_TOOLONG;

    memset(out, 0, out_cap * sizeof(*out));
    for (i = 0; i < n; i++) {
        struct gy_qspgs_apx_line *l = &out[i];
        uint32_t pl, sl;

        if (off + 1 + 4 + 2 > len)
            goto malformed;
        l->line_type = in[off++];
        if (!apx_line_type_ok(l->line_type))
            goto malformed;
        l->author_index = gy_be32_get(in + off);
        off += 4;
        pl = gy_be16_get(in + off);
        off += 2;
        if (pl > len - off)
            goto malformed;
        l->payload = pl != 0 ? in + off : NULL;
        l->payload_len = pl;
        off += pl;
        if (off + 2 > len)
            goto malformed;
        sl = gy_be16_get(in + off);
        off += 2;
        /* the signature width is the fixed tier width (canonical; the verifier
         * hands this length to liboqs). */
        if (sl != desc->dsa_sig_len || sl > len - off)
            goto malformed;
        l->sig = in + off;
        l->sig_len = sl;
        off += sl;
    }
    if (off != len)
        goto malformed; /* strict: exact length. */

    apx->lines = out;
    apx->n_lines = n;
    *consumed = off;
    return GY_OK;

malformed:
    memset(out, 0, out_cap * sizeof(*out));
    return GY_ERR_VERIFY;
}

/* ---- invite queue (item 6) ---------------------------------------------- */

int
gy_qspgs_invite_queue_encode(uint8_t suite_id,
                             const struct gy_qspgs_invite_entry *entries,
                             size_t n, uint8_t *out, size_t cap, size_t *outlen)
{
    size_t off, need, i;
    int rc;

    if (out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(suite_id) == NULL)
        return GY_ERR_ARG;
    if (n > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_ARG;
    if (n != 0 && entries == NULL)
        return GY_ERR_ARG;

    need = GY_QSPGS_OBJ_HDR_LEN + 2;
    for (i = 0; i < n; i++) {
        if (entries[i].ct == NULL || entries[i].ct_len == 0)
            return GY_ERR_ARG; /* an invite entry is never empty. */
        need += 4 + entries[i].ct_len;
    }
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_INVITE_QUEUE, suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    gy_be16_put(out + off, (uint16_t)n);
    off += 2;
    for (i = 0; i < n; i++) {
        gy_be32_put(out + off, (uint32_t)entries[i].ct_len);
        off += 4;
        memcpy(out + off, entries[i].ct, entries[i].ct_len);
        off += entries[i].ct_len;
    }
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_invite_queue_decode(uint8_t suite_id,
                             struct gy_qspgs_invite_entry *out, size_t out_cap,
                             const uint8_t *in, size_t len, size_t *n_out,
                             size_t *consumed)
{
    size_t off, i, n;
    int rc;

    if (out == NULL || in == NULL || n_out == NULL || consumed == NULL)
        return GY_ERR_ARG;
    if (wire_hybrid_desc(suite_id) == NULL)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_INVITE_QUEUE, suite_id, in, len);
    if (rc != GY_OK)
        return rc;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + 2 > len)
        return GY_ERR_VERIFY;
    n = gy_be16_get(in + off);
    off += 2;
    if (n > GY_QSPGS_MAX_ENTRIES)
        return GY_ERR_VERIFY;
    if (n > out_cap)
        return GY_ERR_TOOLONG;

    memset(out, 0, out_cap * sizeof(*out));
    for (i = 0; i < n; i++) {
        uint32_t el;

        if (off + 4 > len)
            goto malformed;
        el = gy_be32_get(in + off);
        off += 4;
        if (el == 0 || el > len - off)
            goto malformed; /* an invite entry is never empty. */
        out[i].ct = in + off;
        out[i].ct_len = el;
        off += el;
    }
    if (off != len)
        goto malformed; /* strict: exact length. */

    *n_out = n;
    *consumed = off;
    return GY_OK;

malformed:
    memset(out, 0, out_cap * sizeof(*out));
    return GY_ERR_VERIFY;
}

/* ---- registration record (section 7.2, GY_QOBJ_ACCT) -------------------- */

int
gy_qspgs_acct_encode(uint8_t suite_id, const uint8_t *vkb, const uint8_t *acq,
                     uint64_t ep, const uint8_t *ed_sig, size_t ed_sig_len,
                     const uint8_t *mldsa_sig, size_t mldsa_sig_len,
                     uint8_t *out, size_t cap, size_t *outlen)
{
    size_t off, need, vkblen, mklen;
    int rc;

    if (vkb == NULL || acq == NULL || ed_sig == NULL || mldsa_sig == NULL ||
        out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    mklen = gy_qspgs_master_key_len(suite_id);
    if (vkblen == 0 || mklen == 0)
        return GY_ERR_ARG;
    if (ed_sig_len == 0 || ed_sig_len > 0xffff || mldsa_sig_len == 0 ||
        mldsa_sig_len > 0xffff)
        return GY_ERR_ARG;

    need = GY_QSPGS_OBJ_HDR_LEN + vkblen + mklen + 8 + 2 + ed_sig_len + 2 +
           mldsa_sig_len;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = obj_put_header(GY_QOBJ_ACCT, suite_id, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_QSPGS_OBJ_HDR_LEN;
    memcpy(out + off, vkb, vkblen);
    off += vkblen;
    memcpy(out + off, acq, mklen);
    off += mklen;
    gy_be64_put(out + off, ep);
    off += 8;
    gy_be16_put(out + off, (uint16_t)ed_sig_len);
    off += 2;
    memcpy(out + off, ed_sig, ed_sig_len);
    off += ed_sig_len;
    gy_be16_put(out + off, (uint16_t)mldsa_sig_len);
    off += 2;
    memcpy(out + off, mldsa_sig, mldsa_sig_len);
    off += mldsa_sig_len;
    *outlen = off;
    return GY_OK;
}

int
gy_qspgs_acct_decode(uint8_t suite_id, const uint8_t *in, size_t len,
                     const uint8_t **vkb, const uint8_t **acq, uint64_t *ep,
                     const uint8_t **ed_sig, size_t *ed_sig_len,
                     const uint8_t **mldsa_sig, size_t *mldsa_sig_len,
                     size_t *consumed)
{
    size_t off, vkblen, mklen;
    uint32_t esl, msl;
    int rc;

    if (in == NULL || vkb == NULL || acq == NULL || ep == NULL ||
        ed_sig == NULL || ed_sig_len == NULL || mldsa_sig == NULL ||
        mldsa_sig_len == NULL || consumed == NULL)
        return GY_ERR_ARG;
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    mklen = gy_qspgs_master_key_len(suite_id);
    if (vkblen == 0 || mklen == 0)
        return GY_ERR_ARG;
    rc = obj_check_header(GY_QOBJ_ACCT, suite_id, in, len);
    if (rc != GY_OK)
        return rc;

    off = GY_QSPGS_OBJ_HDR_LEN;
    if (off + vkblen + mklen + 8 + 2 > len)
        return GY_ERR_VERIFY;
    *vkb = in + off;
    off += vkblen;
    *acq = in + off;
    off += mklen;
    *ep = gy_be64_get(in + off);
    off += 8;
    esl = gy_be16_get(in + off);
    off += 2;
    if (esl == 0 || esl > len - off)
        return GY_ERR_VERIFY;
    *ed_sig = in + off;
    *ed_sig_len = esl;
    off += esl;
    if (off + 2 > len)
        return GY_ERR_VERIFY;
    msl = gy_be16_get(in + off);
    off += 2;
    if (msl == 0 || len != off + msl)
        return GY_ERR_VERIFY; /* strict: exact length, non-empty signatures. */
    *mldsa_sig = in + off;
    *mldsa_sig_len = msl;
    off += msl;
    *consumed = off;
    return GY_OK;
}
