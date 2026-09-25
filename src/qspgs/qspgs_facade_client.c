/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS public client facade (geryon_qspgs.h).  The quantum-safe
 * group client EXTENDS the custodian, exactly as the classical
 * group_facade_client.c does: QSPGS secret state (the per-user main key, the
 * KR-ML-DSA base pair, and each group key) seals into the custodian's existing
 * store, under a reserved record-kind band, via a small adapter that forwards
 * to c->sealed_store (which seals under the custodian KEK).  So this target
 * links geryon_proto and reaches the custodian through its internal header.
 *
 * The section-5 composition engine (qspgs_ops.c), the key hierarchy
 * (qspgs_keys.c), and the *_stored persistence wrappers (qspgs_store.c) are
 * unchanged: they operate over the gy_qspgs_store trio, which here is bound to
 * the custodian rather than to a separate application store.  The two
 * identity-anchored objects are signed via the custodian's typed QSPGS signers
 * (gy_custodian_qspgs_sign_reguser / _invaccept), which build the objects and
 * pick their labels themselves, so the identity keys never leave the custodian
 * and can sign only those two canonical objects.  This increment lands the
 * store adapter and the accessors; the client operations follow.
 */

#include <stdlib.h>
#include <string.h>

#include "geryon_qspgs.h"

#include "custodian.h"   /* struct gy_custodian + the identity dual-sign seam */
#include "qspgs_field.h" /* ek-field seals, member ct, and the join slot */
#include "qspgs_keys.h"  /* muk / base-pair derivations and tier sizes */
#include "qspgs_ops.h"   /* section-5 ops, GY_QSPGS_PERS_*_MAX */
#include "qspgs_store.h" /* struct gy_qspgs_store, GY_QREC_*, *_store/_load */
#include "qspgs_wire.h"  /* GY_QSPGS_GID_LEN, gy_qspgs_acct_encode/_verify */

#include "error.h"
#include "qspgs_hooks.h" /* GY_TEST_HOOKS forging seams (compiled out of prod) */
#include "rng.h"         /* gy_random_bytes (fresh muk) */
#include "util.h"        /* gy_secure_zero */

/*
 * The public constants are the QSPGS-internal constants under a stable public
 * name; pin them equal so the two can never drift apart silently.
 */
_Static_assert(GY_QSGROUP_GID_LEN == GY_QSPGS_GID_LEN,
               "public GID length must match the wire GID length");
_Static_assert(GY_QSGROUP_UID_MAX == GY_QSPGS_UID_MAX,
               "public UID bound must match the internal UID bound");
_Static_assert(GY_QSGROUP_FORMAT_VERSION == GY_QSPGS_FORMAT_VERSION,
               "public format epoch must match the wire format epoch");
_Static_assert(GY_QSGROUP_ACCT_MAX >= GY_QSPGS_OBJ_HDR_LEN + GY_QSPGS_VKB_MAX +
                                          GY_QSPGS_MASTER_KEY_MAX + 8 + 2 +
                                          GY_QSPGS_PERS_ED_SIG_MAX + 2 +
                                          GY_QSPGS_PERS_MLDSA_SIG_MAX,
               "public ACCT bound must cover the largest wire record");
_Static_assert(GY_QSGROUP_USER_KEY_MAX == GY_QSPGS_MASTER_KEY_MAX,
               "public user-key bound must match the internal 2*kappa width");

/* ---- custodian-store adapter (QSPGS records -> sealed_store) ------------- */

static int
adap_load(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
          size_t id_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_custodian *c = ctx;

    return c->sealed_store.load_record(
        c->sealed_store.ctx, GY_QSGROUP_STORE_KIND_MIN + (int)kind - 1, id,
        id_len, out, cap, out_len);
}

static int
adap_store(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
           size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct gy_custodian *c = ctx;

    return c->sealed_store.store_record(
        c->sealed_store.ctx, GY_QSGROUP_STORE_KIND_MIN + (int)kind - 1, id,
        id_len, blob, blob_len);
}

static int
adap_remove(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
            size_t id_len)
{
    struct gy_custodian *c = ctx;

    return c->sealed_store.delete_record(
        c->sealed_store.ctx, GY_QSGROUP_STORE_KIND_MIN + (int)kind - 1, id,
        id_len);
}

static void
mk_store(struct gy_custodian *c, struct gy_qspgs_store *st)
{
    st->ctx = c;
    st->load = adap_load;
    st->store = adap_store;
    st->remove = adap_remove;
}

/*
 * Shared guard: a QSPGS call needs an unlocked, hybrid-suite custodian.  A
 * classical-suite custodian's group type is the [CPZ] construction, reached
 * through geryon_group.h, so QSPGS calls on it are GY_ERR_UNSUPPORTED.
 */
static int
qsgroup_guard(gy_custodian *c)
{
    if (c == NULL)
        return GY_ERR_ARG;
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (c->desc == NULL || !c->desc->is_hybrid)
        return GY_ERR_UNSUPPORTED;
    return GY_OK;
}

/* ---- accessors ---------------------------------------------------------- */

int
gy_custodian_qsgroup_self_uid(gy_custodian *c, uint8_t *out, size_t *out_len)
{
    int rc;

    if (out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    if (c->self_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_STATE;
    if (out == NULL) {
        *out_len = c->self_uid_len;
        return GY_OK;
    }
    if (*out_len < c->self_uid_len)
        return GY_ERR_ARG;
    memcpy(out, c->self_uid, c->self_uid_len);
    *out_len = c->self_uid_len;
    return GY_OK;
}

int
gy_custodian_qsgroup_format_version(gy_custodian *c,
                                    const uint8_t gid[GY_QSGROUP_GID_LEN],
                                    uint16_t *out_version)
{
    struct gy_qspgs_store st;
    int rc;

    if (gid == NULL || out_version == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    mk_store(c, &st);
    return gy_qspgs_format_version_load(&st, GY_QREC_GROUP_KEY, gid,
                                        GY_QSPGS_GID_LEN, out_version);
}

/* ---- registration and acquaintance -------------------------------------- */

/*
 * Mint-and-seal the per-user QSPGS hierarchy (the main key muk and the KR-ML-DSA
 * base pair) into the custodian store on first use, then load them, all keyed on
 * the custodian self-UID.  Idempotent: an already-provisioned user is loaded as
 * is.  This mirrors group creation minting its group key inline (there is no
 * separate provision step).  muk / skb / vkb receive the loaded material.
 */
static int
provision_user(gy_custodian *c, struct gy_qspgs_store *st, uint8_t *muk,
               uint8_t *skb, uint8_t *vkb)
{
    uint8_t suite = c->desc->suite_id;
    const uint8_t *uid = c->self_uid;
    size_t uidlen = c->self_uid_len;
    size_t mklen = gy_qspgs_master_key_len(suite);
    size_t mkout;
    int rc;

    if (mklen == 0)
        return GY_ERR_UNSUPPORTED;

    rc = gy_qspgs_muk_load(st, suite, uid, uidlen, muk, GY_QSPGS_MASTER_KEY_MAX,
                           &mkout);
    if (rc == GY_ERR_NOT_FOUND) {
        rc = gy_random_bytes(muk, mklen);
        if (rc == GY_OK)
            rc = gy_qspgs_muk_store(st, suite, uid, uidlen, muk);
    }
    if (rc != GY_OK)
        return rc;

    rc = gy_qspgs_base_key_load(st, suite, uid, uidlen, skb, vkb);
    if (rc == GY_ERR_NOT_FOUND) {
        rc = gy_qspgs_base_keygen(suite, vkb, skb);
        if (rc == GY_OK)
            rc = gy_qspgs_base_key_store(st, suite, uid, uidlen, skb, vkb);
    }
    return rc;
}

int
gy_custodian_qsgroup_register(gy_custodian *c, uint64_t ep, uint8_t *out,
                              size_t *out_len)
{
    struct gy_qspgs_store st;
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t acq[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ed_sig[GY_QSPGS_PERS_ED_SIG_MAX];
    uint8_t mldsa_sig[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    uint8_t suite;
    size_t ed_len, mldsa_len;
    int rc;

    if (out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;

    /* Size query: the record width is fixed by the tier, no work needed. */
    if (out == NULL) {
        *out_len = GY_QSPGS_OBJ_HDR_LEN + gy_qspgs_base_vkb_len(suite) +
                   gy_qspgs_master_key_len(suite) + 8 + 2 + c->desc->sig_len +
                   2 + c->desc->dsa_sig_len;
        return GY_OK;
    }
    if (c->self_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_STATE;
    mk_store(c, &st);

    rc = provision_user(c, &st, muk, skb, vkb);
    if (rc != GY_OK)
        goto out;

    /* Derive uk(ep) -> acq, then have the custodian build and sign (vkbase,
     * acq): it owns the object layout so no identity secret key leaves it and
     * the key signs only this canonical object (SEC-v1.5.0 LOW-6). */
    rc = gy_qspgs_derive_uk(suite, muk, ep, uk);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_acq(suite, uk, acq);
    if (rc != GY_OK)
        goto out;
    rc = gy_custodian_qspgs_sign_reguser(c, vkb, acq, ed_sig, &ed_len,
                                         mldsa_sig, &mldsa_len);
    if (rc != GY_OK)
        goto out;

    rc = gy_qspgs_acct_encode(suite, vkb, acq, ep, ed_sig, ed_len, mldsa_sig,
                              mldsa_len, out, *out_len, out_len);
out:
    gy_secure_zero(muk, sizeof(muk));
    gy_secure_zero(skb, sizeof(skb));
    gy_secure_zero(uk, sizeof(uk));
    gy_secure_zero(acq, sizeof(acq));
    return rc;
}

int
gy_custodian_qsgroup_accept_acquaintance(
    gy_custodian *c, const uint8_t *granter_uid, size_t granter_uid_len,
    const uint8_t *granter_curve_pk, const uint8_t *granter_mldsa_pk,
    const uint8_t *acct, size_t acct_len, const uint8_t *uk, size_t uk_len)
{
    struct gy_qspgs_store st;
    const uint8_t *vkb, *acq;
    uint8_t acq_check[GY_QSPGS_MASTER_KEY_MAX];
    uint64_t ep;
    size_t mklen;
    uint8_t suite;
    int rc;

    if (granter_uid == NULL || granter_curve_pk == NULL ||
        granter_mldsa_pk == NULL || acct == NULL || uk == NULL)
        return GY_ERR_ARG;
    if (granter_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (uk_len != mklen)
        return GY_ERR_ARG;

    /* vkb / acq point into acct on success (zero-copy); seal them right away. */
    rc = gy_qspgs_acct_verify(suite, granter_curve_pk, granter_mldsa_pk, acct,
                              acct_len, &vkb, &acq, &ep);
    if (rc != GY_OK)
        return rc;

    /* IsCorrectUserKey (Fig. 8, D-QGS-13 E4): the conveyed uk must open the
     * attested acquaintance tag, acq == KDF(uk, "ACQ-Tag"). */
    rc = gy_qspgs_derive_acq(suite, uk, acq_check);
    if (rc != GY_OK)
        return rc;
    if (gy_const_memcmp(acq_check, acq, mklen) != 0) {
        gy_secure_zero(acq_check, sizeof(acq_check));
        return GY_ERR_VERIFY;
    }
    gy_secure_zero(acq_check, sizeof(acq_check));
    mk_store(c, &st);
    return gy_qspgs_acquaintance_store(&st, suite, granter_uid, granter_uid_len,
                                       vkb, acq, uk, ep);
}

int
gy_custodian_qsgroup_export_user_key(gy_custodian *c, uint64_t ep, uint8_t *out,
                                     size_t *out_len)
{
    struct gy_qspgs_store st;
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    size_t mklen;
    uint8_t suite;
    int rc;

    if (out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (out == NULL) {
        *out_len = mklen;
        return GY_OK;
    }
    if (*out_len < mklen)
        return (*out_len = mklen), GY_ERR_TOOLONG;
    if (c->self_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_STATE;
    mk_store(c, &st);

    /* uk = KDF(muk, "uk@" || ep) from the caller's OWN master user key: the
     * (UID, uk) a member conveys to an acquaintance (Fig. 8 GrantAcquaintance). */
    rc = provision_user(c, &st, muk, skb, vkb);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_uk(suite, muk, ep, uk);
    if (rc == GY_OK) {
        memcpy(out, uk, mklen);
        *out_len = mklen;
    }
    gy_secure_zero(muk, sizeof(muk));
    gy_secure_zero(skb, sizeof(skb));
    gy_secure_zero(uk, sizeof(uk));
    return rc;
}

/* ---- group creation and roster read ------------------------------------- */

/*
 * Assemble the sealed header plaintext ([CFG+] §3.2): the one-byte
 * settings prefix flags = b_add | b_attr<<1 | b_adm<<2 followed by the opaque
 * attributes, so a fetching client can read the gating bits CheckAppendixLine
 * needs.  attr may be NULL only when attr_len is 0.
 */
static int
settings_plaintext(uint8_t flags, const uint8_t *attr, size_t attr_len,
                   uint8_t *out, size_t cap, size_t *outlen)
{
    if (attr == NULL && attr_len != 0)
        return GY_ERR_ARG;
    if (attr_len > GY_QSGROUP_ATTR_MAX)
        return GY_ERR_TOOLONG;
    if (cap < 1 + attr_len)
        return GY_ERR_TOOLONG;
    out[0] = flags;
    if (attr_len != 0)
        memcpy(out + 1, attr, attr_len);
    *outlen = 1 + attr_len;
    return GY_OK;
}

int
gy_custodian_qsgroup_create(gy_custodian *c,
                            const uint8_t gid[GY_QSGROUP_GID_LEN], uint64_t ep,
                            uint8_t settings_flags, uint8_t aead_id,
                            const uint8_t *attr, size_t attr_len,
                            uint8_t *hdr_out, size_t *hdr_len,
                            uint8_t *member_list_out, size_t *member_list_len,
                            uint8_t *vk_lst_out, size_t *vk_lst_len,
                            uint8_t *sig_out, size_t *sig_len,
                            uint8_t fet_out[GY_QSGROUP_FET_LEN])
{
    struct gy_qspgs_store st;
    struct gy_qspgs_member_ctx mctx;
    struct gy_qspgs_member member;
    struct gy_qspgs_core core;
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t vkhash[GY_QSPGS_HASH_MAX];
    uint8_t mct_buf[512];
    uint8_t sa_pt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t sa_s[1 + GY_QSGROUP_ATTR_MAX + 64];
    uint8_t hdr_s[256 + GY_QSGROUP_ATTR_MAX], ml_s[512], vk_s[256], sig_s[8192],
        tbs[2048 + GY_QSGROUP_ATTR_MAX];
    size_t hn, mn, vn, sn, mctlen, sa_ptlen, sa_slen;
    uint8_t suite;
    int rc, query;

    if (gid == NULL || hdr_len == NULL || member_list_len == NULL ||
        vk_lst_len == NULL || sig_len == NULL)
        return GY_ERR_ARG;
    if (attr == NULL && attr_len != 0)
        return GY_ERR_ARG;
    if (attr_len > GY_QSGROUP_ATTR_MAX)
        return GY_ERR_TOOLONG;
    /* SEC-v1.5.0 INFO-6: the admin pins the group's field AEAD here, immutable
     * for the group's life.  Reject one outside the group-approved set before
     * any provisioning. */
    if (!gy_qspgs_group_aead_ok(aead_id))
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    if (c->self_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_STATE;
    suite = c->desc->suite_id;
    mk_store(c, &st);

    memset(&mctx, 0, sizeof(mctx));
    memset(&member, 0, sizeof(member));
    memset(&core, 0, sizeof(core));

    rc = provision_user(c, &st, muk, skb, vkb);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_uk(suite, muk, ep, uk);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_group_key_gen(suite, gk);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_ctx_open(&mctx, suite, gk, skb, vkb, c->self_uid,
                                  c->self_uid_len);
    if (rc != GY_OK)
        goto out;

    /* Assemble the founding core: self as the sole admin member, the caller's
     * initial settings + attributes sealed into the header, state version
     * (1, 0) at the format epoch. */
    core.suite_id = suite;
    memcpy(core.gid, gid, GY_QSGROUP_GID_LEN);
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    core.aead_id = aead_id;
    core.vmaj = 1;
    rc = gy_qspgs_derive_fet(suite, gk, core.fet);
    if (rc != GY_OK)
        goto out;
    rc = settings_plaintext(settings_flags, attr, attr_len, sa_pt,
                            sizeof(sa_pt), &sa_ptlen);
    if (rc != GY_OK)
        goto out;
    rc =
        gy_qspgs_field_seal(suite, aead_id, mctx.ek, GY_QSPGS_FIELD_HEADER, gid,
                            sa_pt, sa_ptlen, sa_s, sizeof(sa_s), &sa_slen);
    if (rc != GY_OK)
        goto out;
    core.sa_ct = sa_s;
    core.sa_ct_len = sa_slen;
    rc = gy_qspgs_member_build(
        suite, aead_id, mctx.ek, gid, mctx.rrs, c->self_uid, c->self_uid_len,
        uk, vkb, 1, &member, mct_buf, sizeof(mct_buf), &mctlen, vkhash);
    if (rc != GY_OK)
        goto out;
    core.members = &member;
    core.n_members = 1;
    core.vkhash = vkhash;
    core.n_vk = 1;
    core.last_vmin = 0;

    rc = gy_qspgs_header_encode(&core, hdr_s, sizeof(hdr_s), &hn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_list_encode(&core, ml_s, sizeof(ml_s), &mn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_vk_lst_encode(&core, vk_s, sizeof(vk_s), &vn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_core_sign(&core, 0, &mctx, sig_s, sizeof(sig_s), &sn, tbs,
                            sizeof(tbs));
    if (rc != GY_OK)
        goto out;

    /* Size query (any out NULL): report the four sizes, seal nothing. */
    query = (hdr_out == NULL || member_list_out == NULL || vk_lst_out == NULL ||
             sig_out == NULL);
    if (query) {
        *hdr_len = hn;
        *member_list_len = mn;
        *vk_lst_len = vn;
        *sig_len = sn;
        rc = GY_OK;
        goto out;
    }
    if (*hdr_len < hn || *member_list_len < mn || *vk_lst_len < vn ||
        *sig_len < sn) {
        *hdr_len = hn;
        *member_list_len = mn;
        *vk_lst_len = vn;
        *sig_len = sn;
        rc = GY_ERR_TOOLONG;
        goto out;
    }

    /* Capacities are sufficient: now seal the group key and copy the core out. */
    rc = gy_qspgs_group_key_store(&st, suite, gid, gk);
    if (rc != GY_OK)
        goto out;
    memcpy(hdr_out, hdr_s, hn);
    *hdr_len = hn;
    memcpy(member_list_out, ml_s, mn);
    *member_list_len = mn;
    memcpy(vk_lst_out, vk_s, vn);
    *vk_lst_len = vn;
    memcpy(sig_out, sig_s, sn);
    *sig_len = sn;
    /* Hand the fetch token to the deployer as a separate server record, not
     * inside the header (SEC-v1.5.0 LOW-1).  Optional: an admin can also derive
     * it later with gy_custodian_qsgroup_fetch_token. */
    if (fet_out != NULL)
        memcpy(fet_out, core.fet, GY_QSGROUP_FET_LEN);
    rc = GY_OK;
out:
    gy_qspgs_member_ctx_clear(&mctx);
    gy_secure_zero(muk, sizeof(muk));
    gy_secure_zero(skb, sizeof(skb));
    gy_secure_zero(uk, sizeof(uk));
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(mct_buf, sizeof(mct_buf));
    gy_secure_zero(sa_pt, sizeof(sa_pt));
    gy_secure_zero(sa_s, sizeof(sa_s));
    return rc;
}

/*
 * Resolve the signing admin's base verification key into vkb_out: the caller's
 * own (from the sealed base pair) when the signer is self, otherwise the copy
 * sealed by accept-acquaintance, keyed by the signer's UID.
 */
/*
 * Resolve a member's base verification key into vkb_out ([CFG+] Fig. 16
 * GetPseudoVkBase): the caller's own (from the sealed base pair) when the UID is
 * self; otherwise the copy sealed by accept-acquaintance, keyed by the UID; and,
 * failing that, the vkbase carried in a caller-supplied ACCT for that UID (the
 * server-served registration record, decoded here for vkbase only; the ACCT's
 * identity-signature and acq-tag check is IsCorrectUserKey, run per member in
 * check_user_key).  GY_ERR_NOT_FOUND if none of the three resolves the UID.
 */
static int
resolve_member_vkb(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
                   const uint8_t *uid, size_t uidlen,
                   const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
                   uint8_t *vkb_out)
{
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t acq[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint64_t ep;
    size_t k, vkblen;
    int rc;

    if (uidlen == c->self_uid_len &&
        gy_const_memcmp(uid, c->self_uid, uidlen) == 0) {
        rc = gy_qspgs_base_key_load(st, suite, uid, uidlen, skb, vkb_out);
        gy_secure_zero(skb, sizeof(skb));
        return rc;
    }
    rc = gy_qspgs_acquaintance_load(st, suite, uid, uidlen, vkb_out, acq, uk,
                                    &ep);
    gy_secure_zero(acq, sizeof(acq));
    gy_secure_zero(uk, sizeof(uk));
    if (rc == GY_OK || rc != GY_ERR_NOT_FOUND)
        return rc;

    /* GetPseudoVkBase fall-through: a server-served ACCT for this UID. */
    vkblen = gy_qspgs_base_vkb_len(suite);
    for (k = 0; k < n_accts; k++) {
        const uint8_t *vkb, *acqp, *eds, *mls;
        size_t edl, mll, cons;
        uint64_t aep;

        if (accts[k].uid == NULL || accts[k].uid_len != uidlen ||
            gy_const_memcmp(accts[k].uid, uid, uidlen) != 0)
            continue;
        rc = gy_qspgs_acct_decode(suite, accts[k].acct, accts[k].acct_len, &vkb,
                                  &acqp, &aep, &eds, &edl, &mls, &mll, &cons);
        if (rc != GY_OK)
            return rc;
        memcpy(vkb_out, vkb, vkblen);
        return GY_OK;
    }
    return GY_ERR_NOT_FOUND;
}

/*
 * Full vk-lst recompute ([CFG+] Fig. 15, D-QGS-13 E5): require one vk-lst entry
 * per member, then for every member recompute H(RandVK(vkbase, rho)) from its
 * resolved base key and require it to equal the received vk-lst hash at that
 * index.  This is what makes the received vk-lst trustworthy despite a corrupt
 * server: a planted foreign hash for ANY member (not just the signer) is caught.
 * A member whose base key resolves to none of self / acquaintance / accts is
 * GY_ERR_NOT_FOUND (the deployer supplies its server-served ACCT).
 */
static int
check_vklst_recompute(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
                      const struct gy_qspgs_core *core,
                      const uint8_t ek[GY_QSPGS_EK_BYTES],
                      const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                      const struct gy_qsgroup_acct_ref *accts, size_t n_accts)
{
    const struct gy_suite_desc *d = gy_suite_desc(suite);
    struct gy_qspgs_member_view v;
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t hbuf[GY_QSPGS_HASH_MAX];
    size_t hlen, i;
    int rc = GY_OK;

    if (d == NULL)
        return GY_ERR_ARG;
    hlen = d->hash_len;
    if (core->n_vk != core->n_members)
        return GY_ERR_VERIFY;

    memset(&v, 0, sizeof(v));
    for (i = 0; i < core->n_members; i++) {
        rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                     &core->members[i], &v);
        if (rc != GY_OK)
            break;
        rc = resolve_member_vkb(c, st, suite, v.uid, v.uidlen, accts, n_accts,
                                vkb);
        if (rc == GY_OK)
            rc =
                gy_qspgs_attribute_hash(suite, rrs, vkb, v.uid, v.uidlen, hbuf);
        if (rc == GY_OK &&
            gy_const_memcmp(hbuf, core->vkhash + i * hlen, hlen) != 0)
            rc = GY_ERR_VERIFY;
        gy_qspgs_member_view_clear(&v);
        if (rc != GY_OK)
            break;
    }
    gy_qspgs_member_view_clear(&v);
    gy_secure_zero(vkb, sizeof(vkb));
    gy_secure_zero(hbuf, sizeof(hbuf));
    return rc;
}

/*
 * CheckAppendixLine ([CFG+] Fig. 16) for one appendix line: recompute the
 * author's pseudonym key and verify the line signature under it, then apply the
 * kind-specific gate / commitment check.  The author is an existing roster
 * member (its stored H(vkpsdn) pins the key) for every kind but JOIN, whose
 * author is a newcomer not yet in the vk-lst: its UID is carried inside the
 * sealed line, resolved to a base key through an AcqRec / accts entry, and no
 * stored hash gates it.  addUser is gated on b_add and modAttr on b_attr; a JOIN
 * needs an open join link; an addUser's C_UID' must open to (UID', r').  Returns
 * 1 if the line verified and is to be applied, 0 if it is invalid and must be
 * ignored (bad signature, unresolvable author, gated off, no link, commitment
 * mismatch), or a negative GY_ERR_* on a hard error.
 */
static int
check_apx_line(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
               const struct gy_qspgs_core *core,
               const uint8_t ek[GY_QSPGS_EK_BYTES],
               const uint8_t rrs[GY_QSPGS_RRS_BYTES], uint32_t apx_vmaj,
               uint32_t apx_vmin, const struct gy_qspgs_apx_line *line,
               uint8_t b_add, uint8_t b_attr,
               const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
               uint8_t *scratch, size_t scratch_cap)
{
    struct gy_qspgs_member_view av;
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t nuid[GY_QSPGS_UID_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t key[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t cuid[GY_QSPGS_HASH_MAX];
    uint8_t fldpt[GY_QSGROUP_ATTR_MAX]; /* refresh uk / modAttr plaintext */
    size_t hlen, nuidlen, mklen, fldlen;
    uint8_t form;
    int rc, valid = 0;

    hlen = c->desc->hash_len;
    mklen = gy_qspgs_master_key_len(suite);
    memset(&av, 0, sizeof(av));

    if (line->line_type == GY_QAPX_JOIN) {
        /* Newcomer author: no open link means no valid join line.  The payload
         * is C_UID'(hash_len) || Enc_ek(UID', r', uk'), like addUser. */
        if (core->join_ct == NULL || core->join_ct_len == 0)
            return 0;
        if (line->payload_len <= hlen)
            goto done; /* missing the C_UID' prefix: invalid. */
        rc = gy_qspgs_member_ct_open(suite, core->aead_id, ek, core->gid,
                                     line->payload + hlen,
                                     line->payload_len - hlen, &form, nuid,
                                     sizeof(nuid), &nuidlen, rc_open, key);
        if (rc == GY_ERR_VERIFY)
            goto done;
        if (rc != GY_OK)
            goto err;
        rc = resolve_member_vkb(c, st, suite, nuid, nuidlen, accts, n_accts,
                                vkb);
        if (rc == GY_ERR_NOT_FOUND)
            goto done;
        if (rc != GY_OK)
            goto err;
        rc = gy_qspgs_apx_line_resolve_verify(
            suite, core->gid, apx_vmaj, apx_vmin, line, rrs, vkb, nuid, nuidlen,
            NULL, scratch, scratch_cap);
        if (rc == GY_ERR_VERIFY)
            goto done;
        if (rc != GY_OK)
            goto err;
        /* C_UID' must open to (UID', r') (Fig. 16); a mismatch is invalid. */
        rc = gy_qspgs_cuid_commit(suite, nuid, nuidlen, rc_open, cuid);
        if (rc != GY_OK)
            goto err;
        valid = (gy_const_memcmp(cuid, line->payload, hlen) == 0) ? 1 : 0;
        goto done;
    }

    /* All other kinds are authored by an existing roster member. */
    if (line->author_index >= core->n_members)
        return 0;
    rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                 &core->members[line->author_index], &av);
    if (rc != GY_OK)
        goto err;
    rc = resolve_member_vkb(c, st, suite, av.uid, av.uidlen, accts, n_accts,
                            vkb);
    if (rc == GY_ERR_NOT_FOUND)
        goto done;
    if (rc != GY_OK)
        goto err;
    rc = gy_qspgs_apx_line_resolve_verify(
        suite, core->gid, apx_vmaj, apx_vmin, line, rrs, vkb, av.uid, av.uidlen,
        core->vkhash + line->author_index * hlen, scratch, scratch_cap);
    if (rc == GY_ERR_VERIFY)
        goto done;
    if (rc != GY_OK)
        goto err;

    switch (line->line_type) {
    case GY_QAPX_LEAVE:
        valid = 1;
        break;
    case GY_QAPX_REFRESH:
        /* MED-1: the ek payload must open here ([CFG+] Fig. 16 decrypts inside
         * CheckAppendixLine), so a signed line with a garbage or wrong-length
         * refresh uk is marked invalid and skipped, never aborting the fold. */
        rc = gy_qspgs_field_open(suite, core->aead_id, ek, GY_QSPGS_FIELD_UK,
                                 core->gid, line->payload, line->payload_len,
                                 fldpt, sizeof(fldpt), &fldlen);
        if (rc == GY_ERR_VERIFY)
            break; /* invalid line. */
        if (rc != GY_OK)
            goto err;
        valid = (fldlen == mklen) ? 1 : 0; /* a refresh conveys exactly a uk. */
        break;
    case GY_QAPX_MODATTR:
        if (!b_attr) /* gated on b_attr. */
            break;
        /* MED-1: the attribute payload must open here too. */
        rc = gy_qspgs_field_open(suite, core->aead_id, ek, GY_QSPGS_FIELD_ATTR,
                                 core->gid, line->payload, line->payload_len,
                                 fldpt, sizeof(fldpt), &fldlen);
        if (rc == GY_ERR_VERIFY)
            break; /* invalid line. */
        if (rc != GY_OK)
            goto err;
        valid = 1;
        break;
    case GY_QAPX_ADDUSER:
        if (!b_add) /* gated on b_add. */
            break;
        if (line->payload_len <= hlen)
            break;
        rc = gy_qspgs_member_ct_open(suite, core->aead_id, ek, core->gid,
                                     line->payload + hlen,
                                     line->payload_len - hlen, &form, nuid,
                                     sizeof(nuid), &nuidlen, rc_open, key);
        if (rc == GY_ERR_VERIFY)
            break;
        if (rc != GY_OK)
            goto err;
        rc = gy_qspgs_cuid_commit(suite, nuid, nuidlen, rc_open, cuid);
        if (rc != GY_OK)
            goto err;
        /* C_UID' must open to (UID', r'); a mismatch is an invalid line. */
        valid = (gy_const_memcmp(cuid, line->payload, hlen) == 0) ? 1 : 0;
        break;
    default:
        break;
    }

done:
    rc = valid;
err:
    gy_qspgs_member_view_clear(&av);
    gy_secure_zero(vkb, sizeof(vkb));
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(key, sizeof(key));
    gy_secure_zero(fldpt, sizeof(fldpt));
    return rc;
}

/*
 * Invite-queue settling ([CFG+] App. B.7) for ONE pending member.  Invite
 * acceptances are sealed to the invite key derived from that member's PER-INVITE
 * gk' (its mct key slot, recovered by the caller), NOT the group key, so isk is
 * derived from gkprime.  Each queue entry is opened under isk and, when one
 * decrypts to this member's UID and its invitee signature verifies under that
 * UID's ACCT identity keys, uk_out receives the accepted uk, *entry_out the
 * consumed entry index, and the return is 1 (settled).  Returns 0 if no entry
 * settles this member (still pending), or a negative GY_ERR_* on a hard error.
 * A malformed / foreign entry is skipped, not an error.
 */
static int
settle_one(uint8_t suite, const uint8_t *gkprime,
           const uint8_t gid[GY_QSPGS_GID_LEN],
           const struct gy_qspgs_invite_entry *entries, size_t n_entries,
           const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
           const uint8_t *uid, size_t uidlen, uint8_t *uk_out,
           size_t *entry_out)
{
    gy_qspgs_join_pk_t ipk;
    gy_qspgs_join_sk_t isk;
    struct gy_qspgs_invite inv;
    size_t mklen, e, k;
    int rc, settled = 0;

    memset(&ipk, 0, sizeof(ipk));
    memset(&isk, 0, sizeof(isk));
    memset(&inv, 0, sizeof(inv));
    mklen = gy_qspgs_master_key_len(suite);

    rc = gy_qspgs_join_derive(suite, gkprime, &ipk, &isk);
    if (rc != GY_OK)
        goto out;

    for (e = 0; e < n_entries && !settled; e++) {
        rc = gy_qspgs_invite_open(suite, &isk, entries[e].ct, entries[e].ct_len,
                                  &inv);
        if (rc != GY_OK) {
            gy_qspgs_invite_clear(&inv);
            continue; /* foreign / malformed: skip. */
        }
        if (inv.uidlen != uidlen ||
            gy_const_memcmp(inv.uid, uid, uidlen) != 0) {
            gy_qspgs_invite_clear(&inv);
            continue;
        }
        for (k = 0; k < n_accts; k++) {
            if (accts[k].uid == NULL || accts[k].uid_len != uidlen ||
                gy_const_memcmp(accts[k].uid, uid, uidlen) != 0 ||
                accts[k].curve_pk == NULL || accts[k].mldsa_pk == NULL)
                continue;
            rc = gy_qspgs_invite_verify(suite, gid, accts[k].curve_pk,
                                        accts[k].mldsa_pk, &inv);
            if (rc == GY_OK) {
                memcpy(uk_out, inv.uk, mklen);
                *entry_out = e;
                settled = 1;
            }
            break;
        }
        gy_qspgs_invite_clear(&inv);
    }
    rc = settled;
out:
    gy_qspgs_invite_clear(&inv);
    gy_qspgs_join_sk_clear(&isk);
    return rc;
}

/*
 * IsCorrectUserKey ([CFG+] Fig. 15, D-QGS-13 E4, D-QGS-14 E12) for one fetched
 * member: the conveyed / decrypted user key uk must be attested by the member's
 * ACCT.  The caller's own entry is trusted (it minted the uk).  An AcqRec
 * exempts a member only on an EXACT (UID, uk) match: the stored uk was attested
 * at accept-acquaintance time, so a roster uk equal to it is trusted, but a
 * roster uk that differs (a refresh to a new epoch, or an admin-planted uk) is
 * NOT exempt.  For any non-exempt member the matching accts entry's identity
 * signature must verify under its supplied identity public keys AND
 * acq == KDF(uk) must hold; a member with no matching AcqRec and no verifiable
 * ACCT for this uk is GY_ERR_VERIFY (the version is invalid).  The caller must
 * therefore supply the NEW-epoch ACCT for a member that refreshed its uk.
 */
static int
check_user_key(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
               const uint8_t *uid, size_t uidlen, const uint8_t *uk,
               size_t uk_len, const struct gy_qsgroup_acct_ref *accts,
               size_t n_accts)
{
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t acq[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t stored_uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t acq_check[GY_QSPGS_MASTER_KEY_MAX];
    uint64_t ep;
    size_t mklen, k;
    int rc;

    mklen = gy_qspgs_master_key_len(suite);
    if (uk_len != mklen)
        return GY_ERR_VERIFY;

    /* Own entry: the caller minted this uk. */
    if (uidlen == c->self_uid_len &&
        gy_const_memcmp(uid, c->self_uid, uidlen) == 0)
        return GY_OK;

    /*
     * AcqRec: an acquaintance record exempts this member only on an exact
     * (UID, uk) match (D-QGS-14 E12).  The stored uk was attested at accept-
     * acquaintance time, so a roster uk equal to it is trusted; a roster uk
     * that differs (a refresh to a new epoch, or a planted uk) is NOT exempt
     * and falls through to the ACCT check below.
     */
    rc = gy_qspgs_acquaintance_load(st, suite, uid, uidlen, vkb, acq, stored_uk,
                                    &ep);
    gy_secure_zero(vkb, sizeof(vkb));
    gy_secure_zero(acq, sizeof(acq));
    if (rc == GY_OK) {
        int match = (gy_const_memcmp(stored_uk, uk, mklen) == 0);

        gy_secure_zero(stored_uk, sizeof(stored_uk));
        if (match)
            return GY_OK;
    } else {
        gy_secure_zero(stored_uk, sizeof(stored_uk));
        if (rc != GY_ERR_NOT_FOUND)
            return rc;
    }

    /* No AcqRec (or a uk that does not match one): run the check against the
     * server-served ACCT for this UID. */
    for (k = 0; k < n_accts; k++) {
        const uint8_t *acct_vkb, *acct_acq;

        if (accts[k].uid == NULL || accts[k].uid_len != uidlen ||
            gy_const_memcmp(accts[k].uid, uid, uidlen) != 0)
            continue;
        if (accts[k].curve_pk == NULL || accts[k].mldsa_pk == NULL)
            return GY_ERR_VERIFY;
        rc = gy_qspgs_acct_verify(suite, accts[k].curve_pk, accts[k].mldsa_pk,
                                  accts[k].acct, accts[k].acct_len, &acct_vkb,
                                  &acct_acq, &ep);
        if (rc != GY_OK)
            return rc;
        rc = gy_qspgs_derive_acq(suite, uk, acq_check);
        if (rc != GY_OK)
            return rc;
        rc = (gy_const_memcmp(acq_check, acct_acq, mklen) == 0) ? GY_OK
                                                                : GY_ERR_VERIFY;
        gy_secure_zero(acq_check, sizeof(acq_check));
        return rc;
    }
    return GY_ERR_VERIFY;
}

int
gy_custodian_qsgroup_fetch(
    gy_custodian *c, const uint8_t *hdr, size_t hdr_len,
    const uint8_t *member_list, size_t member_list_len, const uint8_t *vk_lst,
    size_t vk_lst_len, const uint8_t *sig, size_t sig_len, const uint8_t *apx,
    size_t apx_len, const uint8_t *invite_queue, size_t invite_queue_len,
    uint32_t prior_vmaj, uint32_t prior_vmin, uint32_t prior_apx_line_count,
    const struct gy_qsgroup_member_view *prior, size_t prior_count,
    const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
    struct gy_qsgroup_member_view *out, size_t max, size_t *out_count,
    struct gy_qsgroup_apx_report *reports, size_t reports_cap,
    size_t *n_reports, uint8_t *attr_out, size_t attr_cap, size_t *attr_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_appendix apxo;
    struct gy_qspgs_apx_line *lines = NULL;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_view v;
    struct gy_qsgroup_member_view *work = NULL;
    uint8_t *removed = NULL;
    uint8_t *pending = NULL;
    uint8_t *pending0 = NULL;
    uint8_t *gkprimes = NULL;
    uint8_t *linevalid = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t signer_uid[GY_QSPGS_UID_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t nuid[GY_QSPGS_UID_MAX];
    uint8_t hdrpt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t attrbuf[GY_QSGROUP_ATTR_MAX];
    uint8_t *scratch = NULL;
    uint8_t *apxscratch = NULL;
    const uint8_t *sigp;
    size_t consumed, sigplen, gkout, scratch_cap, apxscratch_cap, n, nwork;
    size_t mklen, hlen, i, j, signer_uidlen, hdrptlen, attrlen, eff;
    uint32_t signer_index, last_vmin;
    uint8_t suite, signer_admn, b_add, b_attr, b_adm, form;
    int rc;

    if (hdr == NULL || member_list == NULL || vk_lst == NULL || sig == NULL ||
        out_count == NULL || (apx != NULL && apx_len > 0 && n_reports == NULL))
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    hlen = c->desc->hash_len;
    mk_store(c, &st);

    memset(&core, 0, sizeof(core));
    memset(&apxo, 0, sizeof(apxo));
    memset(&v, 0, sizeof(v));
    core.suite_id = suite;
    apxo.suite_id = suite;
    attrlen = 0;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    work = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*work));
    removed = calloc(GY_QSPGS_MAX_ENTRIES, 1);
    pending = calloc(GY_QSPGS_MAX_ENTRIES, 1);
    pending0 = calloc(GY_QSPGS_MAX_ENTRIES, 1);
    gkprimes = calloc(GY_QSPGS_MAX_ENTRIES, GY_QSPGS_MASTER_KEY_MAX);
    lines = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*lines));
    scratch_cap = hdr_len + member_list_len + vk_lst_len + 64;
    scratch = calloc(1, scratch_cap);
    if (members == NULL || work == NULL || removed == NULL || pending == NULL ||
        pending0 == NULL || gkprimes == NULL || lines == NULL ||
        scratch == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    rc = gy_qspgs_header_decode(&core, hdr, hdr_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_list_decode(&core, members, GY_QSPGS_MAX_ENTRIES,
                                     member_list, member_list_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_vk_lst_decode(&core, vk_lst, vk_lst_len, &consumed);
    if (rc != GY_OK)
        goto out;
    n = core.n_members;

    /* Decode the appendix (its header GID and vMaj must match the core). */
    if (apx != NULL && apx_len > 0) {
        rc = gy_qspgs_appendix_decode(&apxo, lines, GY_QSPGS_MAX_ENTRIES, apx,
                                      apx_len, &consumed);
        if (rc != GY_OK)
            goto out;
        if (apxo.vmaj != core.vmaj ||
            gy_const_memcmp(apxo.gid, core.gid, GY_QSPGS_GID_LEN) != 0) {
            rc = GY_ERR_VERIFY;
            goto out;
        }
    }
    if (n_reports != NULL)
        *n_reports = apxo.n_lines;

    /*
     * Roster-size query / short buffers.  The effective roster can grow by at
     * most one member per appendix line, so n + n_lines is a safe upper bound
     * for a caller to size out[] to before the verifying call.
     */
    if (out == NULL) {
        *out_count = n + apxo.n_lines;
        rc = GY_OK;
        goto out;
    }
    if (apxo.n_lines > 0 && reports != NULL && reports_cap < apxo.n_lines) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }

    rc = gy_qspgs_core_sig_decode(suite, sig, sig_len, &signer_index,
                                  &last_vmin, &sigp, &sigplen, &consumed);
    if (rc != GY_OK)
        goto out;
    if (consumed != sig_len) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    core.last_vmin = last_vmin;
    if (signer_index >= n) {
        rc = GY_ERR_ARG;
        goto out;
    }

    /* Load the group key by the header's GID; derive the read/rerand keys. */
    rc = gy_qspgs_group_key_load(&st, suite, core.gid, gk, sizeof(gk), &gkout);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_sub_key(suite, gk, ek, rrs);
    if (rc != GY_OK)
        goto out;

    /* Verify the admin core signature: recover the signer's UID from its member
     * entry, resolve its base key, and check the signature under rrs.  Keep the
     * signer's UID and its fetched admn flag for the lineage check below. */
    rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                 &core.members[signer_index], &v);
    if (rc != GY_OK)
        goto out;
    signer_uidlen = v.uidlen;
    memcpy(signer_uid, v.uid, v.uidlen);
    signer_admn = core.members[signer_index].admn;
    rc =
        resolve_member_vkb(c, &st, suite, v.uid, v.uidlen, accts, n_accts, vkb);
    if (rc == GY_OK)
        rc = gy_qspgs_core_resolve_verify(&core, signer_index, rrs, vkb, v.uid,
                                          v.uidlen, sigp, sigplen, scratch,
                                          scratch_cap);
    gy_qspgs_member_view_clear(&v);
    if (rc != GY_OK)
        goto out;

    /*
     * Anti-rollback lineage ([CFG+] Fig. 15 UsrVfyUpdate, D-QGS-14 E11).  The
     * signer must be an admin in the FETCHED roster (its member entry's admn
     * flag; the server enforces that this was an admin already in the prior
     * version, sub-step A).  With a retained prior view the fetched version
     * follows the paper exactly: a rollback (lower major, or same major with a
     * lower core-sig last-vMin) and a SKIP past the next major (vMaj >
     * prior + 1, Fig. 15 "version skipped") are both refused.  On the exact
     * next major the new core's folded last-vMin must equal
     * prior_apx_line_count, the NUMBER of appendix lines the caller last saw
     * (Consolidate signs last_vMin = |apx|; this is NOT the appendix header's
     * vMin field).  Fig. 15 "min version skipped": the admin consolidated
     * exactly the appendix the caller was caught up to, so a colluding server
     * cannot fold from a hidden shorter appendix.  Supplying too small a value
     * here (e.g. a constant header vMin) would let such a short fold pass, so
     * the caller MUST pass the true line count.  The
     * signer must have been an admin in the caller's prior view (so a freshly
     * self-promoted admin cannot be presented).  A same-major refetch whose
     * core-sig last-vMin is unchanged is the Fig. 10 minor-version path.
     * Passing NULL forfeits all of this (the library keeps no membership state).
     */
    if (!signer_admn) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    if (prior != NULL && prior_count > 0) {
        if (core.vmaj < prior_vmaj ||
            (core.vmaj == prior_vmaj && core.last_vmin < prior_vmin)) {
            rc = GY_ERR_STATE; /* rollback. */
            goto out;
        }
        if (core.vmaj > prior_vmaj + 1) {
            rc = GY_ERR_STATE; /* version skipped (Fig. 15). */
            goto out;
        }
        if (core.vmaj == prior_vmaj + 1) {
            int ok = 0;

            if (core.last_vmin != prior_apx_line_count) {
                rc = GY_ERR_STATE; /* min version skipped (Fig. 15). */
                goto out;
            }
            for (j = 0; j < prior_count; j++)
                if (prior[j].uidlen == signer_uidlen && prior[j].admn &&
                    gy_const_memcmp(prior[j].uid, signer_uid, signer_uidlen) ==
                        0) {
                    ok = 1;
                    break;
                }
            if (!ok) {
                rc = GY_ERR_VERIFY;
                goto out;
            }
        }
    }

    /* E5: recompute EVERY member's vk-lst hash, not just the signer's. */
    rc = check_vklst_recompute(c, &st, suite, &core, ek, rrs, accts, n_accts);
    if (rc != GY_OK)
        goto out;

    /* Decrypt the core roster into the working set (indices 0..n). */
    for (i = 0; i < n; i++) {
        rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                     &core.members[i], &v);
        if (rc != GY_OK)
            goto out;
        memset(&work[i], 0, sizeof(work[i]));
        memcpy(work[i].uid, v.uid, v.uidlen);
        work[i].uidlen = v.uidlen;
        work[i].admn = v.admn;
        /* A pending invite (D-QGS-13 E3) has no uk yet: report uk_len 0.
         * IsCorrectUserKey runs later, over the EFFECTIVE roster, once the
         * appendix and queue passes have refreshed / added / settled uks
         * (D-QGS-14 E12); it is not run per core entry here. */
        if (v.pending) {
            work[i].uk_len = 0;
            pending[i] = pending0[i] = 1;
            /* Stash the per-invite gk' (the pending mct's key slot) so invite
             * settling can open the queue under this member's own isk. */
            memcpy(gkprimes + i * GY_QSPGS_MASTER_KEY_MAX, v.uk, mklen);
        } else {
            memcpy(work[i].uk, v.uk, mklen);
            work[i].uk_len = mklen;
        }
        gy_qspgs_member_view_clear(&v);
    }
    nwork = n;

    /* Group attributes: the sealed header field is flags(1) || attributes. */
    rc = gy_qspgs_field_open(suite, core.aead_id, ek, GY_QSPGS_FIELD_HEADER,
                             core.gid, core.sa_ct, core.sa_ct_len, hdrpt,
                             sizeof(hdrpt), &hdrptlen);
    if (rc != GY_OK)
        goto out;
    if (hdrptlen < 1) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    b_add = (hdrpt[0] & GY_QSGROUP_SETTING_ADD) ? 1 : 0;
    b_attr = (hdrpt[0] & GY_QSGROUP_SETTING_ATTR) ? 1 : 0;
    b_adm = (hdrpt[0] & GY_QSGROUP_SETTING_ADM) ? 1 : 0;
    attrlen = hdrptlen - 1;
    if (attrlen > 0)
        memcpy(attrbuf, hdrpt + 1, attrlen);

    /*
     * CheckAppendixLine per line ([CFG+] Fig. 16), then apply the valid lines
     * in the paper's kind order: join / addUser append, refresh replaces a uk,
     * modAttr replaces the attributes, leave removes.  linevalid[] records each
     * line's outcome (also copied into reports[] in wire order for attribution).
     */
    if (apxo.n_lines > 0) {
        linevalid = calloc(apxo.n_lines, 1);
        apxscratch_cap = apx_len + 128;
        apxscratch = calloc(1, apxscratch_cap);
        if (linevalid == NULL || apxscratch == NULL) {
            rc = GY_ERR_CRYPTO;
            goto out;
        }
        for (i = 0; i < apxo.n_lines; i++) {
            rc = check_apx_line(c, &st, suite, &core, ek, rrs, apxo.vmaj,
                                apxo.vmin, &lines[i], b_add, b_attr, accts,
                                n_accts, apxscratch, apxscratch_cap);
            if (rc < 0)
                goto out;
            linevalid[i] = (uint8_t)rc;
            /*
             * ApproveJoin gate (b_adm, [CFG+] App. B.8, D-QGS-14 E9): a valid
             * JOIN line in a group that requires admin approval is held out of
             * the roster and reported pending; an admin folds it later at
             * Consolidate.  Every other outcome reports pending_approval 0.
             */
            if (linevalid[i] && lines[i].line_type == GY_QAPX_JOIN && b_adm) {
                linevalid[i] = 0;
                if (reports != NULL)
                    reports[i].pending_approval = 1;
            } else if (reports != NULL) {
                reports[i].pending_approval = 0;
            }
            if (reports != NULL) {
                reports[i].line_type = lines[i].line_type;
                reports[i].author_index = lines[i].author_index;
                reports[i].valid = linevalid[i];
            }
        }
        /* Pass 1: append join / addUser newcomers. */
        for (i = 0; i < apxo.n_lines; i++) {
            const uint8_t *ctp;
            size_t ctlen, nuidlen;

            if (!linevalid[i])
                continue;
            if (lines[i].line_type == GY_QAPX_ADDUSER ||
                lines[i].line_type == GY_QAPX_JOIN) {
                /* Both newcomer kinds carry C_UID'(hash_len) || ct. */
                ctp = lines[i].payload + hlen;
                ctlen = lines[i].payload_len - hlen;
            } else {
                continue;
            }
            if (nwork >= GY_QSPGS_MAX_ENTRIES) {
                rc = GY_ERR_TOOLONG;
                goto out;
            }
            memset(&work[nwork], 0, sizeof(work[nwork]));
            rc = gy_qspgs_member_ct_open(suite, core.aead_id, ek, core.gid, ctp,
                                         ctlen, &form, nuid, sizeof(nuid),
                                         &nuidlen, rc_open, work[nwork].uk);
            if (rc != GY_OK)
                goto out;
            memcpy(work[nwork].uid, nuid, nuidlen);
            work[nwork].uidlen = nuidlen;
            work[nwork].admn = 0;
            work[nwork].uk_len = mklen;
            nwork++;
        }
        /* Pass 2: refresh replaces the member's uk. */
        for (i = 0; i < apxo.n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_REFRESH)
                continue;
            j = lines[i].author_index;
            if (j >= n || removed[j])
                continue;
            rc = gy_qspgs_field_open(suite, core.aead_id, ek, GY_QSPGS_FIELD_UK,
                                     core.gid, lines[i].payload,
                                     lines[i].payload_len, work[j].uk,
                                     sizeof(work[j].uk), &work[j].uk_len);
            if (rc != GY_OK)
                goto out;
        }
        /* Pass 3: modAttr replaces the returned attributes (last valid wins). */
        for (i = 0; i < apxo.n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_MODATTR)
                continue;
            rc = gy_qspgs_field_open(suite, core.aead_id, ek,
                                     GY_QSPGS_FIELD_ATTR, core.gid,
                                     lines[i].payload, lines[i].payload_len,
                                     attrbuf, sizeof(attrbuf), &attrlen);
            if (rc != GY_OK)
                goto out;
        }
        /* Pass 4: leave removes the member. */
        for (i = 0; i < apxo.n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_LEAVE)
                continue;
            j = lines[i].author_index;
            if (j < n)
                removed[j] = 1;
        }
    }

    /*
     * Settle still-pending invites against the queue: each pending member's
     * acceptance is sealed under its own per-invite gk', so open the queue with
     * that member's isk (settle_one).
     */
    if (invite_queue != NULL && invite_queue_len > 0) {
        struct gy_qspgs_invite_entry *entries = NULL;
        size_t n_entries, qconsumed, eidx;

        entries = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*entries));
        if (entries == NULL) {
            rc = GY_ERR_CRYPTO;
            goto out;
        }
        rc = gy_qspgs_invite_queue_decode(suite, entries, GY_QSPGS_MAX_ENTRIES,
                                          invite_queue, invite_queue_len,
                                          &n_entries, &qconsumed);
        if (rc != GY_OK) {
            free(entries);
            goto out;
        }
        for (i = 0; i < n; i++) {
            if (!pending0[i])
                continue;
            rc = settle_one(suite, gkprimes + i * GY_QSPGS_MASTER_KEY_MAX,
                            core.gid, entries, n_entries, accts, n_accts,
                            work[i].uid, work[i].uidlen, work[i].uk, &eidx);
            if (rc < 0) {
                free(entries);
                goto out;
            }
            if (rc == 1) {
                work[i].uk_len = mklen;
                pending[i] = 0;
            }
        }
        free(entries);
        rc = GY_OK;
    }

    /*
     * IsCorrectUserKey over the EFFECTIVE roster ([CFG+] Fig. 15 "Check new
     * acquaintances", D-QGS-14 E12): now that the appendix (refresh / addUser /
     * join) and the queue settling have produced final uks, verify every
     * surviving member's uk.  An AcqRec exempts a member only on an exact
     * (UID, uk) match (inside check_user_key); a refreshed or planted uk falls
     * through to the member's ACCT.  A settled invitee (pending in the core,
     * now carrying a uk) is exempt: its uk is bound by the invitee's own
     * identity signature on the acceptance (Fig. 15 AcceptedInvite), checked at
     * settle time.  A still-pending invite (uk_len 0) is skipped.
     */
    for (i = 0; i < nwork; i++) {
        if (removed[i])
            continue;
        if (i < n &&
            pending0[i]) /* invitee: still pending, or settled-exempt. */
            continue;
        if (work[i].uk_len != mklen)
            continue;
        rc = check_user_key(c, &st, suite, work[i].uid, work[i].uidlen,
                            work[i].uk, work[i].uk_len, accts, n_accts);
        if (rc != GY_OK)
            goto out;
    }

    /* Compact the working set into the caller's out[] (skip removed). */
    eff = 0;
    for (i = 0; i < nwork; i++)
        if (!removed[i])
            eff++;
    if (max < eff) {
        *out_count = eff;
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    for (i = 0, j = 0; i < nwork; i++) {
        if (removed[i])
            continue;
        out[j++] = work[i];
    }
    *out_count = eff;

    /* Emit the group attributes (buffer convention). */
    if (attr_len != NULL) {
        if (attr_out == NULL) {
            *attr_len = attrlen;
        } else if (attr_cap < attrlen) {
            *attr_len = attrlen;
            rc = GY_ERR_TOOLONG;
            goto out;
        } else {
            if (attrlen > 0)
                memcpy(attr_out, attrbuf, attrlen);
            *attr_len = attrlen;
        }
    }
    rc = GY_OK;
out:
    gy_qspgs_member_view_clear(&v);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(vkb, sizeof(vkb));
    gy_secure_zero(signer_uid, sizeof(signer_uid));
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(hdrpt, sizeof(hdrpt));
    gy_secure_zero(attrbuf, sizeof(attrbuf));
    if (work != NULL)
        gy_secure_zero(work, GY_QSPGS_MAX_ENTRIES * sizeof(*work));
    if (gkprimes != NULL)
        gy_secure_zero(gkprimes,
                       GY_QSPGS_MAX_ENTRIES * GY_QSPGS_MASTER_KEY_MAX);
    free(members);
    free(work);
    free(removed);
    free(pending);
    free(pending0);
    free(gkprimes);
    free(lines);
    free(linevalid);
    free(scratch);
    free(apxscratch);
    return rc;
}

/* ---- values for talking to a section-7.3 server ------------------------- */

_Static_assert(GY_QSGROUP_VKR_MAX == GY_QSPGS_VKR_MAX,
               "public vkr bound must match the internal pseudonym-key width");
_Static_assert(GY_QSGROUP_FET_LEN == GY_QSPGS_FET_LEN,
               "public fetch-token width must match the wire token width");

int
gy_custodian_qsgroup_self_vkr(gy_custodian *c,
                              const uint8_t gid[GY_QSGROUP_GID_LEN],
                              uint8_t *out, size_t *out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_member_ctx mctx;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    size_t gkout, vkrlen;
    uint8_t suite;
    int rc;

    if (gid == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    vkrlen = c->desc->dsa_pk_len; /* the tier's ML-DSA pk == the vkr width. */
    if (out == NULL) {
        *out_len = vkrlen;
        return GY_OK;
    }
    if (*out_len < vkrlen)
        return GY_ERR_ARG;
    mk_store(c, &st);

    memset(&mctx, 0, sizeof(mctx));
    rc = gy_qspgs_group_key_load(&st, suite, gid, gk, sizeof(gk), &gkout);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_base_key_load(&st, suite, c->self_uid, c->self_uid_len, skb,
                                vkb);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_ctx_open(&mctx, suite, gk, skb, vkb, c->self_uid,
                                  c->self_uid_len);
    if (rc != GY_OK)
        goto out;
    memcpy(out, mctx.vkr, vkrlen);
    *out_len = vkrlen;
out:
    gy_qspgs_member_ctx_clear(&mctx);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(skb, sizeof(skb));
    return rc;
}

int
gy_custodian_qsgroup_fetch_token(gy_custodian *c,
                                 const uint8_t gid[GY_QSGROUP_GID_LEN],
                                 uint8_t *out, size_t *out_len)
{
    struct gy_qspgs_store st;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t fet[GY_QSPGS_FET_LEN];
    size_t gkout;
    uint8_t suite;
    int rc;

    if (gid == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    if (out == NULL) {
        *out_len = GY_QSPGS_FET_LEN;
        return GY_OK;
    }
    if (*out_len < GY_QSPGS_FET_LEN)
        return GY_ERR_ARG;
    mk_store(c, &st);

    rc = gy_qspgs_group_key_load(&st, suite, gid, gk, sizeof(gk), &gkout);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_fet(suite, gk, fet);
    if (rc != GY_OK)
        goto out;
    memcpy(out, fet, GY_QSPGS_FET_LEN);
    *out_len = GY_QSPGS_FET_LEN;
out:
    gy_secure_zero(gk, sizeof(gk));
    return rc;
}

int
gy_custodian_qsgroup_leave_fetch_token(gy_custodian *c,
                                       const uint8_t gid[GY_QSGROUP_GID_LEN],
                                       uint32_t k, uint8_t *out,
                                       size_t *out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_member_ctx mctx;
    size_t siglen;
    uint8_t suite;
    int rc;

    if (gid == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    siglen = c->desc->dsa_sig_len;
    if (out == NULL) {
        *out_len = siglen;
        return GY_OK;
    }
    if (*out_len < siglen)
        return GY_ERR_TOOLONG;
    mk_store(c, &st);

    /* Rederive the caller's pseudonym signing key from its still-held group key
     * and base pair, and sign (GID || k) under it. */
    memset(&mctx, 0, sizeof(mctx));
    rc = gy_qspgs_member_ctx_open_stored(&mctx, &st, suite, gid, c->self_uid,
                                         c->self_uid_len);
    if (rc != GY_OK)
        goto out;
    rc =
        gy_qspgs_leave_token_sign(suite, &mctx, gid, k, out, *out_len, &siglen);
    if (rc == GY_OK)
        *out_len = siglen;
out:
    gy_qspgs_member_ctx_clear(&mctx);
    return rc;
}

int
gy_custodian_qsgroup_export_key(gy_custodian *c, const uint8_t *uk,
                                size_t uk_len, uint8_t *out, size_t *out_len)
{
    uint8_t expkey[GY_QSPGS_EXPKEY_BYTES];
    uint8_t suite;
    size_t mklen;
    int rc;

    if (out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    if (out == NULL) {
        *out_len = GY_QSPGS_EXPKEY_BYTES;
        return GY_OK;
    }
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (uk == NULL || uk_len != mklen)
        return GY_ERR_ARG;
    if (*out_len < GY_QSPGS_EXPKEY_BYTES)
        return GY_ERR_TOOLONG;

    rc = gy_qspgs_derive_exp_key(suite, uk, expkey);
    if (rc == GY_OK) {
        memcpy(out, expkey, GY_QSPGS_EXPKEY_BYTES);
        *out_len = GY_QSPGS_EXPKEY_BYTES;
    }
    gy_secure_zero(expkey, sizeof(expkey));
    return rc;
}

int
gy_custodian_qsgroup_identity_public(gy_custodian *c, uint8_t *curve_pk,
                                     size_t *curve_len, uint8_t *mldsa_pk,
                                     size_t *mldsa_len)
{
    const uint8_t *cp, *mp;
    size_t clen, mlen;
    int rc;

    if (curve_len == NULL || mldsa_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    clen = c->desc->curve_pk_len;
    mlen = c->desc->dsa_pk_len;
    if (curve_pk == NULL || mldsa_pk == NULL) {
        *curve_len = clen;
        *mldsa_len = mlen;
        return GY_OK;
    }
    if (*curve_len < clen || *mldsa_len < mlen) {
        *curve_len = clen;
        *mldsa_len = mlen;
        return GY_ERR_ARG;
    }
    rc = gy_custodian_identity_dual_pub(c, &cp, &mp);
    if (rc != GY_OK)
        return rc;
    memcpy(curve_pk, cp, clen);
    *curve_len = clen;
    memcpy(mldsa_pk, mp, mlen);
    *mldsa_len = mlen;
    return GY_OK;
}

_Static_assert(GY_QSGROUP_KEY_ENVELOPE_MAX >= GY_QSPGS_OBJ_HDR_LEN +
                                                  GY_QSGROUP_GID_LEN +
                                                  GY_QSPGS_MASTER_KEY_MAX,
               "public key-envelope bound must cover the object header + GID + "
               "the group key");

int
gy_custodian_qsgroup_export_group_key(gy_custodian *c,
                                      const uint8_t gid[GY_QSGROUP_GID_LEN],
                                      uint8_t *out, size_t *out_len)
{
    struct gy_qspgs_store st;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    size_t gkout, mklen, need;
    uint8_t suite;
    int rc;

    if (gid == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    /* Typed distribution frame (SEC-v1.5.0 INFO-4): the standard 3-byte object
     * header (obj_type || wire_version || suite_id) that every other top-level
     * QSPGS wire object carries, then GID || gk.  The tag is identification and
     * versioning only (a forged tag changes nothing verifiable; suite binding
     * lives in the store record), matching the classical D-GEN-1
     * GROUP_KEY_DISTRIBUTION frame. */
    need = GY_QSPGS_OBJ_HDR_LEN + GY_QSGROUP_GID_LEN + mklen;
    if (out == NULL) {
        *out_len = need;
        return GY_OK;
    }
    if (*out_len < need) {
        *out_len = need;
        return GY_ERR_ARG;
    }
    mk_store(c, &st);
    rc = gy_qspgs_group_key_load(&st, suite, gid, gk, sizeof(gk), &gkout);
    if (rc != GY_OK)
        goto out;
    out[0] = GY_QOBJ_GROUP_KEY;
    out[1] = GY_QSPGS_WIRE_VERSION;
    out[2] = suite;
    memcpy(out + GY_QSPGS_OBJ_HDR_LEN, gid, GY_QSGROUP_GID_LEN);
    memcpy(out + GY_QSPGS_OBJ_HDR_LEN + GY_QSGROUP_GID_LEN, gk, mklen);
    *out_len = need;
out:
    gy_secure_zero(gk, sizeof(gk));
    return rc;
}

int
gy_custodian_qsgroup_install_group_key(gy_custodian *c, const uint8_t *env,
                                       size_t env_len,
                                       uint8_t out_gid[GY_QSGROUP_GID_LEN])
{
    struct gy_qspgs_store st;
    size_t mklen;
    uint8_t suite;
    int rc;

    if (env == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (env_len != GY_QSPGS_OBJ_HDR_LEN + GY_QSGROUP_GID_LEN + mklen)
        return GY_ERR_ARG;
    /* Validate the typed distribution frame (SEC-v1.5.0 INFO-4): the object
     * header must name this object kind, this wire version, and this
     * custodian's suite.  A mismatch is a wrong / foreign / stale-version
     * envelope, rejected before it can overwrite the stored gk (GY_ERR_VERIFY,
     * matching the core object-header check).  This is a wire-well-formedness
     * gate only; WHO may hand a member an envelope (accept it solely from the
     * admin that added you) is an application-layer identity decision the
     * library cannot make (D-SES-1 / GROUP_SPEC section 9 duty split), and the
     * install still overwrites unconditionally so a legitimate re-add works. */
    if (env[0] != GY_QOBJ_GROUP_KEY || env[1] != GY_QSPGS_WIRE_VERSION ||
        env[2] != suite)
        return GY_ERR_VERIFY;
    mk_store(c, &st);
    rc = gy_qspgs_group_key_store(&st, suite, env + GY_QSPGS_OBJ_HDR_LEN,
                                  env + GY_QSPGS_OBJ_HDR_LEN +
                                      GY_QSGROUP_GID_LEN);
    if (rc == GY_OK && out_gid != NULL)
        memcpy(out_gid, env + GY_QSPGS_OBJ_HDR_LEN, GY_QSGROUP_GID_LEN);
    return rc;
}

/* ---- admin core edits -------------------------- */

/*
 * Decode and VERIFY the current core into *core (members backs the member list),
 * load its group key by GID, and derive (ek, rrs).  Verification resolves the
 * signing admin exactly as fetch does, so an edit only ever builds on an
 * authentic core.  On GY_OK the caller mutates *core and re-signs.
 */
static int
open_current(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
             const struct gy_qsgroup_core *cur, struct gy_qspgs_core *core,
             struct gy_qspgs_member *members, uint8_t *gk, uint8_t *ek,
             uint8_t *rrs)
{
    struct gy_qspgs_member_view v;
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t *scratch = NULL;
    const uint8_t *sigp;
    size_t consumed, sigplen, gkout, scap;
    uint32_t signer_index, last_vmin;
    int rc;

    memset(core, 0, sizeof(*core));
    memset(&v, 0, sizeof(v));
    core->suite_id = suite;

    rc = gy_qspgs_header_decode(core, cur->hdr, cur->hdr_len, &consumed);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_member_list_decode(core, members, GY_QSPGS_MAX_ENTRIES,
                                     cur->member_list, cur->member_list_len,
                                     &consumed);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_vk_lst_decode(core, cur->vk_lst, cur->vk_lst_len, &consumed);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_core_sig_decode(suite, cur->sig, cur->sig_len, &signer_index,
                                  &last_vmin, &sigp, &sigplen, &consumed);
    if (rc != GY_OK)
        return rc;
    if (consumed != cur->sig_len)
        return GY_ERR_VERIFY;
    core->last_vmin = last_vmin;
    if (signer_index >= core->n_members)
        return GY_ERR_ARG;

    rc = gy_qspgs_group_key_load(st, suite, core->gid, gk,
                                 GY_QSPGS_MASTER_KEY_MAX, &gkout);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_derive_sub_key(suite, gk, ek, rrs);
    if (rc != GY_OK)
        return rc;

    scap = cur->hdr_len + cur->member_list_len + cur->vk_lst_len + 64;
    scratch = calloc(1, scap);
    if (scratch == NULL)
        return GY_ERR_CRYPTO;
    rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                 &core->members[signer_index], &v);
    if (rc == GY_OK)
        rc = resolve_member_vkb(c, st, suite, v.uid, v.uidlen, NULL, 0, vkb);
    if (rc == GY_OK)
        rc = gy_qspgs_core_resolve_verify(core, signer_index, rrs, vkb, v.uid,
                                          v.uidlen, sigp, sigplen, scratch,
                                          scap);
    gy_qspgs_member_view_clear(&v);
    /*
     * open_current only re-verifies that the current core is authentically
     * admin-signed; it does NOT run the E5 all-member recompute.  That is a
     * fetch-time property (the caller verified the roster in full when it
     * fetched the core it now edits), and it must NOT be required here: this
     * helper also backs a non-admin member appending an appendix line, which
     * holds only its own and acquaintance base keys, not every member's.  A
     * rotation that rebuilds the whole vk-lst recomputes each entry in
     * rebuild_and_emit instead.
     */
    gy_secure_zero(vkb, sizeof(vkb));
    free(scratch);
    return rc;
}

/*
 * Find the caller's own member index and require it to be an admin.  Returns
 * GY_OK with *idx set, GY_ERR_STATE if the caller is not a member or not an
 * admin, or a decryption error.
 */
static int
self_admin_index(gy_custodian *c, uint8_t suite,
                 const struct gy_qspgs_core *core, const uint8_t *ek,
                 uint32_t *idx)
{
    struct gy_qspgs_member_view v;
    size_t i;
    int rc;

    for (i = 0; i < core->n_members; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                     &core->members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            return rc;
        }
        if (v.uidlen == c->self_uid_len &&
            gy_const_memcmp(v.uid, c->self_uid, v.uidlen) == 0) {
            rc = v.admn ? GY_OK : GY_ERR_STATE;
            *idx = (uint32_t)i;
            gy_qspgs_member_view_clear(&v);
            return rc;
        }
        gy_qspgs_member_view_clear(&v);
    }
    return GY_ERR_STATE; /* the caller is not a member of this group. */
}

/*
 * Re-sign *core under the caller's group pseudonym (opened under the operative
 * group key) and emit its four objects into next, following the buffer
 * convention (any next buffer NULL => size query; short => GY_ERR_TOOLONG).
 * Does NOT seal anything; a group-key-rotating edit seals separately.
 */
static int
emit_edited(gy_custodian *c, uint8_t suite, struct gy_qspgs_core *core,
            const uint8_t *gk_op, const uint8_t *self_skb,
            const uint8_t *self_vkb, uint32_t self_index,
            struct gy_qsgroup_core *next)
{
    struct gy_qspgs_member_ctx mctx;
    uint8_t *hs = NULL, *ms = NULL, *vs = NULL, *ss = NULL, *tbs = NULL;
    size_t hcap, mcap, vcap, scap, tcap, hn, mn, vn, sn, n = core->n_members;
    int rc, query;

    memset(&mctx, 0, sizeof(mctx));
    hcap = 128 + core->sa_ct_len + core->join_ct_len;
    mcap = 64 + n * (GY_QSPGS_HASH_MAX + 3 + 512);
    vcap = 64 + n * GY_QSPGS_HASH_MAX;
    scap = 8192;
    tcap = hcap + mcap + vcap + 64;
    hs = calloc(1, hcap);
    ms = calloc(1, mcap);
    vs = calloc(1, vcap);
    ss = calloc(1, scap);
    tbs = calloc(1, tcap);
    if (hs == NULL || ms == NULL || vs == NULL || ss == NULL || tbs == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    rc = gy_qspgs_member_ctx_open(&mctx, suite, gk_op, self_skb, self_vkb,
                                  c->self_uid, c->self_uid_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_header_encode(core, hs, hcap, &hn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_list_encode(core, ms, mcap, &mn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_vk_lst_encode(core, vs, vcap, &vn);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_core_sign(core, self_index, &mctx, ss, scap, &sn, tbs, tcap);
    if (rc != GY_OK)
        goto out;

    query = (next->hdr == NULL || next->member_list == NULL ||
             next->vk_lst == NULL || next->sig == NULL);
    if (query) {
        next->hdr_len = hn;
        next->member_list_len = mn;
        next->vk_lst_len = vn;
        next->sig_len = sn;
        rc = GY_OK;
        goto out;
    }
    if (next->hdr_len < hn || next->member_list_len < mn ||
        next->vk_lst_len < vn || next->sig_len < sn) {
        next->hdr_len = hn;
        next->member_list_len = mn;
        next->vk_lst_len = vn;
        next->sig_len = sn;
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    memcpy(next->hdr, hs, hn);
    next->hdr_len = hn;
    memcpy(next->member_list, ms, mn);
    next->member_list_len = mn;
    memcpy(next->vk_lst, vs, vn);
    next->vk_lst_len = vn;
    memcpy(next->sig, ss, sn);
    next->sig_len = sn;
    /* SEC-v1.5.0 LOW-1: fet is a separate server record, derived from the
     * operative group key (unchanged on a non-rotating edit, the freshly minted
     * key on a rotating one), never carried in the header. */
    rc = gy_qspgs_derive_fet(suite, gk_op, next->fet);
    if (rc != GY_OK)
        goto out;
    rc = GY_OK;
out:
    gy_qspgs_member_ctx_clear(&mctx);
    free(hs);
    free(ms);
    free(vs);
    free(ss);
    free(tbs);
    return rc;
}

/* True when the next bundle is a size query (any out buffer NULL). */
static int
is_query(const struct gy_qsgroup_core *next)
{
    return (next->hdr == NULL || next->member_list == NULL ||
            next->vk_lst == NULL || next->sig == NULL);
}

/*
 * Shared body of RemoveMember / RotateGroupKey: mint a fresh group key, rebuild
 * every surviving member under it (dropping remove_uid when non-NULL), re-sign,
 * emit, and seal the new key on a committed (non-query) success.  core / members
 * are the verified current core from open_current; ek/rrs are its CURRENT
 * sub-keys (to decrypt survivors).
 */
static int
rebuild_and_emit(gy_custodian *c, struct gy_qspgs_store *st, uint8_t suite,
                 const struct gy_qspgs_core *core, const uint8_t *ek,
                 const uint8_t *self_skb, const uint8_t *self_vkb,
                 const uint8_t *remove_uid, size_t remove_len,
                 struct gy_qsgroup_core *next)
{
    struct gy_qspgs_core nc;
    struct gy_qspgs_member *newmembers = NULL;
    struct gy_qspgs_member_view v;
    uint8_t new_gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t new_ek[GY_QSPGS_EK_BYTES];
    uint8_t new_rrs[GY_QSPGS_RRS_BYTES];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t jls[GY_QSPGS_JOINLINK_SECRET];
    uint8_t newslot[512];
    uint8_t sa_pt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t sa_new[1 + GY_QSGROUP_ATTR_MAX + 64];
    uint8_t *mct_arena = NULL, *newvk = NULL;
    size_t n = core->n_members, hash_len = c->desc->hash_len, i, j = 0, mctlen;
    size_t newslotlen, jlen, sa_ptlen, sa_newlen;
    uint32_t self_new_idx = 0;
    int rc, self_found = 0, target_found = 0, join_dropped = 0;

    memset(&v, 0, sizeof(v));
    memset(&nc, 0, sizeof(nc));

    rc = gy_qspgs_group_key_gen(suite, new_gk);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_sub_key(suite, new_gk, new_ek, new_rrs);
    if (rc != GY_OK)
        goto out;

    newmembers = calloc(n > 0 ? n : 1, sizeof(*newmembers));
    mct_arena = calloc(n > 0 ? n : 1, 512);
    newvk = calloc(n > 0 ? n : 1, hash_len);
    if (newmembers == NULL || mct_arena == NULL || newvk == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    for (i = 0; i < n; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                     &core->members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        if (remove_uid != NULL && v.uidlen == remove_len &&
            gy_const_memcmp(v.uid, remove_uid, remove_len) == 0) {
            target_found = 1;
            gy_qspgs_member_view_clear(&v);
            continue; /* dropped. */
        }
        rc = resolve_member_vkb(c, st, suite, v.uid, v.uidlen, NULL, 0, vkb);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        /*
         * Preserve a co-pending invite across the rotation: its key slot is the
         * per-invite gk' (independent of gk), rebuilt under the new ek in
         * PENDING form so it does not decay into a PRESENT member (D-QGS-14
         * E10).  PRESENT members rebuild with their uk as before.
         */
        if (v.pending)
            rc = gy_qspgs_member_build_pending(
                suite, core->aead_id, new_ek, core->gid, new_rrs, v.uid,
                v.uidlen, v.uk, vkb, &newmembers[j], mct_arena + j * 512, 512,
                &mctlen, newvk + j * hash_len);
        else
            rc = gy_qspgs_member_build(
                suite, core->aead_id, new_ek, core->gid, new_rrs, v.uid,
                v.uidlen, v.uk, vkb, v.admn, &newmembers[j],
                mct_arena + j * 512, 512, &mctlen, newvk + j * hash_len);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        if (v.uidlen == c->self_uid_len &&
            gy_const_memcmp(v.uid, c->self_uid, v.uidlen) == 0) {
            self_found = 1;
            self_new_idx = (uint32_t)j;
        }
        gy_qspgs_member_view_clear(&v);
        j++;
    }
    if (remove_uid != NULL && !target_found) {
        rc = GY_ERR_NOT_FOUND;
        goto out;
    }
    if (!self_found) {
        rc = GY_ERR_STATE; /* the signer must remain a member. */
        goto out;
    }

    nc.suite_id = suite;
    memcpy(nc.gid, core->gid, GY_QSPGS_GID_LEN);
    nc.format_version = core->format_version;
    nc.aead_id = core->aead_id; /* INFO-6: pinned, immutable across the edit. */
    nc.vmaj = core->vmaj + 1;
    rc = gy_qspgs_derive_fet(suite, new_gk, nc.fet);
    if (rc != GY_OK)
        goto out;
    /*
     * The sealed header field (flags || attributes) is ek-bound, and this path
     * rotates the group key, so it must be re-sealed under new_ek rather than
     * carried forward: open it with the old ek and re-seal the same plaintext.
     */
    rc = gy_qspgs_field_open(suite, core->aead_id, ek, GY_QSPGS_FIELD_HEADER,
                             core->gid, core->sa_ct, core->sa_ct_len, sa_pt,
                             sizeof(sa_pt), &sa_ptlen);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_field_seal(suite, core->aead_id, new_ek,
                             GY_QSPGS_FIELD_HEADER, core->gid, sa_pt, sa_ptlen,
                             sa_new, sizeof(sa_new), &sa_newlen);
    if (rc != GY_OK)
        goto out;
    nc.sa_ct = sa_new;
    nc.sa_ct_len = sa_newlen;
    /*
     * Join link ([CFG+] App. B.8): the link must survive rotation, so
     * re-seal (gk_new, fet_new) under the STATIC link secret rather than carry
     * the retired slot forward.  If the caller holds jls (the creator-admin),
     * re-seal into a fresh slot; if not (another admin, no stored secret), drop
     * the slot and flag it so the caller can ask the link owner to re-enable.
     */
    if (core->join_ct_len > 0) {
        rc = gy_qspgs_joinlink_secret_load(st, core->gid, jls, sizeof(jls),
                                           &jlen);
        if (rc == GY_OK) {
            rc = gy_qspgs_joinlink_seal(suite, core->aead_id, jls, core->gid,
                                        new_gk, nc.fet, newslot,
                                        sizeof(newslot), &newslotlen);
            if (rc != GY_OK)
                goto out;
            nc.join_ct = newslot;
            nc.join_ct_len = newslotlen;
        } else if (rc == GY_ERR_NOT_FOUND) {
            nc.join_ct = NULL;
            nc.join_ct_len = 0;
            join_dropped = 1;
            rc = GY_OK;
        } else {
            goto out;
        }
    } else {
        nc.join_ct = NULL;
        nc.join_ct_len = 0;
    }
    nc.members = newmembers;
    nc.n_members = j;
    nc.vkhash = newvk;
    nc.n_vk = j;
    nc.last_vmin = 0;

    rc = emit_edited(c, suite, &nc, new_gk, self_skb, self_vkb, self_new_idx,
                     next);
    if (rc == GY_OK && !is_query(next)) {
        /* SEC-v1.5.0 LOW-4: stage the fresh gk rather than overwrite the current
         * one; the caller commits it on server accept or rolls it back on
         * reject (gy_custodian_qsgroup_commit / _rollback).  GY_ERR_STATE here
         * means a prior edit's gk is still unresolved. */
        rc = gy_qspgs_group_key_stage(st, suite, core->gid, new_gk);
        /* Rotation staged; report the dropped-link caveat if it applies. */
        if (rc == GY_OK && join_dropped)
            rc = GY_QSGROUP_JOIN_LINK_DROPPED;
    }
out:
    gy_qspgs_member_view_clear(&v);
    gy_secure_zero(new_gk, sizeof(new_gk));
    gy_secure_zero(new_ek, sizeof(new_ek));
    gy_secure_zero(new_rrs, sizeof(new_rrs));
    gy_secure_zero(vkb, sizeof(vkb));
    gy_secure_zero(jls, sizeof(jls));
    gy_secure_zero(newslot, sizeof(newslot));
    gy_secure_zero(sa_pt, sizeof(sa_pt));
    if (mct_arena != NULL)
        gy_secure_zero(mct_arena, (n > 0 ? n : 1) * 512);
    free(newmembers);
    free(mct_arena);
    free(newvk);
    return rc;
}

/* Shared edit preamble: guard, decode+verify the current core, find the caller
 * as an admin member, and load the caller's base pair.  On GY_OK the caller
 * mutates *core (members backs it) and emits. */
static int
edit_begin(gy_custodian *c, const struct gy_qsgroup_core *cur,
           const struct gy_qsgroup_core *next, struct gy_qspgs_store *st,
           uint8_t *suite_out, struct gy_qspgs_core *core,
           struct gy_qspgs_member *members, uint8_t *gk, uint8_t *ek,
           uint8_t *rrs, uint8_t *self_skb, uint8_t *self_vkb,
           uint32_t *self_idx)
{
    uint8_t suite;
    int rc;

    if (cur == NULL || next == NULL || cur->hdr == NULL ||
        cur->member_list == NULL || cur->vk_lst == NULL || cur->sig == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mk_store(c, st);

    rc = open_current(c, st, suite, cur, core, members, gk, ek, rrs);
    if (rc != GY_OK)
        return rc;
    rc = self_admin_index(c, suite, core, ek, self_idx);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_base_key_load(st, suite, c->self_uid, c->self_uid_len,
                                self_skb, self_vkb);
    if (rc != GY_OK)
        return rc;
    *suite_out = suite;
    return GY_OK;
}

int
gy_custodian_qsgroup_add_member(gy_custodian *c,
                                const struct gy_qsgroup_core *cur,
                                const uint8_t *new_uid, size_t new_uid_len,
                                struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t new_vkb[GY_QSPGS_VKB_MAX];
    uint8_t acq_tmp[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t new_uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t new_vkhash[GY_QSPGS_HASH_MAX];
    uint8_t mct_buf[512];
    uint8_t *newvk = NULL;
    uint64_t ep_tmp;
    size_t n, hash_len, mctlen;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;

    if (new_uid == NULL || new_uid_len != GY_QSPGS_UID_LEN) {
        rc = GY_ERR_ARG;
        goto out;
    }
    n = core.n_members;
    if (n >= GY_QSPGS_MAX_ENTRIES) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    /* The new member's uk comes from the acquaintance record (its acq tag was
     * verified against this uk at accept-acquaintance, D-QGS-13 E4); no uk is
     * accepted out of band. */
    rc = gy_qspgs_acquaintance_load(&st, suite, new_uid, new_uid_len, new_vkb,
                                    acq_tmp, new_uk, &ep_tmp);
    gy_secure_zero(acq_tmp, sizeof(acq_tmp));
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_build(suite, core.aead_id, ek, core.gid, rrs, new_uid,
                               new_uid_len, new_uk, new_vkb, 0, &members[n],
                               mct_buf, sizeof(mct_buf), &mctlen, new_vkhash);
    gy_secure_zero(new_uk, sizeof(new_uk));
    if (rc != GY_OK)
        goto out;

    hash_len = c->desc->hash_len;
    newvk = calloc(n + 1, hash_len);
    if (newvk == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    memcpy(newvk, core.vkhash, n * hash_len);
    memcpy(newvk + n * hash_len, new_vkhash, hash_len);
    core.members = members;
    core.n_members = n + 1;
    core.vkhash = newvk;
    core.n_vk = n + 1;
    core.vmaj += 1;
    core.last_vmin = 0;

    /* Group key unchanged: sign under the current key, seal nothing. */
    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(mct_buf, sizeof(mct_buf));
    free(members);
    free(newvk);
    return rc;
}

int
gy_custodian_qsgroup_set_admin(gy_custodian *c,
                               const struct gy_qsgroup_core *cur,
                               const uint8_t *target_uid, size_t target_uid_len,
                               int admin, struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_view v;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    size_t i;
    uint32_t self_idx;
    uint8_t suite;
    int rc, found = 0;

    memset(&v, 0, sizeof(v));
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    if (target_uid == NULL || target_uid_len != GY_QSPGS_UID_LEN) {
        rc = GY_ERR_ARG;
        goto out;
    }

    for (i = 0; i < core.n_members; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                     &core.members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        if (v.uidlen == target_uid_len &&
            gy_const_memcmp(v.uid, target_uid, target_uid_len) == 0) {
            found = 1;
            gy_qspgs_member_view_clear(&v);
            break;
        }
        gy_qspgs_member_view_clear(&v);
    }
    if (!found) {
        rc = GY_ERR_NOT_FOUND;
        goto out;
    }
    members[i].admn = admin ? 1 : 0;
    core.members = members;
    core.vmaj += 1;
    core.last_vmin = 0;

    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
out:
    gy_qspgs_member_view_clear(&v);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    free(members);
    return rc;
}

int
gy_custodian_qsgroup_remove_member(gy_custodian *c,
                                   const struct gy_qsgroup_core *cur,
                                   const uint8_t *target_uid,
                                   size_t target_uid_len,
                                   struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    if (target_uid == NULL || target_uid_len != GY_QSPGS_UID_LEN) {
        rc = GY_ERR_ARG;
        goto out;
    }
    if (target_uid_len == c->self_uid_len &&
        gy_const_memcmp(target_uid, c->self_uid, target_uid_len) == 0) {
        rc = GY_ERR_ARG; /* the signer cannot remove itself. */
        goto out;
    }
    rc = rebuild_and_emit(c, &st, suite, &core, ek, self_skb, self_vkb,
                          target_uid, target_uid_len, next);
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    free(members);
    return rc;
}

int
gy_custodian_qsgroup_rotate_group_key(gy_custodian *c,
                                      const struct gy_qsgroup_core *cur,
                                      struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    rc = rebuild_and_emit(c, &st, suite, &core, ek, self_skb, self_vkb, NULL, 0,
                          next);
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    free(members);
    return rc;
}

/*
 * SEC-v1.5.0 LOW-4: resolve the group key a rotating edit staged.  Commit
 * promotes the staged gk to current (call it once the server accepts the edit's
 * core); rollback drops the staged gk and keeps the current one (call it if the
 * server rejects).  Mirrors the messaging send path's gy_commit / gy_rollback.
 */
int
gy_custodian_qsgroup_commit(gy_custodian *c,
                            const uint8_t gid[GY_QSGROUP_GID_LEN])
{
    struct gy_qspgs_store st;
    int rc;

    if (gid == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    mk_store(c, &st);
    return gy_qspgs_group_key_commit(&st, c->desc->suite_id, gid);
}

int
gy_custodian_qsgroup_rollback(gy_custodian *c,
                              const uint8_t gid[GY_QSGROUP_GID_LEN])
{
    struct gy_qspgs_store st;
    int rc;

    if (gid == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    mk_store(c, &st);
    return gy_qspgs_group_key_rollback(&st, gid);
}

/* ---- invitations ------------------------------- */

/* The invite entry is the join-seal overhead plus the invite plaintext
 * (uidlen(1) || UID || uk || the two length-prefixed identity signatures). */
_Static_assert(GY_QSGROUP_INVITE_MAX >=
                   GY_QSPGS_JOIN_CURVE_MAX + GY_QSPGS_JOIN_KEM_CT_MAX + 16 + 1 +
                       GY_QSPGS_UID_MAX + GY_QSPGS_MASTER_KEY_MAX + 2 +
                       GY_QSPGS_PERS_ED_SIG_MAX + 2 +
                       GY_QSPGS_PERS_MLDSA_SIG_MAX,
               "public invite bound must cover the largest sealed entry");

int
gy_custodian_qsgroup_invite(gy_custodian *c, const struct gy_qsgroup_core *cur,
                            const uint8_t *invitee_uid, size_t invitee_uid_len,
                            const struct gy_qsgroup_acct_ref *acct,
                            uint8_t *gkprime_out, size_t *gkprime_out_len,
                            struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t new_vkb[GY_QSPGS_VKB_MAX];
    uint8_t gkprime[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t new_vkhash[GY_QSPGS_HASH_MAX];
    uint8_t mct_buf[512];
    uint8_t *newvk = NULL;
    size_t n, hash_len, mctlen, mklen, n_accts = 0;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    if (gkprime_out_len == NULL || invitee_uid == NULL ||
        invitee_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    mklen = gy_qspgs_master_key_len(suite);
    if (!is_query(next) && (gkprime_out == NULL || *gkprime_out_len < mklen)) {
        *gkprime_out_len = mklen;
        rc = gkprime_out == NULL ? GY_ERR_ARG : GY_ERR_TOOLONG;
        goto out;
    }
    n = core.n_members;
    if (n >= GY_QSPGS_MAX_ENTRIES) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }

    /* Resolve the invitee's base key (GetPseudoVkBase): an acquaintance record,
     * else the server-served ACCT the caller supplies.  No uk is minted. */
    if (acct != NULL)
        n_accts = 1;
    rc = resolve_member_vkb(c, &st, suite, invitee_uid, invitee_uid_len, acct,
                            n_accts, new_vkb);
    if (rc != GY_OK)
        goto out;

    /* Mint the per-invite join-key basis gk' and seal a PENDING entry that
     * carries it in place of uk; H(vkpsdn) is the invitee's final slot. */
    rc = gy_qspgs_group_key_gen(suite, gkprime);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_build_pending(suite, core.aead_id, ek, core.gid, rrs,
                                       invitee_uid, invitee_uid_len, gkprime,
                                       new_vkb, &members[n], mct_buf,
                                       sizeof(mct_buf), &mctlen, new_vkhash);
    if (rc != GY_OK)
        goto out;

    hash_len = c->desc->hash_len;
    newvk = calloc(n + 1, hash_len);
    if (newvk == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    memcpy(newvk, core.vkhash, n * hash_len);
    memcpy(newvk + n * hash_len, new_vkhash, hash_len);
    core.members = members;
    core.n_members = n + 1;
    core.vkhash = newvk;
    core.n_vk = n + 1;
    core.vmaj += 1;
    core.last_vmin = 0;

    /* Group key unchanged: sign under the current key, seal nothing. */
    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
    if (rc == GY_OK && !is_query(next)) {
        memcpy(gkprime_out, gkprime, mklen);
        *gkprime_out_len = mklen;
    }
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(gkprime, sizeof(gkprime));
    gy_secure_zero(mct_buf, sizeof(mct_buf));
    free(members);
    free(newvk);
    return rc;
}

int
gy_custodian_qsgroup_accept_invitation(gy_custodian *c,
                                       const uint8_t gid[GY_QSGROUP_GID_LEN],
                                       const uint8_t *gkprime,
                                       size_t gkprime_len, uint64_t ep,
                                       uint8_t *entry_out,
                                       size_t *entry_out_len)
{
    struct gy_qspgs_store st;
    gy_qspgs_join_pk_t ipk;
    gy_qspgs_join_sk_t isk;
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX];
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ed_sig[GY_QSPGS_PERS_ED_SIG_MAX];
    uint8_t mldsa_sig[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    size_t ed_len, mldsa_len, mklen;
    uint8_t suite;
    int rc;

    memset(&isk, 0, sizeof(isk));
    if (gid == NULL || gkprime == NULL || entry_out == NULL ||
        entry_out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    if (c->self_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_STATE;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (gkprime_len != mklen)
        return GY_ERR_ARG;
    mk_store(c, &st);

    /* uk = KDF(muk, "uk@" || ep) from the invitee's OWN master user key. */
    rc = provision_user(c, &st, muk, skb, vkb);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_uk(suite, muk, ep, uk);
    if (rc != GY_OK)
        goto out;

    /* Sign (UID, uk, GID) with the invitee's OWN identity, seal to the invite
     * ipk derived from the admin-shared gk'. */
    rc = gy_qspgs_join_derive(suite, gkprime, &ipk, &isk); /* only ipk used. */
    if (rc != GY_OK)
        goto out;
    rc = gy_custodian_qspgs_sign_invaccept(c, c->self_uid, c->self_uid_len, uk,
                                           gid, ed_sig, &ed_len, mldsa_sig,
                                           &mldsa_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_invite_seal_signed(suite, &ipk, c->self_uid, c->self_uid_len,
                                     uk, ed_sig, ed_len, mldsa_sig, mldsa_len,
                                     entry_out, *entry_out_len, entry_out_len);
out:
    gy_qspgs_join_sk_clear(&isk);
    gy_secure_zero(muk, sizeof(muk));
    gy_secure_zero(skb, sizeof(skb));
    gy_secure_zero(uk, sizeof(uk));
    return rc;
}

int
gy_custodian_qsgroup_open_invitation(gy_custodian *c,
                                     const uint8_t gid[GY_QSGROUP_GID_LEN],
                                     const uint8_t *gkprime, size_t gkprime_len,
                                     const uint8_t *entry, size_t entry_len,
                                     const uint8_t *invitee_curve_pk,
                                     const uint8_t *invitee_mldsa_pk,
                                     struct gy_qsgroup_invite_view *out)
{
    gy_qspgs_join_pk_t ipk;
    gy_qspgs_join_sk_t isk;
    struct gy_qspgs_invite inv;
    size_t mklen;
    uint8_t suite;
    int rc;

    memset(&isk, 0, sizeof(isk));
    memset(&inv, 0, sizeof(inv));
    if (gid == NULL || gkprime == NULL || entry == NULL ||
        invitee_curve_pk == NULL || invitee_mldsa_pk == NULL || out == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    if (gkprime_len != mklen)
        return GY_ERR_ARG;

    /* isk from the same gk' the acceptance sealed to; verify against the
     * INVITED UID's identity keys, not the inviter's (D-QGS-13 E3). */
    rc = gy_qspgs_join_derive(suite, gkprime, &ipk, &isk); /* only isk used. */
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_invite_open(suite, &isk, entry, entry_len, &inv);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_invite_verify(suite, gid, invitee_curve_pk, invitee_mldsa_pk,
                                &inv);
    if (rc != GY_OK)
        goto out;
    memset(out, 0, sizeof(*out));
    memcpy(out->uid, inv.uid, inv.uidlen);
    out->uidlen = inv.uidlen;
    memcpy(out->uk, inv.uk, mklen);
    out->uk_len = mklen;
    rc = GY_OK;
out:
    gy_qspgs_invite_clear(&inv);
    gy_qspgs_join_sk_clear(&isk);
    return rc;
}

int
gy_custodian_qsgroup_complete_invitation(gy_custodian *c,
                                         const struct gy_qsgroup_core *cur,
                                         const uint8_t *invitee_uid,
                                         size_t invitee_uid_len,
                                         const uint8_t *invitee_uk,
                                         size_t invitee_uk_len,
                                         struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_view v;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t mct_buf[512];
    size_t i, mctlen, found = (size_t)-1;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    memset(&v, 0, sizeof(v));
    if (invitee_uid == NULL || invitee_uk == NULL ||
        invitee_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    if (invitee_uk_len != gy_qspgs_master_key_len(suite)) {
        rc = GY_ERR_ARG;
        goto out;
    }

    /* Find the invitee's PENDING entry and fill in the accepted uk. */
    for (i = 0; i < core.n_members; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                     &core.members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        if (v.uidlen == invitee_uid_len &&
            gy_const_memcmp(v.uid, invitee_uid, invitee_uid_len) == 0) {
            found = v.pending ? i : (size_t)-1;
            gy_qspgs_member_view_clear(&v);
            break;
        }
        gy_qspgs_member_view_clear(&v);
    }
    if (found == (size_t)-1) {
        rc = GY_ERR_NOT_FOUND; /* no pending entry for this UID. */
        goto out;
    }

    /* Re-seal that entry PRESENT with the accepted uk (fresh r_c, matching
     * C_UID); admn and the vk-lst hash are unchanged. */
    rc = gy_random_bytes(rc_open, sizeof(rc_open));
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_ct_seal(suite, core.aead_id, ek, core.gid, invitee_uid,
                                 invitee_uid_len, rc_open, invitee_uk, mct_buf,
                                 sizeof(mct_buf), &mctlen);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_cuid_commit(suite, invitee_uid, invitee_uid_len, rc_open,
                              members[found].cuid);
    if (rc != GY_OK)
        goto out;
    members[found].mct = mct_buf;
    members[found].mct_len = mctlen;
    core.members = members;
    core.vmaj += 1;
    core.last_vmin = 0;

    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(mct_buf, sizeof(mct_buf));
    free(members);
    return rc;
}

/*
 * Is appendix-line index i in the caller's ApproveJoin approval list?  Gates
 * the b_adm-held JOIN lines at Consolidate (D-QGS-14 E9); an empty / NULL list
 * approves none.
 */
static int
idx_approved(size_t i, const uint32_t *approved_idx, size_t n_approved)
{
    size_t k;

    if (approved_idx == NULL)
        return 0;
    for (k = 0; k < n_approved; k++)
        if ((size_t)approved_idx[k] == i)
            return 1;
    return 0;
}

/* One entry in Consolidate's effective-roster working set. */
struct consolidate_work {
    uint8_t uid[GY_QSPGS_UID_MAX];
    size_t uidlen;
    uint8_t vkb[GY_QSPGS_VKB_MAX];
    uint8_t key[GY_QSPGS_MASTER_KEY_MAX]; /* uk if settled, gk' if pending. */
    uint8_t admn;
    uint8_t pending;
    uint8_t removed;
};

int
gy_custodian_qsgroup_consolidate(
    gy_custodian *c, const struct gy_qsgroup_core *cur, const uint8_t *apx,
    size_t apx_len, const uint8_t *invite_queue, size_t invite_queue_len,
    const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
    const uint32_t *approved_idx, size_t n_approved,
    struct gy_qsgroup_core *next, uint8_t *queue_out, size_t *queue_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core, nc;
    struct gy_qspgs_appendix apxo;
    struct gy_qspgs_apx_line *lines = NULL;
    struct gy_qspgs_invite_entry *entries = NULL;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member *newmembers = NULL;
    struct consolidate_work *work = NULL;
    struct gy_qspgs_member_view v;
    uint8_t *linevalid = NULL, *qconsumed = NULL, *apxscratch = NULL;
    uint8_t *mct_arena = NULL, *newvk = NULL, *queue_tmp = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t new_gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t new_ek[GY_QSPGS_EK_BYTES];
    uint8_t new_rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t jls[GY_QSPGS_JOINLINK_SECRET];
    uint8_t newslot[512];
    uint8_t nuid[GY_QSPGS_UID_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t uk_tmp[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t hdrpt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t attrbuf[GY_QSGROUP_ATTR_MAX];
    uint8_t sa_pt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t sa_new[1 + GY_QSGROUP_ATTR_MAX + 64];
    const uint8_t *gk_op, *ek_op, *rrs_op;
    size_t n, nwork, hlen, mklen, i, j, consumed, n_lines = 0, n_entries = 0;
    size_t attrlen, hdrptlen, sa_ptlen, sa_newlen, newslotlen, jlen;
    size_t apxscratch_cap, survn, qneed = 0;
    uint32_t self_idx, self_new_idx = 0;
    uint8_t suite, flags, form, leave_folded = 0, join_dropped = 0;
    int rc, self_found = 0;

    memset(&v, 0, sizeof(v));
    memset(&nc, 0, sizeof(nc));
    memset(&apxo, 0, sizeof(apxo));
    if (invite_queue != NULL && invite_queue_len > 0 && queue_out_len == NULL)
        return GY_ERR_ARG;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    newmembers = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*newmembers));
    work = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*work));
    lines = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*lines));
    if (members == NULL || newmembers == NULL || work == NULL ||
        lines == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    hlen = c->desc->hash_len;
    mklen = gy_qspgs_master_key_len(suite);
    n = core.n_members;
    mct_arena = calloc(GY_QSPGS_MAX_ENTRIES, 512);
    newvk = calloc(GY_QSPGS_MAX_ENTRIES, hlen);
    if (mct_arena == NULL || newvk == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* Decode the appendix; its header GID and vMaj must match the core. */
    if (apx != NULL && apx_len > 0) {
        apxo.suite_id = suite;
        rc = gy_qspgs_appendix_decode(&apxo, lines, GY_QSPGS_MAX_ENTRIES, apx,
                                      apx_len, &consumed);
        if (rc != GY_OK)
            goto out;
        if (apxo.vmaj != core.vmaj ||
            gy_const_memcmp(apxo.gid, core.gid, GY_QSPGS_GID_LEN) != 0) {
            rc = GY_ERR_VERIFY;
            goto out;
        }
        n_lines = apxo.n_lines;
    }

    /* Settings and base attributes from the current sealed header field. */
    rc = gy_qspgs_field_open(suite, core.aead_id, ek, GY_QSPGS_FIELD_HEADER,
                             core.gid, core.sa_ct, core.sa_ct_len, hdrpt,
                             sizeof(hdrpt), &hdrptlen);
    if (rc != GY_OK)
        goto out;
    if (hdrptlen < 1) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    flags = hdrpt[0];
    attrlen = hdrptlen - 1;
    if (attrlen > 0)
        memcpy(attrbuf, hdrpt + 1, attrlen);

    /* Effective roster from the current members (resolve each base key). */
    for (i = 0; i < n; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                     &core.members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            goto out;
        }
        memset(&work[i], 0, sizeof(work[i]));
        memcpy(work[i].uid, v.uid, v.uidlen);
        work[i].uidlen = v.uidlen;
        work[i].admn = v.admn;
        work[i].pending = v.pending;
        memcpy(work[i].key, v.uk, mklen); /* uk, or gk' for a pending entry. */
        rc = resolve_member_vkb(c, &st, suite, v.uid, v.uidlen, accts, n_accts,
                                work[i].vkb);
        gy_qspgs_member_view_clear(&v);
        if (rc != GY_OK)
            goto out;
    }
    nwork = n;

    /* Fold the valid appendix lines in the paper's kind order (Fig. 18). */
    if (n_lines > 0) {
        linevalid = calloc(n_lines, 1);
        apxscratch_cap = apx_len + 128;
        apxscratch = calloc(1, apxscratch_cap);
        if (linevalid == NULL || apxscratch == NULL) {
            rc = GY_ERR_CRYPTO;
            goto out;
        }
        for (i = 0; i < n_lines; i++) {
            rc = check_apx_line(c, &st, suite, &core, ek, rrs, apxo.vmaj,
                                apxo.vmin, &lines[i],
                                (flags & GY_QSGROUP_SETTING_ADD) ? 1 : 0,
                                (flags & GY_QSGROUP_SETTING_ATTR) ? 1 : 0,
                                accts, n_accts, apxscratch, apxscratch_cap);
            if (rc < 0)
                goto out;
            linevalid[i] = (uint8_t)rc;
            /*
             * ApproveJoin gate (b_adm, [CFG+] App. B.8, D-QGS-14 E9): with
             * admin approval required, a valid JOIN line folds only if its
             * appendix-line index is approved; otherwise it drops unfolded.
             */
            if (linevalid[i] && lines[i].line_type == GY_QAPX_JOIN &&
                (flags & GY_QSGROUP_SETTING_ADM) &&
                !idx_approved(i, approved_idx, n_approved))
                linevalid[i] = 0;
        }
        /* Pass 1: append join / addUser newcomers. */
        for (i = 0; i < n_lines; i++) {
            const uint8_t *ctp;
            size_t ctlen, nuidlen;

            if (!linevalid[i])
                continue;
            if (lines[i].line_type == GY_QAPX_ADDUSER ||
                lines[i].line_type == GY_QAPX_JOIN) {
                /* Both newcomer kinds carry C_UID'(hash_len) || ct. */
                ctp = lines[i].payload + hlen;
                ctlen = lines[i].payload_len - hlen;
            } else {
                continue;
            }
            if (nwork >= GY_QSPGS_MAX_ENTRIES) {
                rc = GY_ERR_TOOLONG;
                goto out;
            }
            memset(&work[nwork], 0, sizeof(work[nwork]));
            rc = gy_qspgs_member_ct_open(suite, core.aead_id, ek, core.gid, ctp,
                                         ctlen, &form, nuid, sizeof(nuid),
                                         &nuidlen, rc_open, work[nwork].key);
            if (rc != GY_OK)
                goto out;
            memcpy(work[nwork].uid, nuid, nuidlen);
            work[nwork].uidlen = nuidlen;
            rc = resolve_member_vkb(c, &st, suite, nuid, nuidlen, accts,
                                    n_accts, work[nwork].vkb);
            if (rc != GY_OK)
                goto out;
            nwork++;
        }
        /* Pass 2: refresh replaces the member's uk. */
        for (i = 0; i < n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_REFRESH)
                continue;
            j = lines[i].author_index;
            if (j >= n || work[j].removed)
                continue;
            rc = gy_qspgs_field_open(suite, core.aead_id, ek, GY_QSPGS_FIELD_UK,
                                     core.gid, lines[i].payload,
                                     lines[i].payload_len, work[j].key,
                                     sizeof(work[j].key), &jlen);
            if (rc != GY_OK)
                goto out;
        }
        /* Pass 3: modAttr replaces the folded attributes (last valid wins). */
        for (i = 0; i < n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_MODATTR)
                continue;
            rc = gy_qspgs_field_open(suite, core.aead_id, ek,
                                     GY_QSPGS_FIELD_ATTR, core.gid,
                                     lines[i].payload, lines[i].payload_len,
                                     attrbuf, sizeof(attrbuf), &attrlen);
            if (rc != GY_OK)
                goto out;
        }
        /* Pass 4: leave removes the member and forces a group-key rotation. */
        for (i = 0; i < n_lines; i++) {
            if (!linevalid[i] || lines[i].line_type != GY_QAPX_LEAVE)
                continue;
            j = lines[i].author_index;
            if (j < n) {
                work[j].removed = 1;
                leave_folded = 1;
            }
        }
    }

    /* Drain the invite queue: settle pending members from accepted invites. */
    if (invite_queue != NULL && invite_queue_len > 0) {
        entries = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*entries));
        qconsumed = calloc(GY_QSPGS_MAX_ENTRIES, 1);
        if (entries == NULL || qconsumed == NULL) {
            rc = GY_ERR_CRYPTO;
            goto out;
        }
        rc = gy_qspgs_invite_queue_decode(suite, entries, GY_QSPGS_MAX_ENTRIES,
                                          invite_queue, invite_queue_len,
                                          &n_entries, &consumed);
        if (rc != GY_OK)
            goto out;
        for (i = 0; i < n; i++) {
            size_t eidx;

            if (!work[i].pending || work[i].removed)
                continue;
            rc = settle_one(suite, work[i].key, core.gid, entries, n_entries,
                            accts, n_accts, work[i].uid, work[i].uidlen, uk_tmp,
                            &eidx);
            if (rc < 0)
                goto out;
            if (rc == 1) {
                memcpy(work[i].key, uk_tmp, mklen);
                work[i].pending = 0;
                qconsumed[eidx] = 1;
            }
        }
    }

    /* Rotate the group key iff a leave folded (section 3.3); else keep it. */
    if (leave_folded) {
        rc = gy_qspgs_group_key_gen(suite, new_gk);
        if (rc == GY_OK)
            rc = gy_qspgs_derive_sub_key(suite, new_gk, new_ek, new_rrs);
        if (rc != GY_OK)
            goto out;
        gk_op = new_gk;
        ek_op = new_ek;
        rrs_op = new_rrs;
    } else {
        gk_op = gk;
        ek_op = ek;
        rrs_op = rrs;
    }

    /* Rebuild every surviving member under the operative keys. */
    nc.suite_id = suite;
    memcpy(nc.gid, core.gid, GY_QSPGS_GID_LEN);
    nc.format_version = core.format_version;
    nc.aead_id = core.aead_id; /* INFO-6: pinned, immutable across the edit. */
    nc.vmaj = core.vmaj + 1;
    rc = gy_qspgs_derive_fet(suite, gk_op, nc.fet);
    if (rc != GY_OK)
        goto out;
    j = 0;
    for (i = 0; i < nwork; i++) {
        size_t mctlen;

        if (work[i].removed)
            continue;
        if (work[i].pending)
            rc = gy_qspgs_member_build_pending(
                suite, core.aead_id, ek_op, core.gid, rrs_op, work[i].uid,
                work[i].uidlen, work[i].key, work[i].vkb, &newmembers[j],
                mct_arena + j * 512, 512, &mctlen, newvk + j * hlen);
        else
            rc = gy_qspgs_member_build(suite, core.aead_id, ek_op, core.gid,
                                       rrs_op, work[i].uid, work[i].uidlen,
                                       work[i].key, work[i].vkb, work[i].admn,
                                       &newmembers[j], mct_arena + j * 512, 512,
                                       &mctlen, newvk + j * hlen);
        if (rc != GY_OK)
            goto out;
        if (work[i].uidlen == c->self_uid_len &&
            gy_const_memcmp(work[i].uid, c->self_uid, work[i].uidlen) == 0) {
            self_found = 1;
            self_new_idx = (uint32_t)j;
        }
        j++;
    }
    if (!self_found) {
        rc = GY_ERR_STATE; /* the signer must remain a member. */
        goto out;
    }

    /* Re-seal the header field (flags || attributes) under the operative ek. */
    sa_pt[0] = flags;
    if (attrlen > 0)
        memcpy(sa_pt + 1, attrbuf, attrlen);
    sa_ptlen = 1 + attrlen;
    rc = gy_qspgs_field_seal(suite, core.aead_id, ek_op, GY_QSPGS_FIELD_HEADER,
                             core.gid, sa_pt, sa_ptlen, sa_new, sizeof(sa_new),
                             &sa_newlen);
    if (rc != GY_OK)
        goto out;
    nc.sa_ct = sa_new;
    nc.sa_ct_len = sa_newlen;

    /* Join link: re-seal on rotation (App. B.8), else carry it forward. */
    if (core.join_ct_len > 0 && leave_folded) {
        rc = gy_qspgs_joinlink_secret_load(&st, core.gid, jls, sizeof(jls),
                                           &jlen);
        if (rc == GY_OK) {
            rc = gy_qspgs_joinlink_seal(suite, core.aead_id, jls, core.gid,
                                        new_gk, nc.fet, newslot,
                                        sizeof(newslot), &newslotlen);
            if (rc != GY_OK)
                goto out;
            nc.join_ct = newslot;
            nc.join_ct_len = newslotlen;
        } else if (rc == GY_ERR_NOT_FOUND) {
            nc.join_ct = NULL;
            nc.join_ct_len = 0;
            join_dropped = 1;
        } else {
            goto out;
        }
    } else {
        nc.join_ct = core.join_ct; /* unchanged gk: the slot stays valid. */
        nc.join_ct_len = core.join_ct_len;
    }

    nc.members = newmembers;
    nc.n_members = j;
    nc.vkhash = newvk;
    nc.n_vk = j;
    nc.last_vmin = (uint32_t)n_lines;

    rc = emit_edited(c, suite, &nc, gk_op, self_skb, self_vkb, self_new_idx,
                     next);
    if (rc == GY_OK && !is_query(next) && leave_folded) {
        /* SEC-v1.5.0 LOW-4: a folded leave rotates gk; stage it for commit on
         * server accept (gy_custodian_qsgroup_commit / _rollback). */
        rc = gy_qspgs_group_key_stage(&st, suite, core.gid, new_gk);
        if (rc == GY_OK && join_dropped)
            rc = GY_QSGROUP_JOIN_LINK_DROPPED;
    }
    if (rc != GY_OK && rc != GY_QSGROUP_JOIN_LINK_DROPPED)
        goto out;

    /* Emit the drained invite queue (consumed acceptances removed). */
    if (invite_queue != NULL && invite_queue_len > 0) {
        survn = 0;
        for (i = 0; i < n_entries; i++)
            if (!qconsumed[i])
                entries[survn++] = entries[i];
        queue_tmp = calloc(1, invite_queue_len + 16);
        if (queue_tmp == NULL) {
            rc = GY_ERR_CRYPTO;
            goto out;
        }
        rc = gy_qspgs_invite_queue_encode(suite, entries, survn, queue_tmp,
                                          invite_queue_len + 16, &qneed);
        if (rc != GY_OK)
            goto out;
        if (queue_out == NULL) {
            *queue_out_len = qneed;
        } else if (*queue_out_len < qneed) {
            *queue_out_len = qneed;
            rc = GY_ERR_TOOLONG;
            goto out;
        } else {
            memcpy(queue_out, queue_tmp, qneed);
            *queue_out_len = qneed;
        }
    }
    if (rc == GY_OK && join_dropped)
        rc = GY_QSGROUP_JOIN_LINK_DROPPED;
out:
    gy_qspgs_member_view_clear(&v);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(new_gk, sizeof(new_gk));
    gy_secure_zero(new_ek, sizeof(new_ek));
    gy_secure_zero(new_rrs, sizeof(new_rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(jls, sizeof(jls));
    gy_secure_zero(newslot, sizeof(newslot));
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(uk_tmp, sizeof(uk_tmp));
    gy_secure_zero(hdrpt, sizeof(hdrpt));
    gy_secure_zero(attrbuf, sizeof(attrbuf));
    gy_secure_zero(sa_pt, sizeof(sa_pt));
    if (work != NULL)
        gy_secure_zero(work, GY_QSPGS_MAX_ENTRIES * sizeof(*work));
    if (mct_arena != NULL)
        gy_secure_zero(mct_arena, GY_QSPGS_MAX_ENTRIES * 512);
    free(members);
    free(newmembers);
    free(work);
    free(lines);
    free(entries);
    free(qconsumed);
    free(linevalid);
    free(apxscratch);
    free(mct_arena);
    free(newvk);
    free(queue_tmp);
    return rc;
}

int
gy_custodian_qsgroup_revoke_invitation(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t *cur_queue, size_t cur_queue_len, const uint8_t *target_uid,
    size_t target_uid_len, struct gy_qsgroup_core *next, uint8_t *out_queue,
    size_t *out_queue_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    gy_qspgs_join_pk_t ipk;
    gy_qspgs_join_sk_t isk;
    struct gy_qspgs_invite inv;
    struct gy_qspgs_invite_entry *ents = NULL, *keep = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t gkprime[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t tuid[GY_QSPGS_UID_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t form;
    uint32_t self_idx;
    size_t n, consumed, nkeep = 0, i, tuidlen, found = (size_t)-1;
    uint8_t suite;
    int rc, revrc;

    memset(&core, 0, sizeof(core));
    memset(&isk, 0, sizeof(isk));
    memset(&inv, 0, sizeof(inv));
    if (cur_queue == NULL || target_uid == NULL || out_queue == NULL ||
        out_queue_len == NULL)
        return GY_ERR_ARG;
    if (target_uid_len != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    ents = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*ents));
    keep = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*keep));
    if (members == NULL || ents == NULL || keep == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* Open + verify the current core as an admin (edit_begin); capture the
     * target's PENDING entry index and its per-invite gk' before the edit, so
     * the opaque queue entry can be identified after (spec section 5,
     * D-QGS-13 E3). */
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    /* Open each member ct: a PENDING entry's key slot is the per-invite gk'
     * (member_decrypt discards it, so open directly, as the queue-scrub half
     * needs gk' to derive the isk the acceptance was sealed to). */
    for (i = 0; i < core.n_members; i++) {
        rc = gy_qspgs_member_ct_open(suite, core.aead_id, ek, core.gid,
                                     core.members[i].mct,
                                     core.members[i].mct_len, &form, tuid,
                                     sizeof(tuid), &tuidlen, rc_open, gkprime);
        if (rc != GY_OK)
            goto out;
        if (form == GY_QSPGS_MEMBER_FORM_PENDING && tuidlen == target_uid_len &&
            gy_const_memcmp(tuid, target_uid, target_uid_len) == 0) {
            found = i; /* gkprime now holds this invite's gk'. */
            break;
        }
    }
    if (found == (size_t)-1) {
        rc = GY_ERR_NOT_FOUND; /* no pending invite for this UID. */
        goto out;
    }

    /* Drop the pending entry and rotate gk (Fig. 17: remove the (C_UID, mct, 0)
     * line, similar as RemoveMember), re-signing and emitting the new core. */
    revrc = rebuild_and_emit(c, &st, suite, &core, ek, self_skb, self_vkb,
                             target_uid, target_uid_len, next);
    if (revrc != GY_OK && revrc != GY_QSGROUP_JOIN_LINK_DROPPED) {
        rc = revrc;
        goto out;
    }

    /* Drain the target's queued acceptance: entries are opaque, identified by
     * opening them with the isk from the captured gk'. */
    rc = gy_qspgs_join_derive(suite, gkprime, &ipk, &isk); /* only isk used. */
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_invite_queue_decode(suite, ents, GY_QSPGS_MAX_ENTRIES,
                                      cur_queue, cur_queue_len, &n, &consumed);
    if (rc != GY_OK)
        goto out;
    for (i = 0; i < n; i++) {
        int drop = 0;

        memset(&inv, 0, sizeof(inv));
        if (gy_qspgs_invite_open(suite, &isk, ents[i].ct, ents[i].ct_len,
                                 &inv) == GY_OK &&
            inv.uidlen == target_uid_len &&
            gy_const_memcmp(inv.uid, target_uid, target_uid_len) == 0)
            drop = 1;
        gy_qspgs_invite_clear(&inv);
        if (!drop)
            keep[nkeep++] = ents[i]; /* opaque ct copied verbatim. */
    }
    rc = gy_qspgs_invite_queue_encode(suite, keep, nkeep, out_queue,
                                      *out_queue_len, out_queue_len);
    if (rc == GY_OK)
        rc =
            revrc; /* propagate JOIN_LINK_DROPPED if the rotation dropped it. */
out:
    gy_qspgs_invite_clear(&inv);
    gy_qspgs_join_sk_clear(&isk);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(gkprime, sizeof(gkprime));
    gy_secure_zero(rc_open, sizeof(rc_open));
    free(members);
    free(ents);
    free(keep);
    return rc;
}

int
gy_custodian_qsgroup_invite_queue_append(gy_custodian *c,
                                         const uint8_t *cur_queue,
                                         size_t cur_queue_len,
                                         const uint8_t *entry, size_t entry_len,
                                         uint8_t *out_queue,
                                         size_t *out_queue_len)
{
    struct gy_qspgs_invite_entry *ents = NULL;
    size_t n = 0, consumed;
    uint8_t suite;
    int rc;

    if (entry == NULL || entry_len == 0 || out_queue == NULL ||
        out_queue_len == NULL)
        return GY_ERR_ARG;
    if (cur_queue == NULL && cur_queue_len != 0)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;

    /* Leave room for the appended entry, so a full queue is GY_ERR_TOOLONG. */
    ents = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*ents));
    if (ents == NULL)
        return GY_ERR_CRYPTO;
    if (cur_queue_len != 0) {
        rc = gy_qspgs_invite_queue_decode(suite, ents, GY_QSPGS_MAX_ENTRIES - 1,
                                          cur_queue, cur_queue_len, &n,
                                          &consumed);
        if (rc != GY_OK)
            goto out;
    }
    ents[n].ct = entry;
    ents[n].ct_len = entry_len;
    n++;
    rc = gy_qspgs_invite_queue_encode(suite, ents, n, out_queue, *out_queue_len,
                                      out_queue_len);
out:
    free(ents);
    return rc;
}

/* ---- settings, appendix, join link ------------- */

int
gy_custodian_qsgroup_change_settings(gy_custodian *c,
                                     const struct gy_qsgroup_core *cur,
                                     uint8_t settings_flags,
                                     const uint8_t *attr, size_t attr_len,
                                     struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t sa_pt[1 + GY_QSGROUP_ATTR_MAX];
    uint8_t *sa = NULL;
    size_t sa_cap, sa_len, sa_ptlen;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    if (attr == NULL && attr_len != 0)
        return GY_ERR_ARG;
    if (attr_len > GY_QSGROUP_ATTR_MAX)
        return GY_ERR_TOOLONG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;

    rc = settings_plaintext(settings_flags, attr, attr_len, sa_pt,
                            sizeof(sa_pt), &sa_ptlen);
    if (rc != GY_OK)
        goto out;
    sa_cap = sa_ptlen + gy_qspgs_field_overhead(core.aead_id) + 16;
    sa = calloc(1, sa_cap);
    if (sa == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = gy_qspgs_field_seal(suite, core.aead_id, ek, GY_QSPGS_FIELD_HEADER,
                             core.gid, sa_pt, sa_ptlen, sa, sa_cap, &sa_len);
    if (rc != GY_OK)
        goto out;
    core.sa_ct = sa;
    core.sa_ct_len = sa_len;
    core.vmaj += 1;
    core.last_vmin = 0;
    /* Group key unchanged: sign under the current key, seal nothing. */
    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(sa_pt, sizeof(sa_pt));
    free(members);
    free(sa);
    return rc;
}

/* Find the caller's own member index (no admin requirement). */
static int
find_self_index(gy_custodian *c, uint8_t suite,
                const struct gy_qspgs_core *core, const uint8_t *ek,
                uint32_t *idx)
{
    struct gy_qspgs_member_view v;
    size_t i;
    int rc;

    for (i = 0; i < core->n_members; i++) {
        memset(&v, 0, sizeof(v));
        rc = gy_qspgs_member_decrypt(suite, core->aead_id, ek, core->gid,
                                     &core->members[i], &v);
        if (rc != GY_OK) {
            gy_qspgs_member_view_clear(&v);
            return rc;
        }
        if (v.uidlen == c->self_uid_len &&
            gy_const_memcmp(v.uid, c->self_uid, v.uidlen) == 0) {
            *idx = (uint32_t)i;
            gy_qspgs_member_view_clear(&v);
            return GY_OK;
        }
        gy_qspgs_member_view_clear(&v);
    }
    return GY_ERR_STATE; /* the caller is not a member of this group. */
}

/* Sign one appendix line with mctx and frame it as a single-line appendix
 * object at (gid, vmaj, vmin) into out. */
static int
frame_line(uint8_t suite, const struct gy_qspgs_member_ctx *mctx,
           const uint8_t gid[GY_QSGROUP_GID_LEN], uint32_t vmaj, uint32_t vmin,
           uint8_t line_type, uint32_t author_index, const uint8_t *payload,
           size_t payload_len, uint8_t *out, size_t *out_len)
{
    struct gy_qspgs_apx_line line;
    struct gy_qspgs_appendix apx;
    uint8_t sig[GY_QSPGS_SIG_MAX];
    uint8_t *scratch = NULL;
    size_t sig_len, scap = payload_len + 64;
    int rc;

    scratch = calloc(1, scap);
    if (scratch == NULL)
        return GY_ERR_CRYPTO;
    rc = gy_qspgs_apx_line_sign(suite, mctx, gid, vmaj, vmin, line_type,
                                author_index, payload, payload_len, sig,
                                sizeof(sig), &sig_len, scratch, scap);
    if (rc != GY_OK)
        goto out;

    memset(&line, 0, sizeof(line));
    line.line_type = line_type;
    line.author_index = author_index;
    line.payload = payload;
    line.payload_len = payload_len;
    line.sig = sig;
    line.sig_len = sig_len;

    memset(&apx, 0, sizeof(apx));
    apx.suite_id = suite;
    memcpy(apx.gid, gid, GY_QSGROUP_GID_LEN);
    apx.vmaj = vmaj;
    apx.vmin = vmin;
    apx.lines = &line;
    apx.n_lines = 1;
    rc = gy_qspgs_appendix_encode(&apx, out, *out_len, out_len);
out:
    free(scratch);
    return rc;
}

/*
 * Shared appendix preamble: verify the current core, find the caller's own
 * member index, and open the caller's member context under the current group
 * key.  On GY_OK *st is bound, core carries the header (gid, vmaj), mctx is the
 * caller's signing context (mctx->ek is the group AEAD key), and *self_idx is
 * the caller's author index.
 */
static int
appendix_prepare(gy_custodian *c, const struct gy_qsgroup_core *cur,
                 struct gy_qspgs_store *st, uint8_t *suite_out,
                 struct gy_qspgs_core *core, struct gy_qspgs_member *members,
                 struct gy_qspgs_member_ctx *mctx, uint32_t *self_idx)
{
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t suite;
    int rc;

    if (cur == NULL || cur->hdr == NULL || cur->member_list == NULL ||
        cur->vk_lst == NULL || cur->sig == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mk_store(c, st);

    rc = open_current(c, st, suite, cur, core, members, gk, ek, rrs);
    if (rc != GY_OK)
        goto out;
    rc = find_self_index(c, suite, core, ek, self_idx);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_base_key_load(st, suite, c->self_uid, c->self_uid_len,
                                self_skb, self_vkb);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_ctx_open(mctx, suite, gk, self_skb, self_vkb,
                                  c->self_uid, c->self_uid_len);
    *suite_out = suite;
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    return rc;
}

int
gy_custodian_qsgroup_appendix_leave(gy_custodian *c,
                                    const struct gy_qsgroup_core *cur,
                                    uint32_t vmin, uint8_t *line_out,
                                    size_t *line_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (line_out == NULL || line_out_len == NULL)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc =
        appendix_prepare(c, cur, &st, &suite, &core, members, &mctx, &self_idx);
    if (rc != GY_OK)
        goto out;
    rc = frame_line(suite, &mctx, core.gid, core.vmaj, vmin, GY_QAPX_LEAVE,
                    self_idx, NULL, 0, line_out, line_out_len);
out:
    gy_qspgs_member_ctx_clear(&mctx);
    free(members);
    return rc;
}

int
gy_custodian_qsgroup_appendix_refresh(gy_custodian *c,
                                      const struct gy_qsgroup_core *cur,
                                      uint32_t vmin, uint64_t ep,
                                      uint8_t *line_out, size_t *line_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ukp[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t payload[512];
    size_t mkout, plen, mklen;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (line_out == NULL || line_out_len == NULL)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc =
        appendix_prepare(c, cur, &st, &suite, &core, members, &mctx, &self_idx);
    if (rc != GY_OK)
        goto out;
    mklen = gy_qspgs_master_key_len(suite);
    rc = gy_qspgs_muk_load(&st, suite, c->self_uid, c->self_uid_len, muk,
                           sizeof(muk), &mkout);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_derive_uk(suite, muk, ep, ukp);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_field_seal(suite, core.aead_id, mctx.ek, GY_QSPGS_FIELD_UK,
                             core.gid, ukp, mklen, payload, sizeof(payload),
                             &plen);
    if (rc != GY_OK)
        goto out;
    rc = frame_line(suite, &mctx, core.gid, core.vmaj, vmin, GY_QAPX_REFRESH,
                    self_idx, payload, plen, line_out, line_out_len);
out:
    gy_qspgs_member_ctx_clear(&mctx);
    gy_secure_zero(muk, sizeof(muk));
    gy_secure_zero(ukp, sizeof(ukp));
    gy_secure_zero(payload, sizeof(payload));
    free(members);
    return rc;
}

int
gy_custodian_qsgroup_appendix_mod_attr(gy_custodian *c,
                                       const struct gy_qsgroup_core *cur,
                                       uint32_t vmin, const uint8_t *attr,
                                       size_t attr_len, uint8_t *line_out,
                                       size_t *line_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    uint8_t *payload = NULL;
    size_t plen, pcap;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (line_out == NULL || line_out_len == NULL ||
        (attr == NULL && attr_len != 0))
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc =
        appendix_prepare(c, cur, &st, &suite, &core, members, &mctx, &self_idx);
    if (rc != GY_OK)
        goto out;
    pcap = attr_len + gy_qspgs_field_overhead(core.aead_id) + 16;
    payload = calloc(1, pcap);
    if (payload == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = gy_qspgs_field_seal(suite, core.aead_id, mctx.ek, GY_QSPGS_FIELD_ATTR,
                             core.gid, attr, attr_len, payload, pcap, &plen);
    if (rc != GY_OK)
        goto out;
    rc = frame_line(suite, &mctx, core.gid, core.vmaj, vmin, GY_QAPX_MODATTR,
                    self_idx, payload, plen, line_out, line_out_len);
out:
    gy_qspgs_member_ctx_clear(&mctx);
    free(members);
    free(payload);
    return rc;
}

int
gy_custodian_qsgroup_appendix_add_user(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint32_t vmin,
    const uint8_t *new_uid, size_t new_uid_len, const uint8_t *new_uk,
    size_t new_uk_len, uint8_t *line_out, size_t *line_out_len,
    uint8_t *vkhash_out, size_t *vkhash_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t cuid[GY_QSPGS_HASH_MAX];
    uint8_t new_vkb[GY_QSPGS_VKB_MAX];
    uint8_t acq_tmp[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t uk_tmp[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t vkhash[GY_QSPGS_HASH_MAX];
    uint8_t *payload = NULL;
    uint64_t ep_tmp;
    size_t hlen, ctlen, pcap, mklen;
    uint32_t self_idx;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (line_out == NULL || line_out_len == NULL || new_uid == NULL ||
        new_uk == NULL || vkhash_out_len == NULL)
        return GY_ERR_ARG;
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc =
        appendix_prepare(c, cur, &st, &suite, &core, members, &mctx, &self_idx);
    if (rc != GY_OK)
        goto out;
    mklen = gy_qspgs_master_key_len(suite);
    hlen = c->desc->hash_len;
    if (new_uid_len != GY_QSPGS_UID_LEN || new_uk_len != mklen) {
        rc = GY_ERR_ARG;
        goto out;
    }

    /*
     * The newcomer's attribution hash H(vkpsdn) (Fig. 12): recompute it from the
     * newcomer's base key (held in the caller's acquaintance record) under the
     * current group rrs, so the deployer can append it to vk-lst on acceptance.
     */
    rc = gy_qspgs_acquaintance_load(&st, suite, new_uid, new_uid_len, new_vkb,
                                    acq_tmp, uk_tmp, &ep_tmp);
    gy_secure_zero(acq_tmp, sizeof(acq_tmp));
    gy_secure_zero(uk_tmp, sizeof(uk_tmp));
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_attribute_hash(suite, mctx.rrs, new_vkb, new_uid, new_uid_len,
                                 vkhash);
    if (rc != GY_OK)
        goto out;

    rc = gy_random_bytes(rc_open, sizeof(rc_open));
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_cuid_commit(suite, new_uid, new_uid_len, rc_open, cuid);
    if (rc != GY_OK)
        goto out;

    /* payload = C_UID'(hash_len) || Enc_ek(UID', r', uk'). */
    pcap = hlen + GY_QSPGS_MEMBER_PT_MAX +
           gy_qspgs_field_overhead(core.aead_id) + 16;
    payload = calloc(1, pcap);
    if (payload == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    memcpy(payload, cuid, hlen);
    rc = gy_qspgs_member_ct_seal(suite, core.aead_id, mctx.ek, core.gid,
                                 new_uid, new_uid_len, rc_open, new_uk,
                                 payload + hlen, pcap - hlen, &ctlen);
    if (rc != GY_OK)
        goto out;
    rc = frame_line(suite, &mctx, core.gid, core.vmaj, vmin, GY_QAPX_ADDUSER,
                    self_idx, payload, hlen + ctlen, line_out, line_out_len);
    if (rc != GY_OK)
        goto out;

    /* Emit H(vkpsdn) per the buffer convention (size query when NULL). */
    if (vkhash_out == NULL) {
        *vkhash_out_len = hlen;
    } else if (*vkhash_out_len < hlen) {
        *vkhash_out_len = hlen;
        rc = GY_ERR_TOOLONG;
        goto out;
    } else {
        memcpy(vkhash_out, vkhash, hlen);
        *vkhash_out_len = hlen;
    }
out:
    gy_qspgs_member_ctx_clear(&mctx);
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(new_vkb, sizeof(new_vkb));
    free(members);
    free(payload);
    return rc;
}

int
gy_custodian_qsgroup_toggle_join_link(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    uint8_t link_secret_out[GY_QSGROUP_LINK_SECRET_LEN],
    struct gy_qsgroup_core *next)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t jls[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t slot[512];
    size_t slotlen;
    uint32_t self_idx;
    uint8_t suite;
    int enable, rc;

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    rc = edit_begin(c, cur, next, &st, &suite, &core, members, gk, ek, rrs,
                    self_skb, self_vkb, &self_idx);
    if (rc != GY_OK)
        goto out;
    /*
     * A true toggle keyed on the current slot: an open link is closed, a
     * closed link is opened.  Enable requires link_secret_out (the fresh
     * secret to share out of band); disable leaves it untouched.
     */
    enable = (core.join_ct_len == 0);
    if (enable) {
        if (link_secret_out == NULL) {
            rc = GY_ERR_ARG;
            goto out;
        }
        rc = gy_random_bytes(jls, sizeof(jls));
        if (rc != GY_OK)
            goto out;
        /* fet is no longer decoded from the header (SEC-v1.5.0 LOW-1); derive
         * it from the current group key to seal (gk, fet) into the slot. */
        rc = gy_qspgs_derive_fet(suite, gk, core.fet);
        if (rc != GY_OK)
            goto out;
        rc = gy_qspgs_joinlink_seal(suite, core.aead_id, jls, core.gid, gk,
                                    core.fet, slot, sizeof(slot), &slotlen);
        if (rc != GY_OK)
            goto out;
        core.join_ct = slot;
        core.join_ct_len = slotlen;
    } else {
        /* Disable: drop the slot; the link secret is retired below. */
        core.join_ct = NULL;
        core.join_ct_len = 0;
    }
    core.vmaj += 1;
    core.last_vmin = 0;
    /* Group key unchanged: sign under the current key, seal nothing. */
    rc = emit_edited(c, suite, &core, gk, self_skb, self_vkb, self_idx, next);
    if (rc != GY_OK || is_query(next))
        goto out;
    /*
     * Persist / retire the link secret so it survives group-key rotation
     * ([CFG+] App. B.8; the ONE at-rest secret outside muk/base/gk per
     * D-QGS-8).  Enable stores jls and hands it back; disable removes it.
     */
    if (enable) {
        rc = gy_qspgs_joinlink_secret_store(&st, core.gid, jls);
        if (rc == GY_OK)
            memcpy(link_secret_out, jls, sizeof(jls));
    } else {
        rc = gy_qspgs_joinlink_secret_delete(&st, core.gid);
    }
out:
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(self_skb, sizeof(self_skb));
    gy_secure_zero(jls, sizeof(jls));
    gy_secure_zero(slot, sizeof(slot));
    free(members);
    return rc;
}

int
gy_custodian_qsgroup_join_via_link(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t link_secret[GY_QSGROUP_LINK_SECRET_LEN], uint64_t ep,
    const uint8_t *signer_acct, size_t signer_acct_len, uint8_t *uk_out,
    size_t *uk_out_len, uint8_t *line_out, size_t *line_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    struct gy_qspgs_member_view sv;
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t fet[GY_QSPGS_FET_LEN];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t signer_vkb[GY_QSPGS_VKB_MAX];
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t self_skb[GY_QSPGS_SKB_MAX];
    uint8_t self_vkb[GY_QSPGS_VKB_MAX];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t cuid[GY_QSPGS_HASH_MAX];
    uint8_t *payload = NULL;
    uint8_t *scratch = NULL;
    const uint8_t *sigp, *sacq, *seds, *smls;
    size_t consumed, mklen, hlen, ctlen, pcap, sigplen, scap, sedl, smll, scons;
    size_t vkblen;
    uint32_t author_index, signer_index, signer_vmin;
    uint64_t saep;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    memset(&sv, 0, sizeof(sv));
    if (cur == NULL || cur->hdr == NULL || cur->member_list == NULL ||
        cur->vk_lst == NULL || cur->sig == NULL || signer_acct == NULL ||
        link_secret == NULL || uk_out == NULL || uk_out_len == NULL ||
        line_out == NULL || line_out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mklen = gy_qspgs_master_key_len(suite);
    hlen = c->desc->hash_len;
    if (*uk_out_len < mklen) {
        *uk_out_len = mklen;
        return GY_ERR_TOOLONG;
    }
    mk_store(c, &st);
    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;

    memset(&core, 0, sizeof(core));
    core.suite_id = suite;
    rc = gy_qspgs_header_decode(&core, cur->hdr, cur->hdr_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_list_decode(&core, members, GY_QSPGS_MAX_ENTRIES,
                                     cur->member_list, cur->member_list_len,
                                     &consumed);
    if (rc != GY_OK)
        goto out;
    if (core.join_ct == NULL || core.join_ct_len == 0) {
        rc = GY_ERR_VERIFY; /* the group has no open join link. */
        goto out;
    }
    rc = gy_qspgs_joinlink_open(suite, core.aead_id, link_secret, core.gid,
                                core.join_ct, core.join_ct_len, gk, fet);
    if (rc != GY_OK)
        goto out;

    /*
     * D-QGS-13 E8: verify the current core's admin signature BEFORE
     * installing the recovered group key, so a joiner never adopts a gk out of
     * a forged or tampered core.  The joiner holds no acquaintance records yet,
     * so this is a signature-only check against the signer's ACCT supplied by
     * the caller out of band (the caller vouches for that identity; full ACCT
     * dual-signature verification is accept_acquaintance's job, and the E5
     * all-member recompute runs at the joiner's first fetch).  gk stays in a
     * local buffer until the check passes.
     */
    rc = gy_qspgs_vk_lst_decode(&core, cur->vk_lst, cur->vk_lst_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_core_sig_decode(suite, cur->sig, cur->sig_len, &signer_index,
                                  &signer_vmin, &sigp, &sigplen, &consumed);
    if (rc != GY_OK)
        goto out;
    if (consumed != cur->sig_len || signer_index >= core.n_members) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    core.last_vmin = signer_vmin;
    rc = gy_qspgs_derive_sub_key(suite, gk, ek, rrs);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_decrypt(suite, core.aead_id, ek, core.gid,
                                 &core.members[signer_index], &sv);
    if (rc != GY_OK)
        goto out;

    /* The signer's base verify key comes from the caller-supplied ACCT. */
    {
        const uint8_t *svkb;
        rc = gy_qspgs_acct_decode(suite, signer_acct, signer_acct_len, &svkb,
                                  &sacq, &saep, &seds, &sedl, &smls, &smll,
                                  &scons);
        if (rc != GY_OK)
            goto out;
        vkblen = gy_qspgs_base_vkb_len(suite);
        memcpy(signer_vkb, svkb, vkblen);
    }
    scap = cur->hdr_len + cur->member_list_len + cur->vk_lst_len + 64;
    scratch = calloc(1, scap);
    if (scratch == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = gy_qspgs_core_resolve_verify(&core, signer_index, rrs, signer_vkb,
                                      sv.uid, sv.uidlen, sigp, sigplen, scratch,
                                      scap);
    if (rc != GY_OK)
        goto out;

    /* Seal the recovered group key locally: the caller can now fetch. */
    rc = gy_qspgs_group_key_store(&st, suite, core.gid, gk);
    if (rc != GY_OK)
        goto out;

    rc = provision_user(c, &st, muk, self_skb, self_vkb);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_uk(suite, muk, ep, uk); /* uk = KDF(muk, ep). */
    gy_secure_zero(muk, sizeof(muk));
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_ctx_open(&mctx, suite, gk, self_skb, self_vkb,
                                  c->self_uid, c->self_uid_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_random_bytes(rc_open, sizeof(rc_open));
    if (rc != GY_OK)
        goto out;
    /* C_UID' commitment, prefixed ahead of the ct exactly as addUser does, so
     * CheckAppendixLine checks the join newcomer's commitment (D-QGS-14 E14). */
    rc = gy_qspgs_cuid_commit(suite, c->self_uid, c->self_uid_len, rc_open,
                              cuid);
    if (rc != GY_OK)
        goto out;

    /* JOIN payload = C_UID'(hash_len) || Enc_ek(own UID, r, uk); proposed slot
     * = current count. */
    pcap = hlen + GY_QSPGS_MEMBER_PT_MAX +
           gy_qspgs_field_overhead(core.aead_id) + 16;
    payload = calloc(1, pcap);
    if (payload == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    memcpy(payload, cuid, hlen);
    rc = gy_qspgs_member_ct_seal(suite, core.aead_id, mctx.ek, core.gid,
                                 c->self_uid, c->self_uid_len, rc_open, uk,
                                 payload + hlen, pcap - hlen, &ctlen);
    if (rc != GY_OK)
        goto out;
    author_index = (uint32_t)core.n_members;
    rc =
        frame_line(suite, &mctx, core.gid, core.vmaj, 0, GY_QAPX_JOIN,
                   author_index, payload, hlen + ctlen, line_out, line_out_len);
    if (rc != GY_OK)
        goto out;
    memcpy(uk_out, uk, mklen);
    *uk_out_len = mklen;
out:
    gy_qspgs_member_ctx_clear(&mctx);
    gy_qspgs_member_view_clear(&sv);
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(fet, sizeof(fet));
    gy_secure_zero(ek, sizeof(ek));
    gy_secure_zero(rrs, sizeof(rrs));
    gy_secure_zero(signer_vkb, sizeof(signer_vkb));
    gy_secure_zero(uk, sizeof(uk));
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(self_skb, sizeof(self_skb));
    free(members);
    free(payload);
    free(scratch);
    return rc;
}

#ifdef GY_TEST_HOOKS
/*
 * Test-only forging seam (qspgs_hooks.h): sign caller-
 * supplied core objects under the caller's group pseudonym.  Never compiled
 * into a production build (GY_PRODUCTION_BUILD + GY_TEST_HOOKS is a hard error).
 */
int
gy_custodian_qsgroup_hook_sign_core(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN], const uint8_t *hdr,
    size_t hdr_len, const uint8_t *member_list, size_t member_list_len,
    const uint8_t *vk_lst, size_t vk_lst_len, uint32_t signer_index,
    uint32_t last_vmin, uint8_t *sig_out, size_t *sig_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_core core;
    struct gy_qspgs_member *members = NULL;
    struct gy_qspgs_member_ctx mctx;
    uint8_t *scratch = NULL;
    size_t consumed, scap;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (gid == NULL || hdr == NULL || member_list == NULL || vk_lst == NULL ||
        sig_out == NULL || sig_out_len == NULL)
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mk_store(c, &st);

    members = calloc(GY_QSPGS_MAX_ENTRIES, sizeof(*members));
    if (members == NULL)
        return GY_ERR_CRYPTO;
    memset(&core, 0, sizeof(core));
    core.suite_id = suite;
    rc = gy_qspgs_header_decode(&core, hdr, hdr_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_member_list_decode(&core, members, GY_QSPGS_MAX_ENTRIES,
                                     member_list, member_list_len, &consumed);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_vk_lst_decode(&core, vk_lst, vk_lst_len, &consumed);
    if (rc != GY_OK)
        goto out;
    core.last_vmin = last_vmin;

    rc = gy_qspgs_member_ctx_open_stored(&mctx, &st, suite, gid, c->self_uid,
                                         c->self_uid_len);
    if (rc != GY_OK)
        goto out;

    scap = hdr_len + member_list_len + vk_lst_len + 256;
    scratch = calloc(1, scap);
    if (scratch == NULL) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = gy_qspgs_core_sign(&core, signer_index, &mctx, sig_out, *sig_out_len,
                            sig_out_len, scratch, scap);
out:
    gy_qspgs_member_ctx_clear(&mctx);
    free(members);
    free(scratch);
    return rc;
}
#endif /* GY_TEST_HOOKS */

#ifdef GY_TEST_HOOKS
/*
 * Test-only forging seam (qspgs_hooks.h): sign a caller-supplied appendix-line
 * payload under the caller's group pseudonym, without constructing or checking
 * the payload.  Never compiled into a production build.
 */
int
gy_custodian_qsgroup_hook_sign_line(gy_custodian *c,
                                    const uint8_t gid[GY_QSGROUP_GID_LEN],
                                    uint32_t vmaj, uint32_t vmin,
                                    uint8_t line_type, uint32_t author_index,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *line_out, size_t *line_out_len)
{
    struct gy_qspgs_store st;
    struct gy_qspgs_member_ctx mctx;
    uint8_t suite;
    int rc;

    memset(&mctx, 0, sizeof(mctx));
    if (gid == NULL || line_out == NULL || line_out_len == NULL ||
        (payload == NULL && payload_len != 0))
        return GY_ERR_ARG;
    rc = qsgroup_guard(c);
    if (rc != GY_OK)
        return rc;
    suite = c->desc->suite_id;
    mk_store(c, &st);

    rc = gy_qspgs_member_ctx_open_stored(&mctx, &st, suite, gid, c->self_uid,
                                         c->self_uid_len);
    if (rc != GY_OK)
        goto out;
    rc = frame_line(suite, &mctx, gid, vmaj, vmin, line_type, author_index,
                    payload, payload_len, line_out, line_out_len);
out:
    gy_qspgs_member_ctx_clear(&mctx);
    return rc;
}
#endif /* GY_TEST_HOOKS */
