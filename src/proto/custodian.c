/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gy_custodian object, lifecycle, handle model, and identity/prekey sealing.
 * proto/ touches only session/ symbols and opaque bytes,
 * so this file does its own endian work (no core/ dependency, matching
 * envelope.c) and reaches sealing only through the session/ and proto/
 * wrappers, gy_keystore_* and gy_sealed_store_bind, never gy_seal or
 * gy_kekprot_* directly (the nm audit).
 */

#include <stdlib.h>
#include <string.h>

#include "custodian.h"
#include "envelope.h"

/*
 * Fixed policy for the KEK-protector seam (D-CUST-1 item 4): AEGIS-256
 * default, and the compiled-in Argon2id floor as the operating point.
 * gy_custodian_create/open/change_credential expose no opslimit/memlimit
 * argument (CUSTODY_SPEC section 12): security-relevant limits are fixed at
 * create/open, not runtime-mutable (this ticket's "immutable configuration"
 * requirement).
 */
#define GY_CUSTODIAN_WRAP_ALG GY_SEAL_ALG_AEGIS256
#define GY_CUSTODIAN_OPSLIMIT GY_PWHASH_OPSLIMIT_MIN
#define GY_CUSTODIAN_MEMLIMIT GY_PWHASH_MEMLIMIT_MIN

/*
 * Debug-build re-entrancy guard (D-GEN-8), matching session/store.c's
 * OP_ENTER/OP_CB_BEGIN/OP_CB_END: c->active is set while an app_store
 * callback runs, so a callback that re-enters the custodian on the same c
 * trips the assertion at the next entry.  Compiled out under NDEBUG.
 */
#ifndef NDEBUG
#include <assert.h>
#define CUST_ENTER(c)                                                          \
    assert(!(c)->active && "proto/ custodian re-entrancy (D-GEN-8)")
#define CUST_CB_BEGIN(c) ((c)->active = 1)
#define CUST_CB_END(c) ((c)->active = 0)
#else
#define CUST_ENTER(c) ((void)0)
#define CUST_CB_BEGIN(c) ((void)0)
#define CUST_CB_END(c) ((void)0)
#endif

/* ---- local endian helpers (no core/ dependency) ------------------------ */

static void
put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t
get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void
put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void
put_be64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

/* ---- bootstrap header (see custodian.h for the persistence rationale) -- */

int
gy_cust_header_encode(const struct gy_cust_header *h, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    size_t n, off;

    if (h == NULL || out == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (h->self_uid_len > GY_USER_ID_MAX ||
        h->self_did_len > GY_DEVICE_ID_MAX ||
        h->wrap_len > GY_KEYSTORE_WRAP_MAX)
        return GY_ERR_ARG;

    n = 1 + 1 + 1 + h->self_uid_len + 1 + h->self_did_len + 2 + h->wrap_len;
    if (n > cap)
        return GY_ERR_TOOLONG;

    out[0] = GY_CUST_HDR_VERSION;
    out[1] = h->suite_id;
    off = 2;
    out[off] = (uint8_t)h->self_uid_len;
    off += 1;
    memcpy(out + off, h->self_uid, h->self_uid_len);
    off += h->self_uid_len;
    out[off] = (uint8_t)h->self_did_len;
    off += 1;
    memcpy(out + off, h->self_did, h->self_did_len);
    off += h->self_did_len;
    put_be16(out + off, (uint16_t)h->wrap_len);
    off += 2;
    memcpy(out + off, h->wrap, h->wrap_len);
    off += h->wrap_len;

    *out_len = off;
    return GY_OK;
}

int
gy_cust_header_decode(const uint8_t *in, size_t in_len,
                      struct gy_cust_header *h, size_t *consumed)
{
    size_t off;

    if (in == NULL || h == NULL)
        return GY_ERR_ARG;
    if (in_len < 2)
        return GY_ERR_ARG;
    if (in[0] != GY_CUST_HDR_VERSION)
        return GY_ERR_ARG;
    h->suite_id = in[1];
    off = 2;

    if (off + 1 > in_len)
        return GY_ERR_ARG;
    h->self_uid_len = in[off];
    off += 1;
    if (h->self_uid_len > GY_USER_ID_MAX || off + h->self_uid_len > in_len)
        return GY_ERR_ARG;
    memcpy(h->self_uid, in + off, h->self_uid_len);
    off += h->self_uid_len;

    if (off + 1 > in_len)
        return GY_ERR_ARG;
    h->self_did_len = in[off];
    off += 1;
    if (h->self_did_len > GY_DEVICE_ID_MAX || off + h->self_did_len > in_len)
        return GY_ERR_ARG;
    memcpy(h->self_did, in + off, h->self_did_len);
    off += h->self_did_len;

    if (off + 2 > in_len)
        return GY_ERR_ARG;
    h->wrap_len = get_be16(in + off);
    off += 2;
    if (h->wrap_len > GY_KEYSTORE_WRAP_MAX || off + h->wrap_len > in_len)
        return GY_ERR_ARG;
    memcpy(h->wrap, in + off, h->wrap_len);
    off += h->wrap_len;

    if (consumed != NULL)
        *consumed = off;
    return GY_OK;
}

/* ---- bootstrap-blob persistence helpers --------------------------------
 *
 * Every write to the store_identity slot is header || tail, where tail is
 * either empty (create, before an identity exists), the sealed identity
 * material (generate_identity), or whatever sealed identity material was
 * already there, carried through unmodified (change_credential: D-CUST-1
 * item 6, the KEK and the material under it are untouched by a credential
 * change).  Always through the RAW app_store, never c->sealed_store (see
 * custodian.h).
 */

static int
cust_persist_header(struct gy_custodian *c, const uint8_t *tail,
                    size_t tail_len)
{
    struct gy_cust_header hdr;
    uint8_t *buf;
    size_t hdrlen;
    int rc;

    if (tail_len > GY_CUST_HYBRID_IDMAT_SEALED_MAX)
        return GY_ERR_ARG;

    buf = calloc(1, GY_CUST_BLOB_MAX);
    if (buf == NULL)
        return GY_ERR_CRYPTO;

    hdr.suite_id = c->suite_id;
    memcpy(hdr.self_uid, c->self_uid, c->self_uid_len);
    hdr.self_uid_len = c->self_uid_len;
    memcpy(hdr.self_did, c->self_did, c->self_did_len);
    hdr.self_did_len = c->self_did_len;
    memcpy(hdr.wrap, c->wrap, c->wrap_len);
    hdr.wrap_len = c->wrap_len;

    rc = gy_cust_header_encode(&hdr, buf, GY_CUST_BLOB_MAX, &hdrlen);
    gy_wipe(&hdr, sizeof(hdr));
    if (rc != GY_OK) {
        free(buf);
        return rc;
    }
    if (tail_len > 0)
        memcpy(buf + hdrlen, tail, tail_len);

    CUST_CB_BEGIN(c);
    rc = c->app_store.store_identity(c->app_store.ctx, buf, hdrlen + tail_len);
    CUST_CB_END(c);

    gy_wipe(buf, GY_CUST_BLOB_MAX);
    free(buf);
    return rc;
}

/* Associated data for the sealed identity-material blob: distinct from
 * sealed_store.c's own TAG_RECORD/TAG_IDENTITY/TAG_PREKEY namespace (0x01-
 * 0x03), since this is a separate direct gy_keystore_seal/unseal call, not
 * routed through gy_sealed_store_bind. */
static const uint8_t IDMAT_AD[1] = {0x10};
/* Distinct AD for the hybrid sealed idmat (a different struct shape). */
static const uint8_t IDMAT_HYBRID_AD[1] = {0x11};

/*
 * Guarded-allocation size for a custodian of the given suite: a hybrid suite
 * gets the composed gy_hybrid_custodian (base + hybrid material).  Used for both
 * the allocation and every gy_wipe of the whole object, so hybrid key bytes are
 * always zeroized on teardown.
 */
#define CUST_SIZE(desc)                                                        \
    (((desc) != NULL && (desc)->is_hybrid)                                     \
         ? sizeof(struct gy_hybrid_custodian)                                  \
         : sizeof(struct gy_custodian))

/* Upcast a base custodian to its outer hybrid struct (valid iff hybrid). */
static struct gy_hybrid_custodian *
cust_as_hybrid(struct gy_custodian *c)
{
    return (struct gy_hybrid_custodian *)c;
}

/* Rebuild c->spk_kps[0..n_spks) from c->spks[0..n_spks): the dense
 * gy_keypair view gy_recv_ctx_init actually takes (see custodian.h). */
static void
cust_rebuild_spk_view(struct gy_custodian *c)
{
    size_t i;

    for (i = 0; i < c->n_spks; i++)
        c->spk_kps[i] = c->spks[i].kp;
}

/* Re-wire the receive context over the CURRENT spks[]/opks[] (called
 * again after every rotation/replenishment/deletion, not just once
 * at generate_identity). c->desc/store/expiry/clock/self_did/ik must already
 * be set. */
static int
cust_reinit_recv(struct gy_custodian *c)
{
    uint8_t aead = gy_default_aead(c->desc);

    return gy_recv_ctx_init(&c->recv, &c->store, c->desc, &c->ik, c->spk_kps,
                            c->n_spks, c->opks, c->n_opks, aead, &c->expiry,
                            c->clock, c->clock_ctx);
}

/* Seal the CURRENT ik/spks/opks into one blob and persist it appended after
 * the bootstrap header (see custodian.h and the cust_persist_header
 * docstring above). */
static int
cust_seal_and_persist_idmat(struct gy_custodian *c)
{
    struct gy_cust_idmat *idmat;
    uint8_t *sealed;
    size_t sealed_len, i;
    int rc;

    idmat = gy_guarded_alloc(sizeof(*idmat));
    if (idmat == NULL)
        return GY_ERR_CRYPTO;
    memset(idmat, 0, sizeof(*idmat));

    idmat->ik = c->ik;
    for (i = 0; i < c->n_spks; i++)
        idmat->spks[i] = c->spks[i];
    idmat->n_spks = (uint64_t)c->n_spks;
    for (i = 0; i < c->n_opks; i++) {
        idmat->opks[i] = c->opks[i];
        idmat->opk_used[i] = (uint8_t)c->opk_used[i];
        idmat->opk_consumed[i] = (uint8_t)c->opk_consumed[i];
    }
    idmat->n_opks = (uint64_t)c->n_opks;
    for (i = 0; i < c->n_saks; i++)
        idmat->saks[i] = c->saks[i];
    idmat->n_saks = (uint64_t)c->n_saks;

    sealed = calloc(1, GY_CUST_IDMAT_SEALED_MAX);
    if (sealed == NULL) {
        gy_guarded_free(idmat);
        return GY_ERR_CRYPTO;
    }
    sealed_len = GY_CUST_IDMAT_SEALED_MAX;
    rc = gy_keystore_seal(&c->ks, GY_CUSTODIAN_WRAP_ALG, IDMAT_AD,
                          sizeof(IDMAT_AD), (const uint8_t *)idmat,
                          sizeof(*idmat), sealed, &sealed_len);
    gy_guarded_free(idmat);
    if (rc != GY_OK) {
        free(sealed);
        return rc;
    }

    rc = cust_persist_header(c, sealed, sealed_len);
    free(sealed);
    return rc;
}

/* Seal the CURRENT hybrid ik/hspks/hopks/hsaks and persist. */
static int
cust_seal_and_persist_hybrid_idmat(struct gy_custodian *c)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_cust_hybrid_idmat *idmat;
    uint8_t *sealed;
    size_t sealed_len, i;
    int rc;

    idmat = gy_guarded_alloc(sizeof(*idmat));
    if (idmat == NULL)
        return GY_ERR_CRYPTO;
    memset(idmat, 0, sizeof(*idmat));

    idmat->ik = hc->hik;
    for (i = 0; i < hc->n_hspks; i++)
        idmat->spks[i] = hc->hspks[i];
    idmat->n_spks = (uint64_t)hc->n_hspks;
    for (i = 0; i < hc->n_hopks; i++) {
        idmat->opks[i] = hc->hopks[i];
        idmat->opk_used[i] = (uint8_t)hc->hopk_used[i];
        idmat->opk_consumed[i] = (uint8_t)hc->hopk_consumed[i];
    }
    idmat->n_opks = (uint64_t)hc->n_hopks;
    for (i = 0; i < hc->n_hsaks; i++)
        idmat->saks[i] = hc->hsaks[i];
    idmat->n_saks = (uint64_t)hc->n_hsaks;

    sealed = calloc(1, GY_CUST_HYBRID_IDMAT_SEALED_MAX);
    if (sealed == NULL) {
        gy_guarded_free(idmat);
        return GY_ERR_CRYPTO;
    }
    sealed_len = GY_CUST_HYBRID_IDMAT_SEALED_MAX;
    rc = gy_keystore_seal(&c->ks, GY_CUSTODIAN_WRAP_ALG, IDMAT_HYBRID_AD,
                          sizeof(IDMAT_HYBRID_AD), (const uint8_t *)idmat,
                          sizeof(*idmat), sealed, &sealed_len);
    gy_guarded_free(idmat);
    if (rc != GY_OK) {
        free(sealed);
        return rc;
    }

    rc = cust_persist_header(c, sealed, sealed_len);
    free(sealed);
    return rc;
}

/*
 * Internal slot registration: like gy_custodian_slot_alloc, but skips the
 * c->unlocked gate.  Used only from inside create/open/generate_identity/
 * rotate/replenish, which already know they are mid-construction of a
 * to-become-unlocked custodian (gy_custodian_slot_alloc's public gate is for
 * callers OUTSIDE this file, e.g. the SAK allocation).
 */
static gy_key_handle
cust_slot_register(struct gy_custodian *c, int type, uint32_t key_id)
{
    size_t i;

    for (i = 0; i < GY_CUSTODIAN_MAX_SLOTS; i++) {
        if (!c->slots[i].in_use) {
            c->slots[i].in_use = 1;
            c->slots[i].type = type;
            c->slots[i].key_id = key_id;
            return (gy_key_handle)(i + 1);
        }
    }
    return GY_KEY_HANDLE_INVALID;
}

/* Find the slot (if any) registered for (type, key_id); GY_KEY_HANDLE_INVALID
 * if none.  Does not gate on c->unlocked (internal use alongside
 * cust_slot_register; gy_custodian_find_prekey wraps this publicly). */
static gy_key_handle
cust_slot_find(struct gy_custodian *c, int type, uint32_t key_id)
{
    size_t i;

    for (i = 0; i < GY_CUSTODIAN_MAX_SLOTS; i++)
        if (c->slots[i].in_use && c->slots[i].type == type &&
            c->slots[i].key_id == key_id)
            return (gy_key_handle)(i + 1);
    return GY_KEY_HANDLE_INVALID;
}

/* Unseal sealed[0..sealed_len) into c->ik/spks/opks and wire the send/
 * receive contexts over it.  c->desc/store/expiry/clock/self_did must
 * already be set. */
static int
cust_load_idmat(struct gy_custodian *c, const uint8_t *sealed,
                size_t sealed_len)
{
    struct gy_cust_idmat *idmat;
    size_t ptlen, i;
    int rc;

    idmat = gy_guarded_alloc(sizeof(*idmat));
    if (idmat == NULL)
        return GY_ERR_CRYPTO;

    ptlen = sizeof(*idmat);
    rc = gy_keystore_unseal(&c->ks, IDMAT_AD, sizeof(IDMAT_AD), sealed,
                            sealed_len, (uint8_t *)idmat, &ptlen);
    if (rc != GY_OK) {
        gy_guarded_free(idmat);
        return rc;
    }
    if (ptlen != sizeof(*idmat)) {
        gy_guarded_free(idmat);
        return GY_ERR_VERIFY;
    }
    /*
     * The decrypted counts are used directly below as loop bounds and array
     * indices, so a value past its fixed maximum would drive an out-of-bounds
     * write.  The AEAD tag already gates external tampering (this is reached
     * only from a KEK-valid blob, and cust_seal_and_persist_idmat only ever
     * writes bounded counts), so an out-of-range count here means a corrupt or
     * format-skewed store: fold it into the same GY_ERR_VERIFY as any other
     * unseal failure, with no distinguishing oracle.
     */
    if (idmat->n_spks > GY_CUSTODIAN_SPK_HISTORY_MAX ||
        idmat->n_opks > GY_OPK_BATCH_MAX ||
        idmat->n_saks > GY_CUSTODIAN_SAK_HISTORY_MAX) {
        gy_guarded_free(idmat);
        return GY_ERR_VERIFY;
    }

    c->ik = idmat->ik;
    c->n_spks = (size_t)idmat->n_spks;
    for (i = 0; i < c->n_spks; i++)
        c->spks[i] = idmat->spks[i];
    c->n_opks = (size_t)idmat->n_opks;
    for (i = 0; i < c->n_opks; i++) {
        c->opks[i] = idmat->opks[i];
        c->opk_used[i] = idmat->opk_used[i];
        c->opk_consumed[i] = idmat->opk_consumed[i];
    }
    c->n_saks = (size_t)idmat->n_saks;
    for (i = 0; i < c->n_saks; i++)
        c->saks[i] = idmat->saks[i];
    gy_guarded_free(idmat);

    cust_rebuild_spk_view(c);
    for (i = 0; i < c->n_spks; i++)
        (void)cust_slot_register(c, GY_SLOT_SPK, c->spks[i].kp.pub.pkid);
    for (i = 0; i < c->n_opks; i++)
        if (c->opk_used[i])
            (void)cust_slot_register(c, GY_SLOT_OPK, c->opks[i].pub.pkid);
    for (i = 0; i < c->n_saks; i++)
        (void)cust_slot_register(c, GY_SLOT_SAK, c->saks[i].kp.pub.pkid);

    rc = gy_send_ctx_init(&c->send, &c->store, c->desc, &c->ik,
                          gy_default_aead(c->desc), &c->expiry, c->self_uid,
                          c->self_uid_len, c->self_did, c->self_did_len);
    if (rc != GY_OK)
        return rc;
    rc = cust_reinit_recv(c);
    if (rc != GY_OK)
        return rc;
    c->have_identity = 1;
    return GY_OK;
}

/*
 * Wire the (classical) send/receive contexts for a hybrid custodian: NULL
 * classical identity/SPKs (the hybrid material is passed per-call to
 * gy_send_initiate_hybrid / gy_hybrid_recv), but the same op arenas, store,
 * expiry, and self ids.  Steady-state encrypt/recv dispatch on the session
 * suite, so these contexts serve hybrid sessions unchanged.
 */
static int
cust_wire_hybrid_ctxs(struct gy_custodian *c)
{
    uint8_t aead = gy_default_aead(c->desc);
    int rc;

    rc = gy_send_ctx_init(&c->send, &c->store, c->desc, NULL, aead, &c->expiry,
                          c->self_uid, c->self_uid_len, c->self_did,
                          c->self_did_len);
    if (rc != GY_OK)
        return rc;
    return gy_recv_ctx_init(&c->recv, &c->store, c->desc, NULL, NULL, 0, NULL,
                            0, aead, &c->expiry, c->clock, c->clock_ctx);
}

/* Unseal hybrid sealed idmat into hc->hik/hspks/hopks/hsaks, register slots,
 * and wire the contexts.  Mirror of cust_load_idmat for hybrid suites. */
static int
cust_load_hybrid_idmat(struct gy_custodian *c, const uint8_t *sealed,
                       size_t sealed_len)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_cust_hybrid_idmat *idmat;
    size_t ptlen, i;
    int rc;

    idmat = gy_guarded_alloc(sizeof(*idmat));
    if (idmat == NULL)
        return GY_ERR_CRYPTO;

    ptlen = sizeof(*idmat);
    rc = gy_keystore_unseal(&c->ks, IDMAT_HYBRID_AD, sizeof(IDMAT_HYBRID_AD),
                            sealed, sealed_len, (uint8_t *)idmat, &ptlen);
    if (rc != GY_OK) {
        gy_guarded_free(idmat);
        return rc;
    }
    if (ptlen != sizeof(*idmat)) {
        gy_guarded_free(idmat);
        return GY_ERR_VERIFY;
    }
    if (idmat->n_spks > GY_CUSTODIAN_SPK_HISTORY_MAX ||
        idmat->n_opks > GY_OPK_BATCH_MAX ||
        idmat->n_saks > GY_CUSTODIAN_SAK_HISTORY_MAX) {
        gy_guarded_free(idmat);
        return GY_ERR_VERIFY;
    }

    hc->hik = idmat->ik;
    hc->n_hspks = (size_t)idmat->n_spks;
    for (i = 0; i < hc->n_hspks; i++)
        hc->hspks[i] = idmat->spks[i];
    hc->n_hopks = (size_t)idmat->n_opks;
    for (i = 0; i < hc->n_hopks; i++) {
        hc->hopks[i] = idmat->opks[i];
        hc->hopk_used[i] = idmat->opk_used[i];
        hc->hopk_consumed[i] = idmat->opk_consumed[i];
    }
    hc->n_hsaks = (size_t)idmat->n_saks;
    for (i = 0; i < hc->n_hsaks; i++)
        hc->hsaks[i] = idmat->saks[i];
    gy_guarded_free(idmat);

    for (i = 0; i < hc->n_hspks; i++)
        (void)cust_slot_register(c, GY_SLOT_SPK,
                                 hc->hspks[i].kp.pub.curve.pkid);
    for (i = 0; i < hc->n_hopks; i++)
        if (hc->hopk_used[i])
            (void)cust_slot_register(c, GY_SLOT_OPK,
                                     hc->hopks[i].pub.curve.pkid);
    for (i = 0; i < hc->n_hsaks; i++)
        (void)cust_slot_register(c, GY_SLOT_SAK, hc->hsaks[i].kp.pub.pkid);

    rc = cust_wire_hybrid_ctxs(c);
    if (rc != GY_OK)
        return rc;
    c->have_identity = 1;
    return GY_OK;
}

/* ---- internal store trampolines (int-kind sealed_store <-> enum-kind
 * session/ gy_store); every record/prekey/session blob. ----- */

static int
tr_load_record(void *raw, enum gy_rec_kind kind, const uint8_t *id,
               size_t id_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.load_record(c->sealed_store.ctx, (int)kind, id,
                                       id_len, out, cap, out_len);
}

static int
tr_store_record(void *raw, enum gy_rec_kind kind, const uint8_t *id,
                size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.store_record(c->sealed_store.ctx, (int)kind, id,
                                        id_len, blob, blob_len);
}

static int
tr_delete_record(void *raw, enum gy_rec_kind kind, const uint8_t *id,
                 size_t id_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.delete_record(c->sealed_store.ctx, (int)kind, id,
                                         id_len);
}

static int
tr_load_identity(void *raw, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.load_identity(c->sealed_store.ctx, out, cap,
                                         out_len);
}

static int
tr_store_identity(void *raw, const uint8_t *blob, size_t blob_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.store_identity(c->sealed_store.ctx, blob, blob_len);
}

static int
tr_load_prekey(void *raw, enum gy_prekey_kind kind, uint32_t pkid, uint8_t *out,
               size_t cap, size_t *out_len)
{
    struct gy_custodian *c = raw;

    return c->sealed_store.load_prekey(c->sealed_store.ctx, (int)kind, pkid,
                                       out, cap, out_len);
}

static int
tr_consume_opk(void *raw, uint32_t pkid)
{
    struct gy_custodian *c = raw;
    size_t i;
    int rc;

    rc = c->sealed_store.consume_opk(c->sealed_store.ctx, pkid);
    if (rc != GY_OK)
        return rc;

    /*
     * Delete-on-use (D-X3DH-10, hardened): a one-time prekey used to
     * ESTABLISH a session (this callback fires only after the first frame
     * verifies) has its PRIVATE key destroyed immediately, so a second
     * initiation with a DIFFERENT base key that tries to reuse the same OPK
     * cannot find the key and fails closed - reuse is made impossible, not
     * merely flagged.  This deliberately reverses the earlier "retain the
     * consumed OPK; presence gates matching; base-key dedupe is the sole
     * replay defense" note (docs/decisions/custody.md, 2026-08-13).
     *
     * Wiping opks[i] in place is safe here: recv_init finished its X3DH
     * before this deferred consume runs; c->recv.opks is the SAME array by
     * pointer, so the wipe is visible without rebuilding the recv context;
     * and a legitimate retransmit of the same initial message routes through
     * base-key dedupe to the established session (never re-touching an OPK).
     * We must NOT cust_reinit_recv here (it would rebuild the very recv
     * context currently on the stack); the slot stays free for the next
     * reinit.  The idmat re-seal makes the deletion durable so a reopen never
     * restores the spent key.  Its return code is PROPAGATED, not swallowed:
     * a persist failure leaves the key gone in memory (reuse blocked for this
     * session) but still present in the last-sealed idmat, so a reopen could
     * restore the spent private key.  Returning the failure makes the receive
     * path (gy_op_consume_opk -> recv_init) fail closed rather than complete a
     * receive whose OPK consumption is not durable.
     *
     * A hybrid custodian holds its OPK pool in hc->hopks (the classical
     * c->opks is empty), and the hybrid receive path reads hc->hopks live per
     * call, so the same delete-on-use applies there against the hybrid pool,
     * resealing the hybrid idmat.
     */
    if (c->desc->is_hybrid) {
        struct gy_hybrid_custodian *hc = cust_as_hybrid(c);

        for (i = 0; i < hc->n_hopks; i++) {
            if (hc->hopk_used[i] && hc->hopks[i].pub.curve.pkid == pkid) {
                gy_key_handle h = cust_slot_find(c, GY_SLOT_OPK, pkid);

                if (h != GY_KEY_HANDLE_INVALID)
                    gy_custodian_slot_free(c, h);
                gy_wipe(&hc->hopks[i], sizeof(hc->hopks[i]));
                hc->hopk_used[i] = 0;
                hc->hopk_consumed[i] = 0;
                return cust_seal_and_persist_hybrid_idmat(c);
            }
        }
        return GY_OK;
    }

    for (i = 0; i < c->n_opks; i++) {
        if (c->opk_used[i] && c->opks[i].pub.pkid == pkid) {
            gy_key_handle h = cust_slot_find(c, GY_SLOT_OPK, pkid);

            if (h != GY_KEY_HANDLE_INVALID)
                gy_custodian_slot_free(c, h);
            gy_wipe(&c->opks[i], sizeof(c->opks[i]));
            c->opk_used[i] = 0;
            c->opk_consumed[i] = 0;
            return cust_seal_and_persist_idmat(c);
        }
    }
    return GY_OK;
}

static void
cust_wire_store(struct gy_custodian *c)
{
    c->store.ctx = c;
    c->store.load_record = tr_load_record;
    c->store.store_record = tr_store_record;
    c->store.delete_record = tr_delete_record;
    c->store.load_identity = tr_load_identity;
    c->store.store_identity = tr_store_identity;
    c->store.load_prekey = tr_load_prekey;
    c->store.consume_opk = tr_consume_opk;
}

/* ---- handle model / slot table ------------------------------------------
 *
 * A handle is a flat 1-based slot index; it carries no type information
 * (D-CUST-1 item 1) and 0 is the invalid handle (D-GEN-2 zero-sentinel).
 * The table lives only in the unlocked custodian, so once locked (closed)
 * every handle is unconditionally rejected: there is no stale-handle-vs-
 * fresh-table ambiguity to track with a generation counter.
 */

int
gy_custodian_slot_alloc(struct gy_custodian *c, int type, uint32_t key_id,
                        gy_key_handle *out)
{
    size_t i;

    if (c == NULL || out == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    for (i = 0; i < GY_CUSTODIAN_MAX_SLOTS; i++) {
        if (!c->slots[i].in_use) {
            c->slots[i].in_use = 1;
            c->slots[i].type = type;
            c->slots[i].key_id = key_id;
            *out = (gy_key_handle)(i + 1);
            return GY_OK;
        }
    }
    return GY_ERR_NO_SPACE;
}

int
gy_custodian_slot_get(struct gy_custodian *c, gy_key_handle h, int *type,
                      uint32_t *key_id)
{
    struct gy_key_slot *s;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (h == GY_KEY_HANDLE_INVALID || h > GY_CUSTODIAN_MAX_SLOTS)
        return GY_ERR_NOT_FOUND;

    s = &c->slots[h - 1];
    if (!s->in_use)
        return GY_ERR_NOT_FOUND;
    if (type != NULL)
        *type = s->type;
    if (key_id != NULL)
        *key_id = s->key_id;
    return GY_OK;
}

void
gy_custodian_slot_free(struct gy_custodian *c, gy_key_handle h)
{
    if (c == NULL || h == GY_KEY_HANDLE_INVALID || h > GY_CUSTODIAN_MAX_SLOTS)
        return;
    CUST_ENTER(c);
    memset(&c->slots[h - 1], 0, sizeof(c->slots[h - 1]));
}

/* ---- lifecycle ----------------------------------------------------------
 *
 * States (CUSTODY_SPEC section 7): absent -> locked -> unlocked -> locked
 * (close) -> absent (reset).  A gy_custodian instance in this API exists
 * ONLY in the unlocked state: create/open allocate it fresh and return an
 * unlocked custodian or an error, and close frees it (zeroize + free), so
 * there is no in-memory object representing "locked".  The locked state is
 * purely a property of the store: a header persisted via app_store, with
 * no live gy_custodian pointing at it.
 */

int
gy_custodian_create(struct gy_custodian **out, uint8_t suite_id,
                    const gy_store_callbacks *store, const uint8_t *cred,
                    size_t cred_len, const uint8_t *self_uid,
                    size_t self_uid_len, const uint8_t *self_did,
                    size_t self_did_len, gy_clock_fn clock, void *clock_ctx,
                    const gy_config *cfg)
{
    const struct gy_suite_desc *desc;
    struct gy_custodian *c;
    int rc;

    if (out == NULL || store == NULL || cred == NULL)
        return GY_ERR_ARG;
    if (self_uid_len > GY_USER_ID_MAX || self_did_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (gy_runtime_init() != GY_OK)
        return GY_ERR_CRYPTO;
    desc = gy_suite_lookup(suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    /* struct gy_custodian holds every unlocked key (ik, spks, opks, saks)
     * plus the embedded send/recv ratchet state directly, so the object
     * itself - not just the KEK - must live in guarded (sodium_malloc)
     * memory per CUSTODY_SPEC section 15. */
    c = gy_guarded_alloc(CUST_SIZE(desc));
    if (c == NULL)
        return GY_ERR_CRYPTO;
    memset(c, 0, CUST_SIZE(desc));

    c->desc = desc;
    c->suite_id = suite_id;
    c->app_store = *store;
    c->clock = clock;
    c->clock_ctx = clock_ctx;
    if (self_uid != NULL && self_uid_len > 0)
        memcpy(c->self_uid, self_uid, self_uid_len);
    c->self_uid_len = self_uid_len;
    if (self_did != NULL && self_did_len > 0)
        memcpy(c->self_did, self_did, self_did_len);
    c->self_did_len = self_did_len;
    if (cfg != NULL && cfg->enabled) {
        rc = gy_expiry_cfg_init(&c->expiry, cfg->max_send, cfg->max_recv,
                                cfg->max_latency);
        if (rc != GY_OK) {
            gy_wipe(c, CUST_SIZE(c->desc));
            gy_guarded_free(c);
            return rc;
        }
    }

    c->wrap_len = sizeof(c->wrap);
    rc = gy_keystore_create(&c->ks, GY_CUSTODIAN_WRAP_ALG,
                            GY_CUSTODIAN_OPSLIMIT, GY_CUSTODIAN_MEMLIMIT, cred,
                            cred_len, c->wrap, &c->wrap_len);
    if (rc != GY_OK) {
        gy_wipe(c, CUST_SIZE(c->desc));
        gy_guarded_free(c);
        return rc;
    }

    rc = cust_persist_header(c, NULL, 0);
    if (rc != GY_OK) {
        gy_keystore_close(&c->ks);
        gy_wipe(c, CUST_SIZE(c->desc));
        gy_guarded_free(c);
        return rc;
    }

    rc = gy_sealed_store_bind(&c->ss, &c->ks, store, GY_CUSTODIAN_WRAP_ALG,
                              &c->sealed_store);
    if (rc != GY_OK) {
        gy_keystore_close(&c->ks);
        gy_wipe(c, CUST_SIZE(c->desc));
        gy_guarded_free(c);
        return rc;
    }
    cust_wire_store(c);

    c->unlocked = 1;
    *out = c;
    return GY_OK;
}

int
gy_custodian_open(struct gy_custodian **out, const gy_store_callbacks *store,
                  const uint8_t *cred, size_t cred_len)
{
    const struct gy_suite_desc *desc;
    struct gy_custodian *c;
    struct gy_cust_header hdr;
    uint8_t *buf;
    size_t loaded_len, consumed, tail_len;
    int rc;

    if (out == NULL || store == NULL || cred == NULL)
        return GY_ERR_ARG;
    if (gy_runtime_init() != GY_OK)
        return GY_ERR_CRYPTO;

    /*
     * Load and decode the bootstrap header BEFORE allocating the object: the
     * header names the suite, which determines whether this is a classical or
     * (larger) hybrid custodian, and hence CUST_SIZE.  No custodian exists yet,
     * so the load runs without a re-entrancy guard.
     */
    buf = calloc(1, GY_CUST_BLOB_MAX);
    if (buf == NULL)
        return GY_ERR_CRYPTO;

    loaded_len = GY_CUST_BLOB_MAX;
    rc = store->load_identity(store->ctx, buf, loaded_len, &loaded_len);
    if (rc != GY_OK) {
        free(buf);
        return rc;
    }
    if (loaded_len == 0) {
        free(buf); /* absent: no custodian has ever been created */
        return GY_ERR_STATE;
    }
    rc = gy_cust_header_decode(buf, loaded_len, &hdr, &consumed);
    if (rc != GY_OK) {
        gy_wipe(&hdr, sizeof(hdr));
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        return rc;
    }
    desc = gy_suite_lookup(hdr.suite_id);
    if (desc == NULL) {
        gy_wipe(&hdr, sizeof(hdr));
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        return GY_ERR_ARG;
    }

    /* Guarded allocation sized to the suite (CUSTODY_SPEC section 15: the object
     * embeds every unlocked key directly). */
    c = gy_guarded_alloc(CUST_SIZE(desc));
    if (c == NULL) {
        gy_wipe(&hdr, sizeof(hdr));
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        return GY_ERR_CRYPTO;
    }
    memset(c, 0, CUST_SIZE(desc));

    c->desc = desc;
    c->suite_id = hdr.suite_id;
    c->app_store = *store;
    memcpy(c->self_uid, hdr.self_uid, hdr.self_uid_len);
    c->self_uid_len = hdr.self_uid_len;
    memcpy(c->self_did, hdr.self_did, hdr.self_did_len);
    c->self_did_len = hdr.self_did_len;

    rc = gy_keystore_open(&c->ks, cred, cred_len, hdr.wrap, hdr.wrap_len);
    if (rc != GY_OK) {
        /* wrong credential or a corrupt wrap blob: the single uniform error
         * (CUSTODY_SPEC section 15), already GY_ERR_VERIFY from the keystore */
        gy_wipe(&hdr, sizeof(hdr));
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        gy_wipe(c, CUST_SIZE(c->desc));
        gy_guarded_free(c);
        return rc;
    }
    memcpy(c->wrap, hdr.wrap, hdr.wrap_len);
    c->wrap_len = hdr.wrap_len;
    gy_wipe(&hdr, sizeof(hdr));

    rc = gy_sealed_store_bind(&c->ss, &c->ks, store, GY_CUSTODIAN_WRAP_ALG,
                              &c->sealed_store);
    if (rc != GY_OK) {
        gy_keystore_close(&c->ks);
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        gy_wipe(c, CUST_SIZE(c->desc));
        gy_guarded_free(c);
        return rc;
    }
    cust_wire_store(c);

    tail_len = loaded_len - consumed;
    if (tail_len > 0) {
        rc = c->desc->is_hybrid
                 ? cust_load_hybrid_idmat(c, buf + consumed, tail_len)
                 : cust_load_idmat(c, buf + consumed, tail_len);
        if (rc != GY_OK) {
            gy_keystore_close(&c->ks);
            gy_wipe(buf, GY_CUST_BLOB_MAX);
            free(buf);
            gy_wipe(c, CUST_SIZE(c->desc));
            gy_guarded_free(c);
            return rc;
        }
    }

    gy_wipe(buf, GY_CUST_BLOB_MAX);
    free(buf);
    c->unlocked = 1;
    *out = c;
    return GY_OK;
}

void
gy_custodian_close(struct gy_custodian *c)
{
    if (c == NULL)
        return;
    gy_keystore_close(&c->ks);
    gy_wipe(c, CUST_SIZE(c->desc));
    gy_guarded_free(c);
}

int
gy_custodian_reset(struct gy_custodian *c)
{
    gy_store_callbacks store;
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    store = c->app_store;
    gy_keystore_close(&c->ks);

    /* Delete-by-empty-write: store_identity has no dedicated delete
     * callback (D-SES-2: one identity slot per device, no id to key a
     * delete_identity by), so a zero-length write is the persisted
     * "absent" state, matching the zero-length "no identity" sentinel
     * gy_custodian_open and sealed_store.c's load side already use. */
    CUST_CB_BEGIN(c);
    rc = store.store_identity(store.ctx, NULL, 0);
    CUST_CB_END(c);

    gy_wipe(c, CUST_SIZE(c->desc));
    gy_guarded_free(c);
    return rc;
}

int
gy_custodian_change_credential(struct gy_custodian *c, const uint8_t *new_cred,
                               size_t new_cred_len)
{
    struct gy_cust_header old_hdr;
    uint8_t *buf;
    uint8_t new_wrap[GY_KEYSTORE_WRAP_MAX];
    size_t loaded_len, consumed, tail_len, new_wrap_len;
    int rc;

    if (c == NULL || new_cred == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    /* Preserve whatever sealed identity material already follows the header
     * (D-CUST-1 item 6: a credential change re-wraps only the KEK; the
     * material under it is untouched) by reading the CURRENT blob back and
     * keeping everything past the header as opaque bytes. */
    buf = calloc(1, GY_CUST_BLOB_MAX);
    if (buf == NULL)
        return GY_ERR_CRYPTO;

    loaded_len = GY_CUST_BLOB_MAX;
    CUST_CB_BEGIN(c);
    rc = c->app_store.load_identity(c->app_store.ctx, buf, loaded_len,
                                    &loaded_len);
    CUST_CB_END(c);
    if (rc != GY_OK) {
        free(buf);
        return rc;
    }
    rc = gy_cust_header_decode(buf, loaded_len, &old_hdr, &consumed);
    gy_wipe(&old_hdr, sizeof(old_hdr));
    if (rc != GY_OK) {
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        return rc;
    }
    tail_len = loaded_len - consumed;

    new_wrap_len = sizeof(new_wrap);
    rc = gy_keystore_change_credential(
        &c->ks, GY_CUSTODIAN_WRAP_ALG, GY_CUSTODIAN_OPSLIMIT,
        GY_CUSTODIAN_MEMLIMIT, new_cred, new_cred_len, new_wrap, &new_wrap_len);
    if (rc != GY_OK) {
        gy_wipe(buf, GY_CUST_BLOB_MAX);
        free(buf);
        return rc;
    }
    memcpy(c->wrap, new_wrap, new_wrap_len);
    c->wrap_len = new_wrap_len;
    gy_wipe(new_wrap, sizeof(new_wrap));

    rc = cust_persist_header(c, buf + consumed, tail_len);
    gy_wipe(buf, GY_CUST_BLOB_MAX);
    free(buf);
    return rc;
}

/*
 * Default hybrid SPK advertisement (section 5.3): ML-KEM refresh interval
 * [1,100], ChaCha20-Poly1305 (bit 32) offered.  Well-formed per
 * gy_hybrid_flags_validate.
 */
#define CUST_HYBRID_SPK_FLAGS                                                  \
    (UINT64_C(1) | (UINT64_C(100) << 16) | (UINT64_C(1) << 32))

/* Hybrid identity generation (section 4/5): hybrid ik + SPK + OPK batch, sealed
 * as the hybrid idmat, contexts wired over the base with no classical id. */
static int
cust_gen_hybrid_identity(struct gy_custodian *c, uint64_t spk_timestamp,
                         size_t n_opks)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    size_t i;
    int rc;

    rc = gy_hybrid_identity_generate(c->desc, &hc->hik);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_signed_prekey_generate(c->desc, &hc->hspks[0], &hc->hik,
                                          spk_timestamp, CUST_HYBRID_SPK_FLAGS);
    if (rc != GY_OK) {
        gy_wipe(&hc->hik, sizeof(hc->hik));
        return rc;
    }
    hc->n_hspks = 1;

    if (n_opks > 0) {
        rc = gy_hybrid_opk_generate(c->desc, hc->hopks, n_opks, NULL, 0);
        if (rc != GY_OK) {
            gy_wipe(&hc->hik, sizeof(hc->hik));
            gy_wipe(hc->hspks, sizeof(hc->hspks[0]));
            hc->n_hspks = 0;
            return rc;
        }
    }
    for (i = 0; i < n_opks; i++) {
        hc->hopk_used[i] = 1;
        hc->hopk_consumed[i] = 0;
    }
    hc->n_hopks = n_opks;

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        gy_wipe(&hc->hik, sizeof(hc->hik));
        gy_wipe(hc->hspks, sizeof(hc->hspks));
        hc->n_hspks = 0;
        gy_wipe(hc->hopks, sizeof(hc->hopks));
        memset(hc->hopk_used, 0, sizeof(hc->hopk_used));
        memset(hc->hopk_consumed, 0, sizeof(hc->hopk_consumed));
        hc->n_hopks = 0;
        return rc;
    }

    (void)cust_slot_register(c, GY_SLOT_SPK, hc->hspks[0].kp.pub.curve.pkid);
    for (i = 0; i < n_opks; i++)
        (void)cust_slot_register(c, GY_SLOT_OPK, hc->hopks[i].pub.curve.pkid);

    rc = cust_wire_hybrid_ctxs(c);
    if (rc != GY_OK)
        return rc;
    c->have_identity = 1;
    return GY_OK;
}

int
gy_custodian_generate_identity(struct gy_custodian *c, uint64_t spk_timestamp,
                               size_t n_opks)
{
    size_t i;
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (c->have_identity)
        return GY_ERR_STATE;
    if (n_opks > GY_OPK_BATCH_MAX)
        return GY_ERR_ARG;

    if (c->desc->is_hybrid)
        return cust_gen_hybrid_identity(c, spk_timestamp, n_opks);

    rc = gy_identity_generate(c->desc, &c->ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_signed_prekey_generate(c->desc, &c->spks[0], c->ik.sk,
                                   spk_timestamp);
    if (rc != GY_OK) {
        gy_wipe(&c->ik, sizeof(c->ik));
        return rc;
    }
    c->n_spks = 1;

    if (n_opks > 0) {
        rc = gy_opk_generate(c->desc, c->opks, n_opks, NULL, 0);
        if (rc != GY_OK) {
            gy_wipe(&c->ik, sizeof(c->ik));
            gy_wipe(c->spks, sizeof(c->spks[0]));
            c->n_spks = 0;
            return rc;
        }
    }
    for (i = 0; i < n_opks; i++) {
        c->opk_used[i] = 1;
        c->opk_consumed[i] = 0;
    }
    c->n_opks = n_opks;

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        /* Nothing was durably persisted: wipe the generated material rather
         * than leaving it live in c under have_identity == 0, matching
         * every other write path's persist-failure discipline (rotate_*,
         * generate_onetime_prekeys, generate_appkey) - a retry must start
         * from a clean slate, not silently overwrite still-live key bytes
         * in place. */
        gy_wipe(&c->ik, sizeof(c->ik));
        gy_wipe(c->spks, sizeof(c->spks));
        c->n_spks = 0;
        gy_wipe(c->opks, sizeof(c->opks));
        memset(c->opk_used, 0, sizeof(c->opk_used));
        memset(c->opk_consumed, 0, sizeof(c->opk_consumed));
        c->n_opks = 0;
        return rc;
    }

    cust_rebuild_spk_view(c);
    (void)cust_slot_register(c, GY_SLOT_SPK, c->spks[0].kp.pub.pkid);
    for (i = 0; i < n_opks; i++)
        (void)cust_slot_register(c, GY_SLOT_OPK, c->opks[i].pub.pkid);

    rc = gy_send_ctx_init(&c->send, &c->store, c->desc, &c->ik,
                          gy_default_aead(c->desc), &c->expiry, c->self_uid,
                          c->self_uid_len, c->self_did, c->self_did_len);
    if (rc != GY_OK)
        return rc;
    rc = cust_reinit_recv(c);
    if (rc != GY_OK)
        return rc;
    c->have_identity = 1;
    return GY_OK;
}

/*
 * Hybrid SPK rotation: generate a fresh hybrid signed prekey, push it to the
 * front of hc->hspks (evicting/zeroizing the oldest at capacity), reseal.  No
 * recv rewire: the hybrid receive path reads hc->hspks directly per-call.
 */
static int
cust_rotate_hybrid_spk(struct gy_custodian *c, uint64_t spk_timestamp)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_hybrid_signed_prekey newspk;
    struct gy_hybrid_signed_prekey backup[GY_CUSTODIAN_SPK_HISTORY_MAX];
    size_t backup_n, i;
    gy_key_handle evict_h = GY_KEY_HANDLE_INVALID;
    int rc;

    rc = gy_hybrid_signed_prekey_generate(c->desc, &newspk, &hc->hik,
                                          spk_timestamp, CUST_HYBRID_SPK_FLAGS);
    if (rc != GY_OK)
        return rc;

    backup_n = hc->n_hspks;
    memcpy(backup, hc->hspks, sizeof(hc->hspks));
    if (hc->n_hspks == GY_CUSTODIAN_SPK_HISTORY_MAX) {
        size_t tail = GY_CUSTODIAN_SPK_HISTORY_MAX - 1;

        evict_h =
            cust_slot_find(c, GY_SLOT_SPK, hc->hspks[tail].kp.pub.curve.pkid);
        hc->n_hspks--;
    }
    for (i = hc->n_hspks; i > 0; i--)
        hc->hspks[i] = hc->hspks[i - 1];
    hc->hspks[0] = newspk;
    gy_wipe(&newspk, sizeof(newspk));
    hc->n_hspks++;

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        memcpy(hc->hspks, backup, sizeof(hc->hspks));
        hc->n_hspks = backup_n;
        gy_wipe(backup, sizeof(backup));
        return rc;
    }
    gy_wipe(backup, sizeof(backup));

    if (evict_h != GY_KEY_HANDLE_INVALID)
        gy_custodian_slot_free(c, evict_h);
    (void)cust_slot_register(c, GY_SLOT_SPK, hc->hspks[0].kp.pub.curve.pkid);
    return GY_OK;
}

int
gy_custodian_rotate_signed_prekey(struct gy_custodian *c,
                                  uint64_t spk_timestamp)
{
    struct gy_signed_prekey newspk;
    struct gy_signed_prekey backup_spks[GY_CUSTODIAN_SPK_HISTORY_MAX];
    size_t backup_n_spks, i;
    gy_key_handle evict_h = GY_KEY_HANDLE_INVALID;
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;

    if (c->desc->is_hybrid)
        return cust_rotate_hybrid_spk(c, spk_timestamp);

    rc = gy_signed_prekey_generate(c->desc, &newspk, c->ik.sk, spk_timestamp);
    if (rc != GY_OK)
        return rc;

    /* Back up the live state before mutating: if the persist below fails,
     * c->spks is restored exactly, so publish-facing state (c->spks[0])
     * never diverges from what c->recv (untouched until persist succeeds)
     * can actually resolve. */
    backup_n_spks = c->n_spks;
    memcpy(backup_spks, c->spks, sizeof(c->spks));

    if (c->n_spks == GY_CUSTODIAN_SPK_HISTORY_MAX) {
        /* Mark the oldest (the tail) for eviction; the slot is freed and
         * the entry zeroized only once the persist below succeeds
         * (D-X3DH-4/5 zeroizing delete). */
        size_t tail = GY_CUSTODIAN_SPK_HISTORY_MAX - 1;

        evict_h = cust_slot_find(c, GY_SLOT_SPK, c->spks[tail].kp.pub.pkid);
        c->n_spks--;
    }
    for (i = c->n_spks; i > 0; i--)
        c->spks[i] = c->spks[i - 1];
    c->spks[0] = newspk;
    gy_wipe(&newspk, sizeof(newspk));
    c->n_spks++;

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        memcpy(c->spks, backup_spks, sizeof(c->spks));
        c->n_spks = backup_n_spks;
        gy_wipe(backup_spks, sizeof(backup_spks));
        return rc;
    }
    gy_wipe(backup_spks, sizeof(backup_spks));

    if (evict_h != GY_KEY_HANDLE_INVALID)
        gy_custodian_slot_free(c, evict_h);
    cust_rebuild_spk_view(c);
    (void)cust_slot_register(c, GY_SLOT_SPK, c->spks[0].kp.pub.pkid);
    return cust_reinit_recv(c);
}

/* Slot idx is free (never allocated, or freed by a prior deletion). */
static int
cust_opk_slot_is_free(struct gy_custodian *c, size_t idx)
{
    return !(idx < c->n_opks && c->opk_used[idx]);
}

/*
 * OPK replenishment core (no CUST_ENTER; the caller already holds the
 * custodian): generate `count` fresh one-time prekeys into free slots, seal
 * the idmat, and rewire the receive context.  c must be unlocked with an
 * identity.  Shared by gy_custodian_generate_onetime_prekeys (public) and
 * gy_custodian_publish_bundle (mints one when the pool is spent).
 */
static int
cust_replenish_opks(struct gy_custodian *c, size_t count)
{
    uint32_t existing[GY_OPK_BATCH_MAX];
    size_t touched[GY_OPK_BATCH_MAX]; /* slot indices this call fills */
    size_t n_existing, free_slots, n_touched, saved_n_opks, i, slot;
    struct gy_keypair *gen;
    int rc;

    /* Hard cap up front: with count bounded by
     * GY_OPK_BATCH_MAX, the count * sizeof(*gen) guarded allocation below is
     * provably within a small compile-time constant and cannot overflow
     * (sodium_malloc has no calloc-style two-argument form).  Mirrors the
     * n_opks bound gy_custodian_generate_identity and gy_opk_batch enforce. */
    if (count == 0 || count > GY_OPK_BATCH_MAX)
        return GY_ERR_ARG;

    n_existing = 0;
    free_slots = 0;
    for (i = 0; i < GY_OPK_BATCH_MAX; i++) {
        if (i < c->n_opks && c->opk_used[i])
            existing[n_existing++] = c->opks[i].pub.pkid;
        else
            free_slots++;
    }
    if (count > free_slots)
        return GY_ERR_NO_SPACE;

    gen = gy_guarded_alloc(count * sizeof(*gen));
    if (gen == NULL)
        return GY_ERR_CRYPTO;
    rc = gy_opk_generate(c->desc, gen, count, existing, n_existing);
    if (rc != GY_OK) {
        gy_guarded_free(gen);
        return rc;
    }

    /* Stage into c->opks (the persist below reads live c state directly),
     * recording exactly which slots this call touched so a persist failure
     * can be rolled back precisely - c->recv (untouched until persist
     * succeeds) must never diverge from publish-facing state. */
    saved_n_opks = c->n_opks;
    slot = 0;
    n_touched = 0;
    for (i = 0; i < count; i++) {
        while (slot < GY_OPK_BATCH_MAX && !cust_opk_slot_is_free(c, slot))
            slot++;
        c->opks[slot] = gen[i];
        c->opk_used[slot] = 1;
        c->opk_consumed[slot] = 0;
        if (slot + 1 > c->n_opks)
            c->n_opks = slot + 1;
        (void)cust_slot_register(c, GY_SLOT_OPK, c->opks[slot].pub.pkid);
        touched[n_touched++] = slot;
        slot++;
    }
    gy_guarded_free(gen);

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        gy_key_handle h;

        for (i = 0; i < n_touched; i++) {
            slot = touched[i];
            h = cust_slot_find(c, GY_SLOT_OPK, c->opks[slot].pub.pkid);
            if (h != GY_KEY_HANDLE_INVALID)
                gy_custodian_slot_free(c, h);
            gy_wipe(&c->opks[slot], sizeof(c->opks[slot]));
            c->opk_used[slot] = 0;
            c->opk_consumed[slot] = 0;
        }
        c->n_opks = saved_n_opks;
        return rc;
    }

    return cust_reinit_recv(c);
}

/*
 * Hybrid OPK replenishment core (no CUST_ENTER; caller holds the custodian):
 * generate `count` hybrid one-time prekeys into free hopk slots, reseal.  Shared
 * by generate_onetime_prekeys and (b-iii-2b) the hybrid one-shot bundle path.
 */
static int
cust_replenish_hybrid_opks(struct gy_custodian *c, size_t count)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    uint32_t existing[GY_OPK_BATCH_MAX];
    size_t touched[GY_OPK_BATCH_MAX];
    size_t n_existing, free_slots, n_touched, saved_n, i, slot;
    struct gy_hybrid_keypair *gen;
    int rc;

    if (count == 0 || count > GY_OPK_BATCH_MAX)
        return GY_ERR_ARG;

    n_existing = 0;
    free_slots = 0;
    for (i = 0; i < GY_OPK_BATCH_MAX; i++) {
        if (i < hc->n_hopks && hc->hopk_used[i])
            existing[n_existing++] = hc->hopks[i].pub.curve.pkid;
        else
            free_slots++;
    }
    if (count > free_slots)
        return GY_ERR_NO_SPACE;

    gen = gy_guarded_alloc(count * sizeof(*gen));
    if (gen == NULL)
        return GY_ERR_CRYPTO;
    rc = gy_hybrid_opk_generate(c->desc, gen, count, existing, n_existing);
    if (rc != GY_OK) {
        gy_guarded_free(gen);
        return rc;
    }

    saved_n = hc->n_hopks;
    slot = 0;
    n_touched = 0;
    for (i = 0; i < count; i++) {
        while (slot < GY_OPK_BATCH_MAX &&
               (slot < hc->n_hopks && hc->hopk_used[slot]))
            slot++;
        hc->hopks[slot] = gen[i];
        hc->hopk_used[slot] = 1;
        hc->hopk_consumed[slot] = 0;
        if (slot + 1 > hc->n_hopks)
            hc->n_hopks = slot + 1;
        (void)cust_slot_register(c, GY_SLOT_OPK,
                                 hc->hopks[slot].pub.curve.pkid);
        touched[n_touched++] = slot;
        slot++;
    }
    gy_guarded_free(gen);

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        gy_key_handle h;

        for (i = 0; i < n_touched; i++) {
            slot = touched[i];
            h = cust_slot_find(c, GY_SLOT_OPK, hc->hopks[slot].pub.curve.pkid);
            if (h != GY_KEY_HANDLE_INVALID)
                gy_custodian_slot_free(c, h);
            gy_wipe(&hc->hopks[slot], sizeof(hc->hopks[slot]));
            hc->hopk_used[slot] = 0;
            hc->hopk_consumed[slot] = 0;
        }
        hc->n_hopks = saved_n;
        return rc;
    }
    return GY_OK;
}

int
gy_custodian_generate_onetime_prekeys(struct gy_custodian *c, size_t count)
{
    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (c->desc->is_hybrid)
        return cust_replenish_hybrid_opks(c, count);
    return cust_replenish_opks(c, count);
}

/* First reservable (held, not-yet-exported) OPK slot, or (size_t)-1. */
static size_t
cust_first_reservable_opk(const struct gy_custodian *c)
{
    size_t i;

    for (i = 0; i < c->n_opks; i++)
        if (c->opk_used[i] && !c->opk_consumed[i])
            return i;
    return (size_t)-1;
}

/* ---- hybrid publish (section 5.4/5.5) ---------------------------------- */

static size_t
cust_first_reservable_hybrid_opk(const struct gy_hybrid_custodian *hc)
{
    size_t i;

    for (i = 0; i < hc->n_hopks; i++)
        if (hc->hopk_used[i] && !hc->hopk_consumed[i])
            return i;
    return (size_t)-1;
}

/* Assemble a published hybrid bundle from the current identity/SPK and an OPK
 * (opk_idx == (size_t)-1 leaves the OPK all-zeros, i.e. a registration). */
static void
cust_build_hybrid_bundle(const struct gy_hybrid_custodian *hc,
                         const struct gy_suite_desc *desc, size_t opk_idx,
                         struct gy_hybrid_prekey_bundle *b)
{
    memset(b, 0, sizeof(*b));
    b->ik = hc->hik.pub;
    b->spk = hc->hspks[0].kp.pub;
    b->spk_timestamp = hc->hspks[0].timestamp;
    b->spk_flags = hc->hspks[0].flags;
    b->spk_ik_id = hc->hspks[0].ik_id;
    memcpy(b->spk_ed_sig, hc->hspks[0].ed_sig, desc->sig_len);
    memcpy(b->spk_mldsa_sig, hc->hspks[0].mldsa_sig, desc->dsa_sig_len);
    if (opk_idx != (size_t)-1)
        b->opk = hc->hopks[opk_idx].pub;
}

static int
cust_publish_hybrid_registration(struct gy_custodian *c, uint8_t *out,
                                 size_t *out_len)
{
    struct gy_hybrid_prekey_bundle b;

    if (out == NULL) {
        *out_len = gy_hybrid_bundle_wire_len(c->desc);
        return GY_OK;
    }
    cust_build_hybrid_bundle(cust_as_hybrid(c), c->desc, (size_t)-1, &b);
    return gy_hybrid_bundle_put(out, *out_len, out_len, c->desc, &b);
}

static int
cust_publish_hybrid_bundle(struct gy_custodian *c, uint8_t *out,
                           size_t *out_len)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_hybrid_prekey_bundle b;
    size_t idx;
    int rc;

    if (out == NULL) {
        *out_len = gy_hybrid_bundle_wire_len(c->desc);
        return GY_OK;
    }
    idx = cust_first_reservable_hybrid_opk(hc);
    if (idx == (size_t)-1) {
        rc = cust_replenish_hybrid_opks(c, 1);
        if (rc != GY_OK)
            return rc;
        idx = cust_first_reservable_hybrid_opk(hc);
        if (idx == (size_t)-1)
            return GY_ERR_CRYPTO;
    }
    hc->hopk_consumed[idx] = 1; /* reserved (exported); private key retained */
    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        hc->hopk_consumed[idx] = 0;
        return rc;
    }
    cust_build_hybrid_bundle(hc, c->desc, idx, &b);
    return gy_hybrid_bundle_put(out, *out_len, out_len, c->desc, &b);
}

static int
cust_publish_hybrid_opk_batch(struct gy_custodian *c, uint8_t *out,
                              size_t *out_len)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_hybrid_public_key *pubs;
    size_t i, n;
    int rc;

    n = 0;
    for (i = 0; i < hc->n_hopks; i++)
        if (hc->hopk_used[i] && !hc->hopk_consumed[i])
            n++;

    if (out == NULL) {
        *out_len = gy_hybrid_opk_batch_wire_len(c->desc, n);
        return GY_OK;
    }

    /* Public keys only (no secret material): plain heap, not guarded. */
    pubs = calloc(n ? n : 1, sizeof(*pubs));
    if (pubs == NULL)
        return GY_ERR_CRYPTO;
    n = 0;
    for (i = 0; i < hc->n_hopks; i++)
        if (hc->hopk_used[i] && !hc->hopk_consumed[i])
            pubs[n++] = hc->hopks[i].pub;
    rc = gy_hybrid_opk_batch_put(out, *out_len, out_len, c->desc, pubs, n);
    free(pubs);
    return rc;
}

int
gy_custodian_publish_bundle(struct gy_custodian *c, uint8_t *out,
                            size_t *out_len)
{
    struct gy_prekey_bundle b;
    size_t idx;
    int rc;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;

    if (c->desc->is_hybrid)
        return cust_publish_hybrid_bundle(c, out, out_len);

    /* A one-shot bundle is the directory-less / direct-handoff path: it always
     * carries an OPK (no server will slice one in later), so the size is
     * fixed.  The size query must not mutate. */
    if (out == NULL) {
        *out_len = gy_bundle_wire_len(c->desc, 1);
        return GY_OK;
    }

    /*
     * Reserve a fresh OPK for THIS bundle so no other export ever hands out
     * the same one-time key: pick the first not-yet-exported OPK, or mint one
     * if the pool is spent, then mark it consumed (exported).  The PRIVATE key
     * is retained here - the peer that receives this bundle needs it to
     * complete the handshake, at which point delete-on-use destroys it.
     * Unlike the granular publish_opk_batch path (a directory that assembles
     * and hands out one OPK per fetch), the one-shot path has no server, so
     * the reservation is the custodian's own responsibility.
     */
    idx = cust_first_reservable_opk(c);
    if (idx == (size_t)-1) {
        rc = cust_replenish_opks(c, 1);
        if (rc != GY_OK)
            return rc;
        idx = cust_first_reservable_opk(c);
        if (idx == (size_t)-1)
            return GY_ERR_CRYPTO;
    }
    c->opk_consumed[idx] = 1; /* reserved (exported); private key retained */
    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        c->opk_consumed[idx] = 0; /* roll back the reservation */
        return rc;
    }

    memset(&b, 0, sizeof(b));
    b.ik = c->ik.pub;
    b.spk = c->spks[0].kp.pub;
    b.spk_timestamp = c->spks[0].timestamp;
    memcpy(b.spk_sig, c->spks[0].sig, c->desc->sig_len);
    b.opk = c->opks[idx].pub;
    return gy_bundle_put(out, *out_len, out_len, c->desc, &b);
}

int
gy_custodian_opk_stats(struct gy_custodian *c, size_t *total, size_t *used,
                       size_t *unused)
{
    size_t i, n, t = 0, u = 0;
    const int *used_flags, *consumed_flags;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    if (c->desc->is_hybrid) {
        struct gy_hybrid_custodian *hc = cust_as_hybrid(c);

        n = hc->n_hopks;
        used_flags = hc->hopk_used;
        consumed_flags = hc->hopk_consumed;
    } else {
        n = c->n_opks;
        used_flags = c->opk_used;
        consumed_flags = c->opk_consumed;
    }
    for (i = 0; i < n; i++) {
        if (!used_flags[i])
            continue;
        t++;
        if (consumed_flags[i])
            u++;
    }
    if (total != NULL)
        *total = t;
    if (used != NULL)
        *used = u;
    if (unused != NULL)
        *unused = t - u;
    return GY_OK;
}

int
gy_custodian_publish_registration(struct gy_custodian *c, uint8_t *out,
                                  size_t *out_len)
{
    struct gy_prekey_bundle b;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (c->desc->is_hybrid)
        return cust_publish_hybrid_registration(c, out, out_len);
    if (out == NULL) {
        *out_len = gy_bundle_wire_len(c->desc, 0);
        return GY_OK;
    }
    memset(&b, 0, sizeof(b));
    b.ik = c->ik.pub;
    b.spk = c->spks[0].kp.pub;
    b.spk_timestamp = c->spks[0].timestamp;
    memcpy(b.spk_sig, c->spks[0].sig, c->desc->sig_len);
    b.opk.pkid = 0; /* registration never carries an OPK */
    return gy_bundle_put(out, *out_len, out_len, c->desc, &b);
}

int
gy_custodian_publish_opk_batch(struct gy_custodian *c, uint8_t *out,
                               size_t *out_len)
{
    struct gy_public_key pubs[GY_OPK_BATCH_MAX];
    size_t i, n;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (c->desc->is_hybrid)
        return cust_publish_hybrid_opk_batch(c, out, out_len);

    n = 0;
    for (i = 0; i < c->n_opks; i++)
        if (c->opk_used[i] && !c->opk_consumed[i])
            pubs[n++] = c->opks[i].pub;

    if (out == NULL) {
        *out_len = gy_opk_batch_wire_len(c->desc, n);
        return GY_OK;
    }
    return gy_opk_batch_put(out, *out_len, out_len, c->desc, pubs, n);
}

gy_key_handle
gy_custodian_find_prekey(struct gy_custodian *c, int kind, uint32_t pkid)
{
    int type;

    if (c == NULL)
        return GY_KEY_HANDLE_INVALID;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_KEY_HANDLE_INVALID;
    if (kind == GY_PK_SPK)
        type = GY_SLOT_SPK;
    else if (kind == GY_PK_OPK)
        type = GY_SLOT_OPK;
    else
        return GY_KEY_HANDLE_INVALID;
    return cust_slot_find(c, type, pkid);
}

/*
 * Delete a retained hybrid SPK (not the active one) or a hybrid OPK by handle,
 * mirroring the classical path below but on hc->hspks / hc->hopks and resealing
 * the hybrid idmat.  No recv rewire: the hybrid receive path reads hc->hspks /
 * hc->hopks directly per-call (api.c).  Runs with the public entry's gates
 * checked and slot already resolved to (type, key_id).
 */
static int
cust_delete_hybrid_prekey(struct gy_custodian *c, gy_key_handle h, int type,
                          uint32_t key_id)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_hybrid_signed_prekey backup_spks[GY_CUSTODIAN_SPK_HISTORY_MAX];
    struct gy_hybrid_keypair backup_opk;
    size_t backup_n_spks = 0, opk_idx = (size_t)-1, i;
    int backup_opk_used = 0, backup_opk_consumed = 0, found = 0;
    int rc;

    memset(&backup_opk, 0, sizeof(backup_opk));
    if (type == GY_SLOT_SPK) {
        if (hc->n_hspks > 0 && hc->hspks[0].kp.pub.curve.pkid == key_id)
            return GY_ERR_STATE; /* refuse to delete the active SPK */
        backup_n_spks = hc->n_hspks;
        memcpy(backup_spks, hc->hspks, sizeof(hc->hspks));
        for (i = 1; i < hc->n_hspks; i++) {
            if (hc->hspks[i].kp.pub.curve.pkid == key_id) {
                for (; i + 1 < hc->n_hspks; i++)
                    hc->hspks[i] = hc->hspks[i + 1];
                gy_wipe(&hc->hspks[hc->n_hspks - 1], sizeof(hc->hspks[0]));
                hc->n_hspks--;
                found = 1;
                break;
            }
        }
    } else if (type == GY_SLOT_OPK) {
        for (i = 0; i < hc->n_hopks; i++) {
            if (hc->hopk_used[i] && hc->hopks[i].pub.curve.pkid == key_id) {
                opk_idx = i;
                backup_opk = hc->hopks[i];
                backup_opk_used = hc->hopk_used[i];
                backup_opk_consumed = hc->hopk_consumed[i];
                gy_wipe(&hc->hopks[i], sizeof(hc->hopks[i]));
                hc->hopk_used[i] = 0;
                hc->hopk_consumed[i] = 0;
                found = 1;
                break;
            }
        }
    } else {
        return GY_ERR_ARG;
    }
    if (!found) {
        gy_wipe(backup_spks, sizeof(backup_spks));
        gy_wipe(&backup_opk, sizeof(backup_opk));
        return GY_ERR_NOT_FOUND;
    }

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        if (type == GY_SLOT_SPK) {
            memcpy(hc->hspks, backup_spks, sizeof(hc->hspks));
            hc->n_hspks = backup_n_spks;
        } else {
            hc->hopks[opk_idx] = backup_opk;
            hc->hopk_used[opk_idx] = backup_opk_used;
            hc->hopk_consumed[opk_idx] = backup_opk_consumed;
        }
        gy_wipe(backup_spks, sizeof(backup_spks));
        gy_wipe(&backup_opk, sizeof(backup_opk));
        return rc;
    }
    gy_wipe(backup_spks, sizeof(backup_spks));
    gy_wipe(&backup_opk, sizeof(backup_opk));

    gy_custodian_slot_free(c, h);
    return GY_OK;
}

int
gy_custodian_delete_prekey(struct gy_custodian *c, gy_key_handle h)
{
    struct gy_signed_prekey backup_spks[GY_CUSTODIAN_SPK_HISTORY_MAX] = {0};
    struct gy_keypair backup_opk = {0};
    size_t backup_n_spks = 0, opk_idx, i;
    int type, backup_opk_used = 0, backup_opk_consumed = 0;
    uint32_t key_id;
    int rc, found = 0;

    if (c == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    rc = gy_custodian_slot_get(c, h, &type, &key_id);
    if (rc != GY_OK)
        return rc;

    if (c->desc->is_hybrid)
        return cust_delete_hybrid_prekey(c, h, type, key_id);

    /* Stage the deletion into c (the persist below reads live c state
     * directly), keeping enough of a backup to restore exactly on a
     * persist failure - c->recv (untouched until persist succeeds) must
     * never diverge from publish-facing state. */
    opk_idx = (size_t)-1;
    if (type == GY_SLOT_SPK) {
        if (c->n_spks > 0 && c->spks[0].kp.pub.pkid == key_id)
            return GY_ERR_STATE; /* refuse to delete the active SPK */
        backup_n_spks = c->n_spks;
        memcpy(backup_spks, c->spks, sizeof(c->spks));
        for (i = 1; i < c->n_spks; i++) {
            if (c->spks[i].kp.pub.pkid == key_id) {
                for (; i + 1 < c->n_spks; i++)
                    c->spks[i] = c->spks[i + 1];
                gy_wipe(&c->spks[c->n_spks - 1], sizeof(c->spks[0]));
                c->n_spks--;
                found = 1;
                break;
            }
        }
        cust_rebuild_spk_view(c);
    } else if (type == GY_SLOT_OPK) {
        for (i = 0; i < c->n_opks; i++) {
            if (c->opk_used[i] && c->opks[i].pub.pkid == key_id) {
                opk_idx = i;
                backup_opk = c->opks[i];
                backup_opk_used = c->opk_used[i];
                backup_opk_consumed = c->opk_consumed[i];
                gy_wipe(&c->opks[i], sizeof(c->opks[i]));
                c->opk_used[i] = 0;
                c->opk_consumed[i] = 0;
                found = 1;
                break;
            }
        }
    } else {
        return GY_ERR_ARG;
    }
    if (!found)
        return GY_ERR_NOT_FOUND;

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        if (type == GY_SLOT_SPK) {
            memcpy(c->spks, backup_spks, sizeof(c->spks));
            c->n_spks = backup_n_spks;
            cust_rebuild_spk_view(c);
        } else {
            c->opks[opk_idx] = backup_opk;
            c->opk_used[opk_idx] = backup_opk_used;
            c->opk_consumed[opk_idx] = backup_opk_consumed;
        }
        gy_wipe(backup_spks, sizeof(backup_spks));
        gy_wipe(&backup_opk, sizeof(backup_opk));
        return rc;
    }
    gy_wipe(backup_spks, sizeof(backup_spks));
    gy_wipe(&backup_opk, sizeof(backup_opk));

    gy_custodian_slot_free(c, h);
    return cust_reinit_recv(c);
}

/* ---- application signing key ------------------------------
 *
 * Two DISTINCT, FIXED domain-separation labels (never confusable with each
 * other, a protocol signature, or the prekey signature label): the
 * identity's signature over a SAK's cert uses "appkey-cert"; every
 * per-request SAK signature uses "appkey".  Both go through gy_suite_info
 * (facade.h's rename of core's gy_info), so proto/ never references core/
 * directly (nm audit).
 */

#define GY_APPKEY_INFO_MAX                                                     \
    64 /* "geryon.1.<suite>.<purpose>"; matches the
                               * GY_INFO_MAX convention in x3dh.c/he.c/
                               * double_ratchet.c */

/* Build the identity's cert-signing input: appkey-cert info || EncodeEC
 * (sak_pub) || issued_at_be64 || expiry_be64 || identity_pkid_be32.
 * EncodeEC = curve_type || curve_pk (no pkid), matching the SAME convention
 * gy_spk_create already signs prekeys under (prekeys.h). */
static int
cust_appkey_cert_signed_data(uint8_t *out, size_t cap, size_t *outlen,
                             const struct gy_suite_desc *desc,
                             const struct gy_public_key *sak_pub,
                             uint64_t issued_at, uint64_t expiry,
                             uint32_t identity_pkid)
{
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, need, off;
    int rc;

    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                       "appkey-cert");
    if (rc != GY_OK)
        return rc;
    need = infolen + 1 + desc->curve_pk_len + 8 + 8 + 4;
    if (need > cap)
        return GY_ERR_TOOLONG;

    off = 0;
    memcpy(out + off, info, infolen);
    off += infolen;
    out[off++] = sak_pub->curve_type;
    memcpy(out + off, sak_pub->pk, desc->curve_pk_len);
    off += desc->curve_pk_len;
    put_be64(out + off, issued_at);
    off += 8;
    put_be64(out + off, expiry);
    off += 8;
    put_be32(out + off, identity_pkid);
    off += 4;

    *outlen = off;
    return GY_OK;
}

/* Certify a freshly-minted SAK keypair into *sak (issued_at/expiry/
 * identity_pkid filled, identity_sig computed under the identity key). */
static int
cust_certify_sak(struct gy_custodian *c, struct gy_cust_sak *sak,
                 uint64_t expiry)
{
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 1 + GY_CURVE_PK_MAX + 8 + 8 + 4];
    size_t signed_len;
    int rc;

    sak->issued_at = c->clock != NULL ? c->clock(c->clock_ctx) : 0;
    sak->expiry = expiry;
    sak->identity_pkid = c->ik.pub.pkid;

    rc = cust_appkey_cert_signed_data(
        signed_data, sizeof(signed_data), &signed_len, c->desc, &sak->kp.pub,
        sak->issued_at, sak->expiry, sak->identity_pkid);
    if (rc != GY_OK)
        return rc;
    rc = c->desc->sign(sak->identity_sig, c->ik.sk, signed_data, signed_len);
    gy_wipe(signed_data, sizeof(signed_data));
    return rc;
}

/* ---- hybrid (dual-scheme) application signing key -----------------------
 *
 * The hybrid SAK is certified, and signs per-request, under BOTH XEdDSA and
 * ML-DSA (verify requires both), so no identity-signed artifact drops to
 * classical-only authentication in a hybrid suite.  These helpers run with the
 * public entry point's gates already checked and the re-entrancy guard already
 * held; the public functions dispatch here when c->desc->is_hybrid.  The XEdDSA
 * half signs info("appkey[-cert]") || fields exactly as the classical path; the
 * ML-DSA half signs the same bytes with FIPS 204 ctx = info("appkey[-cert]").
 */

/* appkey-cert info || curve_type || curve_pk || mldsa_pk || issued_at_be64 ||
 * expiry_be64 || identity_pkid_be32.  Adds mldsa_pk to the classical layout so
 * BOTH SAK public keys are bound into the certified data. */
static int
cust_hybrid_appkey_cert_signed_data(uint8_t *out, size_t cap, size_t *outlen,
                                    const struct gy_suite_desc *desc,
                                    const struct gy_public_key *sak_curve_pub,
                                    const uint8_t *sak_mldsa_pk,
                                    uint64_t issued_at, uint64_t expiry,
                                    uint32_t identity_pkid)
{
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, need, off;
    int rc;

    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                       "appkey-cert");
    if (rc != GY_OK)
        return rc;
    need = infolen + 1 + desc->curve_pk_len + desc->dsa_pk_len + 8 + 8 + 4;
    if (need > cap)
        return GY_ERR_TOOLONG;

    off = 0;
    memcpy(out + off, info, infolen);
    off += infolen;
    out[off++] = sak_curve_pub->curve_type;
    memcpy(out + off, sak_curve_pub->pk, desc->curve_pk_len);
    off += desc->curve_pk_len;
    memcpy(out + off, sak_mldsa_pk, desc->dsa_pk_len);
    off += desc->dsa_pk_len;
    put_be64(out + off, issued_at);
    off += 8;
    put_be64(out + off, expiry);
    off += 8;
    put_be32(out + off, identity_pkid);
    off += 4;

    *outlen = off;
    return GY_OK;
}

/* Dual-certify a freshly-minted hybrid SAK into *sak under the hybrid
 * identity's XEdDSA and ML-DSA keys. */
static int
cust_certify_hsak(struct gy_custodian *c, struct gy_cust_hsak *sak,
                  uint64_t expiry)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 1 + GY_CURVE_PK_MAX +
                        GY_DSA_PK_MAX + 8 + 8 + 4];
    uint8_t ctx[GY_APPKEY_INFO_MAX];
    size_t signed_len, ctxlen;
    int rc;

    sak->issued_at = c->clock != NULL ? c->clock(c->clock_ctx) : 0;
    sak->expiry = expiry;
    sak->identity_pkid = hc->hik.pub.base.curve.pkid;

    rc = cust_hybrid_appkey_cert_signed_data(
        signed_data, sizeof(signed_data), &signed_len, c->desc, &sak->kp.pub,
        sak->mldsa_pk, sak->issued_at, sak->expiry, sak->identity_pkid);
    if (rc != GY_OK)
        return rc;
    rc = c->desc->sign(sak->identity_ed_sig, hc->hik.curve_sk, signed_data,
                       signed_len);
    if (rc != GY_OK) {
        gy_wipe(signed_data, sizeof(signed_data));
        return rc;
    }
    rc = gy_suite_info(ctx, sizeof(ctx), &ctxlen, c->desc->suite_id,
                       "appkey-cert");
    if (rc == GY_OK)
        rc = c->desc->dsa_sign(sak->identity_mldsa_sig, hc->hik.mldsa_sk,
                               signed_data, signed_len, ctx, ctxlen);
    gy_wipe(signed_data, sizeof(signed_data));
    return rc;
}

/* Mint curve + ML-DSA SAK keypairs into *sak (kp.pub.pkid over the curve key,
 * the slot key) and dual-certify. */
static int
cust_mint_hsak(struct gy_custodian *c, struct gy_cust_hsak *sak,
               uint64_t expiry)
{
    int rc;

    memset(sak, 0, sizeof(*sak));
    rc = gy_identity_generate(c->desc, &sak->kp);
    if (rc != GY_OK)
        return rc;
    rc = c->desc->dsa_keypair(sak->mldsa_pk, sak->mldsa_sk);
    if (rc != GY_OK)
        return rc;
    return cust_certify_hsak(c, sak, expiry);
}

static int
cust_generate_hybrid_appkey(struct gy_custodian *c, uint64_t expiry,
                            gy_key_handle *out)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_cust_hsak *sak;
    int rc;

    if (hc->n_hsaks > 0)
        return GY_ERR_STATE; /* already have one; rotate to replace it */

    sak = gy_guarded_alloc(sizeof(*sak));
    if (sak == NULL)
        return GY_ERR_CRYPTO;
    rc = cust_mint_hsak(c, sak, expiry);
    if (rc != GY_OK) {
        gy_wipe(sak, sizeof(*sak));
        gy_guarded_free(sak);
        return rc;
    }

    hc->hsaks[0] = *sak;
    gy_wipe(sak, sizeof(*sak));
    gy_guarded_free(sak);
    hc->n_hsaks = 1;

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        gy_wipe(&hc->hsaks[0], sizeof(hc->hsaks[0]));
        hc->n_hsaks = 0;
        return rc;
    }
    *out = cust_slot_register(c, GY_SLOT_SAK, hc->hsaks[0].kp.pub.pkid);
    return GY_OK;
}

static int
cust_rotate_hybrid_appkey(struct gy_custodian *c, uint64_t expiry,
                          gy_key_handle *out)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    struct gy_cust_hsak *newsak, *backup;
    size_t backup_n, i;
    gy_key_handle evict_h = GY_KEY_HANDLE_INVALID;
    int rc;

    if (hc->n_hsaks == 0)
        return GY_ERR_STATE; /* nothing to rotate; generate first */

    newsak = gy_guarded_alloc(sizeof(*newsak));
    backup = gy_guarded_alloc(sizeof(*backup) * GY_CUSTODIAN_SAK_HISTORY_MAX);
    if (newsak == NULL || backup == NULL) {
        gy_guarded_free(newsak);
        gy_guarded_free(backup);
        return GY_ERR_CRYPTO;
    }
    rc = cust_mint_hsak(c, newsak, expiry);
    if (rc != GY_OK)
        goto out;

    /* Backup-then-mutate-then-restore-on-failure, matching the classical
     * rotate and gy_custodian_rotate_signed_prekey (see their comments). */
    backup_n = hc->n_hsaks;
    memcpy(backup, hc->hsaks, sizeof(hc->hsaks));

    if (hc->n_hsaks == GY_CUSTODIAN_SAK_HISTORY_MAX) {
        size_t tail = GY_CUSTODIAN_SAK_HISTORY_MAX - 1;

        evict_h = cust_slot_find(c, GY_SLOT_SAK, hc->hsaks[tail].kp.pub.pkid);
        hc->n_hsaks--;
    }
    for (i = hc->n_hsaks; i > 0; i--)
        hc->hsaks[i] = hc->hsaks[i - 1];
    hc->hsaks[0] = *newsak;
    hc->n_hsaks++;

    rc = cust_seal_and_persist_hybrid_idmat(c);
    if (rc != GY_OK) {
        memcpy(hc->hsaks, backup, sizeof(hc->hsaks));
        hc->n_hsaks = backup_n;
        goto out;
    }
    if (evict_h != GY_KEY_HANDLE_INVALID)
        gy_custodian_slot_free(c, evict_h);
    *out = cust_slot_register(c, GY_SLOT_SAK, hc->hsaks[0].kp.pub.pkid);
out:
    gy_wipe(newsak, sizeof(*newsak));
    gy_wipe(backup, sizeof(*backup) * GY_CUSTODIAN_SAK_HISTORY_MAX);
    gy_guarded_free(newsak);
    gy_guarded_free(backup);
    return rc;
}

static int
cust_export_hybrid_appkey_cert(struct gy_custodian *c, uint32_t key_id,
                               uint8_t *out, size_t *out_len)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    size_t i;

    for (i = 0; i < hc->n_hsaks; i++)
        if (hc->hsaks[i].kp.pub.pkid == key_id)
            break;
    if (i == hc->n_hsaks)
        return GY_ERR_NOT_FOUND;

    if (out == NULL) {
        *out_len = gy_hybrid_appkey_cert_wire_len(c->desc);
        return GY_OK;
    }
    return gy_hybrid_appkey_cert_put(
        out, *out_len, out_len, c->desc, &hc->hsaks[i].kp.pub,
        hc->hsaks[i].mldsa_pk, hc->hsaks[i].issued_at, hc->hsaks[i].expiry,
        hc->hsaks[i].identity_pkid, hc->hsaks[i].identity_ed_sig,
        hc->hsaks[i].identity_mldsa_sig);
}

/* Per-request dual signature: sig = ed_sig || mldsa_sig over
 * info("appkey") || be32(app_ctx_len) || app_ctx || msg. */
static int
cust_hybrid_sign(struct gy_custodian *c, uint32_t key_id,
                 const uint8_t *app_ctx, size_t app_ctx_len, const uint8_t *msg,
                 size_t msg_len, uint8_t *sig, size_t *sig_len)
{
    struct gy_hybrid_custodian *hc = cust_as_hybrid(c);
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 4 + GY_CUSTODIAN_SIGN_MAX];
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, off, i, need;
    int rc;

    need = c->desc->sig_len + c->desc->dsa_sig_len;
    for (i = 0; i < hc->n_hsaks; i++)
        if (hc->hsaks[i].kp.pub.pkid == key_id)
            break;
    if (i == hc->n_hsaks)
        return GY_ERR_NOT_FOUND;

    if (sig == NULL) {
        *sig_len = need;
        return GY_OK;
    }
    if (*sig_len < need)
        return GY_ERR_ARG;

    rc = gy_suite_info(info, sizeof(info), &infolen, c->desc->suite_id,
                       "appkey");
    if (rc != GY_OK)
        return rc;
    off = 0;
    memcpy(signed_data + off, info, infolen);
    off += infolen;
    put_be32(signed_data + off, (uint32_t)app_ctx_len);
    off += 4;
    if (app_ctx_len > 0)
        memcpy(signed_data + off, app_ctx, app_ctx_len);
    off += app_ctx_len;
    if (msg_len > 0)
        memcpy(signed_data + off, msg, msg_len);
    off += msg_len;

    rc = c->desc->sign(sig, hc->hsaks[i].kp.sk, signed_data, off);
    if (rc == GY_OK)
        rc = c->desc->dsa_sign(sig + c->desc->sig_len, hc->hsaks[i].mldsa_sk,
                               signed_data, off, info, infolen);
    gy_wipe(signed_data, sizeof(signed_data));
    if (rc != GY_OK)
        return rc;
    *sig_len = need;
    return GY_OK;
}

int
gy_custodian_generate_appkey(struct gy_custodian *c, uint64_t expiry,
                             gy_key_handle *out)
{
    struct gy_cust_sak sak;
    int rc;

    if (c == NULL || out == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (c->desc->is_hybrid)
        return cust_generate_hybrid_appkey(c, expiry, out);
    if (c->n_saks > 0)
        return GY_ERR_STATE; /* already have one; rotate to replace it */

    memset(&sak, 0, sizeof(sak));
    rc = gy_identity_generate(c->desc, &sak.kp);
    if (rc != GY_OK)
        return rc;
    rc = cust_certify_sak(c, &sak, expiry);
    if (rc != GY_OK) {
        gy_wipe(&sak, sizeof(sak));
        return rc;
    }

    c->saks[0] = sak;
    gy_wipe(&sak, sizeof(sak));
    c->n_saks = 1;

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        gy_wipe(&c->saks[0], sizeof(c->saks[0]));
        c->n_saks = 0;
        return rc;
    }

    *out = cust_slot_register(c, GY_SLOT_SAK, c->saks[0].kp.pub.pkid);
    return GY_OK;
}

int
gy_custodian_rotate_appkey(struct gy_custodian *c, uint64_t expiry,
                           gy_key_handle *out)
{
    struct gy_cust_sak newsak;
    struct gy_cust_sak backup_saks[GY_CUSTODIAN_SAK_HISTORY_MAX];
    size_t backup_n_saks, i;
    gy_key_handle evict_h = GY_KEY_HANDLE_INVALID;
    int rc;

    if (c == NULL || out == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (c->desc->is_hybrid)
        return cust_rotate_hybrid_appkey(c, expiry, out);
    if (c->n_saks == 0)
        return GY_ERR_STATE; /* nothing to rotate; generate first */

    memset(&newsak, 0, sizeof(newsak));
    rc = gy_identity_generate(c->desc, &newsak.kp);
    if (rc != GY_OK)
        return rc;
    rc = cust_certify_sak(c, &newsak, expiry);
    if (rc != GY_OK) {
        gy_wipe(&newsak, sizeof(newsak));
        return rc;
    }

    /* Backup-then-mutate-then-restore-on-failure, matching
     * gy_custodian_rotate_signed_prekey exactly (see its comment): c->recv
     * does not depend on saks[], but publish-facing state (a later
     * gy_custodian_export_appkey_cert) must never report a rotation that
     * was not durably persisted. */
    backup_n_saks = c->n_saks;
    memcpy(backup_saks, c->saks, sizeof(c->saks));

    if (c->n_saks == GY_CUSTODIAN_SAK_HISTORY_MAX) {
        size_t tail = GY_CUSTODIAN_SAK_HISTORY_MAX - 1;

        evict_h = cust_slot_find(c, GY_SLOT_SAK, c->saks[tail].kp.pub.pkid);
        c->n_saks--;
    }
    for (i = c->n_saks; i > 0; i--)
        c->saks[i] = c->saks[i - 1];
    c->saks[0] = newsak;
    gy_wipe(&newsak, sizeof(newsak));
    c->n_saks++;

    rc = cust_seal_and_persist_idmat(c);
    if (rc != GY_OK) {
        memcpy(c->saks, backup_saks, sizeof(c->saks));
        c->n_saks = backup_n_saks;
        gy_wipe(backup_saks, sizeof(backup_saks));
        return rc;
    }
    gy_wipe(backup_saks, sizeof(backup_saks));

    if (evict_h != GY_KEY_HANDLE_INVALID)
        gy_custodian_slot_free(c, evict_h);
    *out = cust_slot_register(c, GY_SLOT_SAK, c->saks[0].kp.pub.pkid);
    return GY_OK;
}

int
gy_custodian_export_appkey_cert(struct gy_custodian *c, gy_key_handle h,
                                uint8_t *out, size_t *out_len)
{
    int type;
    uint32_t key_id;
    size_t i;
    int rc;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;

    rc = gy_custodian_slot_get(c, h, &type, &key_id);
    if (rc != GY_OK)
        return rc;
    if (type != GY_SLOT_SAK)
        return GY_ERR_ARG;

    if (c->desc->is_hybrid)
        return cust_export_hybrid_appkey_cert(c, key_id, out, out_len);

    for (i = 0; i < c->n_saks; i++)
        if (c->saks[i].kp.pub.pkid == key_id)
            break;
    if (i == c->n_saks)
        return GY_ERR_NOT_FOUND;

    if (out == NULL) {
        *out_len = gy_appkey_cert_wire_len(c->desc);
        return GY_OK;
    }
    return gy_appkey_cert_put(out, *out_len, out_len, c->desc,
                              &c->saks[i].kp.pub, c->saks[i].issued_at,
                              c->saks[i].expiry, c->saks[i].identity_pkid,
                              c->saks[i].identity_sig);
}

int
gy_custodian_sign(struct gy_custodian *c, gy_key_handle h,
                  const uint8_t *app_ctx, size_t app_ctx_len,
                  const uint8_t *msg, size_t msg_len, uint8_t *sig,
                  size_t *sig_len)
{
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 4 + GY_CUSTODIAN_SIGN_MAX];
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, off, i;
    int type;
    uint32_t key_id;
    int rc;

    if (c == NULL || sig_len == NULL)
        return GY_ERR_ARG;
    if (app_ctx == NULL && app_ctx_len != 0)
        return GY_ERR_ARG;
    if (msg == NULL && msg_len != 0)
        return GY_ERR_ARG;
    CUST_ENTER(c);
    if (!c->unlocked)
        return GY_ERR_STATE;
    if (app_ctx_len > GY_CUSTODIAN_SIGN_MAX ||
        msg_len > GY_CUSTODIAN_SIGN_MAX - app_ctx_len)
        return GY_ERR_TOOLONG;

    rc = gy_custodian_slot_get(c, h, &type, &key_id);
    if (rc != GY_OK)
        return rc;
    if (type != GY_SLOT_SAK)
        return GY_ERR_ARG;

    if (c->desc->is_hybrid)
        return cust_hybrid_sign(c, key_id, app_ctx, app_ctx_len, msg, msg_len,
                                sig, sig_len);

    for (i = 0; i < c->n_saks; i++)
        if (c->saks[i].kp.pub.pkid == key_id)
            break;
    if (i == c->n_saks)
        return GY_ERR_NOT_FOUND;

    if (sig == NULL) {
        *sig_len = c->desc->sig_len;
        return GY_OK;
    }
    if (*sig_len < c->desc->sig_len)
        return GY_ERR_ARG;

    rc = gy_suite_info(info, sizeof(info), &infolen, c->desc->suite_id,
                       "appkey");
    if (rc != GY_OK)
        return rc;

    off = 0;
    memcpy(signed_data + off, info, infolen);
    off += infolen;
    /* Length-delimit app_ctx: a be32 prefix fixes the
     * app_ctx/msg boundary so distinct (app_ctx, msg) pairs can never
     * canonicalize to the same signed bytes.  gy_appkey_verify frames the
     * verified input identically. */
    put_be32(signed_data + off, (uint32_t)app_ctx_len);
    off += 4;
    if (app_ctx_len > 0)
        memcpy(signed_data + off, app_ctx, app_ctx_len);
    off += app_ctx_len;
    if (msg_len > 0)
        memcpy(signed_data + off, msg, msg_len);
    off += msg_len;

    rc = c->desc->sign(sig, c->saks[i].kp.sk, signed_data, off);
    gy_wipe(signed_data, sizeof(signed_data));
    if (rc != GY_OK)
        return rc;
    *sig_len = c->desc->sig_len;
    return GY_OK;
}
