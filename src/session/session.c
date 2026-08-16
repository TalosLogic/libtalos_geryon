/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Sesame record model: SessionID derivation (D-SES-3), the
 * D-SES-5 active/inactive SessionID list operations with D-SES-4 eviction,
 * and versioned encode/decode for the three D-SES-11 record blob types.  This
 * module owns no store and no clock; it operates on caller-held structs and
 * opaque blobs (D-SES-1/7/10).
 */

#include <string.h>

#include "hash.h"
#include "session.h"

/* ---- bounded blob cursors ---------------------------------------------- */

struct wcur {
    uint8_t *p;
    size_t cap;
    size_t off;
    int ok;
};

struct rcur {
    const uint8_t *p;
    size_t len;
    size_t off;
    int ok;
};

static void
w_raw(struct wcur *w, const void *b, size_t n)
{
    if (!w->ok)
        return;
    if (n > w->cap - w->off) {
        w->ok = 0;
        return;
    }
    memcpy(w->p + w->off, b, n);
    w->off += n;
}

static void
w_u8(struct wcur *w, uint8_t v)
{
    w_raw(w, &v, 1);
}

static void
w_be32(struct wcur *w, uint32_t v)
{
    uint8_t t[4];

    gy_be32_put(t, v);
    w_raw(w, t, 4);
}

static void
w_be64(struct wcur *w, uint64_t v)
{
    uint8_t t[8];

    gy_be64_put(t, v);
    w_raw(w, t, 8);
}

static void
r_raw(struct rcur *r, void *out, size_t n)
{
    if (!r->ok)
        return;
    if (n > r->len - r->off) {
        r->ok = 0;
        return;
    }
    memcpy(out, r->p + r->off, n);
    r->off += n;
}

static uint8_t
r_u8(struct rcur *r)
{
    uint8_t v = 0;

    r_raw(r, &v, 1);
    return v;
}

static uint32_t
r_be32(struct rcur *r)
{
    uint8_t t[4] = {0};

    r_raw(r, t, 4);
    return gy_be32_get(t);
}

static uint64_t
r_be64(struct rcur *r)
{
    uint8_t t[8] = {0};

    r_raw(r, t, 8);
    return gy_be64_get(t);
}

/* ---- SessionID (D-SES-3) ----------------------------------------------- */

int
gy_session_id(struct gy_session *s, const struct gy_suite_desc *desc,
              const struct gy_public_key *ik_a,
              const struct gy_public_key *ek_a)
{
    uint8_t buf[1 + 2 * (1 + GY_CURVE_PK_MAX)];
    uint8_t hash[GY_HASH_MAX];
    size_t off = 0;
    int n, rc;

    if (s == NULL || desc == NULL || ik_a == NULL || ek_a == NULL)
        return GY_ERR_ARG;
    if (ik_a->curve_type != desc->curve_type ||
        ek_a->curve_type != desc->curve_type)
        return GY_ERR_STATE; /* cross-suite key (downgrade signal) */

    buf[off++] = desc->suite_id;
    n = gy_encode_ec(buf + off, sizeof(buf) - off, ik_a->curve_type, ik_a->pk);
    if (n < 0)
        return n;
    off += (size_t)n;
    n = gy_encode_ec(buf + off, sizeof(buf) - off, ek_a->curve_type, ek_a->pk);
    if (n < 0)
        return n;
    off += (size_t)n;

    rc = desc->hash(hash, buf, off);
    if (rc != GY_OK)
        return rc;

    s->base_len = (uint8_t)desc->hash_len;
    memcpy(s->base, hash, desc->hash_len);
    memcpy(s->id, hash, GY_SESSION_ID_LEN);
    gy_secure_zero(hash, sizeof(hash));
    return GY_OK;
}

/* ---- Double Ratchet state (de)serialization ---------------------------- */

static void
dr_encode(struct wcur *w, const struct gy_dr_state *dr)
{
    const struct gy_suite_desc *d = dr->desc;
    size_t pk = d->curve_pk_len, sk = d->curve_sk_len;
    size_t i, live = 0;

    w_u8(w, dr->aead_id);
    w_be32(w, dr->dhs.pub.pkid);
    w_u8(w, dr->dhs.pub.curve_type);
    w_raw(w, dr->dhs.pub.pk, pk);
    w_raw(w, dr->dhs.sk, sk);
    w_u8(w, dr->have_dhr);
    w_raw(w, dr->dhr, pk);

    w_raw(w, dr->rk, GY_DR_KEY_LEN);
    w_raw(w, dr->cks, GY_DR_KEY_LEN);
    w_raw(w, dr->ckr, GY_DR_KEY_LEN);
    w_raw(w, dr->hks, GY_DR_KEY_LEN);
    w_raw(w, dr->hkr, GY_DR_KEY_LEN);
    w_raw(w, dr->nhks, GY_DR_KEY_LEN);
    w_raw(w, dr->nhkr, GY_DR_KEY_LEN);

    w_be32(w, dr->ns);
    w_be32(w, dr->nr);
    w_be32(w, dr->pn);
    w_u8(w, dr->have_cks);
    w_u8(w, dr->have_ckr);
    w_u8(w, dr->have_hks);
    w_u8(w, dr->have_hkr);
    w_u8(w, dr->have_nhks);
    w_u8(w, dr->have_nhkr);

    /* Skip store: only the live entries and live epoch slots (D-SES-11). */
    w_be64(w, dr->skipped.recv_count);
    w_be32(w, (uint32_t)dr->skipped.count);
    for (i = 0; i < dr->skipped.count; i++) {
        const struct gy_skipped_key *e = &dr->skipped.ent[i];

        w_be32(w, e->epoch);
        w_be32(w, e->n);
        w_be64(w, e->age);
        w_raw(w, e->mk, GY_DR_KEY_LEN);
    }
    for (i = 0; i < GY_MAX_SKIP; i++)
        if (dr->skipped.epochs[i].refs > 0)
            live++;
    w_be32(w, (uint32_t)live);
    for (i = 0; i < GY_MAX_SKIP; i++) {
        const struct gy_skip_epoch *ep = &dr->skipped.epochs[i];

        if (ep->refs == 0)
            continue;
        w_be32(w, (uint32_t)i);
        w_be32(w, (uint32_t)ep->refs);
        w_raw(w, ep->hk, GY_DR_KEY_LEN);
    }
}

/* Decode into a caller-zeroized dr; validates every count/index in range. */
static void
dr_decode(struct rcur *r, struct gy_dr_state *dr, const struct gy_suite_desc *d)
{
    size_t pk = d->curve_pk_len, sk = d->curve_sk_len;
    uint32_t count, live, i;

    dr->desc = d;
    dr->aead_id = r_u8(r);
    dr->dhs.pub.pkid = r_be32(r);
    dr->dhs.pub.curve_type = r_u8(r);
    r_raw(r, dr->dhs.pub.pk, pk);
    r_raw(r, dr->dhs.sk, sk);
    dr->have_dhr = r_u8(r);
    r_raw(r, dr->dhr, pk);

    r_raw(r, dr->rk, GY_DR_KEY_LEN);
    r_raw(r, dr->cks, GY_DR_KEY_LEN);
    r_raw(r, dr->ckr, GY_DR_KEY_LEN);
    r_raw(r, dr->hks, GY_DR_KEY_LEN);
    r_raw(r, dr->hkr, GY_DR_KEY_LEN);
    r_raw(r, dr->nhks, GY_DR_KEY_LEN);
    r_raw(r, dr->nhkr, GY_DR_KEY_LEN);

    dr->ns = r_be32(r);
    dr->nr = r_be32(r);
    dr->pn = r_be32(r);
    dr->have_cks = r_u8(r);
    dr->have_ckr = r_u8(r);
    dr->have_hks = r_u8(r);
    dr->have_hkr = r_u8(r);
    dr->have_nhks = r_u8(r);
    dr->have_nhkr = r_u8(r);

    dr->skipped.recv_count = r_be64(r);
    count = r_be32(r);
    if (count > GY_MAX_SKIP) {
        r->ok = 0;
        return;
    }
    dr->skipped.count = count;
    for (i = 0; i < count; i++) {
        struct gy_skipped_key *e = &dr->skipped.ent[i];

        e->epoch = r_be32(r);
        e->n = r_be32(r);
        e->age = r_be64(r);
        r_raw(r, e->mk, GY_DR_KEY_LEN);
        if (e->epoch >= GY_MAX_SKIP) {
            r->ok = 0;
            return;
        }
    }

    live = r_be32(r);
    if (live > GY_MAX_SKIP) {
        r->ok = 0;
        return;
    }
    for (i = 0; i < live; i++) {
        uint32_t slot = r_be32(r);
        uint32_t refs = r_be32(r);

        if (slot >= GY_MAX_SKIP || refs == 0 || refs > GY_MAX_SKIP) {
            r->ok = 0;
            return;
        }
        dr->skipped.epochs[slot].refs = refs;
        r_raw(r, dr->skipped.epochs[slot].hk, GY_DR_KEY_LEN);
    }
}

/* ---- SessionRecord ----------------------------------------------------- */

int
gy_session_encode(uint8_t *out, size_t cap, size_t *outlen,
                  const struct gy_session *s)
{
    struct wcur w = {out, cap, 0, 1};
    const struct gy_suite_desc *d;

    if (out == NULL || outlen == NULL || s == NULL)
        return GY_ERR_ARG;
    d = s->dr.desc;
    if (d == NULL)
        return GY_ERR_STATE;

    w_u8(&w, GY_REC_FMT_V1);
    w_u8(&w, 0); /* reserved */
    w_u8(&w, d->suite_id);
    w_u8(&w, s->base_len);
    w_raw(&w, s->base, s->base_len);
    w_raw(&w, s->id, GY_SESSION_ID_LEN);
    w_be64(&w, s->created_at);
    w_be64(&w, s->activated_at);
    w_be64(&w, s->last_recv_at);
    w_be32(&w, s->nsend);
    w_be32(&w, s->nrecv);
    w_u8(&w, s->pq_pending);
    w_u8(&w, s->ad_len);
    w_raw(&w, s->ad, s->ad_len);
    dr_encode(&w, &s->dr);

    if (!w.ok)
        return GY_ERR_ARG;
    *outlen = w.off;
    return GY_OK;
}

int
gy_session_decode(struct gy_session *s, const uint8_t *in, size_t len)
{
    struct rcur r = {in, len, 0, 1};
    const struct gy_suite_desc *d;

    if (s == NULL || in == NULL)
        return GY_ERR_ARG;
    gy_secure_zero(s, sizeof(*s));

    if (r_u8(&r) != GY_REC_FMT_V1)
        return GY_ERR_ARG;
    if (r_u8(&r) != 0) /* reserved must be zero */
        return GY_ERR_ARG;
    d = gy_suite_desc(r_u8(&r));
    if (d == NULL)
        return GY_ERR_ARG;
    s->base_len = r_u8(&r);
    if (s->base_len > GY_HASH_MAX)
        return GY_ERR_ARG;
    r_raw(&r, s->base, s->base_len);
    r_raw(&r, s->id, GY_SESSION_ID_LEN);
    s->created_at = r_be64(&r);
    s->activated_at = r_be64(&r);
    s->last_recv_at = r_be64(&r);
    s->nsend = r_be32(&r);
    s->nrecv = r_be32(&r);
    s->pq_pending = r_u8(&r);
    s->ad_len = r_u8(&r);
    if (s->ad_len > GY_X3DH_AD_MAX) {
        gy_secure_zero(s, sizeof(*s));
        return GY_ERR_ARG;
    }
    r_raw(&r, s->ad, s->ad_len);
    dr_decode(&r, &s->dr, d);

    if (!r.ok || r.off != len) {
        gy_secure_zero(s, sizeof(*s));
        return GY_ERR_ARG;
    }
    return GY_OK;
}

void
gy_session_free(struct gy_session *s)
{
    if (s != NULL)
        gy_secure_zero(s, sizeof(*s));
}

/* ---- DeviceRecord SessionID list (D-SES-5) ----------------------------- */

static int
id_eq(const uint8_t a[GY_SESSION_ID_LEN], const uint8_t b[GY_SESSION_ID_LEN])
{
    return gy_const_memcmp(a, b, GY_SESSION_ID_LEN) == 0;
}

static int
device_has_id(const struct gy_device_record *d,
              const uint8_t id[GY_SESSION_ID_LEN])
{
    uint32_t i;

    if (d->has_active && id_eq(d->active, id))
        return 1;
    for (i = 0; i < d->n_inactive; i++)
        if (id_eq(d->inactive[i], id))
            return 1;
    return 0;
}

/* Push id at the inactive head, tail-evicting at capacity (D-SES-4/5). */
static void
inactive_push_head(struct gy_device_record *d,
                   const uint8_t id[GY_SESSION_ID_LEN],
                   uint8_t evicted[GY_SESSION_ID_LEN], int *did_evict)
{
    *did_evict = 0;
    if (d->n_inactive == GY_SESSION_INACTIVE_MAX) {
        memcpy(evicted, d->inactive[GY_SESSION_INACTIVE_MAX - 1],
               GY_SESSION_ID_LEN);
        *did_evict = 1;
        memmove(d->inactive[1], d->inactive[0],
                (size_t)(GY_SESSION_INACTIVE_MAX - 1) * GY_SESSION_ID_LEN);
    } else {
        if (d->n_inactive > 0)
            memmove(d->inactive[1], d->inactive[0],
                    (size_t)d->n_inactive * GY_SESSION_ID_LEN);
        d->n_inactive++;
    }
    memcpy(d->inactive[0], id, GY_SESSION_ID_LEN);
}

int
gy_device_session_insert(struct gy_device_record *d,
                         const uint8_t id[GY_SESSION_ID_LEN],
                         uint8_t evicted[GY_SESSION_ID_LEN], int *did_evict)
{
    int de = 0;

    if (d == NULL || id == NULL || evicted == NULL || did_evict == NULL)
        return GY_ERR_ARG;
    if (device_has_id(d, id))
        return GY_ERR_STATE; /* SessionID collision (D-SES-3) */

    if (d->has_active)
        inactive_push_head(d, d->active, evicted, &de);
    memcpy(d->active, id, GY_SESSION_ID_LEN);
    d->has_active = 1;
    *did_evict = de;
    return GY_OK;
}

int
gy_device_session_activate(struct gy_device_record *d,
                           const uint8_t id[GY_SESSION_ID_LEN])
{
    uint8_t tmp[GY_SESSION_ID_LEN], ev[GY_SESSION_ID_LEN];
    uint32_t i;
    int k = -1, de;

    if (d == NULL || id == NULL)
        return GY_ERR_ARG;
    for (i = 0; i < d->n_inactive; i++)
        if (id_eq(d->inactive[i], id)) {
            k = (int)i;
            break;
        }
    if (k < 0)
        return GY_ERR_STATE; /* not an inactive session of this record */

    memcpy(tmp, d->inactive[k], GY_SESSION_ID_LEN);
    memmove(d->inactive[k], d->inactive[k + 1],
            (size_t)(d->n_inactive - 1 - (uint32_t)k) * GY_SESSION_ID_LEN);
    d->n_inactive--;
    gy_secure_zero(d->inactive[d->n_inactive], GY_SESSION_ID_LEN);

    if (d->has_active)
        inactive_push_head(d, d->active, ev, &de); /* room freed: no evict */
    memcpy(d->active, tmp, GY_SESSION_ID_LEN);
    d->has_active = 1;
    return GY_OK;
}

int
gy_devrec_key(const uint8_t *user_id, size_t user_id_len,
              const uint8_t *device_id, size_t device_id_len,
              uint8_t out[GY_DEVKEY_LEN])
{
    static const char label[] = "geryon-devrec-key";
    uint8_t buf[sizeof(label) - 1 + 4 + GY_USER_ID_MAX + 4 + GY_DEVICE_ID_MAX];
    size_t off = 0;

    if (user_id == NULL || device_id == NULL || out == NULL)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX ||
        device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;

    memcpy(buf + off, label, sizeof(label) - 1);
    off += sizeof(label) - 1;
    gy_be32_put(buf + off, (uint32_t)user_id_len);
    off += 4;
    memcpy(buf + off, user_id, user_id_len);
    off += user_id_len;
    gy_be32_put(buf + off, (uint32_t)device_id_len);
    off += 4;
    memcpy(buf + off, device_id, device_id_len);
    off += device_id_len;

    return gy_sha512(out, buf, off);
}

int
gy_device_record_init(struct gy_device_record *d, uint8_t suite_id,
                      const uint8_t *device_id, size_t device_id_len,
                      const struct gy_public_key *ik,
                      const uint8_t *fingerprint, size_t fp_len)
{
    const struct gy_suite_desc *dd = gy_suite_desc(suite_id);

    if (d == NULL || device_id == NULL || ik == NULL || dd == NULL)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (fp_len > GY_HASH_MAX)
        return GY_ERR_ARG;

    gy_secure_zero(d, sizeof(*d));
    d->suite_id = suite_id;
    d->device_id_len = (uint8_t)device_id_len;
    memcpy(d->device_id, device_id, device_id_len);
    /* Copy only the meaningful fields (not the whole struct, and only
     * curve_pk_len key bytes): the caller's gy_public_key may carry stack
     * garbage in its tail padding and in pk[] beyond curve_pk_len, neither
     * of which is serialized, so the memset-zeroed tail stays canonical. */
    d->ik.pkid = ik->pkid;
    d->ik.curve_type = ik->curve_type;
    memcpy(d->ik.pk, ik->pk, dd->curve_pk_len);
    d->fp_len = (uint8_t)fp_len;
    if (fingerprint != NULL && fp_len > 0)
        memcpy(d->fingerprint, fingerprint, fp_len);
    return GY_OK;
}

int
gy_device_record_encode(uint8_t *out, size_t cap, size_t *outlen,
                        const struct gy_device_record *d)
{
    struct wcur w = {out, cap, 0, 1};
    const struct gy_suite_desc *dd;
    uint32_t i;

    if (out == NULL || outlen == NULL || d == NULL)
        return GY_ERR_ARG;
    dd = gy_suite_desc(d->suite_id);
    if (dd == NULL)
        return GY_ERR_STATE;

    w_u8(&w, GY_REC_FMT_V1);
    w_u8(&w, 0);
    w_u8(&w, d->suite_id);
    w_u8(&w, d->device_id_len);
    w_raw(&w, d->device_id, d->device_id_len);
    w_be32(&w, d->ik.pkid);
    w_u8(&w, d->ik.curve_type);
    w_raw(&w, d->ik.pk, dd->curve_pk_len);
    w_u8(&w, d->fp_len);
    w_raw(&w, d->fingerprint, d->fp_len);
    w_u8(&w, d->has_active);
    w_raw(&w, d->active, GY_SESSION_ID_LEN);
    w_u8(&w, d->stale);
    w_be64(&w, d->stale_at);
    w_be32(&w, d->n_inactive);
    for (i = 0; i < d->n_inactive; i++)
        w_raw(&w, d->inactive[i], GY_SESSION_ID_LEN);

    if (!w.ok)
        return GY_ERR_ARG;
    *outlen = w.off;
    return GY_OK;
}

int
gy_device_record_decode(struct gy_device_record *d, const uint8_t *in,
                        size_t len)
{
    struct rcur r = {in, len, 0, 1};
    const struct gy_suite_desc *dd;
    uint32_t i;

    if (d == NULL || in == NULL)
        return GY_ERR_ARG;
    gy_secure_zero(d, sizeof(*d));

    if (r_u8(&r) != GY_REC_FMT_V1)
        return GY_ERR_ARG;
    if (r_u8(&r) != 0)
        return GY_ERR_ARG;
    d->suite_id = r_u8(&r);
    dd = gy_suite_desc(d->suite_id);
    if (dd == NULL)
        return GY_ERR_ARG;
    d->device_id_len = r_u8(&r);
    if (d->device_id_len == 0 || d->device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    r_raw(&r, d->device_id, d->device_id_len);
    d->ik.pkid = r_be32(&r);
    d->ik.curve_type = r_u8(&r);
    r_raw(&r, d->ik.pk, dd->curve_pk_len);
    d->fp_len = r_u8(&r);
    if (d->fp_len > GY_HASH_MAX)
        return GY_ERR_ARG;
    r_raw(&r, d->fingerprint, d->fp_len);
    d->has_active = r_u8(&r);
    r_raw(&r, d->active, GY_SESSION_ID_LEN);
    d->stale = r_u8(&r);
    d->stale_at = r_be64(&r);
    d->n_inactive = r_be32(&r);
    if (d->n_inactive > GY_SESSION_INACTIVE_MAX) {
        gy_secure_zero(d, sizeof(*d));
        return GY_ERR_ARG;
    }
    for (i = 0; i < d->n_inactive; i++)
        r_raw(&r, d->inactive[i], GY_SESSION_ID_LEN);

    if (!r.ok || r.off != len) {
        gy_secure_zero(d, sizeof(*d));
        return GY_ERR_ARG;
    }
    return GY_OK;
}

void
gy_device_record_free(struct gy_device_record *d)
{
    if (d != NULL)
        gy_secure_zero(d, sizeof(*d));
}

/* ---- UserRecord device index (D-SES-4) --------------------------------- */

static int
user_find(const struct gy_user_record *u, const uint8_t *device_id,
          size_t device_id_len)
{
    uint32_t i;

    for (i = 0; i < u->n_devices; i++)
        if (u->device_id_len[i] == device_id_len &&
            gy_const_memcmp(u->device_id[i], device_id, device_id_len) == 0)
            return (int)i;
    return -1;
}

static void
user_remove(struct gy_user_record *u, uint32_t k)
{
    uint32_t tail = u->n_devices - 1 - k;

    memmove(u->device_id[k], u->device_id[k + 1],
            (size_t)tail * GY_DEVICE_ID_MAX);
    memmove(&u->device_id_len[k], &u->device_id_len[k + 1], tail);
    memmove(&u->device_stale[k], &u->device_stale[k + 1], tail);
    u->n_devices--;
    gy_secure_zero(u->device_id[u->n_devices], GY_DEVICE_ID_MAX);
    u->device_id_len[u->n_devices] = 0;
    u->device_stale[u->n_devices] = 0;
}

int
gy_user_record_init(struct gy_user_record *u, uint8_t suite_id,
                    const uint8_t *user_id, size_t user_id_len)
{
    if (u == NULL || user_id == NULL)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;

    gy_secure_zero(u, sizeof(*u));
    u->suite_id = suite_id;
    u->user_id_len = (uint8_t)user_id_len;
    memcpy(u->user_id, user_id, user_id_len);
    return GY_OK;
}

int
gy_user_device_insert(struct gy_user_record *u, const uint8_t *device_id,
                      size_t device_id_len,
                      uint8_t out_evicted[GY_DEVICE_ID_MAX],
                      size_t *out_evicted_len, int *did_evict)
{
    uint32_t idx;

    if (u == NULL || device_id == NULL || did_evict == NULL)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    *did_evict = 0;

    if (user_find(u, device_id, device_id_len) >= 0)
        return GY_ERR_STATE; /* duplicate DeviceID */

    if (u->n_devices == GY_DEVICE_MAX) {
        int k = -1;
        uint32_t i;

        for (i = 0; i < u->n_devices; i++)
            if (u->device_stale[i]) {
                k = (int)i;
                break;
            }
        if (k < 0)
            return GY_ERR_STATE; /* full and no stale device to evict */
        if (out_evicted != NULL)
            memcpy(out_evicted, u->device_id[k], u->device_id_len[k]);
        if (out_evicted_len != NULL)
            *out_evicted_len = u->device_id_len[k];
        *did_evict = 1;
        user_remove(u, (uint32_t)k);
    }

    idx = u->n_devices;
    memcpy(u->device_id[idx], device_id, device_id_len);
    u->device_id_len[idx] = (uint8_t)device_id_len;
    u->device_stale[idx] = 0;
    u->n_devices++;
    return GY_OK;
}

int
gy_user_device_mark_stale(struct gy_user_record *u, const uint8_t *device_id,
                          size_t device_id_len)
{
    int k;

    if (u == NULL || device_id == NULL)
        return GY_ERR_ARG;
    k = user_find(u, device_id, device_id_len);
    if (k < 0)
        return GY_ERR_STATE;
    u->device_stale[k] = 1;
    return GY_OK;
}

int
gy_user_device_index(const struct gy_user_record *u, const uint8_t *device_id,
                     size_t device_id_len)
{
    if (u == NULL || device_id == NULL)
        return -1;
    return user_find(u, device_id, device_id_len);
}

int
gy_user_device_remove(struct gy_user_record *u, const uint8_t *device_id,
                      size_t device_id_len)
{
    int k;

    if (u == NULL || device_id == NULL)
        return GY_ERR_ARG;
    k = user_find(u, device_id, device_id_len);
    if (k < 0)
        return GY_ERR_STATE;
    user_remove(u, (uint32_t)k);
    return GY_OK;
}

int
gy_user_record_encode(uint8_t *out, size_t cap, size_t *outlen,
                      const struct gy_user_record *u)
{
    struct wcur w = {out, cap, 0, 1};
    uint32_t i;

    if (out == NULL || outlen == NULL || u == NULL)
        return GY_ERR_ARG;

    w_u8(&w, GY_REC_FMT_V1);
    w_u8(&w, 0);
    w_u8(&w, u->suite_id);
    w_u8(&w, u->user_id_len);
    w_raw(&w, u->user_id, u->user_id_len);
    w_u8(&w, u->stale);
    w_be32(&w, u->n_devices);
    for (i = 0; i < u->n_devices; i++) {
        w_u8(&w, u->device_id_len[i]);
        w_raw(&w, u->device_id[i], u->device_id_len[i]);
        w_u8(&w, u->device_stale[i]);
    }

    if (!w.ok)
        return GY_ERR_ARG;
    *outlen = w.off;
    return GY_OK;
}

int
gy_user_record_decode(struct gy_user_record *u, const uint8_t *in, size_t len)
{
    struct rcur r = {in, len, 0, 1};
    uint32_t i;

    if (u == NULL || in == NULL)
        return GY_ERR_ARG;
    gy_secure_zero(u, sizeof(*u));

    if (r_u8(&r) != GY_REC_FMT_V1)
        return GY_ERR_ARG;
    if (r_u8(&r) != 0)
        return GY_ERR_ARG;
    u->suite_id = r_u8(&r);
    u->user_id_len = r_u8(&r);
    if (u->user_id_len == 0 || u->user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;
    r_raw(&r, u->user_id, u->user_id_len);
    u->stale = r_u8(&r);
    u->n_devices = r_be32(&r);
    if (u->n_devices > GY_DEVICE_MAX) {
        gy_secure_zero(u, sizeof(*u));
        return GY_ERR_ARG;
    }
    for (i = 0; i < u->n_devices; i++) {
        u->device_id_len[i] = r_u8(&r);
        if (u->device_id_len[i] == 0 ||
            u->device_id_len[i] > GY_DEVICE_ID_MAX) {
            gy_secure_zero(u, sizeof(*u));
            return GY_ERR_ARG;
        }
        r_raw(&r, u->device_id[i], u->device_id_len[i]);
        u->device_stale[i] = r_u8(&r);
    }

    if (!r.ok || r.off != len) {
        gy_secure_zero(u, sizeof(*u));
        return GY_ERR_ARG;
    }
    return GY_OK;
}

void
gy_user_record_free(struct gy_user_record *u)
{
    if (u != NULL)
        gy_secure_zero(u, sizeof(*u));
}
