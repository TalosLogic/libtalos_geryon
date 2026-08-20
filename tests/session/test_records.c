/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * record model: SessionID determinism/collision (D-SES-3), the
 * D-SES-5 active/inactive list operations with D-SES-4 eviction, and exact
 * versioned blob round-trips for the three D-SES-11 record types plus their
 * decode negatives.
 */

#include <string.h>

#include "session.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
static const struct gy_suite_desc *DH; /* hybrid suite (h25519_512) */
#define AEAD GY_AEAD_CHACHA20POLY1305

static void
mkid(uint8_t out[GY_SESSION_ID_LEN], uint32_t v)
{
    gy_be32_put(out, v);
}

/* ---- SessionID (D-SES-3) ----------------------------------------------- */

TEST(sessionid_determinism)
{
    struct gy_keypair ik, ek, ek2;
    struct gy_session a, b, c;

    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek2), GY_OK);

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));

    ASSERT_EQ(gy_session_id(&a, D, &ik.pub, &ek.pub), GY_OK);
    ASSERT_EQ(gy_session_id(&b, D, &ik.pub, &ek.pub), GY_OK);
    /* Same inputs -> identical base and SessionID. */
    ASSERT_EQ(a.base_len, (uint8_t)D->hash_len);
    ASSERT_TRUE(memcmp(a.base, b.base, a.base_len) == 0, "base deterministic");
    ASSERT_TRUE(memcmp(a.id, b.id, GY_SESSION_ID_LEN) == 0, "id deterministic");
    ASSERT_TRUE(memcmp(a.id, a.base, GY_SESSION_ID_LEN) == 0,
                "id is base prefix");

    /* A different ephemeral key yields a different session. */
    ASSERT_EQ(gy_session_id(&c, D, &ik.pub, &ek2.pub), GY_OK);
    ASSERT_TRUE(memcmp(a.base, c.base, a.base_len) != 0, "distinct base keys");
}

TEST(sessionid_cross_suite_rejected)
{
    struct gy_keypair ik, ek;
    struct gy_session s;

    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    memset(&s, 0, sizeof(s));

    ik.pub.curve_type = GY_CURVE_TYPE_448; /* not the pinned suite */
    ASSERT_EQ(gy_session_id(&s, D, &ik.pub, &ek.pub), GY_ERR_STATE);
}

/* ---- SessionRecord blob round-trip ------------------------------------- */

/* Hand-build a fully-populated session (a realistic DR state with a live skip
 * store spanning two non-contiguous epoch slots) so the round-trip exercises
 * stable-index epoch reconstruction (D-SES-11). */
static void
build_session(struct gy_session *s)
{
    struct gy_keypair ik, ek;

    memset(s, 0, sizeof(*s));
    s->ratchet.base.desc = D;
    s->ratchet.base.aead_id = AEAD;
    ASSERT_EQ(gy_keypair_generate(D, &s->ratchet.base.dhs), GY_OK);

    memset(s->ratchet.base.dhr, 0x88, D->curve_pk_len);
    memset(s->ratchet.base.rk, 0x11, GY_DR_KEY_LEN);
    memset(s->ratchet.base.cks, 0x22, GY_DR_KEY_LEN);
    memset(s->ratchet.base.ckr, 0x33, GY_DR_KEY_LEN);
    memset(s->ratchet.base.hks, 0x44, GY_DR_KEY_LEN);
    memset(s->ratchet.base.hkr, 0x55, GY_DR_KEY_LEN);
    memset(s->ratchet.base.nhks, 0x66, GY_DR_KEY_LEN);
    memset(s->ratchet.base.nhkr, 0x77, GY_DR_KEY_LEN);
    s->ratchet.base.ns = 5;
    s->ratchet.base.nr = 3;
    s->ratchet.base.pn = 2;
    s->ratchet.base.have_dhr = 1;
    s->ratchet.base.have_cks = 1;
    s->ratchet.base.have_ckr = 1;
    s->ratchet.base.have_hks = 1;
    s->ratchet.base.have_hkr = 1;
    s->ratchet.base.have_nhks = 1;
    s->ratchet.base.have_nhkr = 1;

    /* Two entries at epoch slot 3, one at slot 7 (refs match). */
    s->ratchet.base.skipped.recv_count = 42;
    s->ratchet.base.skipped.count = 3;
    s->ratchet.base.skipped.ent[0].epoch = 3;
    s->ratchet.base.skipped.ent[0].n = 1;
    s->ratchet.base.skipped.ent[0].age = 10;
    memset(s->ratchet.base.skipped.ent[0].mk, 0xA0, GY_DR_KEY_LEN);
    s->ratchet.base.skipped.ent[1].epoch = 3;
    s->ratchet.base.skipped.ent[1].n = 2;
    s->ratchet.base.skipped.ent[1].age = 11;
    memset(s->ratchet.base.skipped.ent[1].mk, 0xA1, GY_DR_KEY_LEN);
    s->ratchet.base.skipped.ent[2].epoch = 7;
    s->ratchet.base.skipped.ent[2].n = 1;
    s->ratchet.base.skipped.ent[2].age = 12;
    memset(s->ratchet.base.skipped.ent[2].mk, 0xA2, GY_DR_KEY_LEN);
    s->ratchet.base.skipped.epochs[3].refs = 2;
    memset(s->ratchet.base.skipped.epochs[3].hk, 0xE3, GY_DR_KEY_LEN);
    s->ratchet.base.skipped.epochs[7].refs = 1;
    memset(s->ratchet.base.skipped.epochs[7].hk, 0xE7, GY_DR_KEY_LEN);

    s->created_at = 0x0102030405060708ull;
    s->activated_at = 0x1122334455667788ull;
    s->last_recv_at = 0;
    s->nsend = 9;
    s->nrecv = 4;
    s->pq_pending = 0;

    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_session_id(s, D, &ik.pub, &ek.pub), GY_OK);
}

TEST(session_blob_roundtrip)
{
    static struct gy_session s, s2; /* large; keep off the stack */
    static uint8_t buf[GY_SESSION_BLOB_MAX];
    size_t n;

    build_session(&s);
    ASSERT_EQ(gy_session_encode(buf, sizeof(buf), &n, &s), GY_OK);
    ASSERT_TRUE(n < sizeof(buf), "blob within bound");

    ASSERT_EQ(gy_session_decode(&s2, buf, n), GY_OK);
    ASSERT_TRUE(s2.ratchet.base.desc == D, "desc re-bound from suite_id");
    ASSERT_TRUE(memcmp(&s, &s2, sizeof(s)) == 0, "session round-trip exact");
}

TEST(session_blob_negatives)
{
    static struct gy_session s, s2;
    static uint8_t buf[GY_SESSION_BLOB_MAX];
    size_t n;

    build_session(&s);
    ASSERT_EQ(gy_session_encode(buf, sizeof(buf), &n, &s), GY_OK);

    /* Truncation. */
    ASSERT_EQ(gy_session_decode(&s2, buf, n - 1), GY_ERR_ARG);
    /* Reserved byte must be zero. */
    buf[1] = 0x01;
    ASSERT_EQ(gy_session_decode(&s2, buf, n), GY_ERR_ARG);
    buf[1] = 0x00;
    /* Unknown/future format byte. */
    buf[0] = 0x02;
    ASSERT_EQ(gy_session_decode(&s2, buf, n), GY_ERR_ARG);
}

TEST(session_free_zeroizes)
{
    static struct gy_session s;

    build_session(&s);
    /* Live key material present before teardown (so the check below proves
     * erasure, not absence). */
    ASSERT_TRUE(gy_is_zero(s.ratchet.base.rk, GY_DR_KEY_LEN) == 0, "rk live");
    ASSERT_TRUE(gy_is_zero(s.ratchet.base.skipped.ent[0].mk, GY_DR_KEY_LEN) ==
                    0,
                "skipped mk live");
    ASSERT_TRUE(
        gy_is_zero(s.ratchet.base.skipped.epochs[3].hk, GY_DR_KEY_LEN) == 0,
        "epoch hk live");

    gy_session_free(&s);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&s, sizeof(s)), 1);
}

/* ---- DeviceRecord SessionID list --------------------------------------- */

static void
device_init(struct gy_device_record *d)
{
    struct gy_keypair ik;
    uint8_t fp[GY_HASH_MAX];
    uint8_t did[3] = {0xDE, 0x71, 0xCE};

    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_fingerprint(D, fp, &ik.pub), GY_OK);
    ASSERT_EQ(gy_device_record_init(d, D->suite_id, did, sizeof(did), &ik.pub,
                                    fp, D->hash_len),
              GY_OK);
}

TEST(session_insert_collision)
{
    struct gy_device_record d;
    uint8_t a[GY_SESSION_ID_LEN], b[GY_SESSION_ID_LEN];
    uint8_t ev[GY_SESSION_ID_LEN];
    int de;

    device_init(&d);
    mkid(a, 1);
    mkid(b, 2);

    ASSERT_EQ(gy_device_session_insert(&d, a, ev, &de), GY_OK);
    ASSERT_EQ(de, 0);
    /* a is active: re-insert rejected. */
    ASSERT_EQ(gy_device_session_insert(&d, a, ev, &de), GY_ERR_STATE);
    /* b active, a pushed to inactive head. */
    ASSERT_EQ(gy_device_session_insert(&d, b, ev, &de), GY_OK);
    ASSERT_EQ(de, 0);
    ASSERT_EQ(d.n_inactive, 1u);
    ASSERT_TRUE(memcmp(d.inactive[0], a, GY_SESSION_ID_LEN) == 0, "a inactive");
    /* both an inactive and the active id collide. */
    ASSERT_EQ(gy_device_session_insert(&d, a, ev, &de), GY_ERR_STATE);
    ASSERT_EQ(gy_device_session_insert(&d, b, ev, &de), GY_ERR_STATE);
}

TEST(inactive_eviction_order)
{
    struct gy_device_record d;
    uint8_t id[GY_SESSION_ID_LEN], ev[GY_SESSION_ID_LEN],
        want[GY_SESSION_ID_LEN];
    int de, i;

    device_init(&d);
    /* Fill active + all 40 inactive slots (ids 0..40). */
    for (i = 0; i <= GY_SESSION_INACTIVE_MAX; i++) {
        mkid(id, (uint32_t)i);
        ASSERT_EQ(gy_device_session_insert(&d, id, ev, &de), GY_OK);
        ASSERT_EQ(de, 0);
    }
    ASSERT_EQ(d.n_inactive, (uint32_t)GY_SESSION_INACTIVE_MAX);

    /* One more insert evicts the tail, which is the oldest inactive (id 0). */
    mkid(id, (uint32_t)(GY_SESSION_INACTIVE_MAX + 1));
    ASSERT_EQ(gy_device_session_insert(&d, id, ev, &de), GY_OK);
    ASSERT_EQ(de, 1);
    mkid(want, 0);
    ASSERT_TRUE(memcmp(ev, want, GY_SESSION_ID_LEN) == 0,
                "oldest tail evicted");
    /* Newest active pushed id 40 to the inactive head. */
    mkid(want, (uint32_t)GY_SESSION_INACTIVE_MAX);
    ASSERT_TRUE(memcmp(d.inactive[0], want, GY_SESSION_ID_LEN) == 0,
                "prev active at head");
}

TEST(activate_moves_to_active)
{
    struct gy_device_record d;
    uint8_t a[GY_SESSION_ID_LEN], b[GY_SESSION_ID_LEN], c[GY_SESSION_ID_LEN];
    uint8_t ev[GY_SESSION_ID_LEN];
    int de;

    device_init(&d);
    mkid(a, 10);
    mkid(b, 20);
    mkid(c, 30);
    ASSERT_EQ(gy_device_session_insert(&d, a, ev, &de), GY_OK);
    ASSERT_EQ(gy_device_session_insert(&d, b, ev, &de), GY_OK);
    ASSERT_EQ(gy_device_session_insert(&d, c, ev, &de), GY_OK);
    /* active c; inactive [b, a]. Activate a. */
    ASSERT_EQ(gy_device_session_activate(&d, a), GY_OK);
    ASSERT_EQ(d.has_active, 1);
    ASSERT_TRUE(memcmp(d.active, a, GY_SESSION_ID_LEN) == 0, "a active");
    /* c pushed to inactive head; a removed; b follows. */
    ASSERT_EQ(d.n_inactive, 2u);
    ASSERT_TRUE(memcmp(d.inactive[0], c, GY_SESSION_ID_LEN) == 0, "c at head");
    ASSERT_TRUE(memcmp(d.inactive[1], b, GY_SESSION_ID_LEN) == 0, "b next");
    /* Activating an unknown id fails. */
    ASSERT_EQ(gy_device_session_activate(&d, a), GY_ERR_STATE);
}

TEST(device_blob_roundtrip)
{
    struct gy_device_record d, d2;
    uint8_t id[GY_SESSION_ID_LEN], ev[GY_SESSION_ID_LEN];
    uint8_t buf[GY_DEVICE_BLOB_MAX];
    size_t n;
    int de, i;

    device_init(&d);
    /* Full-capacity record: 1 active + 40 inactive SessionIDs. */
    for (i = 0; i <= GY_SESSION_INACTIVE_MAX; i++) {
        mkid(id, (uint32_t)(100 + i));
        ASSERT_EQ(gy_device_session_insert(&d, id, ev, &de), GY_OK);
    }
    ASSERT_EQ(d.n_inactive, (uint32_t)GY_SESSION_INACTIVE_MAX);
    d.stale = 1;
    d.stale_at = 0x00000000DEADBEEFull;

    ASSERT_EQ(gy_device_record_encode(buf, sizeof(buf), &n, &d), GY_OK);
    ASSERT_EQ(gy_device_record_decode(&d2, buf, n), GY_OK);
    ASSERT_TRUE(memcmp(&d, &d2, sizeof(d)) == 0, "device round-trip exact");

    ASSERT_EQ(gy_device_record_decode(&d2, buf, n - 1), GY_ERR_ARG);
    buf[1] = 0x01;
    ASSERT_EQ(gy_device_record_decode(&d2, buf, n), GY_ERR_ARG);
}

/* ---- UserRecord device index ------------------------------------------- */

TEST(user_device_eviction)
{
    struct gy_user_record u;
    uint8_t uid[4] = {0x55, 0x53, 0x52, 0x31};
    uint8_t did[GY_DEVICE_ID_MAX], ev[GY_DEVICE_ID_MAX];
    size_t evl;
    int de, i;

    ASSERT_EQ(gy_user_record_init(&u, D->suite_id, uid, sizeof(uid)), GY_OK);
    for (i = 0; i < GY_DEVICE_MAX; i++) {
        gy_be32_put(did, (uint32_t)i);
        ASSERT_EQ(gy_user_device_insert(&u, did, 4, ev, &evl, &de), GY_OK);
        ASSERT_EQ(de, 0);
    }
    ASSERT_EQ(u.n_devices, (uint32_t)GY_DEVICE_MAX);

    /* Full and all fresh: insert refused. */
    gy_be32_put(did, 999);
    ASSERT_EQ(gy_user_device_insert(&u, did, 4, ev, &evl, &de), GY_ERR_STATE);

    /* Duplicate DeviceID refused. */
    gy_be32_put(did, 3);
    ASSERT_EQ(gy_user_device_insert(&u, did, 4, ev, &evl, &de), GY_ERR_STATE);

    /* Mark two stale; eviction takes the oldest (lowest index). */
    gy_be32_put(did, 10);
    ASSERT_EQ(gy_user_device_mark_stale(&u, did, 4), GY_OK);
    gy_be32_put(did, 5);
    ASSERT_EQ(gy_user_device_mark_stale(&u, did, 4), GY_OK);

    gy_be32_put(did, 999);
    ASSERT_EQ(gy_user_device_insert(&u, did, 4, ev, &evl, &de), GY_OK);
    ASSERT_EQ(de, 1);
    ASSERT_EQ(evl, 4u);
    {
        uint8_t want[4];
        gy_be32_put(want, 5);
        ASSERT_TRUE(memcmp(ev, want, 4) == 0, "oldest stale evicted");
    }
    ASSERT_EQ(u.n_devices, (uint32_t)GY_DEVICE_MAX);
}

TEST(user_blob_roundtrip)
{
    struct gy_user_record u, u2;
    uint8_t uid[4] = {0x55, 0x53, 0x52, 0x31};
    uint8_t did[GY_DEVICE_ID_MAX], ev[GY_DEVICE_ID_MAX];
    uint8_t buf[GY_USER_BLOB_MAX];
    size_t n, evl;
    int de, i;

    ASSERT_EQ(gy_user_record_init(&u, D->suite_id, uid, sizeof(uid)), GY_OK);
    for (i = 0; i < GY_DEVICE_MAX; i++) {
        gy_be32_put(did, (uint32_t)i);
        ASSERT_EQ(gy_user_device_insert(&u, did, 4, ev, &evl, &de), GY_OK);
    }
    gy_be32_put(did, 7);
    ASSERT_EQ(gy_user_device_mark_stale(&u, did, 4), GY_OK);
    u.stale = 1;

    ASSERT_EQ(gy_user_record_encode(buf, sizeof(buf), &n, &u), GY_OK);
    ASSERT_TRUE(n < sizeof(buf), "blob within bound");
    ASSERT_EQ(gy_user_record_decode(&u2, buf, n), GY_OK);
    ASSERT_TRUE(memcmp(&u, &u2, sizeof(u)) == 0, "user round-trip exact");

    ASSERT_EQ(gy_user_record_decode(&u2, buf, n - 1), GY_ERR_ARG);
    buf[0] = 0x02;
    ASSERT_EQ(gy_user_record_decode(&u2, buf, n), GY_ERR_ARG);
}

/*
 * Hand-build a hybrid session (base DR state + all PQ fields, section 7.2/8)
 * and round-trip it through the blob: the added PQ serialization and the
 * pq_pending byte must survive exactly (GER-M5-08b task 4).
 */
static void
build_hybrid_session(struct gy_session *s)
{
    size_t ek = DH->kem_pk_len, dk = DH->kem_sk_len, ct = DH->kem_ct_len;
    size_t i;

    memset(s, 0, sizeof(*s));
    s->ratchet.base.desc = DH;
    s->ratchet.base.aead_id = AEAD;
    ASSERT_EQ(gy_keypair_generate(DH, &s->ratchet.base.dhs), GY_OK);
    memset(s->ratchet.base.dhr, 0x88, DH->curve_pk_len);
    memset(s->ratchet.base.rk, 0x11, GY_DR_KEY_LEN);
    memset(s->ratchet.base.cks, 0x22, GY_DR_KEY_LEN);
    memset(s->ratchet.base.ckr, 0x33, GY_DR_KEY_LEN);
    memset(s->ratchet.base.hks, 0x44, GY_DR_KEY_LEN);
    memset(s->ratchet.base.hkr, 0x55, GY_DR_KEY_LEN);
    memset(s->ratchet.base.nhks, 0x66, GY_DR_KEY_LEN);
    memset(s->ratchet.base.nhkr, 0x77, GY_DR_KEY_LEN);
    s->ratchet.base.ns = 4;
    s->ratchet.base.nr = 2;
    s->ratchet.base.pn = 1;
    s->ratchet.base.have_dhr = 1;
    s->ratchet.base.have_cks = 1;
    s->ratchet.base.have_ckr = 1;
    s->ratchet.base.have_hks = 1;
    s->ratchet.base.have_hkr = 1;
    s->ratchet.base.have_nhks = 1;
    s->ratchet.base.have_nhkr = 1;
    s->ratchet.base.skipped.recv_count = 9;
    s->ratchet.base.skipped.count = 1;
    s->ratchet.base.skipped.ent[0].epoch = 2;
    s->ratchet.base.skipped.ent[0].n = 1;
    s->ratchet.base.skipped.ent[0].age = 3;
    memset(s->ratchet.base.skipped.ent[0].mk, 0xA0, GY_DR_KEY_LEN);
    s->ratchet.base.skipped.epochs[2].refs = 1;
    memset(s->ratchet.base.skipped.epochs[2].hk, 0xE2, GY_DR_KEY_LEN);

    /* PQ ratchet + confirmation fields. */
    memset(s->ratchet.mlkem_ek, 0xB0, ek);
    memset(s->ratchet.mlkem_dk, 0xB1, dk);
    memset(s->ratchet.remote_ek, 0xB2, ek);
    memset(s->ratchet.kem_ct, 0xB3, ct);
    memset(s->ratchet.confirm_ct, 0xB4, ct);
    memset(s->ratchet.id_mlkem_ek, 0xB5, ek);
    memset(s->ratchet.id_mlkem_dk, 0xB6, dk);
    s->ratchet.mlkem_counter = 7;
    s->ratchet.mlkem_interval = 20;
    s->ratchet.have_remote_ek = 1;
    s->ratchet.have_kem_ct = 1;
    s->ratchet.send_ek_pending = 1;
    s->ratchet.role = GY_HYBRID_ROLE_RESPONDER;
    s->ratchet.pq_state = GY_HYBRID_PQ_CONFIRM_SENT;
    s->ratchet.confirm_pending = 0;
    s->ratchet.send_confirm_pending = 1;
    s->ratchet.have_confirm_ct = 1;
    s->ratchet.have_id_dk = 0;

    /* Session metadata: hybrid base hash + AD_session (2 * hash_len). */
    s->base_len = (uint8_t)DH->hash_len;
    for (i = 0; i < DH->hash_len; i++)
        s->base[i] = (uint8_t)(0xC0 + i);
    memcpy(s->id, s->base, GY_SESSION_ID_LEN);
    s->pq_pending = s->ratchet.pq_state;
    s->ad_len = (uint8_t)(2 * DH->hash_len);
    for (i = 0; i < s->ad_len; i++)
        s->ad[i] = (uint8_t)(0xD0 + i);
    s->created_at = 100;
    s->activated_at = 200;
    s->last_recv_at = 300;
    s->nsend = 4;
    s->nrecv = 2;
}

TEST(hybrid_session_blob_roundtrip)
{
    struct gy_session s, s2;
    static uint8_t buf[GY_SESSION_BLOB_MAX];
    size_t n;

    build_hybrid_session(&s);
    ASSERT_EQ(gy_session_encode(buf, sizeof(buf), &n, &s), GY_OK);
    ASSERT_EQ(gy_session_decode(&s2, buf, n), GY_OK);
    ASSERT_TRUE(s2.ratchet.base.desc == DH, "hybrid desc re-bound");
    ASSERT_EQ(s2.pq_pending, GY_HYBRID_PQ_CONFIRM_SENT);
    ASSERT_EQ(s2.ratchet.pq_state, GY_HYBRID_PQ_CONFIRM_SENT);
    ASSERT_EQ(s2.ratchet.mlkem_interval, 20);
    ASSERT_TRUE(memcmp(&s, &s2, sizeof(s)) == 0, "hybrid session round-trip");
}

/*
 * As session_free_zeroizes, but for a HYBRID session so the PQ secrets in the
 * embedded ratchet (mlkem_dk, id_mlkem_dk, confirm_ct) are live before free.
 * gy_session_free is a whole-struct gy_secure_zero today, so the classical scan
 * already covers the PQ region structurally; this asserts erasure of the PQ
 * secrets non-vacuously (they are nonzero going in), guarding against a future
 * field-by-field free that forgets them (GER-M5-10 task 2).
 */
TEST(hybrid_session_free_zeroizes)
{
    static struct gy_session s;
    size_t dk = DH->kem_sk_len, ct = DH->kem_ct_len;

    build_hybrid_session(&s);
    /* The three PQ secret fields are live before teardown (so the whole-struct
     * scan below proves erasure, not absence). */
    ASSERT_TRUE(gy_is_zero(s.ratchet.mlkem_dk, dk) == 0, "mlkem_dk live");
    ASSERT_TRUE(gy_is_zero(s.ratchet.id_mlkem_dk, dk) == 0, "id_mlkem_dk live");
    ASSERT_TRUE(gy_is_zero(s.ratchet.confirm_ct, ct) == 0, "confirm_ct live");

    gy_session_free(&s);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&s, sizeof(s)), 1);
}

/*
 * Hybrid DeviceRecord round-trip: init from a hybrid identity, add a session,
 * encode/decode exactly (base + PQ identity), and confirm the classical decoder
 * rejects the wider blob (format separation).  GER-M5-08b (b-ii-1).
 */
TEST(hybrid_device_record_roundtrip)
{
    struct gy_hybrid_identity_keypair ik;
    struct gy_hybrid_device_record d, d2;
    struct gy_device_record classical;
    static uint8_t buf[GY_HYBRID_DEVICE_BLOB_MAX];
    uint8_t fp[GY_HASH_MAX];
    uint8_t did[3] = {0xDE, 0x71, 0xCE};
    uint8_t sid[GY_SESSION_ID_LEN], ev[GY_SESSION_ID_LEN];
    size_t n;
    int de;

    ASSERT_EQ(gy_hybrid_identity_keypair_generate(DH, &ik), GY_OK);
    ASSERT_EQ(gy_hybrid_ikhash(DH, &ik.pub, fp), GY_OK);
    ASSERT_EQ(gy_hybrid_device_record_init(&d, DH->suite_id, did, sizeof(did),
                                           &ik.pub, fp, DH->hash_len),
              GY_OK);
    mkid(sid, 5);
    ASSERT_EQ(gy_device_session_insert(&d.base, sid, ev, &de), GY_OK);

    ASSERT_EQ(gy_hybrid_device_record_encode(buf, sizeof(buf), &n, &d), GY_OK);
    ASSERT_TRUE(n < sizeof(buf), "hybrid device blob within bound");
    ASSERT_EQ(gy_hybrid_device_record_decode(&d2, buf, n), GY_OK);
    ASSERT_TRUE(memcmp(&d, &d2, sizeof(d)) == 0, "hybrid device round-trip");

    /* The classical decoder must reject the wider blob (trailing PQ bytes). */
    ASSERT_EQ(gy_device_record_decode(&classical, buf, n), GY_ERR_ARG);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_C25519);
    DH = gy_suite_desc(GY_SUITE_H25519_512);
    if (D == NULL || DH == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(sessionid_determinism),
            GY_TEST(sessionid_cross_suite_rejected),
            GY_TEST(session_blob_roundtrip),
            GY_TEST(hybrid_session_blob_roundtrip),
            GY_TEST(hybrid_device_record_roundtrip),
            GY_TEST(session_blob_negatives),
            GY_TEST(session_free_zeroizes),
            GY_TEST(hybrid_session_free_zeroizes),
            GY_TEST(session_insert_collision),
            GY_TEST(inactive_eviction_order),
            GY_TEST(activate_moves_to_active),
            GY_TEST(device_blob_roundtrip),
            GY_TEST(user_device_eviction),
            GY_TEST(user_blob_roundtrip),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
