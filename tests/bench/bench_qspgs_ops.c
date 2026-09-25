/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS [CFG+] section 7 operation-cost benchmark (QSPGS_SPEC.md section 12,
 * D-QGS-10).  Measures the two operations whose cost the
 * design model turns on, at representative group sizes, and is cross-checked
 * against the design cost model:
 *
 *   AddMember    : build one new member entry (member_build) and re-sign the
 *                  whole core under the admin's skpsdn (core_sign).  Dominated
 *                  by ONE pseudonym signature; roughly constant in n (the [CFG+]
 *                  "about 2 ms / 7.5 KB at any n").
 *   RemoveMember : rotate gk (group_key_gen -> derive_sub_key), re-open the
 *                  admin context under the new key, re-encrypt EVERY surviving
 *                  member under (ek', rrs') (n * member_build), bump vMaj, and
 *                  re-sign.  O(n): the [CFG+] 19 KB at n = 50, 179 KB at
 *                  n = 1,000 scaling.
 *
 * Not a CTest case: a standalone, manually-run advisory report (the
 * bench_krmldsa / libtalos_voleith examples model, same bench_util.h
 * methodology).  It links the CLIENT facade geryon_qspgs to reach the section-5
 * composition primitives.  Record the min/median per size against the design
 * cost model and confirm the scaling matches it.
 *
 * Usage: bench_qspgs_ops [iters]   (default 30, plus a fixed warmup; heavy at
 * n = 1000 because RemoveMember does n member builds per iteration).
 */

#define _POSIX_C_SOURCE 199309L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#include "encode.h" /* GY_SUITE_*, gy_be32_put */
#include "aead.h"   /* GY_AEAD_CHACHA20POLY1305 (group field AEAD, INFO-6) */
#include "error.h"
#include "qspgs_field.h" /* GY_QSPGS_MEMBER_PT_MAX */
#include "qspgs_keys.h"
#include "qspgs_ops.h"
#include "qspgs_wire.h"
#include "suite.h"
#include "util.h"

#define BENCH_WARMUP 4
#define BENCH_MAX_ITERS 2000

/* Representative group sizes; 50 and 1000 are the [CFG+] Table 4 reference
 * points, 10 and 200 bracket them. */
static const size_t SIZES[] = {10, 50, 200, 1000};
#define NSIZES (sizeof(SIZES) / sizeof(SIZES[0]))
#define MAXN 1000
#define CAPN (MAXN + 1) /* room for the AddMember (n+1)th entry. */

#define MCT_CAP (GY_QSPGS_MEMBER_PT_MAX + 64)
#define SCRATCH_CAP (1u << 20) /* TBS working space, sized for n = 1000. */
#define CORESIG_CAP 8192

static const uint8_t bench_gid[GY_QSPGS_GID_LEN] = {
    0x77, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

/* Distinct 8-byte UID for member i. */
static void
set_uid(uint8_t uid[GY_QSPGS_UID_LEN], size_t i)
{
    memset(uid, 0, GY_QSPGS_UID_LEN); /* UIDs are a fixed width (LOW-2). */
    uid[0] = 0xaa;
    uid[1] = 0xbb;
    uid[2] = 0xcc;
    uid[3] = 0xdd;
    gy_be32_put(uid + 4, (uint32_t)i);
}

/*
 * Build an n-member core into the caller buffers, under (ek, rrs).  Member 0 is
 * the admin.  Returns GY_OK or a negative GY_ERR_*.
 */
static int
build_core(uint8_t suite, size_t n, const uint8_t *ek, const uint8_t *rrs,
           const uint8_t *vkb, const uint8_t *uk, size_t hlen,
           struct gy_qspgs_member *members, uint8_t *vkhash, uint8_t *mctbuf)
{
    size_t i, mlen;
    int rc;

    for (i = 0; i < n; i++) {
        uint8_t uid[GY_QSPGS_UID_LEN];
        set_uid(uid, i);
        rc = gy_qspgs_member_build(
            suite, GY_AEAD_CHACHA20POLY1305, ek, bench_gid, rrs, uid,
            sizeof(uid), uk, vkb, i == 0 ? 1 : 0, &members[i],
            mctbuf + i * MCT_CAP, MCT_CAP, &mlen, vkhash + i * hlen);
        if (rc != GY_OK)
            return rc;
    }
    return GY_OK;
}

static int
bench_ops(uint8_t suite, size_t iters, double *samples)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite);
    uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];
    uint8_t seed[32], uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX], gk2[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];
    uint8_t ek2[GY_QSPGS_EK_BYTES], rrs2[GY_QSPGS_RRS_BYTES];
    uint8_t admin_uid[GY_QSPGS_UID_LEN];
    struct gy_qspgs_member_ctx ctx;
    struct gy_qspgs_member *members = NULL;
    uint8_t *vkhash = NULL, *mctbuf = NULL, *scratch = NULL, *coresig = NULL;
    size_t hlen, si, i, mlen, siglen;
    uint64_t t0;
    int rc = -1;

    if (desc == NULL || !desc->is_hybrid)
        return -1;
    hlen = desc->hash_len;

    members = calloc(CAPN, sizeof(*members));
    vkhash = malloc((size_t)CAPN * GY_QSPGS_HASH_MAX);
    mctbuf = malloc((size_t)CAPN * MCT_CAP);
    scratch = malloc(SCRATCH_CAP);
    coresig = malloc(CORESIG_CAP);
    if (!members || !vkhash || !mctbuf || !scratch || !coresig)
        goto out;

    memset(seed, 0x11, sizeof(seed));
    memset(uk, 0x77, sizeof(uk));
    if (gy_qspgs_base_keygen_seed(suite, vkb, skb, seed) != GY_OK)
        goto out;
    if (gy_qspgs_group_key_gen(suite, gk) != GY_OK)
        goto out;
    if (gy_qspgs_derive_sub_key(suite, gk, ek, rrs) != GY_OK)
        goto out;
    set_uid(admin_uid, 0);
    if (gy_qspgs_member_ctx_open(&ctx, suite, gk, skb, vkb, admin_uid,
                                 sizeof(admin_uid)) != GY_OK)
        goto out;

    printf("QSPGS ops %s (%zu iters):\n", desc->name, iters);

    for (si = 0; si < NSIZES; si++) {
        size_t n = SIZES[si];
        struct gy_qspgs_core core;

        if (build_core(suite, n, ek, rrs, vkb, uk, hlen, members, vkhash,
                       mctbuf) != GY_OK)
            goto out_ctx;

        memset(&core, 0, sizeof(core));
        core.suite_id = suite;
        core.format_version = GY_QSPGS_FORMAT_VERSION;
        memcpy(core.gid, bench_gid, sizeof(core.gid));
        core.vmaj = 1;
        memset(core.fet, 0x66, sizeof(core.fet));
        core.members = members;
        core.n_members = n;
        core.vkhash = vkhash;
        core.n_vk = n;
        core.last_vmin = 0;

        printf(" n=%zu:\n", n);

        /* AddMember: build the (n)th entry, re-sign the (n+1)-member core. */
        for (i = 0; i < BENCH_WARMUP; i++) {
            uint8_t uid[GY_QSPGS_UID_LEN];
            set_uid(uid, n);
            if (gy_qspgs_member_build(
                    suite, GY_AEAD_CHACHA20POLY1305, ek, bench_gid, rrs, uid,
                    sizeof(uid), uk, vkb, 0, &members[n], mctbuf + n * MCT_CAP,
                    MCT_CAP, &mlen, vkhash + n * hlen) != GY_OK)
                goto out_ctx;
        }
        for (i = 0; i < iters; i++) {
            uint8_t uid[GY_QSPGS_UID_LEN];
            set_uid(uid, n);
            t0 = bench_now_ns();
            if (gy_qspgs_member_build(
                    suite, GY_AEAD_CHACHA20POLY1305, ek, bench_gid, rrs, uid,
                    sizeof(uid), uk, vkb, 0, &members[n], mctbuf + n * MCT_CAP,
                    MCT_CAP, &mlen, vkhash + n * hlen) != GY_OK)
                goto out_ctx;
            core.n_members = n + 1;
            core.n_vk = n + 1;
            if (gy_qspgs_core_sign(&core, 0, &ctx, coresig, CORESIG_CAP,
                                   &siglen, scratch, SCRATCH_CAP) != GY_OK)
                goto out_ctx;
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;
            core.n_members = n; /* reset for the next iteration. */
            core.n_vk = n;
        }
        bench_print("addmember", bench_compute(samples, iters));

        /* RemoveMember: rotate gk, re-open the admin ctx, re-encrypt every
         * member under the new key, re-sign.  (Removal drops one entry; the
         * dominant cost is re-encrypting the survivors, so we rotate the full
         * n-member core, matching the model's per-n cost.) */
        for (i = 0; i < iters; i++) {
            struct gy_qspgs_member_ctx ctx2;

            t0 = bench_now_ns();
            if (gy_qspgs_group_key_gen(suite, gk2) != GY_OK)
                goto out_ctx;
            if (gy_qspgs_derive_sub_key(suite, gk2, ek2, rrs2) != GY_OK)
                goto out_ctx;
            if (gy_qspgs_member_ctx_open(&ctx2, suite, gk2, skb, vkb, admin_uid,
                                         sizeof(admin_uid)) != GY_OK)
                goto out_ctx;
            if (build_core(suite, n, ek2, rrs2, vkb, uk, hlen, members, vkhash,
                           mctbuf) != GY_OK) {
                gy_qspgs_member_ctx_clear(&ctx2);
                goto out_ctx;
            }
            core.vmaj = 2;
            if (gy_qspgs_core_sign(&core, 0, &ctx2, coresig, CORESIG_CAP,
                                   &siglen, scratch, SCRATCH_CAP) != GY_OK) {
                gy_qspgs_member_ctx_clear(&ctx2);
                goto out_ctx;
            }
            gy_qspgs_member_ctx_clear(&ctx2);
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;
        }
        bench_print("removemember", bench_compute(samples, iters));
    }
    rc = 0;

out_ctx:
    gy_qspgs_member_ctx_clear(&ctx);
out:
    free(members);
    free(vkhash);
    free(mctbuf);
    if (scratch != NULL)
        gy_secure_zero(scratch, SCRATCH_CAP);
    free(scratch);
    free(coresig);
    gy_secure_zero(skb, sizeof(skb));
    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(gk2, sizeof(gk2));
    return rc;
}

int
main(int argc, char **argv)
{
    static double samples[BENCH_MAX_ITERS];
    size_t iters = 30;

    if (gy_core_init() != GY_OK) {
        fprintf(stderr, "gy_core_init failed\n");
        return 1;
    }
    if (argc > 1) {
        long v = strtol(argv[1], NULL, 10);
        if (v < 1 || v > BENCH_MAX_ITERS) {
            fprintf(stderr, "iters must be in [1, %d]\n", BENCH_MAX_ITERS);
            return 1;
        }
        iters = (size_t)v;
    }

    if (bench_ops(GY_SUITE_H25519_512, iters, samples) != 0 ||
        bench_ops(GY_SUITE_H448_1024, iters, samples) != 0) {
        fprintf(stderr, "benchmark: a QSPGS op failed\n");
        return 1;
    }
    return 0;
}
