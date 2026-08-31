/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * XEd448 (XEdDSA spec Revision 1 section 6), route birational-direct
 * (D-XED-13 R1-R7).  The scheme is composed here from three reused, trusted
 * layers plus a bounded in-house point layer:
 *   - libdecaf INTERNAL gf field (field.h): add/sub/mul/sqr/mulw/isr/serialize/
 *     deserialize/lobit/cond_sel, the hard constant-time core (D-XED-13 R2);
 *   - libdecaf PUBLIC decaf_448 scalar ring (decaf.h): the group order q is
 *     XEd448's q (Goldilocks, the decaf group, and the birational curve share
 *     the prime-order subgroup), so s = r + h*a mod q is a direct reuse;
 *   - the RFC 7748 X448 ladder, only indirectly (the map input side).
 * The in-house part is the twisted-Edwards (a = 1) point layer on the curve
 * birationally equivalent to Curve448, d = 39082/39081 mod p, using textbook
 * extended-coordinate (HWCD) formulas so the correctness argument is "the
 * section 6 formulas on the section 6 curve" (D-XED-13 C1).  SHA-512 comes from
 * core/hash.c, never libdecaf's SHAKE (which stays gate-only).
 *
 * Completeness note (review-critical, D-XED-13): the HWCD a = 1 addition law is
 * exception-free for operands in the odd prime-order subgroup and for the
 * identity accumulator (verified: identity + P reduces to P).  XEdDSA section 3
 * verify is cofactor-less (a strict byte-compare, no cofactor clearing), so
 * this file reproduces the spec's raw sB - hA and never clears the cofactor.
 */

/*
 * Include order matters, twice over:
 *   1. libdecaf's internal field.h defines __DECAF_448_GF_DEFINED__ and the full
 *      gf_448 struct; the public decaf.h (point_448.h) only defines that struct
 *      when the guard is unset.  field.h therefore MUST precede decaf.h, exactly
 *      as libdecaf's own decaf.c does (word.h -> field.h -> decaf.h).
 *   2. word.h sets __STDC_WANT_LIB_EXT1__ to 1 (word.h:10), which macOS
 *      (__DARWIN_C_LEVEL) requires BEFORE <string.h> to declare memset_s (word.h
 *      really_memset calls it).  So the decaf headers precede <string.h> here;
 *      we do NOT set the macro ourselves (that would redefine word.h's under
 *      -Werror).  Harmless where Annex K is absent (glibc omits memset_s, so
 *      decaf takes its volatile-loop fallback).
 */
#include "word.h"
#include "field.h"
#include <decaf.h>

#include <string.h>

#include "ed448.h"
#include "error.h"
#include "hash.h"
#include "rng.h"
#include "util.h"

/*
 * hash_1 prefix (D-XED-8): the 57-byte little-endian encoding of 2^456 - 1 - 1,
 * i.e. 0xFE followed by 56 bytes of 0xFF.  Domain-separates the nonce hash
 * (hash_1) from the challenge hash, which uses no prefix.
 */
static const uint8_t hash1_prefix[57] = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Extended twisted-Edwards coordinates (X : Y : Z : T), T = XY/Z, a = 1. */
struct pt {
    gf x, y, z, t;
};

/* Zero a gf that held secret material (the field carries no bytes API). */
static void gf_secure_scrub(gf a);

/*
 * Field inversion for any nonzero z: 1/z via one inverse-square-root.  Since
 * z^2 is always a quadratic residue, gf_isr(z^2) succeeds and yields r with
 * r^2 * z^2 = 1, so 1/z = r^2 * z (D-XED-13 R2; libdecaf exposes no gf_invert).
 */
static void
gf_invert(gf out, const gf z)
{
    gf z2, r, r2;

    gf_sqr(z2, z);
    (void)gf_isr(r, z2);
    gf_sqr(r2, r);
    gf_mul(out, r2, z);
    gf_secure_scrub(z2);
    gf_secure_scrub(r);
    gf_secure_scrub(r2);
}

static void
gf_secure_scrub(gf a)
{
    gy_secure_zero(a, sizeof(gf));
}

/* The birational curve constant d = 39082 * inv(39081) mod p (a = 1 Edwards). */
static void
curve_d(gf d)
{
    gf num, den, iden;

    gf_mulw(num, ONE, 39082);
    gf_mulw(den, ONE, 39081);
    gf_invert(iden, den);
    gf_mul(d, num, iden);
}

/* out = a + b, a - b are handled by field.h; identity point (0 : 1 : 1 : 0). */
static void
pt_identity(struct pt *p)
{
    gf_copy(p->x, ZERO);
    gf_copy(p->y, ONE);
    gf_copy(p->z, ONE);
    gf_copy(p->t, ZERO);
}

static void
pt_copy(struct pt *r, const struct pt *p)
{
    gf_copy(r->x, p->x);
    gf_copy(r->y, p->y);
    gf_copy(r->z, p->z);
    gf_copy(r->t, p->t);
}

/* r = -p: negate X and T; Y, Z unchanged. */
static void
pt_negate(struct pt *r, const struct pt *p)
{
    gf_sub(r->x, ZERO, p->x);
    gf_copy(r->y, p->y);
    gf_copy(r->z, p->z);
    gf_sub(r->t, ZERO, p->t);
}

/* Constant-time select: r = bit ? b : a, over all four coordinates. */
static void
pt_cond_sel(struct pt *r, const struct pt *a, const struct pt *b, mask_t bit)
{
    gf_cond_sel(r->x, a->x, b->x, bit);
    gf_cond_sel(r->y, a->y, b->y, bit);
    gf_cond_sel(r->z, a->z, b->z, bit);
    gf_cond_sel(r->t, a->t, b->t, bit);
}

/*
 * Unified extended-coordinate addition (HWCD add-2008-hwcd) for a = 1:
 *   A=X1X2 B=Y1Y2 C=dT1T2 D=Z1Z2
 *   E=(X1+Y1)(X2+Y2)-A-B  F=D-C  G=D+C  H=B-A
 *   X3=EF  Y3=GH  T3=EH  Z3=FG
 * Locals avoid aliasing so r may alias p or q.
 */
static void
pt_add(struct pt *r, const struct pt *p, const struct pt *q, const gf d)
{
    gf a, b, c, cd, dd, e, f, g, h, t0, t1;

    gf_mul(a, p->x, q->x);
    gf_mul(b, p->y, q->y);
    gf_mul(c, p->t, q->t);
    gf_mul(cd, c, d); /* separate output: gf_mul's out is restrict-qualified. */
    gf_mul(dd, p->z, q->z);
    gf_add(t0, p->x, p->y);
    gf_add(t1, q->x, q->y);
    gf_mul(e, t0, t1);
    gf_sub(e, e, a);
    gf_sub(e, e, b);
    gf_sub(f, dd, cd);
    gf_add(g, dd, cd);
    gf_sub(h, b, a);
    gf_mul(r->x, e, f);
    gf_mul(r->y, g, h);
    gf_mul(r->t, e, h);
    gf_mul(r->z, f, g);
    gf_secure_scrub(a);
    gf_secure_scrub(b);
    gf_secure_scrub(c);
    gf_secure_scrub(cd);
    gf_secure_scrub(dd);
    gf_secure_scrub(e);
    gf_secure_scrub(f);
    gf_secure_scrub(g);
    gf_secure_scrub(h);
    gf_secure_scrub(t0);
    gf_secure_scrub(t1);
}

/*
 * Extended-coordinate doubling (HWCD dbl-2008-hwcd) for a = 1:
 *   A=X1^2 B=Y1^2 C=2Z1^2 E=(X1+Y1)^2-A-B G=A+B F=G-C H=A-B
 *   X3=EF Y3=GH T3=EH Z3=FG
 */
static void
pt_double(struct pt *r, const struct pt *p)
{
    gf a, b, c, e, f, g, h, t0;

    gf_sqr(a, p->x);
    gf_sqr(b, p->y);
    gf_sqr(c, p->z);
    gf_add(c, c, c);
    gf_add(t0, p->x, p->y);
    gf_sqr(e, t0);
    gf_sub(e, e, a);
    gf_sub(e, e, b);
    gf_add(g, a, b);
    gf_sub(f, g, c);
    gf_sub(h, a, b);
    gf_mul(r->x, e, f);
    gf_mul(r->y, g, h);
    gf_mul(r->t, e, h);
    gf_mul(r->z, f, g);
    gf_secure_scrub(a);
    gf_secure_scrub(b);
    gf_secure_scrub(c);
    gf_secure_scrub(e);
    gf_secure_scrub(f);
    gf_secure_scrub(g);
    gf_secure_scrub(h);
    gf_secure_scrub(t0);
}

/*
 * Constant-time scalar multiplication r = scalar * base, MSB-first
 * double-and-add over 448 bits (the scalar is < q < 2^446, so the top bits are
 * zero; iterating the full 56-byte width leaks nothing).  Every step does one
 * double and one add, selecting the add in constant time on the bit, so the
 * control flow is independent of the secret scalar (D-XED-13 R2/R7).
 */
static void
pt_scalarmul(struct pt *r, const struct pt *base, const uint8_t scalar[56],
             const gf d)
{
    struct pt acc, sum;
    int i;

    pt_identity(&acc);
    for (i = 447; i >= 0; i--) {
        mask_t bit;

        pt_double(&acc, &acc);
        pt_add(&sum, &acc, base, d);
        bit = (mask_t)0 - (mask_t)((scalar[i >> 3] >> (i & 7)) & 1);
        pt_cond_sel(&acc, &acc, &sum, bit);
    }
    pt_copy(r, &acc);
    gy_secure_zero(&acc, sizeof(acc));
    gy_secure_zero(&sum, sizeof(sum));
}

/*
 * Recover the affine point from a y-coordinate on the birational curve:
 *   x^2 = (1 - y^2) / (1 - d y^2),   x = sqrt(num/den) via gf_isr.
 * force_zero selects the sign-bit-0 root (converted Montgomery points, whose
 * sign is 0 by convention); otherwise want_sign (0/1) is applied.  Returns a
 * mask_t: all-ones if y is on the curve (num/den is a QR), zero otherwise.
 */
static mask_t
pt_from_y(struct pt *p, const gf y, int force_zero, unsigned want_sign,
          const gf d)
{
    gf y2, num, den, prod, r, x;
    mask_t ok;
    unsigned sgn, want;

    gf_sqr(y2, y);
    gf_sub(num, ONE, y2); /* 1 - y^2 */
    gf_mul(den, d, y2);
    gf_sub(den, ONE, den);  /* 1 - d y^2 */
    gf_mul(prod, num, den); /* num * den */
    ok = gf_isr(r, prod);   /* r = 1/sqrt(num*den) if QR */
    gf_mul(x, num, r);      /* x = num / sqrt(num*den) = sqrt(num/den) */

    /* Apply the requested sign to x (x and -x are both roots). */
    want = force_zero ? 0u : (want_sign & 1u);
    sgn = (unsigned)(gf_lobit(x) & 1);
    gf_cond_neg(x, (mask_t)0 - (mask_t)(sgn ^ want));

    gf_copy(p->x, x);
    gf_copy(p->y, y);
    gf_copy(p->z, ONE);
    gf_mul(p->t, x, y);

    gf_secure_scrub(y2);
    gf_secure_scrub(num);
    gf_secure_scrub(den);
    gf_secure_scrub(prod);
    gf_secure_scrub(r);
    gf_secure_scrub(x);
    return ok;
}

/*
 * Encode an affine/extended point to 57 bytes: 56-byte little-endian y, then a
 * 57th byte holding x's low bit in bit 7 (D-XED-8/13 R6).  force_zero clears the
 * sign (for A, which is defined with sign 0).
 */
static void
pt_encode(uint8_t out[57], const struct pt *p, int force_zero)
{
    gf zi, x, y;
    unsigned sgn;

    gf_invert(zi, p->z);
    gf_mul(x, p->x, zi);
    gf_mul(y, p->y, zi);
    gf_serialize(out, y);
    sgn = force_zero ? 0u : (unsigned)(gf_lobit(x) & 1);
    out[56] = (uint8_t)(sgn << 7);
    gf_secure_scrub(zi);
    gf_secure_scrub(x);
    gf_secure_scrub(y);
}

/*
 * u_to_y(u) = (u + 1) * inv(u - 1) on the birational curve, yielding the Edwards
 * y-coordinate for a Montgomery u.  (This is the value consistent with RFC 7748
 * X448 and d = 39082/39081: the sign-path A = k*B matches the verify-path
 * A = u_to_y(x448(k)) only with this orientation, verified by cross-check
 * against the ladder.  It is the negation of the (1+u)*inv(1-u) form transcribed
 * from XEdDSA section 6; the D-XED-8 CORRECTION (2026-08-20) records this
 * negated, X448-compatible orientation as the one this file uses.)
 * Returns the canonicality mask of u (all-ones if u < p); a non-canonical public
 * key is rejected upstream.
 */
static mask_t
u_to_y(gf y, const uint8_t u_bytes[56])
{
    gf u, onepu, umone, inv;
    mask_t canon;

    canon = gf_deserialize(u, u_bytes, 0);
    gf_add(onepu, u, ONE); /* u + 1 */
    gf_sub(umone, u, ONE); /* u - 1 */
    gf_invert(inv, umone);
    gf_mul(y, onepu, inv);
    gf_secure_scrub(u);
    gf_secure_scrub(onepu);
    gf_secure_scrub(umone);
    gf_secure_scrub(inv);
    return canon;
}

/* B = convert_mont(5): the XEd448 base point, image of the X448 base u = 5. */
static void
base_point(struct pt *b, const gf d)
{
    gf five, y;

    gf_mulw(five, ONE, 5);
    /* y_B = (5 + 1) * inv(5 - 1), the same orientation as u_to_y. */
    {
        gf onepu, umone, inv;

        gf_add(onepu, five, ONE);
        gf_sub(umone, five, ONE);
        gf_invert(inv, umone);
        gf_mul(y, onepu, inv);
        gf_secure_scrub(onepu);
        gf_secure_scrub(umone);
        gf_secure_scrub(inv);
    }
    (void)pt_from_y(b, y, 1, 0, d);
    gf_secure_scrub(five);
    gf_secure_scrub(y);
}

/*
 * Derive the sign-path key pair: A_pt = a * B with a chosen so A encodes with
 * sign bit 0 (calculate_key_pair analog, D-XED-13 R4; geryon follows the paper,
 * never libsignal's s-bit overload, D-XED-11).  a_out is the resulting scalar.
 */
static void
derive_key(struct pt *a_pt, decaf_448_scalar_t a_out, const uint8_t mont_sk[56],
           const gf d, const struct pt *b)
{
    uint8_t k_bytes[56];
    decaf_448_scalar_t k_sc, k_neg;
    struct pt e;
    gf zi, xa;
    mask_t sign;

    /* k reduced mod q (the Montgomery scalar may exceed q). */
    decaf_448_scalar_decode_long(k_sc, mont_sk, 56);
    decaf_448_scalar_encode(k_bytes, k_sc);

    /* E = k * B; read the affine x sign of E. */
    pt_scalarmul(&e, b, k_bytes, d);
    gf_invert(zi, e.z);
    gf_mul(xa, e.x, zi);
    sign = (mask_t)0 - (mask_t)(gf_lobit(xa) & 1);

    /* a = sign ? -k : k, selected in constant time. */
    decaf_448_scalar_sub(k_neg, decaf_448_scalar_zero, k_sc);
    decaf_448_scalar_cond_sel(a_out, k_sc, k_neg, sign);

    pt_copy(a_pt, &e);

    gy_secure_zero(k_bytes, sizeof(k_bytes));
    decaf_448_scalar_destroy(k_sc);
    decaf_448_scalar_destroy(k_neg);
    gy_secure_zero(&e, sizeof(e));
    gf_secure_scrub(zi);
    gf_secure_scrub(xa);
}

int
gy_xed448_calculate_key_pair(uint8_t ed_pk[57], uint8_t scalar_a[57],
                             const uint8_t mont_sk[56])
{
    gf d;
    struct pt b, a_pt;
    decaf_448_scalar_t a;

    curve_d(d);
    base_point(&b, d);
    derive_key(&a_pt, a, mont_sk, d, &b);

    pt_encode(ed_pk, &a_pt, 1); /* A is defined with sign bit 0. */
    memset(scalar_a, 0, 57);
    decaf_448_scalar_encode(scalar_a, a);

    decaf_448_scalar_destroy(a);
    gy_secure_zero(&a_pt, sizeof(a_pt));
    gy_secure_zero(&b, sizeof(b));
    gf_secure_scrub(d);
    return GY_OK;
}

int
gy_xed448_mont_to_ed(uint8_t ed_pk[57], const uint8_t mont_pk[56])
{
    gf d, y;
    struct pt a;
    mask_t canon, oncurve;

    curve_d(d);
    canon = u_to_y(y, mont_pk);
    oncurve = pt_from_y(&a, y, 1, 0, d);
    if (!canon || !oncurve) {
        gf_secure_scrub(d);
        gf_secure_scrub(y);
        gy_secure_zero(&a, sizeof(a));
        return GY_ERR_VERIFY;
    }
    pt_encode(ed_pk, &a, 1);
    gf_secure_scrub(d);
    gf_secure_scrub(y);
    gy_secure_zero(&a, sizeof(a));
    return GY_OK;
}

/* Deterministic signing core; z is the caller-supplied 64-byte nonce. */
static int
xed448_sign_core(uint8_t sig[114], const uint8_t mont_sk[56],
                 const uint8_t *msg, size_t msg_len, const uint8_t z[64])
{
    gf d;
    struct pt b, a_pt, r_pt;
    decaf_448_scalar_t a, r, h, ha, s;
    uint8_t ed_pk[57], a_enc[56], r_bytes[56];
    uint8_t r_hash[64], h_hash[64];
    gy_sha512_state st;
    int rc = GY_OK;

    if (msg_len > GY_XED448_MAX_MSG)
        return GY_ERR_TOOLONG;

    curve_d(d);
    base_point(&b, d);
    derive_key(&a_pt, a, mont_sk, d, &b);
    pt_encode(ed_pk, &a_pt, 1);
    decaf_448_scalar_encode(a_enc, a);

    /* r = hash_1(prefix || a || M || Z) mod q. */
    gy_sha512_init(&st);
    gy_sha512_update(&st, hash1_prefix, sizeof(hash1_prefix));
    gy_sha512_update(&st, a_enc, sizeof(a_enc));
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_update(&st, z, 64);
    gy_sha512_final(&st, r_hash);
    decaf_448_scalar_decode_long(r, r_hash, 64);

    /* R = r * B, encoded into the first 57 bytes of the signature. */
    decaf_448_scalar_encode(r_bytes, r);
    pt_scalarmul(&r_pt, &b, r_bytes, d);
    pt_encode(sig, &r_pt, 0);

    /* h = SHA-512(R || A || M) mod q (no prefix on the challenge hash). */
    gy_sha512_init(&st);
    gy_sha512_update(&st, sig, 57);
    gy_sha512_update(&st, ed_pk, 57);
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_final(&st, h_hash);
    decaf_448_scalar_decode_long(h, h_hash, 64);

    /* s = r + h * a mod q, encoded into bytes 57..113 (56 + a zero byte). */
    decaf_448_scalar_mul(ha, h, a);
    decaf_448_scalar_add(s, r, ha);
    memset(sig + 57, 0, 57);
    decaf_448_scalar_encode(sig + 57, s);

    decaf_448_scalar_destroy(a);
    decaf_448_scalar_destroy(r);
    decaf_448_scalar_destroy(h);
    decaf_448_scalar_destroy(ha);
    decaf_448_scalar_destroy(s);
    gy_secure_zero(a_enc, sizeof(a_enc));
    gy_secure_zero(r_bytes, sizeof(r_bytes));
    gy_secure_zero(r_hash, sizeof(r_hash));
    gy_secure_zero(h_hash, sizeof(h_hash));
    gy_secure_zero(ed_pk, sizeof(ed_pk));
    gy_secure_zero(&a_pt, sizeof(a_pt));
    gy_secure_zero(&r_pt, sizeof(r_pt));
    gy_secure_zero(&b, sizeof(b));
    gy_secure_zero(&st, sizeof(st));
    gf_secure_scrub(d);
    if (rc != GY_OK)
        gy_secure_zero(sig, 114);
    return rc;
}

int
gy_xed448_sign(uint8_t sig[114], const uint8_t mont_sk[56], const uint8_t *msg,
               size_t msg_len)
{
    uint8_t z[64];
    int rc;

    if (msg_len > GY_XED448_MAX_MSG)
        return GY_ERR_TOOLONG;

    rc = gy_random_bytes(z, sizeof(z));
    if (rc != GY_OK)
        return rc;

    rc = xed448_sign_core(sig, mont_sk, msg, msg_len, z);
    gy_secure_zero(z, sizeof(z));
    return rc;
}

#ifdef GY_TEST_HOOKS
int
gy_xed448_sign_z(uint8_t sig[114], const uint8_t mont_sk[56],
                 const uint8_t *msg, size_t msg_len, const uint8_t z[64])
{
    return xed448_sign_core(sig, mont_sk, msg, msg_len, z);
}
#endif /* GY_TEST_HOOKS */

/*
 * Reject a non-canonical scalar encoding s (57 bytes): the 57th byte must be
 * zero and the low 56 bytes must be < q (decaf_448_scalar_decode enforces the
 * latter, returning DECAF_FAILURE otherwise).  Returns GY_OK and fills s_out on
 * success (D-XED-5 malleability strictness, checked before any scalarmul).
 */
static int
decode_canonical_s(decaf_448_scalar_t s_out, const uint8_t s_enc[57])
{
    if (s_enc[56] != 0)
        return GY_ERR_VERIFY;
    if (decaf_448_scalar_decode(s_out, s_enc) != DECAF_SUCCESS)
        return GY_ERR_VERIFY;
    return GY_OK;
}

int
gy_xed448_verify(const uint8_t sig[114], const uint8_t mont_pk[56],
                 const uint8_t *msg, size_t msg_len)
{
    gf d, y;
    struct pt b, a_pt, sb, ha, neg_ha, rc_pt;
    decaf_448_scalar_t s, h;
    uint8_t a_enc[57], rc_enc[57], s_bytes[56], h_bytes[56], h_hash[64];
    gy_sha512_state st;
    mask_t canon, oncurve;
    int rc = GY_ERR_VERIFY;

    if (msg_len > GY_XED448_MAX_MSG)
        return GY_ERR_TOOLONG;

    /* Canonical s BEFORE any point work (D-XED-5). */
    if (decode_canonical_s(s, sig + 57) != GY_OK)
        return GY_ERR_VERIFY;

    curve_d(d);
    base_point(&b, d);

    /* A = u_to_y(mont_pk), sign 0; reject non-canonical u or off-curve A. */
    canon = u_to_y(y, mont_pk);
    oncurve = pt_from_y(&a_pt, y, 1, 0, d);
    if (!canon || !oncurve)
        goto out;
    pt_encode(a_enc, &a_pt, 1);

    /* h = SHA-512(R || A || M) mod q. */
    gy_sha512_init(&st);
    gy_sha512_update(&st, sig, 57);
    gy_sha512_update(&st, a_enc, 57);
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_final(&st, h_hash);
    decaf_448_scalar_decode_long(h, h_hash, 64);

    /* R_check = s*B - h*A (cofactor-less, D-XED-13 C1). */
    decaf_448_scalar_encode(s_bytes, s);
    decaf_448_scalar_encode(h_bytes, h);
    pt_scalarmul(&sb, &b, s_bytes, d);
    pt_scalarmul(&ha, &a_pt, h_bytes, d);
    pt_negate(&neg_ha, &ha);
    pt_add(&rc_pt, &sb, &neg_ha, d);
    pt_encode(rc_enc, &rc_pt, 0);

    /* Strict constant-time byte-compare of encoded R_check against R. */
    if (gy_const_memcmp(rc_enc, sig, 57) == 0)
        rc = GY_OK;

out:
    decaf_448_scalar_destroy(s);
    decaf_448_scalar_destroy(h);
    gf_secure_scrub(d);
    gf_secure_scrub(y);
    gy_secure_zero(&b, sizeof(b));
    gy_secure_zero(&a_pt, sizeof(a_pt));
    gy_secure_zero(&sb, sizeof(sb));
    gy_secure_zero(&ha, sizeof(ha));
    gy_secure_zero(&neg_ha, sizeof(neg_ha));
    gy_secure_zero(&rc_pt, sizeof(rc_pt));
    gy_secure_zero(&st, sizeof(st));
    return rc;
}
