/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Byte-array shim over libdecaf's Decaf448 group, for the 448 half of the
 * independent group KVAC oracle (tools/oracles/group_kvac/verify.py).  Python
 * has no Decaf448 binding; this exposes exactly the operations the oracle needs
 * with plain 56-byte in/out buffers, keeping every decaf_448_point_t /
 * decaf_448_scalar_t inside C (so ctypes never has to size a decaf struct).
 *
 * The arithmetic primitive is geryon's own vendored libdecaf, the SAME
 * primitive geryon's schnorr-448 path uses.  That is intentional and matches
 * the 255 oracle (which shares libsodium ristretto255 with geryon): the group
 * primitive is validated separately (RFC 7748/8032 / the libdecaf gate), and
 * this oracle cross-checks geryon's PROTOCOL composition, not the primitive.
 * The independent part - the Fiat-Shamir transcript (SHAKE256, 114-byte squeeze,
 * decode_long) and the per-equation verify relation - is reconstructed in
 * verify.py from GROUP_SPEC, not taken from geryon.
 *
 * Every function returns 0 on success, -1 on a decode failure.  Points and
 * scalars are the tier's canonical 56-byte encodings.
 */

#include <decaf/point_448.h>

#define N 56

/* out = scalar * point.  scalar is reduced mod l if not already canonical. */
int
gk448_scalarmul(unsigned char *out, const unsigned char *scalar,
                const unsigned char *point)
{
    decaf_448_point_t P, R;
    decaf_448_scalar_t s;

    if (decaf_448_point_decode(P, point, DECAF_TRUE) != DECAF_SUCCESS)
        return -1;
    if (decaf_448_scalar_decode(s, scalar) != DECAF_SUCCESS)
        decaf_448_scalar_decode_long(s, scalar, N); /* reduce non-canonical */
    decaf_448_point_scalarmul(R, P, s);
    decaf_448_point_encode(out, R);
    return 0;
}

/* out = a + b. */
int
gk448_add(unsigned char *out, const unsigned char *a, const unsigned char *b)
{
    decaf_448_point_t A, B, R;

    if (decaf_448_point_decode(A, a, DECAF_TRUE) != DECAF_SUCCESS ||
        decaf_448_point_decode(B, b, DECAF_TRUE) != DECAF_SUCCESS)
        return -1;
    decaf_448_point_add(R, A, B);
    decaf_448_point_encode(out, R);
    return 0;
}

/* out = a - b. */
int
gk448_sub(unsigned char *out, const unsigned char *a, const unsigned char *b)
{
    decaf_448_point_t A, B, R;

    if (decaf_448_point_decode(A, a, DECAF_TRUE) != DECAF_SUCCESS ||
        decaf_448_point_decode(B, b, DECAF_TRUE) != DECAF_SUCCESS)
        return -1;
    decaf_448_point_negate(B, B);
    decaf_448_point_add(R, A, B);
    decaf_448_point_encode(out, R);
    return 0;
}

/* out = the group identity encoding. */
void
gk448_identity(unsigned char *out)
{
    decaf_448_point_encode(out, decaf_448_point_identity);
}

/* out = the standard basepoint encoding. */
void
gk448_basepoint(unsigned char *out)
{
    decaf_448_point_encode(out, decaf_448_point_base);
}

/* out = the 56-byte canonical scalar reduced from a wide hash (decode_long),
 * matching the 448 Fiat-Shamir challenge reduction. */
void
gk448_challenge_reduce(unsigned char *out, const unsigned char *hash,
                       unsigned long hlen)
{
    decaf_448_scalar_t s;

    decaf_448_scalar_decode_long(s, hash, hlen);
    decaf_448_scalar_encode(out, s);
}
