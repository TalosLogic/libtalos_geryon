# XEdDSA Decisions

**Spec:** Signal's XEdDSA specification, "The XEdDSA and VXEdDSA
Signature Schemes", Revision 1 (2016-10-20). See the References section
of DESIGN.md for the full citation.
**Module:** core/ (ed25519.c; x448.c/ed448.c with the 448 tier).
Register conventions and the full index live in [README.md](README.md);
cross-referenced D-GEN/D-X3DH/D-DR IDs live in sibling files.

### D-XED-1: Randomness source

- **Spec gap:** XEdDSA requires 64 bytes of fresh randomness per
  signature; sourcing is implementer-defined.
- **Decision:** libsodium randombytes (getrandom-backed), via
  core/ rng.c.
- **Rationale:** single audited CSPRNG path for the whole library.
- **Validation:** deterministic KATs use seeded test RNG; production
  path covered by the RNG wrapper tests.

### D-XED-2: Identity key dual use

- **Spec gap:** X3DH uses the identity key for both DH and XEdDSA
  signing; formal analyses model these separately.
- **Decision:** accept the dual use, as Signal does; document it as a
  known modeling gap (formal analyses treat the DH key and the signing
  key as independent).
- **Rationale:** wire and bundle compatibility with the X3DH shape.

### D-XED-3: VXEdDSA excluded

- **Spec gap:** the document defines both XEdDSA and VXEdDSA (a VRF);
  whether to implement the VRF is up to the protocol using it.
- **Decision:** geryon implements XEdDSA only. VXEdDSA, and with it
  hash_to_point / Elligator 2, is out of scope: nothing in X3DH, the
  Double Ratchet, or Sesame consumes a VRF.
- **Rationale:** smallest constant-time surface; Elligator 2 and the
  hash_to_point cofactor handling are exactly the kind of subtle code
  the library-first rule exists to avoid. Excluding the VRF also removes
  two known interoperability hazards that the base scheme does not have:
  the XEdDSA spec defines no Elligator 2 retry strategy (a nonstandard
  retry counter breaks interop), and pre-hashing inside hash_to_point
  changes every VRF output. If a VRF need ever appears it enters as a
  new registered decision.
- **Validation:** none (absence of a feature).

### D-XED-4: Hash function is SHA-512 in every suite

- **Spec point (easy to get wrong, so registered):** XEdDSA fixes
  SHA-512 as the hash for BOTH curves; the XEdDSA spec §6 explicitly
  keeps SHA-512 for XEd448 rather than Ed448's SHAKE256 with 912-bit
  output.
- **Decision:** XEdDSA/XEd448 internals use SHA-512 unconditionally.
  The per-suite hash (SHA-256 in the 25519 tier) applies to KDFs,
  PKIDs, and identity hashing, never to XEdDSA. The nonce uses
  hash_1 (b/8 prefix bytes, first byte 0xFE), the challenge h uses
  the unprefixed hash, and hash_0 stays reserved and unused per §2.5.
- **Rationale:** byte-exact spec conformance is what keeps libsignal
  usable as an XEdDSA oracle; a suite-dependent hash would fork the
  scheme for zero benefit.
- **Validation:** libsignal-generated XEdDSA vectors (25519 tier);
  RFC 8032 relationship checks via monocypher key conversion.

### D-XED-5: Construction over libsodium; verification strictness

- **Spec gap:** the spec gives pseudocode; realizing it over a crypto
  library is implementer-defined. libsodium exposes no XEdDSA API.
- **Decision:** signing composes libsodium public primitives exactly
  per the spec pseudocode: crypto_hash_sha512 (incremental,
  multi-input, no concatenation buffers), scalar arithmetic
  (crypto_core_ed25519_scalar_reduce / _mul / _add / _negate), and
  crypto_scalarmult_ed25519_base_noclamp for calculate_key_pair and
  R = rB. The sign path performs NO Montgomery-to-Edwards
  conversion: per the spec's calculate_key_pair, A is E = kB with
  the sign bit cleared, so the signer never needs the u_to_y map.
  Verification does need it (the verifier holds only the peer's
  Montgomery key): the u_to_y birational map comes from vendored
  monocypher's crypto_x25519_to_eddsa (dual-licensed BSD-2/CC0,
  RUNTIME, 25519 tier only; third_party/ submodule pinned at tag
  4.0.3), with the sign bit cleared after conversion. Verification
  performs the spec's explicit range check (u >= p rejected),
  converts, then delegates to libsodium crypto_sign_verify_detached.
  libsodium is STRICTER than the spec's checks: it requires
  canonical s < q (spec allows s < 2^|q|) and rejects small-order
  points. Geryon accepts the stricter set; no honest signer emits
  signatures in the gap, and the strictness removes s-malleability.
- **Design notes:** two tempting shortcuts are deliberately declined.
  (1) Computing the Montgomery public key and converting it in the
  sign path (in addition to computing E = kB) is redundant, since
  calculate_key_pair already yields E = kB directly; geryon drops the
  conversion on the sign path. (2) A hand-rolled verification
  (Rcheck = sB - hA with a constant-time compare) that omits the
  spec's range checks would forgo libsodium's canonical-s and
  small-order rejection for non-canonical u; geryon keeps the explicit
  u check plus delegation instead.
- **Rationale:** library-first; every group operation and scalar op
  stays inside audited constant-time libsodium/monocypher code,
  with only the spec's composition in-house. The 448 tier reuses
  this structure over libdecaf primitives (D-XED-9), except that
  verification is also in-house there (no pass-through verify and
  no monocypher 448 support; see D-XED-9).
- **Validation:** libsignal XEdDSA vectors must reproduce and verify
  byte-exact ONLY for keys where E = kB has sign bit 0; libsignal
  diverges from the spec paper for sign-bit-1 keys (see D-XED-11), so
  the oracle emits sign-bit-0 keys only. A malleated-s (s' = s + q)
  negative test documents the stricter-than-spec acceptance set;
  monocypher conversion cross-checked against geryon-generated keys
  (sign-path A from E must equal verify-path A from u for the same
  key pair).

### D-XED-6: calculate_key_pair timing and converted-key handling

- **Spec gap:** §8 requires constant time and calls out the
  conditional branch in calculate_key_pair; §7 permits caching the
  converted key pair for signing speed.
- **Decision:** the sign-bit negation is a constant-time conditional
  select: compute both k and q - k, select on E.s with a cmov-style
  primitive, never branch (a branch on the sign bit is
  secret-dependent). No caching: conversion runs per signing call and
  the converted scalar is zeroized (secure_zero) before the call
  returns.
- **Rationale:** geryon signs prekeys only, at rotation cadence, so
  the doubled signing cost is irrelevant; declining the cache keeps
  one less copy of identity-equivalent key material resident.
- **Validation:** timing tests across sign-bit classes (keys whose
  Edwards points have s = 0 vs s = 1); zeroization checks.

### D-XED-7: No pre-hashing; bounded message length

- **Spec gap:** §7 notes signing hashes the message twice and leaves
  buffering, maximum message size, and selective pre-hashing to the
  API designer.
- **Decision:** single-shot signing over the complete signed_data, no
  pre-hashing, no streaming API. The maximum message length is a
  compile-time constant sized to the largest signed_data geryon signs
  (an encoded prekey plus a be64 timestamp, well under 8 KB in every
  suite). Internally the hash inputs (prefix, a, M, Z) are fed to
  SHA-512 incrementally rather than concatenated into a buffer; this
  is byte-identical to the buffered form and removes the large-buffer
  path entirely. Pre-hashing in the D-XED-4 sense (hashing M before
  the signed hash) remains excluded; incremental hashing of the same
  bytes is not pre-hashing.
- **Rationale:** every message geryon signs is protocol-internal and
  small, so double-hashing costs nothing; the spec itself cautions
  that pre-hashing widens the collision surface.
- **Validation:** length-bound enforcement test.

### D-XED-8: XEd448 constants

- **Spec point:** the XEdDSA spec §6 pins the Curve448 instantiation:
  hash = SHA-512, p = 2^448 - 2^224 - 1, |p| = 448, |q| = 446,
  b = 456, cofactor c = 4, nonsquare n = -1, u_to_y(u) =
  (1 + u) * inv(1 - u).
- **Decision (recorded facts):** encoded points and integers are 57
  bytes, signatures are 2b = 114 bytes, and the hash_i prefix is the
  57-byte little-endian encoding of 2^456 - 1 - i (low byte 0xFF - i,
  then 56 bytes of 0xFF). The 448-tier signature size (114 bytes) is
  confirmed.
- **Remaining for the 448 tier:** nothing; the provider is decided
  too (D-XED-9). Only the validation gate remains.
- **Validation:** XEd448 self-KATs (no external oracle;
  libsignal is 25519-only).

### D-XED-9: 448-tier provider = libdecaf (ed448-goldilocks)

- **Spec gap:** provider of the curve arithmetic is implementer
  choice; libsodium has no X448/Ed448 support.
- **Decision:** vendor libdecaf (ed448goldilocks), MIT, into geryon's
  third_party/ with its license file, pinned to upstream commit
  ae7b1af200d068b8128791e6eb8b2cf946de3c0c (v1.0.2-22-gae7b1af,
  upstream git://git.code.sf.net/p/ed448goldilocks/code). X448 uses
  the RFC 7748 API; the XEd448 layer stays in-house per plan, built on
  libdecaf scalar/point/field primitives. XEd448 verification CANNOT
  delegate to decaf_ed448_verify: RFC 8032 Ed448 uses SHAKE256 and the
  4-isogenous curve, while XEd448 pins SHA-512 and the birationally
  equivalent curve (XEdDSA spec §6), so unlike the 25519 tier there is
  no pass-through verify.
- **Rationale:** MIT license; authored by Mike Hamburg, Curve448's
  designer and the person the XEdDSA spec credits for Curve448 and
  Elligator 2; strongly constant-time by design with a real security
  maintenance record (2020 RFC 8032 malleability fix, 2022
  steg_encode fix).
- **Status:** locked as provider (July 2026); the validation gate
  runs before first use. The submodule is added with the 448 tier,
  not before (third_party/ currently holds libsodium 1.0.22 and
  monocypher 4.0.3).
- **Validation:** gate: timing tests over the vendored build plus
  RFC 7748/8032 448 vectors run through geryon's wrappers.

### D-XED-10: Montgomery key generation and clamping

- **Spec gap:** the spec's calculate_key_pair consumes a Montgomery
  private key k but never says how k is generated.
- **Decision:** key generation lives in core/ (x25519.c): 32 bytes
  from libsodium randombytes, RFC 7748 clamping applied AT
  GENERATION, and the key stored clamped. DH and XEdDSA signing
  consume the identical stored scalar; nothing re-clamps at point
  of use. Deterministic seeded generation exists only in test
  builds for KATs (D-XED-1). Generation is randombytes + clamp,
  nothing else.
- **Rationale:** clamp-at-generation makes the scalar's identity
  stable across both uses; this matters because
  crypto_scalarmult_ed25519_base_noclamp does NOT clamp, so a
  stored-unclamped key would sign with a different scalar than it
  DHs with, silently breaking the calculate_key_pair
  correspondence.
- **Validation:** sign/DH same-scalar consistency test (public keys
  derived via both paths must correspond under the birational map);
  clamped-bits KAT on generated keys.

### D-XED-11: libsignal signature-encoding divergence (spec over reference)

- **Spec gap:** none in the paper; this records an observed divergence
  between the XEdDSA paper and Signal's reference implementation
  (libsignal), found when the oracle KATs failed for exactly
  the keys whose E = kB has sign bit 1 (~50%).
- **Observed libsignal behavior:** for the identity XEdDSA, libsignal
  does NOT perform the paper's calculate_key_pair adjustment. It signs
  with the Montgomery scalar directly: a = k (no negation), A = kB with
  the sign bit PRESERVED, r = hash_1(prefix || k || M || Z),
  h = hash(R || A || M), s = r + h*k, and it stores A's sign bit in
  bit 255 of s (the top bit of the s half, otherwise 0 since s < q).
  The verifier recovers the Edwards sign from that bit, since the
  Montgomery public key does not carry it. This was reverse-engineered
  purely from oracle input/output (never from libsignal source, per
  geryon's licensing boundary); it reproduces all 256 sign vectors
  byte-exact.
- **Decision:** geryon follows the XEdDSA PAPER, not libsignal, here.
  calculate_key_pair negates to force A.s = 0 (D-XED-5/6); s is always
  canonical (< q, bit 255 = 0); the sign bit is never overloaded.
  Full byte-for-byte libsignal compatibility is explicitly a non-goal:
  geryon already diverges from Signal on AEAD (ChaCha20-Poly1305 default
  vs AES-CBC+HMAC) and on message-key/nonce derivation. The priority is
  exact conformance to the spec where the spec is prescriptive;
  implementation-specific encodings like this one are not inherited.
- **Consequence:** geryon does NOT verify libsignal's sign-bit-1
  signatures (their s is non-canonical to geryon), and does not produce
  them. The two agree byte-exact for sign-bit-0 keys, which is the
  region the paper and the reference share. The oracle
  (tools/oracles/xeddsa_libsignal) therefore emits sign-bit-0 keys only
  (regenerating until the signature's s bit 255 is clear), and the
  vector test skips any sign-bit-1 record defensively.
- **Rationale:** interoperability with Signal was never the goal
  (geryon targets Signal-compatible protocol SEMANTICS, not byte
  compatibility); spec-correctness is. Overloading s bit 255 also conflicts with geryon's
  stricter-than-spec canonical-s acceptance (D-XED-5), which removes
  s-malleability.
- **Validation:** sign-bit-0 libsignal vectors reproduce and verify
  byte-exact; geryon self sign/verify holds for all keys including
  sign-bit-1 (internal spec-consistency).

### D-XED-12: libdecaf integration, Ed448 validation-gate scope, X448 keygen

- **Spec gap:** D-XED-9 locks the provider but defers every build,
  scoping, and keygen detail to the 448-tier implementation.
- **Decision (2026-07-07):**
  - **Build:** vendor the pinned tree (D-XED-9 commit) as
    `third_party/ed448goldilocks-code` with its license file intact
    and a THIRD_PARTY licensing note; integrate via
    `add_subdirectory(... EXCLUDE_FROM_ALL)` linking the
    `decaf-static` target PRIVATE into geryon_core, static + PIC.
    libdecaf's CMake option surface is small, a deliberate deviation
    from the ExternalProject pattern used for libsodium.
  - **Scope:** production 448 signing is XEd448 ONLY.
    `decaf_ed448_sign` / `decaf_ed448_verify` (RFC 8032 Ed448:
    SHAKE256, dom4, the 4-isogenous curve) compute a different
    scheme and are called ONLY by the 448-tier validation gate, test
    side, to run the official RFC 8032 Ed448 vectors against the
    vendored build before any geryon code trusts its arithmetic.
    Library code never calls them (review assertion). All
    production 448 curve arithmetic (scalar, point, field,
    encodings) comes from libdecaf primitives; geryon writes only
    the XEd448 spec composition (the 448 analog of D-XED-5), whose
    construction layer is D-XED-13 (deferred; see below).
  - **X448 key generation** (extends D-XED-10 to the 448 tier):
    56 bytes from gy_random_bytes, RFC 7748 clamping applied AT
    GENERATION (k[0] &= 252; k[55] |= 128), public key via the
    libdecaf RFC 7748 base-point function. gy_x448 applies the
    D-X3DH-8 all-zero output check exactly as gy_x25519 does.
  - **Timing targets:** X448 (fixed vs random peer key), XEd448
    sign and verify, through the dudect harness at the standard
    bar (|t| < 10, >= 1e6). libdecaf has no runtime dispatch to
    split configurations over; the arch selection is compile-time.
- **Deferred sub-decision (BLOCKING for the 448 tier): D-XED-13, the
  XEd448 construction layer.** Which libdecaf layer the composition
  builds on (public decaf_448 API vs internal field/point
  headers), the exact Montgomery-to-Edwards mapping mechanics for
  the birationally-equivalent curve of the XEdDSA spec §6, and the
  57-byte point/scalar encodings. Requires the vendored source and
  the paper side by side; registered by a design spike BEFORE the
  implementation runs.
- **Rationale:** library-first: zero geryon-written primitives in
  the 448 tier; the only in-house crypto is the same class of spec
  composition already accepted for 25519 (D-XED-5). Gate-first
  ordering repeats the 448-tier clause of D-XED-9.
- **Validation:** RFC 7748 X448 vectors and RFC 8032 Ed448 vectors
  through the gate; XEd448 self-KATs and property tests
  (no external XEd448 oracle exists); the
  no-library-calls-Ed448 review assertion; timing targets above.
