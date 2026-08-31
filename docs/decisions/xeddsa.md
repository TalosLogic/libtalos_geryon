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
- **CORRECTION (2026-08-20): the recorded u_to_y has a sign
  error.** The X448-compatible map is u_to_y(u) = (u + 1) * inv(u - 1),
  the NEGATION of the value above. This was found empirically: with
  d = 39082/39081, only (u+1)*inv(u-1) makes the sign-path A = k*B agree
  with the verify-path A = u_to_y(x448(k)) (cross-checked against an
  RFC-7748-validated X448 ladder over random scalars); (1+u)*inv(1-u) is
  X448-incompatible for every d, and since verify starts from the
  Montgomery u-coordinate the map MUST be ladder-compatible, so the
  negated form cannot be right. src/core/ed448.c uses (u+1)*inv(u-1).
  ACTION: reconcile this against the XEdDSA specification §6 (likely a transcription
  sign slip when this entry was written); confirm whether the paper
  writes (u+1)/(u-1) or (u-1)/(u+1) and settle the register text.
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
  e5cc6240690d3ffdfcbdb1e4e851954b789cd5d9 (tag v1.0.3; bumped
  2026-08-20 from the earlier v1.0.2-22-gae7b1af pin during 448-tier
  reconciliation, vendored as a git submodule,
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
- **Status:** locked as provider (July 2026); pin bumped to v1.0.3
  (e5cc624) on 2026-08-20 during 448-tier reconciliation. Now vendored
  as a git submodule at third_party/ed448goldilocks-code alongside
  libsodium 1.0.22 and monocypher 4.0.3; the validation gate runs
  before first use.
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
    `third_party/ed448goldilocks-code` (a git submodule) with its
    license file intact and a THIRD_PARTY licensing note.
    **Build-integration mechanism AMENDED 2026-08-20 (supersedes the
    2026-07-07 `add_subdirectory` text below):** geryon compiles the
    448 slice of libdecaf's C sources DIRECTLY under its own build
    (a geryon-owned `add_library`, the monocypher pattern scaled up),
    running libdecaf's Python code generator via `add_custom_command`.
    geryon does NOT `add_subdirectory` libdecaf's CMake and does NOT
    drive it through ExternalProject.
    - Reason: libdecaf's top-level `project(DECAF ... LANGUAGES C CXX)`
      forces a C++ toolchain at configure time (even though ZERO C++
      is compiled into `decaf-static`; `DECAF_SOURCE_FILES_CXX` is
      empty and every `.hxx` is an optional-API header we never
      touch), and both `add_subdirectory` and ExternalProject would
      inherit that requirement. The hard constraint is that geryon
      must link NO C++ runtime (`libstdc++`) at runtime and prefer no
      C++ at build time either; direct compilation of the C sources
      honors both. It also avoids libdecaf's `install(EXPORT/TARGETS/
      DIRECTORY)` rules leaking `decaf.a`, decaf headers, and a
      `DecafTargets.cmake` export into geryon's install tree (which
      ships only `geryon.h`), and keeps libdecaf's option namespace,
      `-Werror`, and its own (decaf/ristretto, not RFC) CTest cases
      out of geryon's build.
    - The 448 source slice geryon owns (arch auto-selected, x86_64 =>
      `src/p448/arch_x86_64`): common `utils.c`, `shake.c`,
      `sha512.c`, `spongerng.c`; p448 field `arch_x86_64/f_impl.c`,
      `f_arithmetic.c`, generated `c/p448/f_generic.c`; ed448goldilocks
      generated `c/ed448goldilocks/{decaf,elligator,scalar,eddsa}.c`
      plus static `src/ed448goldilocks/decaf_tables.c`; plus the
      generated headers (`c/p448/f_field.h`, the public `decaf/*.h`)
      that those sources `#include`. The generator step re-encodes the
      `template.py` invocations from libdecaf's
      `src/generator/CMakeLists.txt` and per-curve/p448 CMake.
    - Cost accepted: geryon owns a small, enumerable copy of libdecaf's
      448 build graph (source list + generator commands + arch map),
      re-diffed against upstream at each (geryon-controlled) pin bump.
      The internal-field-header exposure of approach #3 (D-XED-13) is
      the SAME under any integration mechanism, so this direct-compile
      choice adds only that build-graph list as extra bump-time work.
    - SUPERSEDED (2026-07-07 original): "integrate via
      `add_subdirectory(... EXCLUDE_FROM_ALL)` linking the
      `decaf-static` target PRIVATE into geryon_core, static + PIC;
      libdecaf's CMake option surface is small, a deliberate deviation
      from the ExternalProject pattern used for libsodium." Retained
      here for the decision trail; the C++-toolchain and
      install-pollution findings above reversed it.
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
  implementation runs. The problem framing the spike starts from (the
  libsodium/libdecaf asymmetry that forces the in-house work, the
  role-mapping table, the arithmetic-reuse inventory, and the
  isogeny-transport vs birational-direct routes) is recorded in D-XED-13
  below; the spike selects a route and finalizes the mechanics.
- **Rationale:** library-first: zero geryon-written primitives in
  the 448 tier; the only in-house crypto is the same class of spec
  composition already accepted for 25519 (D-XED-5). Gate-first
  ordering repeats the 448-tier clause of D-XED-9.
- **Validation:** RFC 7748 X448 vectors and RFC 8032 Ed448 vectors
  through the gate; XEd448 self-KATs and property tests
  (no external XEd448 oracle exists); the
  no-library-calls-Ed448 review assertion; timing targets above.

### D-XED-13: XEd448 construction layer (framing + reuse strategy; mechanics deferred to a design spike)

- **Spec gap:** D-XED-9 locks libdecaf as the 448 provider and states
  there is no pass-through verify, but leaves open HOW the in-house
  XEd448 sign and verify are composed: which libdecaf layer they build
  on, the exact Montgomery-to-Edwards mapping mechanics for the XEdDSA
  spec §6 curve, and the 57-byte encodings. The mechanics remain
  deferred to the design spike; this entry records the problem
  framing, the libsodium/libdecaf asymmetry that forces the in-house
  work, and the arithmetic-reuse strategy the spike starts from.

- **Why 25519 needed only one borrowed function and 448 does not.** The
  25519 tier gets its whole XEdDSA scheme from libraries and patches a
  single gap: XEdDSA §5 targets the twisted Edwards curve birationally
  equivalent to Curve25519, and THAT curve is exactly Ed25519, the curve
  libsodium implements. So libsodium supplies the sign primitives
  (crypto_scalarmult_ed25519_base_noclamp, crypto_core_ed25519_scalar_*)
  and a true pass-through verify (crypto_sign_verify_detached), all on
  the correct curve; the only thing libsodium does not expose is the
  Montgomery-to-Edwards coordinate map, filled by monocypher's
  crypto_x25519_to_eddsa (the ONE monocypher call in geryon, ed25519.c
  mont_to_ed). 448 does not get that coincidence: libdecaf's finished
  Ed448 (decaf_ed448_sign/verify) is a DIFFERENT scheme (SHAKE256, dom4
  prefix) on the Ed448-Goldilocks curve, which is 4-isogenous to
  Curve448, not birationally equivalent to it, while XEdDSA §6 targets
  the curve birationally equivalent to Curve448 (u_to_y(u) =
  (u + 1) * inv(u - 1), the X448-compatible orientation of the D-XED-8
  CORRECTION 2026-08-20). There is therefore no finished sign or
  verify on the right curve to borrow: the gap is not one coordinate
  function, it is the entire XEdDSA Edwards composition, sign AND verify.

  Role mapping across the two tiers:

  | Role | 25519 | 448 | Reusable as-is |
  |------|-------|-----|----------------|
  | Montgomery DH | libsodium X25519 (thin wrapper) | libdecaf RFC 7748 X448 (thin wrapper) | Yes |
  | Field / scalar-mod-q ops | libsodium | libdecaf gf field + decaf scalar | Yes |
  | Edwards sign scalarmul | libsodium, on Ed25519 (= the XEdDSA curve) | libdecaf exposes it on Goldilocks/decaf, not the birational curve | No |
  | Verify | libsodium pass-through (right curve) | decaf_ed448_verify = wrong scheme (SHAKE/dom4) on the 4-isogenous curve | No |
  | Montgomery-to-Edwards map | monocypher (one function) | not exposed, and the target curve differs | No |

  The DH and field/scalar rows are symmetric: libdecaf is used exactly
  like libsodium there. The break is confined to the Edwards SCHEME
  layer, and it is a curve mismatch, not a missing function.

- **No external implementation to lean on.** XEdDSA is instantiated for
  Curve25519 everywhere in practice; XEd448 (§6) is essentially
  unexercised in the ecosystem. libsignal is 25519-only, so there is no
  oracle and no maintained, tested XEd448 to vendor. geryon writes it
  from the spec, held to the full constant-time and clean-room bar, with
  self-KATs and property tests as the only assurance (D-XED-8 validation
  line). This is the same class of in-house spec composition already
  accepted for 25519 (D-XED-5), extended to sign AND verify.

- **Arithmetic reuse strategy (what geryon does NOT reimplement).** The
  library-first rule still binds: geryon writes NO 448 primitive
  libdecaf already provides, and the plan is to reuse all of the
  following:
  - GF(2^448 - 2^224 - 1) field arithmetic (add, sub, mul, sqr, invert,
    inverse-sqrt, serialize/deserialize): the bulk of the hard
    constant-time code, and what makes the map and any birational point
    ops feasible without hand-written bignum field code.
  - Scalar arithmetic mod the group order q (add, sub, mul, invert,
    encode/decode): directly the ops XEdDSA needs for s = r + h*a mod q
    and the reduction of h. Public decaf scalar API.
  - Point group operations: fixed-base scalarmul (R = rB, A = aB),
    variable/double-base scalarmul (verify sB - hA), point
    encode/decode, and libdecaf's EdDSA-style encode/decode with the
    cofactor ratio. These live on the decaf/Goldilocks group, so their
    use is gated on the curve-route decision below.
  - The RFC 7748 X448 ladder (already the plan, D-XED-9).

  What geryon must still write itself is the thin composition, sized
  like the 25519 XEdDSA layer: the u_to_y map application and sign-bit-0
  forcing (calculate_key_pair analog, D-XED-5/6/11), SHA-512 hashing via
  core/hash.c (never libdecaf's SHAKE), the hash_i domain prefixes
  (D-XED-8), canonical-s enforcement (D-XED-5), the 57-byte encodings,
  and zeroization of every secret intermediate.

- **The one open mechanics decision the spike resolves.** Because the
  reusable point layer sits on the Goldilocks/decaf curve while XEdDSA
  wants the birational curve, there are two routes, and the spike picks
  one with a written correctness argument:
  - Isogeny-transport: move the mapped key (and R, and the base point)
    across libdecaf's 4-isogeny into the decaf group and use its public
    scalarmul and verification-equation primitives. Reuses the MOST
    (public API, strongly constant-time), but owes a correctness
    argument for the isogeny's effect on the verification equation and
    the cofactor. libdecaf's encode_like_eddsa /
    decode_like_eddsa_and_mul_by_ratio helpers are the candidate bridge
    and must be checked against XEdDSA §6's encoding.
  - Birational-direct: implement the birational curve's point ops on
    libdecaf's gf field layer (internal headers), so the map and verify
    are textbook XEdDSA §6 with no isogeny bookkeeping. More in-house
    point code, pinned to internal headers, but no isogeny argument to
    get wrong.
  Reused field, scalar, and ladder code is common to both routes; only
  the point layer and the correctness argument differ.

- **Decision (recorded now, mechanics deferred):** the direction is
  fixed even though the mechanics are not. XEd448 sign AND verify are
  in-house spec composition over reused libdecaf field, scalar, point,
  and X448 primitives; nothing is delegated to decaf_ed448_sign/verify
  (the D-XED-9 no-library-calls-Ed448 rule). The isogeny-transport vs
  birational-direct route, and the exact libdecaf layer, are registered
  by the design spike before implementation.

- **Rationale:** library-first for every primitive libdecaf provides;
  in-house only the spec composition, the same class already accepted at
  25519 (D-XED-5), forced here (not chosen) by the Goldilocks/Curve448
  isogeny that denies the pass-through the 25519 tier got for free.

- **Validation:** per D-XED-8 and the D-XED-9 gate: RFC 7748 X448 and
  RFC 8032 Ed448 vectors through the validation gate (arithmetic trust);
  XEd448 self-KATs and property tests (no external oracle); the
  sign-path-A-from-E equals verify-path-A-from-u cross-check (the 448
  analog of the 25519 check, D-XED-5 validation); the
  no-library-calls-Ed448 nm assertion; timing targets (D-XED-12).

- **Preliminary route analysis (paper study 2026-08-20, provisional;
  the binding decision remains the design spike with the vendored source
  in hand).** Reading the XEdDSA specification §3/§5/§6 against the two routes settles
  the lean decisively toward birational-direct, on spec grounds:
  - **§3 verify is cofactor-less.** xeddsa_verify computes
    R_check = sB - hA and returns bytes_equal(R, R_check): a STRICT
    byte-compare of the encoded point, no cofactor multiplication (§5
    states this choice explicitly). The accept set is exactly the points
    that encode identically on the birational curve.
  - **§6 pins the birational curve, not Goldilocks.** The XEd448 twisted
    Edwards curve is x^2 + y^2 = 1 + d x^2 y^2 with d = 39082/39081
    (mod p), the curve birationally equivalent to Curve448. This is a
    DIFFERENT curve from Ed448-Goldilocks (d = -39081), which is
    4-isogenous. §6 says outright: XEd448 "may differ from other
    proposed instantiations of EdDSA which use the 4-isogenous curve
    rather than the birationally equivalent curve. Mapping from the
    Montgomery form Curve448 to the isogenous curve is more
    complicated." The spec author (with Curve448/libdecaf author Mike
    Hamburg credited) chose the birational curve specifically to avoid
    the isogeny.
  - **Consequence for isogeny-transport (Route A).** libdecaf's decaf
    group is the prime-order QUOTIENT of the isogenous Goldilocks curve;
    verifying there is a cofactor-cleared comparison on the wrong curve,
    so it accepts a different set than §6's strict byte-compare (any R
    differing from sB - hA by a cofactor point would pass). To honor §6
    you would have to map back to the birational curve and byte-compare
    the encoding there, which undoes the transport and erases the reuse
    benefit; the decaf base point and generator also do not line up with
    §6's B = convert_mont(5), so the precomputed base tables are not
    directly usable. Net: Route A fights the spec's cofactor-less,
    birational-curve verify and reintroduces exactly the isogeny
    complication §6 was written to avoid.
  - **Consequence for birational-direct (Route B).** Implementing
    Edwards add/double, fixed- and variable-base scalarmul, encode/
    decode, on_curve, and u_to_y on the §6 curve over GF(p448) realizes
    xeddsa_sign/verify verbatim; the correctness argument is "these are
    the §6 formulas on the §6 curve," with no isogeny or cofactor
    bookkeeping. The reused libdecaf parts are its gf field arithmetic
    (the hard constant-time core) and its scalar-mod-q ops (the decaf
    group order is the same q as §6); geryon writes only the bounded
    constant-time Edwards point layer plus the spec composition.
  - **Provisional lean: Route B (birational-direct).** Its only real
    cost is depending on libdecaf INTERNAL field headers (the public API
    exposes only the decaf group), pinned to the vendored commit; this
    is the header-exposure requirement to feed the build integration.
  - **Confirmed against the vendored source (third_party/
    ed448goldilocks-code, 2026-08-20).** The paper lean survives contact
    with the code; the cryptographic reuse is all present:
    - Field layer (src/include/field.h + the generated per-field
      f_field.h + src/p448/arch_*/f_impl.h): gf_add/sub/mul/sqr/mulw,
      gf_isr (constant-time inverse-sqrt, "a^2 x = 1", the sqrt/decode
      primitive), gf_serialize/gf_deserialize (SER_BYTES = 56 for
      p448), gf_lobit (sign bit), gf_eq, gf_strong_reduce, and the
      constant-time gf_cond_sel/neg/swap. Everything the birational
      point ops and point decode need is here. (Q1, Q3 resolved: yes.)
    - Scalar layer (src/per_curve/scalar.tmpl.c): sc_p is the scalar
      modulus, substituted per-curve to the group order, which for
      ed448goldilocks IS the §6 q (the birational curve, Goldilocks, and
      the decaf group share the prime-order subgroup). decaf_448_scalar_*
      reduces mod exactly that q, so s = r + h*a mod q is a direct reuse.
      (Q2 resolved: yes.)
    - Curve constant: src/per_curve/decaf.tmpl.c defines
      EDWARDS_D = $(d), and for ed448goldilocks that is -39081, i.e. the
      library's entire point layer lives on the GOLDILOCKS curve, not the
      §6 birational curve (d = 39082/39081). geryon defines its own d and
      derives B = convert_mont(5); there is no ready-made point op on the
      curve we need, confirming Route B writes the Edwards point layer
      over gf. (Q4: d is ours to define, base point ours to derive.)
    - The isogeny machinery Route A would need is real but
      Goldilocks-bound: eddsa.tmpl.c uses EDDSA_ENCODE_RATIO /
      EDDSA_DECODE_RATIO with point_mul_by_ratio_and_encode_like_eddsa
      and point_decode_like_eddsa_and_mul_by_ratio (comment: "the sigma
      isogeny is in use; the EdDSA base point is on Etwist_d/(1-d)").
      This bakes in RFC 8032 Ed448 cofactor-clearing on the Goldilocks
      curve, which is exactly the cofactor-cleared, wrong-curve accept
      set that diverges from §3's strict byte-compare. Route A's own
      building blocks confirm the divergence.
    - Encodings (Q5): field serialize is 56 bytes; the 57-byte XEd448
      point encoding is that y plus a sign bit from gf_lobit; scalar
      serialize is 56 bytes and s stays < 2^446. Straightforward
      bookkeeping in the composition.
  - **New finding, and the real remaining cost, is the BUILD, not the
    crypto.** libdecaf is a template/generator system: the concrete
    field, scalar, and point headers (f_field.h, decaf_448.h, ...) are
    generated at build time from src/per_field/*.tmpl.* and
    src/per_curve/*.tmpl.* by the python generator, substituting
    $(gf_shortname), $(d), $(cofactor), $(gf_bits), etc. The gf field API
    is INTERNAL (src/include, src/p448/arch_*) and generated, not in
    src/public_include. So reusing gf on our curve means compiling
    geryon's XEd448 source against libdecaf's generated internal field
    headers and linking the non-inline field bodies (gf_mul, gf_sqr,
    gf_isr, gf_serialize, gf_strong_reduce). This is the
    header/build-exposure requirement fed to the build integration. Chosen leaning
    (2026-08-20): the thin internal-include shim (candidate 3), driven
    by two constraints from the maintainer: keep sources separate
    (geryon's XEd448 unit stays in geryon's tree; only that one
    translation unit borrows libdecaf's internal include dirs, PRIVATE),
    and accept the pinned-internal-header risk rather than abstract
    around it (the tree is pinned, so if a version bump changes the
    internal field API we adapt at the bump, with no wrapper/shadow
    layer).
    - Build-integration mechanism SETTLED 2026-08-20 (D-XED-12 Build
      amendment): geryon compiles libdecaf's 448 C-source slice
      directly under its own build and runs the Python generator via
      custom commands (NOT add_subdirectory, NOT ExternalProject), so
      no C++ toolchain is required and no `libstdc++` is linked. The
      non-inline field bodies (gf_mul/sqr/isr/serialize/strong_reduce)
      therefore compile into a geryon-owned decaf-448 static archive,
      and the internal field/arch headers are already in geryon's build
      tree; ed448.c borrows those internal include dirs
      PRIVATE, exactly the candidate-3 shim, now trivially satisfied
      because geryon owns the compilation. Settled in the build
      integration; formal confirmation is that build.
- **Status:** framing, reuse strategy, and a route analysis now
  confirmed against the vendored source (2026-08-20). The lean toward
  birational-direct is source-backed: all cryptographic primitives are
  present (gf field incl. isr, scalar mod q, serialize) and the isogeny
  path is confirmed Goldilocks-bound and cofactor-clearing. The binding
  route decision and construction mechanics were open pending the design
  spike; they are now RATIFIED below. The BUILD sub-decision the earlier
  finding flagged was settled by the build integration (D-XED-12 Build
  amendment, direct-compile), so the internal gf field layer is already
  in geryon's build
  tree.

---

**RATIFICATION (2026-08-20).** The provisional lean is now the
binding decision; the route, the libdecaf layer, and every construction
mechanic below are fixed, and none is left implementation-defined. This
closes the D-XED-12 "deferred sub-decision" clause and unblocks the
implementation.

- **R1 - Route: birational-direct (Route B).** XEd448 sign and verify are
  implemented as textbook XEdDSA spec §6 over the twisted Edwards curve
  birationally equivalent to Curve448 (x^2 + y^2 = 1 + d x^2 y^2,
  d = 39082/39081 mod p), realized on libdecaf's INTERNAL gf field layer.
  Isogeny-transport (Route A) is REJECTED: §3's verify is a cofactor-less
  strict byte-compare on the birational curve, so verifying in libdecaf's
  prime-order decaf quotient of the 4-isogenous Goldilocks curve accepts a
  different set (any R differing from sB - hA by a cofactor point), and
  §6 was written specifically to avoid that isogeny. The correctness
  argument for R1 is C1 below.

- **R2 - libdecaf layer: internal gf field + public decaf scalar; no
  point reuse.** The composition builds on:
  - libdecaf INTERNAL field headers (src/include/field.h + generated
    c/p448/f_field.h + src/p448/arch_*/f_impl.h): gf_add/sub/mul/sqr/mulw,
    gf_isr (constant-time inverse-sqrt), gf_serialize/gf_deserialize
    (SER_BYTES = 56), gf_lobit, gf_eq, gf_strong_reduce, gf_cond_sel/neg/
    swap. These are the hard constant-time core geryon does NOT rewrite.
    Reached via the candidate-3 PRIVATE internal-include shim, already
    in geryon's build tree from the build integration.
  - libdecaf PUBLIC decaf scalar API (decaf_448_scalar_*): the
    ed448goldilocks group order equals §6's q (Goldilocks, the birational
    curve, and the decaf group share the prime-order subgroup), so
    s = r + h*a mod q and the reduction of h are direct reuses.
  - libdecaf RFC 7748 X448 ladder (DH and public-key derivation).
  geryon writes IN-HOUSE the birational Edwards point layer (add, double,
  fixed- and variable-base scalarmul, encode/decode, on_curve, u_to_y)
  over gf, plus the thin XEdDSA composition. Nothing is delegated to
  decaf_ed448_sign/verify or to the decaf group's point ops
  (the D-XED-9 no-library-calls-Ed448 rule; the decaf point layer lives
  on d = -39081, the wrong curve, so it is unusable here regardless).

- **R3 - Curve constants (geryon-owned, cross-checked against D-XED-8).**
  p = 2^448 - 2^224 - 1, |q| = 446, b = 456, cofactor c = 4, nonsquare
  n = -1, hash = SHA-512, u_to_y(u) = (u + 1) * inv(u - 1) (the
  X448-compatible orientation of the D-XED-8 CORRECTION 2026-08-20; the
  cross-check against the ladder is what surfaced that amendment).
  The Edwards constant d = 39082/39081 mod p and the base point
  B = the Edwards image of Montgomery u = 5 under u_to_y (with the §6
  sign convention) are geryon's to define; libdecaf's EDWARDS_D = -39081
  is Goldilocks and is NOT used. B is computed once (constant-folded from
  the fixed u = 5, not secret) and its correctness is pinned by a self-KAT
  against the §6-derived encoding.

- **R4 - Sign path (calculate_key_pair analog, D-XED-5/6/10/11).** Given
  the clamped Montgomery scalar k (stored clamped at generation, D-XED-10)
  and public u:
  1. A_edwards = k * B on the birational curve (fixed-base scalarmul over
     gf); force the sign so A encodes with sign bit 0, negating a = k mod q
     to a = q - k when A's sign bit is 1 (D-XED-5/6). geryon follows the
     PAPER, never libsignal's s-bit-255 overload (D-XED-11); s stays
     canonical (< q, bit 255 = 0).
  2. r = hash_1(k_or_a-prefixed input || M || Z) reduced mod q, using
     SHA-512 from core/hash.c and the D-XED-8 hash_1 domain prefix (the
     57-byte LE encoding of 2^456 - 1 - 1); NEVER libdecaf's SHAKE, which
     stays gate-only.
  3. R = r * B (fixed-base scalarmul); encode R to 57 bytes.
  4. h = hash(R || A || M) mod q (SHA-512, no domain prefix per §6/D-XED-7,
     no pre-hashing).
  5. s = r + h*a mod q (public decaf scalar ops); enforce canonical s
     (< q, D-XED-5) on output. Signature = R || s, 114 bytes.

- **R5 - Verify path (map the public key, no pass-through, D-XED-9).**
  Given the Montgomery public u, R || s, and M:
  1. Map u to the Edwards A via u_to_y = (u + 1) * inv(u - 1) over gf
     (D-XED-8 CORRECTION 2026-08-20), reconstruct A with sign bit 0 (the
     sender forced it so;
     the Montgomery key carries no sign), and reject non-canonical or
     off-curve A (on_curve check over gf).
  2. Reject non-canonical s (s >= q) BEFORE any scalarmul (D-XED-5
     malleability strictness).
  3. h = hash(R || A || M) mod q.
  4. R_check = s*B - h*A (variable-base / double-base scalarmul over gf).
  5. Accept iff the 57-byte encoding of R_check equals R by CONSTANT-TIME
     byte-compare (const_memcmp), matching §3's cofactor-less strict
     compare exactly. No cofactor multiply, no batch/cofactor-cleared
     acceptance.

- **R6 - Encodings (D-XED-8).** Field/point y-coordinate serializes to 56
  bytes (SER_BYTES); the 57-byte XEd448 point encoding is that y plus the
  sign bit taken from gf_lobit in the top bit of byte 56. Scalars serialize
  to 56 bytes and s < 2^446 < 2^448, so its 57-byte integer encoding has
  byte 56 = 0. Signatures are 2b = 114 bytes (57 + 57). All match D-XED-8's
  recorded facts (57-byte points/integers, 114-byte signatures).

- **R7 - Zeroization.** secure_zero every secret intermediate before
  return on ALL exit paths (success and error): the scalar a (and any k
  copy), r, the SHA-512 states and their k/r-prefixed input buffers, and
  the projective coordinates of A_edwards and R that carry the secret
  scalars. Public values (u, R, A, h, the signature) are not secret. The
  X448 ladder's own scratch is zeroized by libdecaf; geryon zeroizes only
  what its composition allocates.

- **C1 - Correctness argument (Route B computes the §6 verification
  relation).** XEdDSA §6's xeddsa_verify accepts (u, M, R || s) iff
  s*B - h*A encodes byte-identically to R, where A = u_to_y(u) with sign
  bit 0, h = hash(R || A || M) mod q, and s is required canonical; there
  is NO cofactor multiplication (§5 states the cofactor-less choice
  explicitly). R5 computes exactly this relation, on exactly the §6 curve
  (d = 39082/39081, B = image of u = 5), with exactly the §6 scalar ring
  (q = the shared prime-order-subgroup order that decaf_448_scalar_*
  reduces to) and exactly the §6 hash (SHA-512 with the D-XED-8 prefixes).
  Because the point ops in R2 are implemented directly on the §6 curve
  over gf, there is no isogeny map and no cofactor factor anywhere between
  the scalars and the byte-compare: the accept predicate is literally
  "these §6 formulas on the §6 curve," so the relation is identical to §6
  by construction, not up to an isogeny/cofactor argument. Soundness of
  the strict byte-compare (no s-malleability, no cofactor-point aliases)
  follows from R4/R5's canonical-s and sign-bit-0 enforcement (D-XED-5).
  Route A would instead compute sB - hA in the decaf quotient of the
  4-isogenous Goldilocks curve and clear the cofactor, accepting the
  larger set { R : R = sB - hA + cofactor point }, which is a STRICT
  superset of §6's accept set and therefore a different (unsound-relative-
  to-§6) predicate; this is the concrete reason R1 rejects it. The
  sign-path A (R4 step 1, A = kB with sign forcing) and the verify-path A
  (R5 step 1, A = u_to_y(k*base)) are the same Edwards point for an honest
  signer, checked by the D-XED-5 cross-check KAT (sign-path-A equals
  verify-path-A).

- **Validation (unchanged from the framing entry, now bound to R1-R7):**
  RFC 7748 X448 + RFC 8032 Ed448 vectors through the validation gate
  (arithmetic trust, already green); XEd448 self-KATs and property tests
  (no external oracle, libsignal is 25519-only); the sign-path-A =
  verify-path-A cross-check (C1); the base-point B self-KAT (R3); the
  no-library-calls-Ed448 nm assertion (already green); the
  constant-time posture of the in-house point layer under the dudect
  targets (D-XED-12). Scratch prototype code, if written to settle API
  shape, is NOT merged; merged code waits for the implementation.

- **Cross-check outcome (task 3).** Every constant registered above
  (p, q, b, c, n, hash, u_to_y, prefix, encodings, signature size) was
  checked against D-XED-8 and agrees; no discrepancy, so no D-XED-8
  amendment. The one constant NOT in D-XED-8, the Edwards d and base
  point B, is new and geryon-owned (R3), flagged for its own self-KAT
  rather than inherited.

---

### D-XED-12 / D-XED-13 validation confirmed (2026-08-24)

Milestone close-out: the "Validation" clauses of D-XED-12 and D-XED-13
are no longer promises. Every item is realized by a landed, green test;
this entry records the mapping (what asserts what) and the timing
outcomes, without reopening either decision.

- **RFC 7748 X448 + RFC 8032 Ed448 vectors through the gate (arithmetic
  trust):** `tests/core/test_gate_448.c` and `test_gate_448_slow.c`. The
  Ed448 RFC-8032 direction runs `decaf_ed448_sign/verify` on the TEST
  side only, exactly the D-XED-12 gate scope.
- **XEd448 self-KATs and property tests (no external oracle):**
  `tests/core_hooks/test_xed448.c` -- `pinned_kat` (regression-pinned
  signature bytes), `sign_verify_round_trip`, `empty_message_round_trip`,
  `sign_is_deterministic_in_z`, `tamper_matrix_rejected`.
- **Sign-path-A = verify-path-A cross-check (D-XED-5 analog, R-C1):**
  `test_xed448.c::cross_check_sign_A_equals_verify_A`, ties the in-house
  §6 Edwards point layer to the RFC-7748 ladder across the scalar range.
  The geryon-owned base point B (R3) is exercised through the same suite
  (basepoint u = 5).
- **No-library-calls-Ed448 assertion (D-XED-9/12):**
  `tests/audit/nm_scope_448.sh`, green -- no production archive carries
  an undefined ref to `decaf_ed448_sign/verify`.
- **Descriptor discipline (one audit, both tiers):**
  `tests/audit/descriptor_discipline.sh` with
  `discipline_allowlist.txt`, green.
- **Timing targets (D-XED-12 bar: |t| < 10 over >= 1e6, 5e5/class),
  scoped by the maintainer principle to geryon-owned code that touches
  SECRET data** (XEd448 verify is all-public and the classical c448 X3DH
  responder adds no geryon secret-dependent branch beyond the X448 DH, so
  both are deliberately omitted; see the header of
  `tests/timing/targets_c448.c`):

  | Target | file | Sandy Bridge \|t\| | macOS \|t\| |
  |---|---|---|---|
  | `x448` (raw-ladder gate) | `targets_gate448.c` | ~1.16 | < 1.0 |
  | `x448_wrap` (gy_x448 wrapper) | `targets_c448.c` | 1.79-2.97 | < 1.0 |
  | `xed448_sign` (in-house sign) | `targets_c448.c` | 0.15 | < 1.0 |

  Note on `x448`: an earlier Sandy Bridge run climbed to ~6.3. That was
  DEMONSTRATED (not merely argued) to be a fixed-vs-random confounder:
  the class-B scalar was filled by a tiled 4-byte counter whose
  Hamming-weight profile differed systematically from the full-entropy
  fixed class-A scalar, which on pre-BMI2/ADX cores shows as a DVFS/power
  |t| climb with no control-flow leak. Replacing the fill with a
  full-range per-byte xorshift, leaving the compiled decaf ladder
  unchanged, collapsed |t| to ~1.16 -- the fingerprint of an input-
  distribution artifact, not a code leak (D-GEN-10). All three targets
  are under the bar on both platforms.
