# PQ Primitive Decisions (core/mlkem.c, core/mldsa.c; M5)

**Scope:** the liboqs-backed ML-KEM / ML-DSA wrappers and everything
that validates them. Register conventions and the full index live in
[README.md](README.md). HYBRID_SPEC.md remains normative for all
protocol-level hybrid behavior; these entries cover the primitive
layer the spec does not reach (FIPS parameter knobs, build and
toolchain, KAT mechanics, timing policy).

All liboqs API facts cited here were verified against the pinned
submodule, not taken from documentation:
`OQS_KEM_keypair_derand` / `OQS_KEM_encaps_derand` (src/kem/kem.h),
`OQS_SIG_sign_with_ctx_str` (src/sig/sig.h),
`OQS_randombytes_custom_algorithm` (src/common/rand/rand.h), and the
mlkem-native `_ref` / `_x86_64` / `_aarch64` backend options
(.CMake/alg_support.cmake). First checked against 0.15.0 on 2026-07-07;
re-verified against the current pin (0.16.0) on 2026-08-17 - all four
entry points and the per-algorithm backend option names are unchanged
across the bump.

### D-PQ-1: ML-DSA signing parameters (ctx, hedged)

- **Spec gap:** FIPS 204 leaves two knobs the protocol spec did not
  originally set: the context string (0-255 bytes, default empty)
  and hedged vs deterministic signing.
- **Decision:** ML-DSA signs the identical `signed_data` bytes as
  XEdDSA (HYBRID_SPEC §5.2, unchanged) with
  `ctx = INFO("prekey")` (the §3.2 info string; `prekey` purpose row
  added). Verification supplies the same ctx; a ctx mismatch is an
  ML-DSA verification failure and maps to the `0x2` diagnostic.
  Signing is HEDGED (FIPS 204 default: fresh randomness per
  signature); the deterministic variant is not used anywhere.
  Implementation uses `OQS_SIG_sign_with_ctx_str`, never the bare
  sign entry point. The wrapper takes ctx as a parameter (Layer 1
  knows no protocol strings); kex/prekeys.c passes INFO("prekey").
- **Rationale:** ctx is the standardized mechanism for exactly this:
  the identity ML-DSA key signs prekeys and nothing else, and
  signed_data does not contain the suite id, so single-use and
  suite binding otherwise rest on structure lengths and the
  identity-per-suite policy, the two things D-GEN-3 forbids being
  load-bearing. The ctx makes both properties checked at
  verification time, costs zero wire bytes, and touches no
  classical-suite code (ML-DSA exists only in hybrid suites, so no
  M1 ripple). Message bytes stay identical across schemes, which is
  what the 0x1/0x2/0x3 diagnostics rely on. Hedged signing: fresh
  randomness resists fault and side-channel attacks on a long-lived
  identity key, and is philosophically consistent with XEdDSA's
  Z-randomized signing (D-XED-1); KAT determinism is injected from
  the test side (D-PQ-3), never by a production deterministic mode.
- **Validation:** ACVP sigGen/sigVer including ctx-bearing cases
  through the wrapper; negative test: signature valid under empty
  ctx must fail geryon verification (ctx actually load-bearing);
  the §11 dual-signature negative matrix unchanged.

### D-PQ-2: liboqs build and integration

- **Spec gap:** D-GEN-5 pins liboqs 0.16.0 as a submodule "NOT
  built until M5" and defers every build decision to M5.
- **Decision:**
  - Cache args: `OQS_USE_OPENSSL=OFF`, `OQS_BUILD_ONLY_LIB=ON`,
    `OQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_1024;
    SIG_ml_dsa_44;SIG_ml_dsa_87"` (exactly the closed suite set,
    D-GEN-7; no other parameter set exists in the binary).
  - Dispatch: geryon cache option `GERYON_OQS_DIST`, default ON for
    Release (`OQS_DIST_BUILD=ON`, runtime CPU dispatch) and OFF for
    Debug (pure-C `_ref` backends via the per-algorithm
    `OQS_ENABLE_*_x86_64/_aarch64=OFF` options), independently
    overridable (the timing configuration needs Release + pure C,
    D-PQ-4).
  - Integration: `ExternalProject_Add`, static,
    `CMAKE_POSITION_INDEPENDENT_CODE=ON`, linked PRIVATE into
    geryon_core - the same isolation pattern as libsodium
    (D-GEN-5), deliberately NOT `add_subdirectory`, so liboqs's
    option namespace and CMake policies stay out of ours.
  - RNG: `OQS_randombytes_custom_algorithm` registered in
    `gy_core_init` with a shim over `gy_random_bytes`. The callback
    returns void, so the shim ABORTS on RNG failure (a failing RNG
    must never return bytes). One getrandom-backed RNG for the
    whole library (D-XED-1); hedged ML-DSA randomness (D-PQ-1)
    draws through it; the D-PQ-3 test shim re-points the same hook,
    so tests exercise the production wiring mechanism.
- **Rationale:** OpenSSL OFF keeps libsodium the only symmetric
  provider and the dependency/licensing story true (liboqs would
  otherwise link OpenSSL silently); with it off, liboqs uses its
  internal SHAKE, which duplicates nothing (libsodium has no
  SHA-3). Release/Debug dispatch split means day-to-day development
  and CI exercise BOTH code paths with the full vector suites as a
  matter of course.
- **Validation:** full ACVP vector suites green on both dispatch
  configurations; the RNG shim's abort path covered by a death
  test; `gy_core_init` registration order covered by an init test
  (ties into the M0-L4 finding: after M5, init-before-use is
  structurally enforced for the PQ layer).

### D-PQ-3: FIPS 203/204 KAT mechanics (ACVP through the wrappers)

- **Spec gap:** HYBRID_SPEC §11.1 requires ACVP vectors "run
  through geryon's wrappers" without fixing the mechanics; ACVP
  vectors are derandomized (keyGen takes d,z / xi; encaps takes m;
  hedged sigGen takes rnd) while production entry points draw from
  the RNG.
- **Decision:** per-primitive seams, all test-build-only:
  - ML-KEM: `gy_mlkem_keypair_derand` / `gy_mlkem_encaps_derand`,
    thin over the liboqs `_derand` entry points, compiled ONLY
    under `GY_TEST_HOOKS` (the M0-L3 lesson: no test-only symbols
    with unconditional external linkage). Decaps needs no seam
    (deterministic); ACVP decaps VAL cases, including implicit
    rejection, run the production path unchanged.
  - ML-DSA: no derand API exists in liboqs, so KATs drive the
    `OQS_randombytes_custom_algorithm` hook (same mechanism as the
    production wiring, D-PQ-2) with a test shim feeding the
    vector's xi / rnd values as the draws. The draw pattern is
    asserted by the KATs themselves (a wrong assumption fails the
    vectors, not silently).
  - Provenance: vectors from the NIST `usnistgov/ACVP-Server`
    gen-val JSON (prompt + expectedResults), pinned to a named
    release tag, recorded in docs/TEST_ORACLES.md (name, version,
    license, generation command) like every oracle. Sets:
    ML-KEM-512/1024 keyGen + encapDecap (encaps AFT, decaps VAL);
    ML-DSA-44/87 keyGen + sigGen (hedged and deterministic groups)
    + sigVer (including ctx-bearing cases, which exercise the
    D-PQ-1 ctx plumbing). An in-tree converter script emits
    geryon's key=hex `.vec` format; only converted vectors are
    checked in (raw ACVP JSON is large), with script, source tag,
    counts, and file hashes in the vectors README.
- **Rationale:** derand entry points are the stable supported
  interface where they exist; the RNG hook is the only option for
  ML-DSA signing and doubles as a test of the production RNG
  wiring. Determinism lives entirely on the test side; production
  code paths never grow a deterministic mode (D-PQ-1).
- **Validation:** the KAT sets themselves, on both dispatch
  configurations (D-PQ-2); release-build symbol check: no
  `_derand` symbols exported when GY_TEST_HOOKS is off.
- **Amendment (2026-08-17, KAT scope = wrapper conformance, not
  primitive re-validation):** the KATs prove GERYON'S WRAPPER is wired
  correctly, NOT that liboqs's ML-KEM/ML-DSA math is correct - liboqs
  validates its own primitives upstream, and geryon does not re-validate
  a linked library's arithmetic (it runs only a handful of RFC 7748
  KATs through the libsodium-backed X25519 wrapper, not an exhaustive
  suite; see tests/core/test_x25519.c). ML-KEM/ML-DSA are treated the
  same way. So the "Provenance" bullet's full ACVP-Server import is
  SUPERSEDED: instead of pinning an ACVP-Server release as an oracle in
  TEST_ORACLES.md and bulk-converting keyGen/encapDecap/sigGen/sigVer
  suites, geryon checks in a SMALL inline KAT set sized to catch the
  three wrapper bugs a round-trip cannot: (1) wrong parameter set (a
  known ML-KEM-512 / ML-DSA-44 vector fails under 768/65), (2) seed
  plumbing (keypair_derand d||z order, encaps_derand m; the ML-DSA rnd
  draw pattern), (3) implicit-rejection passthrough (corrupt-ct decaps
  yields the expected pseudorandom ss as GY_OK, not an error). A few
  vectors per case, embedded inline like the RFC 7748 vectors, each
  citing FIPS 203/204 and its source; no oracle release pinned, no bulk
  converter, no TEST_ORACLES.md oracle entry. The derand seams and the
  ML-DSA RNG-hook mechanism above are unchanged - they are how a
  known-answer vector is driven; only the SET SIZE and provenance
  change. The heading "(ACVP through the wrappers)" now reads
  "wrapper-conformance KATs derived from FIPS 203/204 examples".
  ML-KEM-512 vectors live in tests/core_hooks/mlkem512_kat.h, extracted
  from the NIST ACVP-Server FIPS 203 example vectors (public domain,
  https://github.com/usnistgov/ACVP-Server, the ML-KEM-keyGen-FIPS203 and
  ML-KEM-encapDecap-FIPS203 gen-val directories); the raw JSON is not
  vendored, the header is the checked-in source of truth.
- **Amendment (2026-08-17, ML-DSA KAT = sigVer only, mirror ed25519):**
  ML-DSA sign is HEDGED (randomized), so - like test_ed25519, not
  test_x25519 - the SIGN path is not output-KAT'd (round-trip + hedged
  smoke instead) and only the VERIFY path gets a known-answer. liboqs
  0.16.0 exposes no explicit-rnd/derand ML-DSA sign entry (only
  sign_with_ctx_str), so a sigGen KAT would need shim-injected rnd and
  would re-validate liboqs's signing math regardless; it is dropped. The
  ctx (D-PQ-1) is pinned load-bearing by a ctx-negative matrix, and the
  one-32-byte-rnd-per-sign draw pattern by an op-count assertion, both
  behavioral (no vectors). ML-DSA-44 sigVer vectors live in
  tests/core_hooks/mldsa44_kat.h, extracted from the NIST ACVP-Server
  FIPS 204 ML-DSA-sigVer-FIPS204 gen-val directory (external interface,
  pure, ctx-bearing; public domain); raw JSON not vendored.

### D-PQ-4: PQ timing-harness policy

- **Spec gap:** the project constant-time policy requires timing tests on
  linked-library
  primitives but FIPS 204 explicitly PERMITS the ML-DSA
  rejection-loop iteration count to vary, which a naive two-class
  t-test flags as a leak; and the dispatch split (D-PQ-2) raises
  which build the harness measures.
- **Decision:**
  - Timing configuration: Release + pure C (`GERYON_OQS_DIST=OFF`)
    is THE timing configuration. Scoping rationale, recorded
    deliberately against the policy's "primary paths too" wording:
    timing a DIST build only measures whichever backend the CI
    CPU dispatches (nondeterministic coverage of mlkem-native's
    upstream-verified SIMD assembly, which carries its own
    assurance); Release + pure C deterministically measures the
    path where the real risk lives - C compiled by OUR toolchain
    at production optimization, where a compiler can reintroduce
    secret-dependent branches. Debug builds are never timed
    (unoptimized noise swamps dudect).
  - Targets (the timing harness, |t| < 10 over >= 1e6 samples):
    ML-KEM keygen; encaps (fixed vs random ek); decaps VALID vs
    CORRUPT ciphertext under a fixed dk - the implicit-rejection
    compare, the single most important PQ timing target (a leak
    here is a decryption oracle); ML-DSA keygen; ML-DSA verify
    (public inputs; included because it is cheap).
  - ML-DSA sign: BOTH dudect classes are hedged-random signings
    (class A fixed message / class B random message, both with
    live RNG), so the FIPS-204-permitted rejection-loop iteration
    count is identically distributed across classes and any
    |t| >= 10 indicates a genuinely secret-dependent leak, not the
    permitted loop variation. Sign is NOT excluded from the
    harness; exclusion-with-citation was considered and rejected
    as discarding real coverage.
- **Rationale:** the harness's two-class design cannot distinguish
  permitted from forbidden variance by magnitude, only by class
  construction; constructing the classes so permitted variance is
  class-independent is the only way to keep sign under test.
- **Validation:** the `timing` CTest label gains the six PQ
  targets; harness README documents the class construction and the
  FIPS 204 §3.5.1 (hedged signing) citation; CI timing matrix runs
  the Release + pure-C configuration.
- **Amendment (2026-08-19, time geryon composition only, not liboqs
  primitives):** the six dedicated primitive targets above (ML-KEM
  keygen / encaps / decaps, ML-DSA keygen / verify / sign) are
  DROPPED. Superseding principle: geryon's timing targets cover ONLY
  operations in geryon's own code that act on secret data; a
  linked-library primitive's constant-timeness is that library's
  responsibility, and liboqs validates its own (the pure-C reference
  code as much as the SIMD backend the original decision already
  set aside as "carrying its own assurance"). Re-timing liboqs under
  our harness re-validates liboqs's math, not geryon's, and the
  keygen paths in particular have no fixed-vs-random construction on
  the production API (the derand seams are GY_TEST_HOOKS-only, which
  the GY_TEST_HOOKS/GY_PRODUCTION_BUILD interlock forbids in the
  Release timing build this decision mandates).
  - What remains for the PQ timing coverage is ONE PROTOCOL-level
    target that measures geryon's OWN composition code over secret
    material, with the liboqs decapsulation inside it common-mode
    across both classes (so any |t| is attributable to geryon's
    glue, not the primitive): the hybrid X3DH responder, VALID vs
    CORRUPT KEM ciphertext in the initial-message prefix. It
    exercises geryon's per-pair PQ-first fusion HDH = HASH(kem_ss ||
    dh) and the SK/seed-triple KDF over the decapsulated shared
    secret. Implicit rejection means both classes return GY_OK on the
    identical path; the object under test is the fusion/KDF, not the
    decaps. The ct_spk is UNAUTHENTICATED plaintext in the prefix, so
    a network attacker can corrupt it and probe decaps timing: this
    is the genuinely attacker-reachable KEM-oracle surface.
  - A hybrid Double Ratchet receive target was CONSIDERED and
    dropped. The ratchet kem_ct rides inside the AEAD-sealed
    enc_header, so no attacker can deliver a corrupt-but-header-valid
    kem_ct without first breaking the header key: there is no
    attacker-reachable ratchet decapsulation oracle to leak, and
    constructing a validly-sealed-yet-corrupt kem_ct on the
    production timing build (no GY_TEST_HOOKS, per the interlock)
    would mean hand-re-sealing the header through HE internals to
    measure a non-reachable path. The shared PQ-first combiner code
    the X3DH target exercises is the same combiner the ratchet mix
    uses, so the constant-time property is covered where it is
    attacker-reachable.
  - The pre-existing libsodium primitive targets (x25519, xeddsa_sign,
    aead_tag) are a separate, earlier decision and are unaffected by
    this amendment.
  - Consequent doc changes: the project's Constant-Time Requirements
    wording ("libsodium/liboqs builds are included in the timing
    tests") is narrowed to exclude liboqs primitives from timing
    (liboqs stays in the full vector suites); the harness README
    documents the two protocol targets' class construction. The FIPS
    204 hedged-signing citation is no longer needed in the harness
    (no ML-DSA sign target remains).
