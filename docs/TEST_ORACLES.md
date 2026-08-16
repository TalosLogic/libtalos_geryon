# Test Oracles

External programs used ONLY to generate checked-in test vectors.  Under
geryon's licensing boundary, copyleft or source-available oracles (libsignal
is AGPL-3.0) run as separate processes producing vectors under
`tests/vectors/`.  Their code is never linked into geryon, read for
implementation, or translated line-by-line.  geryon's protocol code is
clean-room from the specifications; oracles only confirm agreement.

Regenerating any vector file requires updating the corresponding row here
(crate/tool version, exact command, and the output file and its hash).

## Coverage

- The primitives and the prescriptive protocol stages are vector-backed where
  an external oracle is prescriptive (XEdDSA and X3DH, below; RFC/NIST vectors
  for the primitives).
- **The session layer (`session/` + `proto/`) uses NO oracle.** Sesame
  message-to-session association under header encryption and geryon's base-key
  dedupe are geryon's own realizations (D-SES-6), and no cross-implementation
  vector format exists for them. They are validated by the decision-derived
  behavior and by the integration and property tests that drive
  `include/geryon.h` end to end (`tests/api/`). libsignal's Sesame behavior is
  an INFORMATIVE reference only, never a linked or ported oracle.

## Oracles

| Vector file | Oracle | Upstream + version | License | Generation command |
|-------------|--------|--------------------|---------|---------------------|
| `tests/vectors/xeddsa_libsignal.vec` | `tools/oracles/xeddsa_libsignal` | libsignal (`libsignal-protocol`), git tag `v0.96.4` (pin to the tag actually built) | AGPL-3.0 | `cd tools/oracles/xeddsa_libsignal && cargo run --release > ../../../tests/vectors/xeddsa_libsignal.vec` |
| `tests/vectors/x3dh_libsignal.vec` | `tools/oracles/x3dh_libsignal` | libsignal (`libsignal-protocol`), git tag `v0.96.4` | AGPL-3.0 | `cd tools/oracles/x3dh_libsignal && cargo run --release > ../../../tests/vectors/x3dh_libsignal.vec` |

## `xeddsa_libsignal.vec`

Validates `src/core/ed25519.c` (XEdDSA sign and verify) against libsignal's
Curve25519 XEdDSA.  Consumed by `tests/core/test_xeddsa_vectors.c`.

Format: UTF-8 text, one `key=hexvalue` per line, records separated by a blank
line, `#` lines ignored.  Two record kinds:

- Sign record (`sk`, `pk`, `msg`, `z`, `sig`): `gy_xeddsa_sign_z(sk, msg, z)`
  must reproduce `sig` byte-exact, and `gy_xeddsa_verify(sig, pk, msg)` must
  accept.  `z` is the 64-byte XEdDSA nonce captured from the signing RNG so
  the otherwise-randomized signature is reproducible.
- Verify record (`pk`, `msg`, `sig`, `valid`): `gy_xeddsa_verify` must accept
  iff `valid == 01`.

Counts: 256 sign records (message lengths varied 0..8192), 64 verify records
(half valid, half with a single flipped bit).

Sign-bit-0 keys only: libsignal deviates from the XEdDSA paper for keys whose
E = kB has sign bit 1 (it stores that sign in bit 255 of s); geryon follows the
paper and produces canonical signatures, so the two agree byte-exact only for
sign-bit-0 keys.  The oracle regenerates keys until the signature's s bit 255
is clear, so every emitted record is sign-bit-0.  This is a deliberate
divergence, not a bug; see docs/decisions/xeddsa.md D-XED-11.  Full byte-for-byte
libsignal compatibility is a non-goal (geryon already diverges on AEAD, KDF, and
the hybrid design).

Reproducibility notes:

- The oracle is NOT part of the CMake build; `test_xeddsa_vectors` reads only
  the checked-in `.vec`, so CI needs no Rust toolchain.  When the file is
  absent the test skips the oracle KATs (cross-validation still runs).
- Commit `tools/oracles/xeddsa_libsignal/Cargo.lock` alongside the vectors so
  regeneration is reproducible.
- Record the SHA-256 of the generated file here once it is committed:
  `sha256(xeddsa_libsignal.vec) = 6ce3ed393482d99a5e8b9cfd284840f45c350dabd701edc95251d5cbec9a20fb`.

## `x3dh_libsignal.vec` (D-GEN-6)

**Spike question:** can libsignal's public Rust API emit, for a synthetic
handshake, the five handshake private keys (IK_A, EK_A, IK_B, SPK_B, OPK_B),
the agreed X3DH secret SK, and the info string it used?

**Finding (partial, timeboxed):** libsignal exposes the per-DH agreement
(`PrivateKey::calculate_agreement`) but NOT the assembled X3DH master secret
or its HKDF info string.  Session establishment
(`initialize_alice_session` / the `SessionBuilder` path) returns an opaque
`SessionRecord`; no public accessor yields the pre-KDF secret or the label.
API surface examined (public, by name/signature, from docs.rs - never read for
implementation): `KeyPair::generate`, `KeyPair::{public_key, private_key}`,
`PrivateKey::serialize`, `PublicKey::serialize`,
`PrivateKey::calculate_agreement`.

**Decision (D-GEN-6):** no compat parameterization and no approximation, so the
SK / info portion of the check is DROPPED, not faked.  The oracle validates the
prescriptive DH stage only: DH1=(IK_A,SPK_B), DH2=(EK_A,IK_B), DH3=(EK_A,SPK_B),
DH4=(EK_A,OPK_B) (the X3DH specification, section 3), each computed with libsignal's X25519 and
reproduced by geryon's descriptor dh op.  The SK / F-prefix / zero-salt / HKDF /
info composition stays covered by the F-guard KAT and self-vectors in
`tests/kex/test_x3dh.c`; geryon's production `x3dh.c` is never
parameterized by a foreign info string.

Consumed by `tests/kex/test_x3dh_vectors.c`.  Format: UTF-8 text, one
`key=hexvalue` per line, records separated by a blank line, `#` lines ignored.
One record per handshake: `ik_a_sk`, `ek_a_sk`, `ik_b_pk`, `spk_b_pk`,
`opk_b_pk` (when `opk=01`), `dh1`..`dh4` (`dh4` when `opk=01`), `opk`
(`01`/`00`).  Counts: 16 records with an OPK, 8 without.

Reproducibility notes:

- The oracle is NOT part of the CMake build; `test_x3dh_vectors` reads only the
  checked-in `.vec`, so CI needs no Rust toolchain.  When the file is absent the
  test skips (prints a notice, no failure).
- Commit `tools/oracles/x3dh_libsignal/Cargo.lock` alongside the vectors.
- Record the SHA-256 of the generated file here once it is committed:
  `sha256(x3dh_libsignal.vec) = 1018279214cd430f39820c00c314f09d9a3b62d6d1a6fc55cb3ab30888c51546`.
