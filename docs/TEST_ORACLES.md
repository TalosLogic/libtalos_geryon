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
  for the primitives, including the FIPS 203/204 ACVP vectors for ML-KEM and
  ML-DSA).
- **The hybrid protocol has NO external oracle.** The libsignal oracles are
  X25519-only: valid for the classical `geryon_c25519` protocol and the shared
  primitives only (`geryon_c448` has no libsignal oracle and rests on the RFC
  8032/7748 primitive vectors plus the shared clean-room protocol logic).
  geryon's hybrid suites are its own design (HYBRID_SPEC.md), so they are
  validated by HYBRID_SPEC-derived known-answer vectors, cross-checks of each
  mixed-in primitive against its FIPS/RFC vectors, and the ProVerif models under
  `formal/`, not by any cross-implementation oracle.
- **Standards vectors are not oracles.** The RFC 7748 (X25519/X448),
  RFC 8032 (Ed25519/Ed448), RFC 5869 (HKDF), RFC 2104/4231 (HMAC), and
  FIPS 203/204 ACVP known-answer vectors are fixed values published in a
  standard, not output regenerated from a copyleft reference. They carry
  no license entanglement and are NOT listed in the Oracles table below;
  only cross-implementation generators (libsignal) are oracles under the
  licensing boundary. The Oracles table is exhaustive for oracles, not
  for test vectors.
- **The classical 448 tier (`geryon_c448`) uses NO oracle.** libsignal
  is 25519-only, so there is no external oracle for X448 or XEd448. The
  tier is validated by RFC 7748 X448 and RFC 8032 Ed448 STANDARDS vectors
  through the libdecaf validation gate (arithmetic trust,
  `tests/core/test_gate_448*.c`), and by geryon-owned self-KATs and
  property tests for the in-house XEd448 composition
  (`tests/core_hooks/test_xed448.c`: regression-pinned KAT, the
  sign-path-A = verify-path-A cross-check tying the §6 point layer to the
  RFC-7748 ladder, round-trip, determinism-in-Z, and the tamper matrix).
  No XEd448 oracle exists or is needed (D-XED-12/13 validation).
- **The session layer (`session/` + `proto/`) uses NO oracle.** Sesame
  message-to-session association under header encryption and geryon's base-key
  dedupe are geryon's own realizations (D-SES-6), and no cross-implementation
  vector format exists for them. They are validated by the decision-derived
  behavior and by the integration and property tests that drive
  `include/geryon.h` end to end (`tests/api/`). libsignal's Sesame behavior is
  an INFORMATIVE reference only, never a linked or ported oracle.
- **The classical group vertical (`geryon_group`) uses NO copyleft oracle.**
  geryon's group KVAC/NIZK layer is clean-room and DELIBERATELY not
  zkgroup-byte-compatible (D-GRP-4: own Fiat-Shamir transcript, SHA-512
  challenge, domain separators, EncodeToG layout), so a zkgroup/poksho
  byte-compat or interop cross-check is impossible by construction and D-GEN-6
  forbids a compat parameterization. BOTH tiers are cross-checked by an
  INDEPENDENT reimplementation of the [CPZ] verify equations + Fiat-Shamir
  transcript (`tools/oracles/group_kvac/verify.py`), clean-room from the paper -
  NOT a copyleft generator, so it is described below but not listed in the
  licensing-boundary Oracles table. The oracle's independence is at the PROTOCOL
  layer (transcript, equation layout, verify relation); the group arithmetic is
  the same primitive geryon uses (255: libsodium ristretto255; 448: geryon's
  vendored libdecaf via a byte-array shim), validated separately (RFC 9496;
  RFC 7748/8032 and the libdecaf gate). Covering the 448 tier is not redundant:
  its transcript differs from the 255 tier in hash (SHAKE256 vs SHA-512), width,
  and reduction, and because geryon's prover and verifier share that transcript
  code, a 448-transcript bug would verify against itself and is invisible both
  to round-trips and to the 255 oracle. The statement-surface self-KATs
  (`tests/group/test_group_stmt_vectors.c`, both tiers) and the round-trip
  property tests remain the always-on checks; the oracle is the independent
  structural cross-check.
- **The quantum-safe group vertical (QSPGS, `geryon_qspgs` /
  `geryon_qsgroups_server`) uses NO oracle.** The authentication primitive is
  [CFG+]'s key-rerandomizable ML-DSA (KR-ML-DSA), and the oracle
  investigation found NO public [CFG+] authors' reference implementation and no
  third-party KR-ML-DSA implementation (only stock ML-DSA / FIPS 204 code, which
  geryon already links via liboqs). So the KATs are geryon's own reviewed
  self-generated vectors, checked against the [CFG+] Figure 3/4 equations, and
  every KAT signature is additionally cross-verified by the UNMODIFIED public
  liboqs `gy_mldsa<set>_verify` (that check ties the bespoke rerandomizing signer
  to the standard verifier with no shared code). The vectors are FROZEN as of
  the v1.5.0 close-out, pinned to geryon's reading of the
  [CFG+] 2026/453 preprint (D-QGS-10): `tests/core_hooks/krmldsa_kat.h`,
  `tests/qspgs/qspgs_keys_kat.h`, `tests/qspgs/qspgs_wire_kat.h`. No entry is
  added to the licensing-boundary Oracles table; the self-generated posture
  stands, revisited only if the authors later publish acceptably licensed code.

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

## `group_kvac.vec` (D-GEN-6, independent-implementation cross-check)

Validates the group credential proofs (pi_I, pi_A, pi_P, pi_BR, pi_BI;
GROUP_SPEC sections 5.1-5.3) on BOTH tiers against an INDEPENDENT
reimplementation of the [CPZ] verify equations and the sound-conjunction
Fiat-Shamir transcript. NOT a copyleft oracle:
`tools/oracles/group_kvac/verify.py` is clean-room from the [CPZ] paper and
GROUP_SPEC. It reconstructs each proof's equation layout itself
(generator-per-slot and each target expression), so a wrong-generator-in-slot
or a wrong target in geryon's assembly fails there even though it verifies
against geryon's own matrix.

The independence is at the protocol layer; the group arithmetic is the same
primitive geryon uses (255: libsodium ristretto255 via ctypes, challenge
SHA-512 -> reduce; 448: geryon's vendored libdecaf via the `decaf448_shim`
shared lib, challenge SHAKE256 114-byte squeeze -> `decode_long`). Both tiers
matter: the 448 transcript differs from 255 in hash, width, and reduction, and a
shared prover/verifier transcript bug is invisible to round-trips and to the 255
oracle. Not under the licensing boundary (no copyleft source linked, read, or
ported), so it is absent from the Oracles table above.

Producer: `tests/group/test_group_kvac_emit.c` (links `geryon_group`), emitting
per proof a `tier` tag, the NAMED atomic points, the proof `(V_j, r_i)`, and the
FS binding `(k, m, UserID, OtherInfo)`. The emitted server-secret scalars are
FIXED test keys, present only so the oracle can reconstruct the secret-derived
eq0 target Z the same way the [CPZ] section 5.2 verifier does.

Format: UTF-8 text, one `key=hexvalue` per line, records separated by a blank
line, `#` lines ignored. Ten records: five proofs x two tiers.

Regeneration (needs a geryon build; 255 verification needs Python 3 +
libsodium, 448 also the built `decaf448_shim`):

```
cmake --build build --target test_group_kvac_emit decaf448_shim
./build/tests/test_group_kvac_emit --dump > tests/vectors/group_kvac.vec
python3 tools/oracles/group_kvac/verify.py \
    --decaf448 build/libdecaf448_shim.so tests/vectors/group_kvac.vec
```

(The shim builds to the pinned path `<build>/libdecaf448_shim.so`, so the
command is a literal path, not a `find` glob; `GROUP_KVAC_DECAF448` works too.)

Reproducibility notes:

- Verification is a manual Python step (or the optional `test_group_kvac_oracle`
  ctest, which skips when the toolchain is absent), so core CI needs no extra
  toolchain. The emitter test (`test_group_kvac_emit`) SKIPs (exit 77) unless
  run with `--dump`.
- The proofs are randomized, so each emitter run yields a different (still
  valid) vector file. Record the SHA-256 here if/when a file is committed:
  `sha256(group_kvac.vec) = <fill in on commit>`.
- See `tools/oracles/group_kvac/README.md` for details.
