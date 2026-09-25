# geryon Quantum-Safe Private Group System Specification (QSPGS)

**Date:** 2026-07-08 (adopted same day); revised 2026-09-12
**Status:** ADOPTED (D-QGS-1, user-confirmed 2026-07-08) as
geryon's SECOND group type, side by side with the classical
[CPZ] type: this document governs the quantum-safe type serving
the HYBRID suites; the classical suites keep the [CPZ] type
(GROUP_SPEC.md), whose development continues unchanged.
**Revision 2026-09-12 (D-QGS-1 / D-QGS-4 amendments, D-QGS-11):**
the authentication primitive is [CFG+]'s own key-rerandomizable
ML-DSA (KR-ML-DSA, §3), implemented over liboqs; the earlier
voleith membership layer is WITHDRAWN from this type. Its design
and the measurements that retired it are retained in the project's
design history. Decided entries:
D-QGS-1, 2, 4, 5, 9, 11 in docs/decisions/qsgroups.md (2, 3, 5
superseded as written; see their status lines). As of the v1.5.0
close-out the register is DECIDED end to
end: D-QGS-6/7/8/10/12 are all resolved, and the D-QGS-10 vector
freeze is executed, pinning geryon's reading of the [CFG+] 2026/453
preprint (a later revision is a D-QGS-12 format_version bump, not a
silent re-cut).
**Normative basis (if adopted):** Connell, Faller, Guenther,
Hesse, Lyubashevsky, Schmidt, "A Quantum-Safe Private Group
System for Signal from Key Rerandomizable Signatures", eprint
2026/453 (docs/references/signal/2026-453.pdf). Cited as [CFG+]
with section numbers. Authorship note: two authors are Signal
Messenger staff; this is Signal's own proposed successor to
[CPZ], NOT third-party work (the D-GRP-9 "third-party" wording
is a recorded error to fix).
**Revision caution:** the paper is dated 2026-05-18 and has no
published revision history, deployed implementation, or
independent review of its UC proofs yet. Any adoption decision
must pin a revision (D-GRP-9 discipline) and must keep KATs
unfrozen until the text stabilizes.

This document specifies membership machinery only; group
MESSAGING remains fan-out over the pairwise messaging sessions,
exactly as in GROUP_SPEC.md §1.1.

---

## 1. Overview

### 1.1. Design summary

- [CPZ] makes the server the gatekeeper: KVAC credentials and
  verifiable deterministic encryption let the server validate
  every entry without reading it. [CFG+] inverts this: CLIENTS
  validate the group state; the server checks only that whoever
  writes an entry is the member authorized to write it ([CFG+]
  §1.1).
- That inversion removes every heavy primitive from the core: no
  KVACs, no verifiable encryption, no OPRFs, no hash-to-group,
  no EncodeToG, no zero-knowledge proofs. The core needs only
  AEAD, PKE, a KDF hierarchy, statistically hiding commitments,
  and ONE public-key primitive: a key rerandomizable signature
  scheme (KRS, §3).
- Group state is AEAD-encrypted under a group key gk shared by
  members; the server stores only ciphertexts, per-member
  pseudonym verification keys, an admin flag, and version
  numbers. The group state is therefore HNDL-safe by
  construction: no classical public-key encryption protects
  anything long-lived ([CFG+] §1.1, §3.2).
- Members act under per-group pseudonym keys derived by key
  rerandomization from a static base key. Other members can
  recompute every member's pseudonym key (in-group
  traceability); the server sees unlinkable pseudonyms
  (cross-group privacy) ([CFG+] §3.2).
- Admins sign the ENTIRE group structure on every core change
  (integrity against a malicious server, no rollback); regular
  members append individually signed lines to an appendix that
  admins reconcile ([CFG+] §3.2).
- Group key rotation is a first-class operation
  (RotateGroupKey); member removal rotates gk and re-encrypts,
  closing [CPZ]'s accepted departed-member/server collusion
  exposure ([CFG+] §3.3, §7).

### 1.2. Relationship to [CFG+] and to GROUP_SPEC.md

Sections marked "transcription" would adopt [CFG+] normatively
with geryon naming and encoding conventions; sections marked
"geryon decision" fill implementer gaps, each backed by a
D-QGS register entry if adoption is confirmed.

Relationship to the D-GRP register (per D-QGS-1: BOTH registers
active, two group types side by side):

- The D-GRP register continues to govern the classical [CPZ]
  type unchanged, including D-GRP-1's EncodeToG work item.
- PRECEDENT SHAPES reused by this document: D-GRP-2 (server ops
  stateless, separate target, policy with the deployer; §7),
  D-GRP-3 (tier pairing and full-suite_id binding; §2.1),
  D-GRP-7 (rederive-only storage model; maps directly, gk and
  muk replacing GroupMasterKey; §9), D-GRP-9 (pin-and-oracle
  discipline, re-applied to [CFG+] at D-QGS-10; §12).
- The earlier plan (hybridizing [CPZ] proofs) is replaced by
  this type; D-GRP-10 is closed as withdrawn and D-GRP-11 is
  decided as the classical type's documentation posture (both
  2026-07-10, groups.md), with the HNDL concern answered
  structurally here (§10.1).

### 1.3. Roles and naming

- User: a registered account (UID, a FIXED 16-byte identifier as
  in GROUP_SPEC.md §1.3; opaque to the group crypto). The width is
  mandatory, not illustrative (GY_QSGROUP_UID_LEN, enforced with
  GY_ERR_ARG): a single width keeps every sealed member entry the same
  length, so a corrupt server learns member indices only, never a
  per-entry length class (SEC-v1.5.0 LOW-2, §10.2 item 6). An
  application whose native account id is not 16 bytes hashes it to this
  width, as the classical group's EncodeToG UID does.
- Member / admin: a user present in a group's member list; the
  admn flag is server-visible and marks admin privileges
  ([CFG+] §3.2). Invited member: an entry in the invite queue.
- Acquaintance: a user whose (UID, uk) another user has learned
  and validated (GrantAcquaintance); only acquaintances may be
  added to groups ([CFG+] §4.1).
- Server: stores group structures, checks pseudonym signatures
  and admin flags, enforces fetch tokens. It holds NO long-term
  secret parameters for the core system (contrast [CPZ]
  ServerSecretParams).

### 1.4. Provider boundary (D-QGS-1 as amended 2026-09-12, D-QGS-11)

1. Authentication and attribution: KR-ML-DSA (§3), [CFG+]'s
   own primitive, over liboqs. Verification is the UNMODIFIED
   public liboqs ML-DSA verifier. Base keygen, RandVK, RandSK,
   and the 2*beta signing loop are geryon composition glue over
   liboqs' mldsa-native internal routines (§3.3); no polynomial
   arithmetic is written in geryon.
2. core/ provides AEAD, KDF, and RNG for the group state; the
   join PKE is the suite KEM hybrid per HYBRID_SPEC
   conventions.
3. libtalos_schnorr plays NO role in this group type; its group
   work items (EncodeToG and the KVAC machinery) belong to the
   classical [CPZ] type per D-GRP-1 and continue there.
4. libtalos_voleith plays NO role in the baseline type. It
   remains the recorded candidate for the tangential
   anonymous-credential side system [CFG+] §6 leaves
   unspecified (liveness checks, registration proofs, §6.4) and
   for the v2 first-flight messaging auth. The 2026-07-08
   voleith-only design was measured and retired
   (130 KB to 845 KB and
   0.3 s to 1.2 s per group operation at the 128-bit tier
   versus 7.5 KB and about 2 ms for KR-ML-DSA, and
   multi-megabyte proofs at the 448 tier).

---

## 2. Tiers, Parameters, and Hashing

### 2.1. Tier pairing and parameters (D-QGS-11 item 1, DECIDED 2026-09-12; supersedes the D-QGS-2 voleith table)

Inherits the D-GRP-3 posture (full-suite_id binding) and the
project's strength-move-together rule. This group type serves
the HYBRID suites only; classical suites use the [CPZ] type
(GROUP_SPEC.md). No runtime negotiation, no cross-suite or
cross-type group membership; same-curve classical/hybrid
identities are NOT group-compatible.

Hybrid suites (KR-ML-DSA, [CFG+] Table 1 rows for the levels
the suites already carry):

| suite | KRS | eta | beta (verify) | 2*beta (sign) | expected attempts | vk_base | sk_base | vk_psdn | signature |
| ----- | --- | --- | ------------- | ------------- | ----------------- | ------- | ------- | ------- | --------- |
| geryon_h25519_512 | KR-ML-DSA-44 | 2 | 78 | 156 | ~18 | 2,976 | 800 | 1,312 | 2,420 |
| geryon_h448_1024 | KR-ML-DSA-87 | 2 | 120 | 240 | ~15 | 5,920 | 1,472 | 2,592 | 4,627 |

(bytes; layouts in §3.3.) The [CFG+] level-3 row (ML-DSA-65) is
not used: no geryon suite carries ML-DSA-65.

Base-key independence invariant (D-QGS-2 item 5 carried to
D-QGS-11): sk_base is fresh randomness (a 32-byte seed from
core/ rng.c expanded per §3.3), NEVER derived from classical
key material (Shor recovers curve scalars from public keys,
making any such derivation quantum-dead) and never derived from
the identity's ML-DSA prekey-signing key either (distinct
lifecycles: the base key is the linkage root across every group
the user joins and is shared only with acquaintances).

Suite binding: every signed structure, KDF label, and
commitment binds app_id || protocol_version || suite_id
(D-GEN-3); for every KR-ML-DSA signature the suite string rides
the FIPS 204 context string exactly as for prekey signatures
(D-PQ-1; carries over D-QGS-5 item 6).

### 2.2. Key hierarchy (transcription of [CFG+] §4, Fig. 6)

User keys:

- muk: main user key, random, 2 kappa bytes per tier. Root of
  the user hierarchy.
- uk = KDF(muk, "uk@" || ep): per-epoch user key, shared with
  acquaintances and fellow group members. Epoch bump (Refresh)
  implements acquaintance reset / blocking.
- acq = KDF(uk, "ACQ-Tag"): acquaintance tag, deposited with
  the server at registration, signed by the personal key.
- expKey = KDF(uk, "EXP-Key"): exporter key for application
  material (profile-data key, send tokens; [CFG+] §6.5).
- (skpers, vkpers): a standard (non-rerandomizable) signature
  pair anchoring registration ([CFG+] Figure 7, registered with
  the paper's idealized PKI). DECIDED at D-QGS-6 item 2,
  following [CFG+] footnote 7: geryon instantiates it with the
  hybrid identity's signing capability, the same XEdDSA +
  ML-DSA pair-signing used for prekeys (both must verify), under
  dedicated QSPGS context strings; no new key. It signs exactly
  two objects: (vkbase, acq) at RegisterUser and (UID, uk, GID)
  inside the invite acceptance. This is a recorded exception to
  the identity-keys-sign-prekeys-only rule (CLAUDE.md).
- (skbase, vkbase): the KR-ML-DSA base pair (§3), long-lived,
  one per hybrid identity, generated at identity creation from
  fresh randomness and held in the custody seam (§9). NOT
  derived from any other key (§2.1 invariant).

Group keys:

- gk: group key, random, 2 kappa bytes, refreshed on every
  major version (rotation, removal).
- (ek, rrs) = KDF(gk, "SUB-KEY"): AEAD key for the group
  structure, and the rerandomization seed.
- (ipk, isk) = PKE.KeyGen(...): join-request keypair, derived
  from group key material; join requests are encrypted to ipk.
  In geryon the PKE is the suite KEM (hybrid suites: ECDH +
  ML-KEM per HYBRID_SPEC conventions). DECIDED
  (2026-09-13; resolves the D-QGS-2 TODO): (ipk, isk) is a single
  GROUP-WIDE keypair rederived from gk by every member (nothing
  derived is stored, section 9), which is what preserves
  anonymity, an inviter seals to one group key and any member
  opens it. isk has two secret halves: a curve (X25519/X448)
  scalar and an ML-KEM decapsulation key. They are derived from
  TWO INDEPENDENT domain-separated HKDF branches off gk (labels
  qspgs-join-ec, qspgs-join-mlkem): PRK = Extract(salt = gy_info
  domain, ikm = gk), out = Expand(PRK, domain). The curve public
  is scalar * base (RFC 7748 base point); the ML-KEM keypair is
  FIPS 203 KeyGen_internal over a 64-byte seed. The independence
  is a SECURITY requirement, not a convenience: HKDF-Expand is
  one-way, so a quantum break of one primitive (recovering that
  secret) reveals neither the PRK nor the other branch; the
  hybrid guarantee therefore holds at the KEY level, not only at
  the per-seal fusion. Feeding one shared raw seed to both
  keygens would collapse this and is forbidden. The join seal is
  the HYBRID_SPEC PQ-first KEM-DEM (fresh ephemeral ECDH + one
  ML-KEM encapsulation to ipk, fused kem_ss || dh into an AEAD
  key, ChaCha20-Poly1305 over the payload with the KEM transcript
  as associated data). Implemented in src/qspgs/qspgs_join.c; the
  ciphertext byte layout is frozen with the rest of the wire in
  section 8.
- Pseudonym keys: rho = KDF(rrs, "rerand@" || UID), 64 bytes
  (the ExpandS seed width, D-QGS-11 item 8);
  skpsdn = RandSK(skbase, vkbase, rho), vkpsdn = RandVK(vkbase,
  rho). Every member recomputes every vkpsdn from rrs; skpsdn
  is derived on demand and never stored (§3.3, §9).

Exact label registry (D-GEN-3 strings, length prefixing) lands
with the §5 transcription and freezes at first published KATs.

The implementation (2026-09-13) lands the user- and group-key
derivations in `src/qspgs/qspgs_keys.c` (target `geryon_qspgs`,
the second group vertical) with the registry in
`src/qspgs/qspgs_labels.h`. Every step is the extract-then-expand
HKDF over the tier hash (D-QGS-11, chosen 2026-09-13):
`domain = gy_info(suite_id, purpose)`;
`PRK = HKDF-Extract(salt = domain, ikm = key)`;
`out = HKDF-Expand(PRK, info = domain || var, L)`, where the
variable field, when present, is `be64(ep)` (uk) or a one-byte
length-prefixed UID (rho). The [CFG+] labels map to the D-GEN-3
purpose slugs `qspgs-uk` (uk@||ep), `qspgs-acq` (ACQ-Tag),
`qspgs-exp` (EXP-Key), `qspgs-sub` (SUB-KEY -> ek||rrs), and
`qspgs-rerand` (rerand@||UID). Widths: uk/acq = 2 kappa (32/56);
expKey/ek/rrs = 32; rho = 64. Pseudonym keys wrap
`gy_kr<set>_randvk` / `randsk` under a suite-generic sk type.
These bytes FREEZE at the key-hierarchy KATs.

The implementation (2026-09-13) adds: (a) the base-pair
generation entry (`gy_qspgs_base_keygen[_seed]`, wrapping
`gy_kr<set>_keygen_base`), with the §2.1 base-key independence
invariant asserted by KAT (a fixed seed fixes vkbase regardless
of muk); (b) skpers (task 4) as dual-scheme (XEdDSA + ML-DSA,
both-or-abort) sign/verify over caller-supplied object bytes in
`src/qspgs/qspgs_pers.c`, following the custodian hybrid-cert
convention (gy_info string prepended for XEdDSA, passed as the
FIPS 204 ctx for ML-DSA). Its two frozen context strings are now
registered: `qspgs-reguser` signs (vkbase, acq) at RegisterUser,
`qspgs-invaccept` signs (UID, uk, GID) in the invite acceptance.
The OBJECTS' byte layouts remain a D-QGS-7 item; only the context
labels freeze. (c) The custody decision (see §9): skbase / muk /
gk live in a dedicated `gy_qspgs_store` (record-kind enum in
`src/qspgs/qspgs_store.h`), the app-sealed keyed-blob analogue of
the classical `gy_group_store` (D-GRP-7), NOT the messaging
custodian's sealed idmat. This keeps the v1.0.0-frozen messaging
custody format untouched and needs no migration (QSPGS is new).
The `*_stored` persistence wrappers over that store LANDED
2026-09-14 (D-QGS-8), exactly as the classical store
landed after its key hierarchy.

The implementation (2026-09-13) lands the (ipk, isk) join
keypair and its hybrid KEM-DEM public-key encryption in
`src/qspgs/qspgs_join.c` (the deferred D-QGS-2 item, above), with
the registry labels `qspgs-join-ec`, `qspgs-join-mlkem`, and the
per-seal fusion label `qspgs-join-kem`. It required promoting the
deterministic ML-KEM keygen (`gy_mlkem{512,1024}_keypair_derand`)
from a `GY_TEST_HOOKS` seam to the production core/ API, since
every member must rederive the identical keypair from gk; the
derandomized encaps seam stays test-only (the seal encapsulates
with fresh randomness). The remaining D-QGS-7 items (the section 4
structure byte layouts, the msg_type, C_UID and H(vkpsdn) bytes)
freeze with the wire codec in the next increment.

### 2.3. Derivation conventions (D-QGS-3 as amended: leaf layout MOOT; conventions carried)

The 2026-07-08 leaf-preimage design (sk || uid || gid ||
join_counter || role_flags || expiry, eight V3 role fields, the
25519 width budget) belonged to the voleith membership layer
and is SUPERSEDED / MOOT (D-QGS-3 status line). Under
KR-ML-DSA there is no leaf: roles are the server-visible admn
flag plus member-entry fields (§4), and group binding is the
per-group rho. What carries over:

1. All KDF steps use core/ HKDF with the tier hash (SHA-256 on
   25519 tiers, SHA-512 on 448 tiers) and D-GEN-3
   domain-separated labels; no SHO, no new hash machinery.
   AEAD for the group structure: the group's pinned field AEAD
   (header `aead_id`, SEC-v1.5.0 INFO-6), ChaCha20-Poly1305 by
   default (per project policy) or AEGIS-256 if the admin selected
   it at Create; fixed for the group's life.
2. Label registry (open under D-QGS-11, freezes with the first
   KATs): the KDF labels of §2.2 ("uk@", "ACQ-Tag", "EXP-Key",
   "SUB-KEY", "rerand@"), the fixed-A label
   `"geryon-QSPGS-KR-ML-DSA-<44|87>-v1"` (§3.3), and the
   per-operation ML-DSA context strings (suite string plus an
   operation tag; D-QGS-7).
3. Commitments: [CFG+] wants statistically hiding commitments
   for C_UID; a hash-based commitment is computationally hiding
   only (Grover-bounded, practically moot, formally a deviation
   to record). With no in-circuit constraint remaining, the
   choice is free; the hash-based commitment with the deviation
   recorded stays the default (D-QGS-7).

---

## 3. Key Rerandomizable Signatures (NORMATIVE transcription of [CFG+] §2; revised 2026-09-12)

This section is normative as of 2026-09-12: the QSPGS type's
authentication is the KR-ML-DSA instantiation of §3.3
(D-QGS-1 / D-QGS-4 amendments, D-QGS-11). §3.2 (Schnorr) is
informative only: the classical suites use the [CPZ] type and
never run KRS.

### 3.1. Definition

Sigma = (Gen, Sgn, Vfy, RandVK, RandSK) with:

- Correctness: (RandSK(s, rho), RandVK(t, rho)) is a valid
  signing pair for the base pair (s, t) and any randomizer rho.
- Unlinkability (UL-CMA, [CFG+] Def. 2): rerandomized
  verification keys (with signatures under them) are
  indistinguishable from fresh keys; the server cannot link
  pseudonyms to base keys or across groups.
- Unforgeability under rerandomized keys (UFRK, [CFG+] Def. 3):
  no forgery under the base OR any rerandomized key, even for
  adversary-chosen randomizers.

Perfect rerandomizability (Fleischhacker et al.) is explicitly
NOT required; unlinkability suffices ([CFG+] §2.1).

### 3.2. Schnorr instantiation

Gen: (x, y = g^x). RandSK(x, rho) = x + rho. RandVK(y, rho) =
y * g^rho. Standard Schnorr signing and verification on the
rerandomized pair ([CFG+] §2, folklore construction). On both
geryon tiers this is existing libtalos_schnorr functionality.

### 3.3. KR-ML-DSA instantiation (NORMATIVE; D-QGS-11, DECIDED 2026-09-12)

[CFG+] §2, Figures 3 and 4, built ON the FIPS 204 standard. The
scheme, in the paper's terms, then geryon's instantiation.

**The scheme ([CFG+] Figures 3 and 4).**

- Gen: as ML-DSA KeyGen except that A is expanded from a FIXED
  public seed rho_A (a common reference string, [CFG+] Figure 4
  caption) rather than a per-key rho, and the base verifying key
  keeps the FULL t (the paper's "entire y = Bx", [CFG+] §2):
  rounding is deferred to RandVK.
- RandSK(sk_b, rho): (s1', s2') = ExpandS(rho) from the
  secret-key distribution S_eta; sk_r = (rho_A, K, tr,
  s1_b + s1', s2_b + s2', t0_r), Figure 4 lines 34-39.
- RandVK(vk_b, rho): t_r = t_b + A s1' + s2' where t_b is
  reconstructed EXACTLY as t1 * 2^d + t0 (Figure 4 line 42),
  then Power2Round (line 44); vk_r = (rho_A, t1_r) has standard
  ML-DSA size and shape (line 45).
- Sgn: standard ML-DSA signing with the rejection bounds at
  2*beta (the rerandomized secret has coefficients in
  [-2eta, 2eta]), squaring the expected repetition count
  ([CFG+] Table 1: about 18 / 15 at levels 2 / 5; about 5x the
  standard's signing time, still milliseconds).
- Vfy: EXACTLY standard ML-DSA verification, unchanged,
  including the bound ||z|| < gamma1 - beta ([CFG+] Figure 3
  line 33). The paper deliberately keeps the verifier and
  absorbs the +beta into the extracted SelfTargetMSIS solution
  (under 1 bit of loss; [CFG+] §2.2, Theorem 1; identical
  SIS-estimator output). Unlinkability is MLWE (Theorem 2).

**Full-t handling (the correctness requirement).** RandVK and
RandSK operate on the UNROUNDED base t. geryon's base verifying
key therefore carries BOTH halves of the standard rounding,
t1 (10-bit coefficients, the standard pk packer) and t0
(13-bit, the standard sk-side t0 packer), and reconstructs
t = t1 * 2^d + t0 losslessly before adding A s1' + s2'
(Figure 4 line 42 verbatim). This is byte-for-byte what the
paper's Figure 4 requires and introduces no new packer;
rounding happens exactly once, on t_r, inside RandVK / RandSK.
The base verifying key is never given to the server; it is
shared with acquaintances only ([CFG+] AcqRec, §2.2).

**geryon instantiation (D-QGS-11 items 1 to 9).**

1. Tiers: KR-ML-DSA-44 on geryon_h25519_512, KR-ML-DSA-87 on
   geryon_h448_1024 (§2.1 table).
2. Provider boundary: Vfy is `gy_mldsa44_verify` /
   `gy_mldsa87_verify` (the public liboqs verifier; core/
   mldsa44.c / mldsa87.c). Gen, RandVK, RandSK, and Sgn are
   geryon glue over liboqs' mldsa-native INTERNAL routines
   (matrix expansion, eta / gamma1 samplers, NTT, pointwise
   products, power2round, the t1 / t0 / eta / z / w1 packers,
   hint packing, SHAKE via liboqs' fips202 shim), reached by
   namespaced symbol; geryon writes no polynomial arithmetic.
3. Backends: the glue is compiled ONCE PER mldsa-native BACKEND
   (ref / x86_64 / aarch64) against that backend's header tree
   with the identical `-DMLD_CONFIG_PARAMETER_SET` /
   `-DMLD_CONFIG_FILE` and target flags liboqs used, so struct
   layouts and symbols match the liboqs archive. A per-set
   dispatcher caches a function-table pointer on first call
   using liboqs' public `OQS_CPU_has_extension` with the SAME
   predicate liboqs' own `OQS_SIG_ml_dsa_<set>_*` wrappers use
   (AVX2 + BMI2 + POPCNT on x86_64, NEON on aarch64), under the
   same `OQS_ENABLE_SIG_ml_dsa_<set>_<arch>` / `OQS_DIST_BUILD`
   macros. Which backends are built follows GERYON_OQS_DIST
   exactly as LIBOQS_BACKEND_ARGS does.
4. Pin: the liboqs tag `_Static_assert` in core/pqinit.c
   (D-PQ-2 / D-GEN-5) guards the internal-symbol dependency; a
   bump re-runs the §12 KATs and any renamed internal fails
   the BUILD.
5. Fixed A: rho_A = SHAKE256-32 of the ASCII label
   `"geryon-QSPGS-KR-ML-DSA-<44|87>-v1"` (no length prefix; the
   label is the whole input), mirroring [CFG+]'s
   `H("PQ-Private-Groups-RerandSig-ML-DSA-65-v1")`. Every base
   and rerandomized key carries rho_A in its rho field; RandVK
   and RandSK REJECT (GY_ERR_ARG) a base key whose rho field is
   not rho_A, by constant-time comparison.
6. Byte layouts (all multi-byte fields are the FIPS 204
   packers, unchanged):
   - vk_b = rho_A (32) || t1 (K x 320) || t0 (K x 416):
     2,976 bytes (44) / 5,920 (87).
   - sk_b = s1 (L x 96, eta packer) || s2 (K x 96) || K_b (32):
     800 (44) / 1,472 (87). Base coefficients are in
     [-eta, eta], so the standard eta packer applies.
   - vk_r: byte-standard ML-DSA public key (1,312 / 2,592).
   - Signatures: byte-standard (2,420 / 4,627).
   - The [CFG+] §3.2 store-H(vk_psdn) optimization is a §8 /
     D-QGS-7 item.
7. sk_r is IN-MEMORY ONLY and BACKEND-AFFINE: it holds s1_r,
   s2_r, t0_r in NTT domain plus rho_A, tr = SHAKE256-64(vk_r),
   and K_r. It is never serialized: s_r coefficients reach
   2*eta (beyond the eta packer's width) and native backends
   keep a backend-specific NTT coefficient order. RandSK is one
   matrix product and is re-run from (sk_b, vk_b, rho) on
   demand; the dispatcher's fixed-after-first-call backend is
   what makes in-memory holding safe. Opaque blob sizes:
   12,544 (44) / 23,680 (87) bytes, 32-byte aligned.
8. Derivations [CFG+] leaves open, and one DELIBERATE deviation from
   FIPS 204's byte layout (D-QGS-13 E8.7): ExpandS is FIPS 204's (eta
   sampler, nonces 0..L+K-1) over the 64-byte rho. The signing seed K
   is carried UNCHANGED from the base key into sk_r, exactly as [CFG+]
   Fig. 4 line 39 ("sk_r reuses K_b"): no per-pseudonym K is derived.
   This is safe and needs no per-pseudonym separation because the
   hedged nonce rho' = H(K || rnd || mu) already binds the pseudonym
   through mu = H(tr || ...), tr = H(vk_r); it also keeps KR-ML-DSA
   squarely inside the [CFG+] Theorems 1/2 construction (a prior
   geryon variant, K_r = H(K_b || rho), was reverted in v1.5.0 as an
   unproven divergence with no security benefit). Base Gen squeezes
   H(seed || K || L) from a 32-byte seed and takes rhoprime =
   bytes [0, 64), K_b = bytes [64, 96), with NO rho slot: FIPS 204
   / Fig. 3 line 02 reserve a 32-byte rho at bytes [0, 32) and take
   rho_s from [32, 96), but A is fixed to rho_A here so no per-key
   rho is sampled and the slicing shifts down by 32 bytes. This one
   remaining deviation from FIPS 204's offsets is deliberate and
   stated so the KAT bytes are reproducible. Signing is hedged
   (FIPS 204 default, D-PQ-1) with the context string as a parameter
   (§2.1 suite binding); mu = H(tr || 0x00 || |ctx| || ctx || M),
   rhoprime = H(K || rnd || mu) as in FIPS 204 Algorithm 2.
9. Attempt cap: 4,096 signing attempts, then GY_ERR_CRYPTO
   (mldsa-native's 814 floor assumes 4.25 expected attempts;
   4,096 gives failure below e^-227 / e^-273 at 18 / 15).

Timing: the rejection-loop count is the only permitted timing
variation (FIPS 204 discipline, project policy). All
secret-dependent arithmetic is inside liboqs routines (D-PQ-4:
liboqs validates its own constant-timeness); geryon's glue
branches only on public quantities (rejection outcomes, which
FIPS 204 §5.5 treats as public, argument checks, fixed lengths).

Public API shape (core/krmldsa44.h, krmldsa87.h; mirrors
mldsa44.h / mldsa87.h conventions): `gy_kr<set>_keygen_base`
(hedged) and `_keygen_base_seed` (deterministic, KATs);
`gy_kr<set>_randvk(vkr, vkb, rho)`; `gy_kr<set>_randsk(rsk, skb,
vkb, rho)` and `gy_kr<set>_rsk_clear`; `gy_kr<set>_sign(sig,
rsk, msg, mlen, ctx, ctxlen)`; `gy_kr<set>_verify(sig, vkr,
msg, mlen, ctx, ctxlen)`. A first UNCOMPILED, UNTESTED draft of
exactly this instantiation exists (src/core/krmldsa/,
src/core/krmldsa44.{c,h}, krmldsa87.{c,h},
cmake/krmldsa.cmake); D-QGS-11 is its authority, not the
reverse.

### 3.4. Standalone-PQ posture (D-QGS-4 as amended 2026-09-12)

The group authentication layer is KR-ML-DSA, standalone: no
voleith rider, no Schnorr rider. Its assumption (MLWE /
SelfTargetMSIS) is the assumption the hybrid suites already
rest on for ML-KEM and the ML-DSA prekey signatures; a hybrid
companion for the group layer would protect nothing the
messaging layer does not already lose in the same event, so
the project's hybrid rule is satisfied in substance by the
suite's existing hybrid structure rather than deviated from.
Residual risks accepted by name at D-QGS-4: a bespoke
parameterization of a standardized scheme argued in a preprint
with no independent review; reliance on liboqs internal
symbols, pinned per tag; no ACVP coverage of keygen or signing
at 2*beta (geryon owns its KATs, §12). The symmetric-only
posture recorded on 2026-07-08 stays valid for the v2
first-flight messaging auth, where voleith remains the plan.

Classical suites are out of this document's scope entirely:
their groups are the [CPZ] type (GROUP_SPEC.md), which carries
no PQ claims, consistent with those suites' documented scope.

---

## 4. Group Data Structure (transcription of [CFG+] §3.2, Fig. 5)

Stored by the server, per group:

1. Header: GID, format/capability epoch format_version (D-QGS-12,
   the classical group-format-version analogue: fixed at Create, immutable, DISTINCT
   from the state version vMaj; see §8), the pinned field-AEAD id
   aead_id (SEC-v1.5.0 INFO-6: admin-selected at Create, immutable,
   like format_version; see §8), major version vMaj, AEAD
   ciphertext of (settings, attributes) under ek, optional
   join-link encryption of (gk, fet) under a join key, and the
   fetching token fet (bearer token authorizing Fetch; rotated per
   major version).
2. Member list, one entry per member:
   (C_UID, mct = Enc_ek(UID, r_c, uk), admn), where admn is the
   server-visible admin flag and r_c opens C_UID.
3. Pseudonym key list vk-lst: each member's vkpsdn (or, as the
   [CFG+] §3.3 optimization for the PQ tier, H(vkpsdn), with
   the full key supplied on first signature).
4. Core signature: the editing admin's signature under skpsdn
   over (their index, header, member list, all pseudonym keys,
   vMaj, and the last reconciled vMin), preventing rollback,
   gaps, and key substitution.
5. Appendix: header (GID, vMaj, vMin) plus append-only lines,
   each individually signed by its author's skpsdn:
   leave(i), refresh(i, Enc_ek(uk')), addUser(i, C_UID',
   Enc_ek(UID', r', uk')), modAttr(i, Enc_ek(attr)),
   join(C_UID', Enc_ek(UID', r', uk')). Both newcomer lines (addUser
   and join) carry the cleartext commitment C_UID' checked at fold
   (D-QGS-14 E14; the earlier join line omitted it).
6. Invite queue: entries
   PKE.Enc_ipk(UID, uk, Sgn(skpers, (UID, uk, GID))) for
   invited users; members hold isk and decide.

Admins reconcile appendix lines into a new core version (new
vMaj, fresh gk if required); invalid appendix lines are ignored
by all honest clients and attributable to their signer.

---

## 5. Operations (transcription of [CFG+] §4, App. B)

The geryon client API is in `src/qspgs/qspgs_ops.
{c,h}` (with the ek-field layer in `qspgs_field.{c,h}`): pure
composition over the frozen §4 wire and the §2.2 key hierarchy,
no persisted or cached derived state (§9, D-GRP-7); the
store-backed facade rides the storage layer. The API-shape mapping is at
the end of this section. Inventory ([CFG+] Table 2; asterisk =
admin-only, (asterisk) = optionally so per group settings):

- Core: RegisterUser, GrantAcquaintance, Create, Fetch,
  AddMember*, RemoveMember*, SetAdminRights*.
- Extended: Refresh, Leave, UserAdd, ChangeSettings*,
  ChangeAttr(*), ToggleJoinLink*, JoinViaLink, ApproveJoin,
  Invite*, RevokeInvitation*, AcceptInvitation, RotateGroupKey.

Channel model ([CFG+] §4.1): all protocols run over a
server-authenticated, client-anonymous encrypted channel,
except RegisterUser (mutually authenticated). gk delivery to
added members rides the pairwise messaging session (the [CPZ]
GroupMasterKey distribution shape carries over; §8).

Notable mechanics to preserve in transcription:

- RemoveMember rotates gk, re-encrypts every remaining entry,
  and republishes every vkpsdn (new rrs); members verify the
  whole new structure ([CFG+] §3.3).
- Refresh bumps the user's epoch (uk' = KDF(muk,
  "uk@" || ep+1)), the blocking mechanism.
- JoinViaLink decrypts (gk, fet) from the header join slot and
  derives uk = KDF(muk, "uk@" || ep) (corrected per D-QGS-13 E3;
  never a random uk), and verifies the four core objects before
  installing the recovered gk (D-QGS-13 E8.5); CompleteInvitation /
  Consolidate drain the invite queue. When b_adm is set (D-QGS-14 E9),
  other members' Fetch reports the joiner's JOIN line as pending
  approval and does NOT apply it to the roster until an admin approves
  it at Consolidate; with b_adm clear the join line is applied as a
  member. The JOIN line carries a cleartext C_UID' commitment like
  addUser (D-QGS-14 E14).

geryon API shapes (client side; the server-side
checks are §7). Every mutating operation ends in a
signature under the acting member's skpsdn, produced through the
transient member context gy_qspgs_member_ctx (ek / rrs / rho /
skpsdn / own vkr, derived from gk and the base pair, never
persisted):

- RegisterUser: gy_qspgs_register (dual skpers sign of
  vkbase || acq, emitted as the ACCT record). GrantAcquaintance
  accept: gy_qspgs_acct_verify (dual-verify, extract the attested
  (vkbase, acq) stored per acquaintance).
- Create / AddMember / RemoveMember / SetAdminRights /
  ChangeSettings / ChangeAttr / RotateGroupKey / CompleteInvitation
  are the caller mutating the in-memory core (its own zero-copy
  member / vk-lst / header buffers) then re-signing with
  gy_qspgs_core_sign, composed from three primitives:
  gy_qspgs_group_key_gen (fresh gk), gy_qspgs_member_build (one
  member entry: mct, C_UID, vk-lst hash), gy_qspgs_core_sign
  (re-sign the whole list). RemoveMember / RotateGroupKey rotate
  gk and member_build every survivor, so every mct is
  re-encrypted and every vkpsdn republished under the new rrs
  (the removed pseudonym stops resolving). SetAdminRights flips
  the admn flag; ChangeSettings / ChangeAttr re-seal the header
  field (gy_qspgs_field_seal).
- Fetch (read; [CFG+] Fig. 15 UsrVfyUpdate, D-QGS-13 E2/E5):
  gy_qspgs_member_decrypt (mct -> view, C_UID opened) and
  gy_qspgs_core_resolve_verify verify the signing admin, then the
  client recomputes EVERY member's vkr from its base key and requires
  the received vk-lst to match entry for entry (not just the
  signer's). Each member's vkbase is resolved by GetPseudoVkBase
  (Fig. 16): the caller's own pair, an acquaintance record, or a
  caller-supplied server-served ACCT for a member it is not
  acquainted with (GY_ERR_NOT_FOUND if none). IsCorrectUserKey runs
  AFTER the appendix and queue passes over the EFFECTIVE roster, and an
  AcqRec exempts a member only on a const-time (UID, uk) match, not UID
  alone (D-QGS-14 E12). The signer must be an admin in the fetched
  roster; with a retained prior view the version lineage follows
  [CFG+] Fig. 15 (D-QGS-14 E11): reject a rollback (vMaj' < prior) and
  a skip (vMaj' > prior + 1); on the exact next major (vMaj' ==
  prior + 1) require the new major's core-sig version to equal the
  NUMBER of appendix lines the caller last saw (the prior_apx_line_count
  fetch input; Consolidate signs last_vMin = |apx|), NOT the appendix
  header's vMin field: passing that constant when it is smaller than the
  true line count would let a colluding server fold from a hidden shorter
  appendix and defeat the check. Also require the signer to have been an
  admin in the prior view; on the same major
  (vMaj' == prior) accept a refetch whose core-sig last_vMin is
  unchanged (the Fig. 10 minor-version path). A deployer that keeps no
  prior forfeits the anti-rollback property (the library holds no
  membership state, §10.2).
- Refresh / Leave / UserAdd / modAttr / JoinViaLink are
  append-only lines: gy_qspgs_apx_line_sign (sign the apx-hdr
  GID || vMaj || vMin, then line_type || author_index || payload,
  under skpsdn; the apx-hdr binds the line to its group and version
  per D-QGS-13 E1) with the payload built by the field seals,
  verified by gy_qspgs_apx_line_resolve_verify (which takes the same
  apx-hdr; a JOIN newcomer's vkpsdn is not yet in the vk-lst, so its
  stored-hash check is skipped).
- ToggleJoinLink: gy_qspgs_joinlink_seal the (gk, fet) slot under
  a fresh link secret, then gy_qspgs_core_sign. JoinViaLink:
  gy_qspgs_joinlink_open recovers (gk, fet).
- Invite (admin; corrected per D-QGS-13 E3): the admin adds a
  PENDING member entry (C_UID,
  Enc_ek(UID, r_c, uk ABSENT, gk), admn = 0) for a UID it need not
  be acquainted with, taking that UID's base key from an
  acquaintance record or a caller-supplied ACCT (gy_qspgs_acct_
  verify); the admin mints NO uk and re-signs the core. The mct
  plaintext carries a form flag (uk present vs pending; a pending
  entry carries gk' in place of uk so later rotations can still
  derive the isk the acceptance seals to).
- AcceptInvitation (INVITEE; corrected per D-QGS-13 E3): the invitee
  signs uidlen || UID || uk || GID with its OWN skpers (through the
  custodian identity seam), with uk = KDF(muk, "uk@" || ep), and
  seals (UID, uk, sigma) to the group ipk; the deployer appends it
  to the invite queue. Opening (any member) verifies against the
  INVITED UID's identity keys, not the inviter's, and returns
  (uid, uk). This is the D-QGS-6 item 2 binding; the earlier
  inviter-signs-a-random-uk shape (a "voucher" recorded in no
  document) is withdrawn.
- CompleteInvitation (gy_custodian_qsgroup_complete_invitation; the
  geryon call the paper folds into invite completion, renamed per
  D-QGS-13 E8.6 so the name ApproveJoin is reserved for the paper's
  gated link-join approval): writes the accepted uk into the pending
  entry (re-seal that mct, admn unchanged) and re-signs; the drained
  queue entry is dropped. RevokeInvitation (corrected per D-QGS-14
  E10): an admin core edit that removes the pending (C_UID, mct, 0)
  entry and its vk-lst hash, rotates gk via the RemoveMember path
  (Fig. 17, "similar as in RemoveMember"), re-signs, and drains the
  target's queued acceptance in the same call; the server sees a
  REPLACE. Leaving the pending entry (the earlier behavior) let the
  invitee, still holding gk', re-accept and be settled.
- Consolidate (gy_custodian_qsgroup_consolidate; geryon's realization
  of [CFG+] Fig. 18): an admin folds a checked appendix into the next
  major version, applying valid lines in kind order, rotating gk when
  any leave is folded, draining the invite queue, and re-signing. Each
  line is checked exactly as Fetch checks it (D-QGS-13 E7). When b_adm
  is set (D-QGS-14 E9), a valid JOIN line is folded only if its
  appendix-line index is in the caller-supplied approved-index array;
  this is the paper's gated ApproveJoin (App. B.8, Fig. 22 AJ.3). With
  b_adm clear, all valid JOIN lines fold as members.
- Fetch-after-leave (gy_custodian_qsgroup_leave_fetch_token, client;
  gy_qsgroups_server_leave_fetch_check, server): a departed member signs
  Sgn_skpsdn(GID, k) under GY_QSPGS_CTX_LEAVEFETCH, verified server-side
  under its retained vk-lst_k, authorizing Fetch until the next gk
  rotation ([CFG+] §6.5; window bounded by E8.1).

Test posture: the operations round-trip and
verify / reject on both tiers (tests/qspgs/test_qspgs_ops.c);
their DETERMINISTIC bytes are already the frozen key-hierarchy
(§12) and §8 wire vectors (C_UID, H(vkpsdn), the core TBS), so no
separate operation KAT is added. The remaining primitives
(hedged ML-DSA signing, the random field nonces and r_c, the
ephemeral join KEM) are randomized and are covered by
round-trip / verify, not frozen bytes. The non-admin-admin-edit
and stale-version rejections are §7.3 SERVER checks.

---

## 6. Authentication, Attribution, and Credentials (D-QGS-5 as amended 2026-09-12)

The 2026-07-08 voleith membership layer (two trees, registered
nullifiers, V3 / V4 / V5 / V6 modules) is WITHDRAWN from this
type; its design is preserved in the project's design history.
This section is [CFG+]'s own mechanism, as
the paper specifies it.

### 6.1. Pseudonym keys

Per group, every member holds skpsdn = RandSK(skbase, vkbase,
rho) and every member can compute every other member's
vkpsdn = RandVK(vkbase, rho) from the group's rrs and the
acquaintance record (§2.2). Every group operation a member
performs is signed under skpsdn with the §2.1 context string.
Unlinkability (UL-CMA) is what hides base keys from the server
and across groups; unforgeability under rerandomized keys
(UFRK) is what makes a pseudonym signature prove "the member on
this line" ([CFG+] §2.1, Theorems 1 and 2).

### 6.2. Attribution and authorization

The server stores each member's vkpsdn (or H(vkpsdn), §8) with
the line and verifies each line's signature against it: per-line
authorization with an opaque, cross-group-unlinkable key. Members
attribute any line to an identity by matching its vkpsdn against
the set they recompute from the decrypted list. Group-key
rotation (new gk, hence new rrs) changes every rho and every
vkpsdn, which is how removal invalidates the removed member's
pseudonym and how attribution re-scopes per major version.

### 6.3. Admin authority

The admin who edits the core list signs the ENTIRE list (header,
member list, all pseudonym keys, versions) under skpsdn; the
server checks that the signing line is an admin line (admn
flag). Non-admin additions (UserAdd, JoinViaLink) are
individually signed appendix lines reconciled by an admin
([CFG+] §3.2, §3.3). Roles are the server-visible admn flag and
whatever member-entry fields the group settings define; a role
change is a list edit signed by an admin, not a key change.

### 6.4. Side credentials (deferred; voleith's remaining role, if any)

[CFG+] §6 leaves three functions to an unspecified anonymous
credential side system, explicitly OFF the hot path: recovery
from state loss via the C_UID commitment, liveness / registration
spot checks, and abuse-limiting tokens. geryon defers all three
past the baseline. If and when one is wanted, libtalos_voleith
(anonymous membership proofs with one-time scopes) is the
recorded candidate: its proof cost is acceptable for a
rare-path credential where it was not for per-operation
authentication (§1.4 item 4). Nothing in the baseline wire
format may depend on it.

### 6.5. Rate limiting

Symmetric send / fetch tokens derived from expKey ([CFG+] §6.5,
§2.2), never signatures or proofs on the hot path. Token design
is a §7 / D-QGS-6 item; token state and policy live with the
deployer (the D-GRP-2 carry-over).

### 6.6. Costs

Per mutating operation: one KR-ML-DSA signature (2,420 / 4,627
bytes) plus the re-signed core; [CFG+] §7 measures AddMember at
7.5 KB and about 9 Mcycles (unoptimized ML-DSA-65) at any group
size, RemoveMember (with gk rotation and re-encryption) at 19 KB
/ 179 KB at n = 50 / 1,000. Signing under a rerandomized key
costs about 5x standard ML-DSA signing (§3.3). Verification, on
the server and on every fetching client, is standard ML-DSA
verification on the public liboqs API.

---

## 7. Server Side (D-QGS-6, DECIDED 2026-09-12)

### 7.1. Shape

Inherits the D-GRP-2 shape: stateless pure crypto functions in
a separate `geryon_qsgroups_server` target; storage, policy,
and channel handling with the deploying application. The
server holds NO secret parameters for the core system; its only
secret material is the send / fetch token check state, and only
if the deployer enables tokens.

### 7.2. Registration and the PKI role (D-QGS-6 item 2)

[CFG+] assumes an idealized PKI that maps UID to vkpers. In
geryon that PKI is the hybrid identity: skpers is the identity's
XEdDSA + ML-DSA signing capability (both signatures required, as
for prekeys), with dedicated context strings (§2.3 registry).
The server's registration record per UID is the paper's Acct:
(vkbase, acq, ep, sigma) with sigma the identity signature over
(vkbase, acq), deposited over the UID-authenticated registration
channel. The server hands this record to anyone who asks for a
UID (user-anonymous query), which is how acquaintances and,
later, every fetching member validate a base-key binding
without contacting its owner.

### 7.3. Shipped server-side checks

All signature checks are `gy_mldsa<set>_verify` (pseudonym
signatures) or the identity pair-verify (registration objects);
the server never touches KR-ML-DSA internals (§3.3 item 2).

1. Core-signature verification against the claimed admin line, with
   the admn flag ALWAYS read from the PRIOR (stored) version, not the
   submitted one (corrected per D-QGS-13 E2;
   [CFG+] Fig. 11 / 17 / 19 / 20 all abort on admn_i' from
   the stored record). The check takes prior + next cores plus an
   operation-kind field on the submission wire; the signed TBS is
   built from the NEXT objects (index, header, member list, vk-lst,
   vMaj, last vMin). Reading admn from the submitted core would let a
   non-admin sign a core that flips its own admn bit. The server also
   DERIVES / bounds the next vk-lst by the operation, and the source
   of the signer's own vkpsdn follows the operation, in the four
   categories the paper's figures reduce to:
   - CREATE (Create): prior absent; vk-lst = submitted, n_members ==
     1, vMaj == 1; signer vkpsdn resolved from the SUBMITTED vk-lst.
   - UNCHANGED (SetAdminRights, ChangeSettings, ChangeAttr,
     ToggleJoinLink): submitted vk-lst MUST equal prior byte for byte;
     signer vkpsdn from the PRIOR vk-lst.
   - APPEND_ONE (AddMember, UserAdd, Invite): submitted vk-lst MUST
     equal prior with exactly one newcomer hash appended (prior is a
     prefix, length + 1); signer vkpsdn from the PRIOR vk-lst, since
     gk is unchanged and the admin's key is not rerandomized
     (Fig. 11: vkpsdn <- (vk-lst')_i, vk-lst <- vk-lst' += vk_UID').
   - REPLACE (RemoveMember, RotateGroupKey): any submitted vk-lst is
     accepted, since rotation rerandomizes every key with the new
     rrs = KDF(gk, "SUB-KEY") and the server holds no gk; signer
     vkpsdn from the SUBMITTED vk-lst (Fig. 20: vkpsdn <- (vk-lst)_i,
     no prime). RemoveMember is delete-one then rotate, so the server
     sees a REPLACE with one fewer entry.
   This is defense in depth; the fetch-time client recompute (§5,
   D-QGS-13 E2/E5) is the guarantee, as the server is the adversary.
2. Appendix-line signature verification against the line
   author's vkpsdn; for UserAdd and JoinViaLink lines, append
   the supplied new vkpsdn to vk-lst.
3. Pseudonym key resolution (D-QGS-6 item 3): vk-lst stores
   H(vkpsdn); a member's first signature under a pseudonym
   carries the full vkpsdn, the server checks the hash, then
   verifies and caches the key for that line's lifetime.
4. Version discipline (D-QGS-6 item 6; prior-version lineage added
   per D-QGS-13 E2): strictly increasing (vMaj, vMin);
   every write names the version it extends and is applied compare-
   and-swap; a losing writer receives a structured conflict error
   and re-fetches. The server never merges. Beyond CAS, a submitted
   core must advance vMaj by exactly one over the stored prior (a
   Create being vMaj 1 with no prior); this, with the prior-version
   admn gate in item 1, is the server half of the anti-rollback
   property. The fetching client enforces the matching lineage on
   its side (§5): it is the client, holding the prior view, that
   fully rejects rollback and skip, since the stateless server
   trusts the deployer's stored prior.
5. Fetch-token comparison (gy_const_memcmp against the stored
   fet for the GID) and send-token checking (§6.5, D-QGS-6
   item 4).
6. Invite-queue and join-slot handling: append PKE-encrypted
   invite acceptances; serve the join slot; the server validates
   nothing inside them (members holding isk do).
7. Registration-record service (7.2): store on RegisterUser and
   Refresh (new acq, new ep), serve on query.

### 7.4. Admission and garbage entries (D-QGS-6 item 5)

The server cannot validate encrypted entry contents ([CFG+]
§4.2) and does not try. A group with no honest admin
accumulates attributable-but-invalid state; only admins clean
up at reconciliation. The mitigation is send-token rate limiting
(§6.5) and admin cleanup. Deployer-facing documentation must
state this plainly.

Availability edge (SEC-v1.5.0 INFO-5, paper-faithful). One bad
newcomer key blocks fetch for the WHOLE group, not just clutter.
Fetch (Fig. 15) runs IsCorrectUserKey over the effective roster
and ABORTS the entire version if any new (UID', uk') fails, so a
single member with b_add (or a link joiner whose b_adm is clear)
who submits a newcomer with a bogus uk' makes the current version
unfetchable for every member. Consolidate (Fig. 18) carries no
IsCorrectUserKey check, so it folds the bad entry into the core,
and every later fetch keeps failing. This matches [CFG+] exactly;
geryon does NOT silently drop failing lines at Consolidate (that
would be an unproven divergence from the paper). Recovery is an
admin RemoveMember of the offending entry, which succeeds because
edits do not re-run IsCorrectUserKey (only Fetch does); the
settings bits (who holds b_add) and send-token rate limiting bound
how often it can be triggered. Deployers must expose an admin
cleanup path and treat a version that fails IsCorrectUserKey as an
admin-remediation event, not a permanent group loss. Related, and
also deployer-visible: geryon RETAINS unconsumed invite-queue
entries across Consolidate where Fig. 18 empties the queue, so a
deployer that wants the paper's drain semantics prunes consumed
entries itself.

### 7.5. What the server learns

As [CFG+] §5: operation type, size, timing, GID, and member
INDICES; never identities and never cross-group linkage (the
pseudonym keys are UL-CMA-unlinkable to vkbase and to each
other). The registration record exposes (UID, vkbase, acq) to
anyone who queries a UID, which is the paper's model: vkbase is
public but unlinkable to any pseudonym without rrs.

---

## 8. Wire Formats and Integration (D-QGS-7, DECIDED 2026-09-13)

The wire freeze is cleared by the satisfied D-QGS-11 benchmark
and is versioned from day one. The QSPGS structure
is a PARALLEL wire beside the classical group vertical, framed
exactly as GROUP_SPEC §9: one D-GEN-1 msg_type and a per-object
header. Implemented in `src/qspgs/qspgs_wire.{c,h}` (structure)
and `src/qspgs/qspgs_join.{c,h}` (join PKE).

**Framing.** msg_type `GY_QSPGS_MSG` = 0x04 (0x01 INIT, 0x02 DR,
0x03 the classical GROUP_KEY_DISTRIBUTION are taken). Every
top-level object carries the 3-byte header
`obj_type || GY_QSPGS_WIRE_VERSION(0x01) || suite_id`. The
object-type registry (FROZEN, append-never-renumber): HEADER
0x01, MEMBER_LIST 0x02, VK_LST 0x03, CORE_SIG 0x04, APPENDIX
0x05, INVITE_QUEUE 0x06, ACCT 0x07 (the §7.2 registration record,
appended by the client operations). Integers are big-endian; lists are a
BE16 count then entries; decode is STRICT (exact length,
trailing bytes rejected). Per-fetch entry bound
`GY_QSPGS_MAX_ENTRIES` = 1024 (the GY_GROUP_MAX_ENTRIES pattern).

**Encrypted / opaque fields are length-prefixed, not fixed
width.** The settings+attributes AEAD ciphertext, each member's
`mct`, the optional join slot, appendix payloads, and invite
entries are carried as length-prefixed opaque blobs: the codec
frames and bounds them but never interprets ciphertext. Their
AEAD-internal layout (nonces, plaintext field order) is a §5
client-operation matter and is deliberately NOT
frozen by the structure grammar. Fixed-width fields are the ones
the crypto already fixes: GID (16), format_version (BE16), aead_id
(1, SEC-v1.5.0 INFO-6), the versions (BE32 vMaj / vMin), and the
tier-hash fields below. (fet
is fixed-width too but is no longer a header field; SEC-v1.5.0
LOW-1, §4 item 1 / §10.2 item 5.)

**Format / capability epoch (D-QGS-12).** `format_version` is a
per-group capability epoch, the QSPGS analogue of the classical
the classical group `format_version`. It is chosen at Create, IMMUTABLE for
the group's life, and orthogonal to the state version vMaj (which
advances on membership / key edits). Since the QSPGS GID is an
opaque caller-supplied value (not a derived hash the way the
classical GroupID is), the epoch cannot be bound into the GID;
instead it rides the HEADER object and is therefore covered by the
admin core signature (the header is inside the core TBS), which
gives the same tamper-evidence. A decoder refuses a group whose
epoch is outside the supported window [MIN, MAX]
(`GY_ERR_UNSUPPORTED`), before consuming any state. New groups mint
at the current version; a future [CFG+] revision that changes a
format raises MAX (new groups use the new epoch, old groups keep
theirs), and deprecation raises MIN past the retired epoch. The
same value is stamped into the `gy_qspgs_store` records (§9), so a
group's at-rest and on-wire epoch are one value. Window opens at 1
(QSPGS is new; nothing to migrate).

**§4 object byte layouts (frozen).**

1. HEADER: `GID(16) || format_version(BE16) || aead_id(1) ||
   vMaj(BE32) || sa_ct_len(BE32) || sa_ct || join_present(1) ||
   [join_len(BE32) || join_ct]`.
   `aead_id` is the group's pinned field AEAD (SEC-v1.5.0 INFO-6, added at
   format_version 1 while v1.5.0 was untagged): the admin selects it at
   Create (0x01 ChaCha20-Poly1305, the default, or 0x03 AEGIS-256; both
   always available, AES-256-GCM 0x02 is excluded as hardware-gated), and
   like format_version it is inside the signed header and IMMUTABLE for the
   group's life. gy_qspgs_server_core_check validates it is group-approved
   at Create and equal to the stored prior on every edit, so there is no
   downgrade path. Every ek-sealed field (§5) uses it.
   The fetch token fet is NOT carried here (SEC-v1.5.0 LOW-1, fixed at
   format_version 1 while v1.5.0 was untagged): keeping it inside the
   signed, byte-exact served header disclosed it to every fetcher. It
   is now emitted alongside the four core objects as a separate server
   record (the emit bundle's fet field / gy_custodian_qsgroup_create's
   fet_out), stored by the server for gy_qsgroups_server_fetch_check,
   and NEVER served back inside the header. fet stays inside the join
   slot's E2EE (gk, fet) plaintext, which reaches only a link joiner.
   See §10.2 item 5.
   sa_ct = Enc_ek(settings, attributes), where the sealed plaintext is
   the frozen settings prefix `flags(1) || attributes` with
   `flags = b_add | b_attr << 1 | b_adm << 2` (b_add /
   b_attr are the [CFG+] gating bits CheckAppendixLine reads; b_adm is
   the [CFG+] App. B.8 admin-approval gate for link joiners, enforced
   at Fetch and Consolidate per D-QGS-14 E9; the attributes are opaque
   app bytes, bounded by GY_QSGROUP_ATTR_MAX). Create and ChangeSettings
   both take (settings_flags, attr) and seal this layout. join_ct = the
   optional join-slot PKE ciphertext (present flag boolean; a present
   flag with an empty blob is invalid).
2. MEMBER_LIST: `hash_len(1) || count(BE16) || count *
   (C_UID(hash_len) || admn(1) || mct_len(BE16) || mct)`. The
   inline hash_len must equal the tier hash; admn is boolean.
3. VK_LST: `hash_len(1) || count(BE16) || count * H(vkpsdn)`
   (packed, hash_len each). The full vkr (1,312 / 2,592) is sent
   with a member's first signature and checked against the stored
   hash.
4. CORE_SIG: `signer_index(BE32) || last_vMin(BE32) ||
   sig_len(BE16) || sig`. sig is the KR-ML-DSA signature under
   the editing admin's skpsdn over the canonical TBS
   `signer_index(BE32) || HEADER-object || MEMBER_LIST-object ||
   VK_LST-object || vMaj(BE32) || last_vMin(BE32)`, under the
   frozen context `qspgs-core`. last_vMin travels here because it
   is covered by the signature but is not a header field.
5. APPENDIX: `GID(16) || vMaj(BE32) || vMin(BE32) || count(BE16)
   || count * (line_type(1) || author_index(BE32) ||
   payload_len(BE16) || payload || sig_len(BE16) || sig)`.
   line_type in {leave 0x01, refresh 0x02, addUser 0x03, modAttr
   0x04, join 0x05}; payload is the opaque op-specific ciphertext,
   except the two newcomer kinds (addUser and join) which prefix a
   cleartext `C_UID'(hash_len)` commitment ahead of the mct, checked at
   fold against Commit(UID', r') (D-QGS-14 E14 aligned the join payload
   to the addUser layout);
   sig is the author's skpsdn signature over the appendix header
   FOLLOWED BY the line (corrected per D-QGS-13 E1;
   [CFG+] Fig. 12/16 sign Sgn(apx-hdr, line)):
   `GID(16) || vMaj(BE32) || vMin(BE32) || line_type(1) ||
   author_index(BE32) || payload` under the single `qspgs-appendix`
   context (the line_type byte inside the signed data separates the
   kinds). Binding (GID, vMaj, vMin) is what stops a corrupt server
   from re-appending an old signed line at a later version (a
   rollback the paper's model excludes); the earlier TBS omitted the
   header and covered only `line_type || author_index || payload`.
   Each honest client ignores an invalid line and attributes it to
   its signer.
6. INVITE_QUEUE: `count(BE16) || count * (entry_len(BE32) ||
   entry)`, each entry the opaque `gy_qspgs_join_seal` ciphertext
   of (UID, uk, Sgn(skpers, (UID, uk, GID))).

**Tier-hash fields (frozen, D-GEN-3 domain-separated).** C_UID =
H(gy_info("qspgs-cuid") || r_c || UID) (a computationally-hiding
hash commitment, the §2.3 item 3 deviation; r_c is 32 bytes).
H(vkpsdn) = H(gy_info("qspgs-vkhash") || vkr). Both are the tier
hash, so the stored width is 32 bytes (SHA-256, 25519 tier) or
64 bytes (SHA-512, 448 tier). The full tier-hash output is used,
not a truncation: it binds a key substitution and is already
small against the 1,312 / 2,592-byte vkr it replaces.

**Join PKE (D-QGS-2 / §2.2).** (ipk, isk) is derived group-wide
from gk via two INDEPENDENT HKDF branches (labels qspgs-join-ec,
qspgs-join-mlkem), then a fresh ephemeral ECDH + one ML-KEM
encapsulation to ipk are fused PQ-first (label qspgs-join-kem)
into a ChaCha20-Poly1305 key; ciphertext =
`eph_curve_pk || mlkem_ct || (aead ct || tag)`, KEM transcript as
AAD. The independence is a security requirement (see §2.2).

**ek-encrypted field layouts (frozen in `src/qspgs/
qspgs_field.{c,h}`).** The opaque blobs of the §4 grammar carry,
inside them, a uniform sealed-field format: `nonce || ct || tag`
under the group's pinned AEAD (the header `aead_id`: ChaCha20-Poly1305
by default, or AEGIS-256; SEC-v1.5.0 INFO-6), with associated data
`gy_info("qspgs-field") || field_tag || GID`. The frame carries no
AEAD id of its own; sealer and opener both read it from the signed
header, so a group fixes one AEAD for its life. The field-kind tag
(MEMBER 0x01, HEADER 0x02, ATTR 0x03, UK 0x04, JOINSLOT 0x05;
append-never-renumber) stops one kind being reinterpreted as
another; the GID stops cross-group replay. No version is bound
(version rollback is caught by the core signature), so
re-encryption on gk rotation is a plain reseal. ek is a
long-lived group key, so each seal draws a fresh random nonce
(unlike the single-use-key join seal). The member tuple mct =
Enc_ek(UID, r_c, uk) has plaintext `uidlen(1) || UID || r_c(32)
|| uk(2*kappa)`. The JOINSLOT field is the exception to the ek
keying: the header join slot must be openable by a link holder
who does NOT yet have gk, so it is keyed by a join-link key
jlk = HKDF(link secret, "qspgs-joinlink") (the secret shared out
of band via the link), using the same field format; its
plaintext is `gk(2*kappa) || fet(32)`. ToggleJoinLink seals it
(fresh link secret) and JoinViaLink opens it.

**Registration and invite objects (frozen with the client operations).** These
are the two skpers-signed objects deferred from the §4 freeze,
and the ACCT carrier (item 7 above).
- The ACCT record (GY_QOBJ_ACCT): `hdr || vkbase(tier VKB) ||
  acq(2*kappa) || ep(BE64) || ed_sig_len(BE16) || ed_sig ||
  mldsa_sig_len(BE16) || mldsa_sig`. sigma = (ed_sig, mldsa_sig)
  is the dual XEdDSA + ML-DSA identity signature (both-or-abort)
  over the object `vkbase || acq` under context `qspgs-reguser`.
  vk_b (2,976 / 5,920 bytes) is shared with acquaintances only,
  never the server as core-secret material.
- The invite entry: sigma_inv is the dual identity signature over
  `uidlen(1) || UID || uk(2*kappa) || GID(16)` under context
  `qspgs-invaccept`; the sealed plaintext is `uidlen(1) || UID ||
  uk || ed_sig_len(BE16) || ed_sig || mldsa_sig_len(BE16) ||
  mldsa_sig`, sealed to ipk with the join PKE and carried as an
  INVITE_QUEUE entry.

**Fixed by D-QGS-11 and NOT open here:** the vk_b / sk_b / vk_r /
signature layouts of §3.3 item 6 and the 64-byte rho.

**Still §5 / later client-operation increments (not a wire freeze):** gk
delivery over pairwise sessions (library vs application duty,
following the GROUP_SPEC §9 resolution) and the core-editing /
appendix operation mechanics. The [CFG+] §3.3 Falcon
dispute-optimization is OUT of scope (new primitive, new license
surface, marginal benefit at geryon's scale).

---

## 9. State, Storage, and Zeroization (D-QGS-8 DECIDED)

Inherits the D-GRP-7 rederive-only posture, which maps directly:

- Stored user secrets: muk and skbase (800 / 1,472 bytes,
  §3.3 item 6). DECIDED (2026-09-13): these live in a
  dedicated `gy_qspgs_store` (the app-sealed keyed-blob analogue
  of the classical `gy_group_store`, D-GRP-7), NOT the messaging
  custodian's sealed idmat. QSPGS is a parallel vertical; folding
  a group key into the frozen messaging custody format would
  couple the two and force a format migration on every hybrid
  messaging identity. The dedicated store honors D-CUST-1
  (opaque, app-sealed, library never holds the KEK) and needs no
  migration (there are no existing QSPGS records). Record kinds
  (`enum gy_qspgs_rec_kind`, `src/qspgs/qspgs_store.h`): MUK,
  BASE_KEY (skbase || vkbase), GROUP_KEY. The `*_stored` wrappers
  over that trio LANDED 2026-09-14
  (`src/qspgs/qspgs_store.c`): each record is
  ver(0x01) || format_version(BE16) || payload, with a per-record
  format-version window (mirroring `gy_group_format_version_load`);
  `gy_qspgs_member_ctx_open_stored` loads only gk and the base
  pair and rederives the rest (the `gy_group_load` analogue).
  skpers is the identity's existing
  signing key (§2.2). vkbase (2,976 / 5,920 bytes) is stored with
  skbase (public but acquaintance-only). Everything else user-side
  (uk, acq, expKey, per-group rho, skpsdn) is rederived on
  demand and zeroized after each operation; nothing derived is
  cached. skpsdn in particular is NEVER serialized (§3.3 item
  7): it is an in-memory, backend-affine object, produced by
  RandSK immediately before signing and cleared immediately
  after.
- Stored group secret: gk only (the GroupMasterKey analogue).
  ek, rrs, ipk/isk, every pseudonym key, and the §6.5 fetch /
  send bearer tokens are rederived per operation. The tokens:
  fet = KDF(gk, "qspgs-fet"), send =
  KDF(gk, "qspgs-send"), two independent HKDF branches off gk and
  therefore per-major-version by gk rotation; the derived fet is
  the one `gy_qspgs_server_fetch_check` compares against. Never
  stored.
- Membership state is never stored or cached by the library;
  the server is authoritative and Fetch results pass through
  the API with structured validation errors. Compile-time entry
  bound per fetch (GY_GROUP_MAX_ENTRIES pattern).
- Zeroization points: derived material after every operation;
  gk (all epochs) and per-group state on leave/eviction/local
  delete; superseded gk immediately after a rotation is
  verified; old-epoch uk material after Refresh confirmation;
  staged material on any operation failure (transactional
  commit, D-SES-10 pattern).
- Rotation improves on [CPZ] here: leave/removal is followed by
  an actual gk rotation, so post-departure exposure is bounded
  by design instead of accepted (the D-GRP-11 concern).

---

## 10. Security Considerations

### 10.1. HNDL posture (resolves the D-GRP-11 analogue)

The group structure is protected by symmetric primitives only
(AEAD under ek, KDF hierarchy); recorded server state exposes
nothing to a future quantum adversary. Authentication is
KR-ML-DSA (MLWE / SelfTargetMSIS, the suites' existing PQ
assumption) and must be secure only at execution time; the
join-queue PKE is the suite KEM hybrid. No classical public-key
primitive appears anywhere in this type. This is the paper's
central design goal ([CFG+] §1.1) and the reason this document
exists. Known non-property (recorded, not claimed):
membership-authentication forward secrecy. A stolen skbase
signs under every past and future pseudonym derivable from
group state; [CFG+] does not claim otherwise, and its recovery
is Refresh (user-key epoch bump) plus gk rotation.

### 10.2. Trade-offs against [CPZ] ([CFG+] §4.2, App. D)

Gains: integrity against a malicious server (admin signatures;
[CPZ] has none), no rollback, group key rotation, stronger
corrupt-server and departed-member guarantees, HNDL safety.

Losses, to be confronted at adoption:

1. DENIABILITY REGRESSION (D-QGS-9, DECIDED 2026-07-08:
   accepted and documented): an insider can prove another
   member's active membership to an outsider (signature or
   proof, attribution-tag mapping, group key, group state;
   [CFG+] §3.3 "On deniability"). [CPZ] avoided this, so the
   regression is specific to THIS group type (the classical
   type keeps its deniability). geryon's offline-deniability
   identity statement governs the MESSAGING protocol;
   group-membership provability is a distinct property, and API
   documentation must state the regression plainly for QSPGS
   groups. The voleith V5 designated-opener improvement path
   recorded on 2026-07-08 is withdrawn with the voleith layer;
   no replacement improvement path is recorded (D-QGS-9 status
   line, 2026-09-12).
2. Garbage entries / DoS: the server cannot validate entry
   well-formedness; a group with no honest admin accumulates
   attributable-but-invalid state (§7).
3. Server no longer knows members are registered users;
   mitigated by §6.4 side-credential check-ins if a deployer
   ever enables them (deferred).
4. Anti-rollback is DEPLOYER-DEPENDENT on the client side
   (D-QGS-13 E2, lineage tightened to [CFG+] Fig. 15 by D-QGS-14 E11).
   The library holds no membership state (D-QGS-8), so the prior
   (vMaj, vMin), the number of appendix lines the caller last saw
   (prior_apx_line_count, NOT the appendix header vMin field), and the
   prior member view are passed in by the caller on every Fetch. When
   they are supplied, the client rejects a rollback, a skip past the next
   major, and a next major whose core-sig version does not match the
   number of lines the caller last saw (the "min version skipped" check;
   passing a too-small value defeats it). A deployer that
   passes NULL each time gets only the current-version admn check and
   forfeits all of those rejections. The property is available, not
   automatic; deployer-facing API docs must say so.
5. A departed member's fetch token (fet) is derived from gk
   (D-QGS-8) and so is refreshed only on rotation, whereas [CFG+]
   samples fet_new on every major version (D-QGS-13 E8.1, KEPT). A
   leaver therefore retains fetch until the next gk rotation;
   Consolidate rotates gk whenever a leave is folded (§3.3), which
   bounds the window to one major version in the common path. Stated
   here as a deliberate, bounded deviation rather than a silent one.

   FIXED (SEC-v1.5.0 LOW-1, CONFIRMED then remediated at
   format_version 1). The original geryon layout carried fet INSIDE
   the signed header (part of the core TBS, §5), unlike [CFG+], where
   hdr = (GID, vMaj, c_hdr, c_join) and fet is a SEPARATE server-record
   field sent E2EE to members (Fig. 11) that the Fig. 10 lower-half
   leaver fetch never sees. Because a fetching client must receive the
   header byte-exact to verify the core signature, fet could not be
   stripped from a served version, and the leaver's own confirmation
   fetch (the one that proves its removal) handed it fet_{N+1}, which
   the server then honored as a bearer token until the rotation AFTER
   the removing one, not the removing rotation. The exposure was
   metadata only (member count, admn flags, vk-lst hash churn,
   ciphertext lengths, appendix activity); never gk or field plaintext.

   Remediation, applied at format_version 1 (v1.5.0 was untagged, so
   no epoch bump was needed and no deployment consumed the old bytes):
   fet was removed from the HEADER object (§4 item 1) and is now
   emitted as a SEPARATE server record alongside the four core objects
   (gy_custodian_qsgroup_create's fet_out / the emit bundle's fet
   field). The server stores it and passes it to
   gy_qsgroups_server_fetch_check, and NEVER serves it back inside the
   header. fet remains inside the join slot's E2EE (gk, fet) plaintext,
   which reaches only a link joiner (matching [CFG+]'s E2EE-to-members
   distribution). A served header now discloses no bearer secret, and
   the leaver-window concern above is closed. fet is unchanged as a
   value (still KDF(gk, "qspgs-fet"), §6.5); only its transport moved.

   Deployer guidance (state it plainly, §7.4): store the emitted fet as
   a per-version record keyed to the group, feed it to the fetch-token
   check, and do not place it in any header served to clients. Continue
   to treat the leave-token path (gy_custodian_qsgroup_leave_fetch_token
   / gy_qsgroups_server_leave_fetch_check) as single-use: serve a leaver
   exactly the one version that proves its removal.
6. FIXED (SEC-v1.5.0 LOW-2, CONFIRMED then remediated at
   format_version 1). Member UIDs are a FIXED width
   (GY_QSGROUP_UID_LEN, 16 bytes), enforced with GY_ERR_ARG at every
   entry point. A variable-length UID would leak its length class
   through the cleartext ciphertext lengths a corrupt server sees: the
   per-entry mct_len (BE16), an invite entry_len, and a newcomer
   payload_len are each a UID length plus a tier constant, so with
   UIDs of differing lengths the server could intersect a per-entry
   length class with the public per-UID ACCT directory to narrow which
   UIDs occupy which entries, and track an entry across rotations by
   length. This would have undercut the §10.3 "member INDICES, never
   identities" claim. A single mandated width makes every sealed member
   entry the same length, so the claim holds unconditionally. An
   application whose native account id is not 16 bytes hashes it to this
   width (the §1.3 "16-byte identifier" convention, matching the
   classical group's EncodeToG UID). Applied at format_version 1 (v1.5.0
   was untagged, so no epoch bump was needed): the sealed layout is
   unchanged (still form || uidlen || UID || r_c || key), only the
   accepted UID length narrowed from 1..64 to exactly 16, so the §8 wire
   vectors (cut with a 16-byte UID) are unaffected.
7. FIXED / documented (SEC-v1.5.0 INFO-4). The group-key distribution
   envelope (gy_custodian_qsgroup_{export,install}_group_key, §5 gk
   delivery) was a bare GID || gk with no header. It is now a TYPED
   frame: the standard 3-byte object header (kind || wire version ||
   suite id, GY_QOBJ_GROUP_KEY) that every other top-level QSPGS wire
   object carries, then GID || gk, so it is versioned from day one like
   the classical group's key-distribution frame. Install validates the
   header (wrong kind / version / suite -> GY_ERR_VERIFY). The tag is
   identification and versioning only (a forged tag changes nothing
   verifiable; the tier length check already blocked cross-suite
   confusion). Applied at format_version 1 (v1.5.0 untagged); the
   envelope is not in the §8 wire vectors, so no re-cut. SEPARATELY, and
   left AS-IS by design: install overwrites the stored gk
   unconditionally, and the envelope is not admin-authenticated. A
   legitimate re-add must overwrite, and the library holds no membership
   state to arbitrate (D-QGS-8), so WHICH peer's envelope to accept
   (only the admin that added you) is an application duty (D-SES-1 /
   GROUP_SPEC §9), stated plainly in the public header.

### 10.3. Leakage model ([CFG+] §5)

Honest server: only operation type/size/timing. Corrupt server:
additionally GID and member INDICES (never identities, no
cross-group linkage; UIDs are a fixed width so no per-entry length
class leaks, SEC-v1.5.0 LOW-2 / §10.2 item 6). Corrupt member: full
group state (unavoidable). Consistency holds against a corrupt server
alone; it falls to corrupt server + corrupt member collusion.

### 10.4. Traceability

Every operation is attributable to a member line by all group
members (vkpsdn rederivation, §6.2). This is a design feature
(mis-behavior detection, [CFG+] §1.1) and a privacy statement:
in-group anonymity does NOT exist and must not be implied by
API naming or docs.

---

## 11. Versioning and Upgrade Paths

[CFG+] §6.1's live-migration protocol targets Signal's deployed
system and does NOT apply to geryon: geryon is greenfield, with
no deployed groups to migrate and no interop requirement with
Signal servers. Adoption resolved 2026-07-08 (D-QGS-1): this
type ships side by side with the classical [CPZ] type, serving
disjoint suite scopes; there is no migration between types.

- Hybrid suites deploy KR-ML-DSA from day one; there is no
  classical-then-upgrade phase, per the project's no-fallback
  posture (the layer is standalone-PQ, D-QGS-4 as amended).
- The component-wise upgrade freedom the paper builds in (swap
  commitments, credentials, PKE independently; [CFG+] §6.1
  "Future migration") is retained as a versioning property of
  §8; there are no core ZK transcripts to bound.
- The fixed-A label carries a version suffix (`-v1`, §3.3 item
  5); a parameter or derivation change to KR-ML-DSA is a new
  label, hence a new rho_A, hence keys that fail the rho_A
  policy check under the old version (a clean break, never
  silent).
- A side credential system (§6.4), if ever adopted, lands as an
  addition next to the baseline, not a change to it.

---

## 12. Test Vector Requirements (D-QGS-10: KAT set consolidated + benchmarked; vector freeze executed at the v1.5.0 close-out)

- Oracle: NO ACVP vector covers KR-ML-DSA (base keygen with a
  fixed A and full t, ExpandS-based rerandomization, signing at
  2*beta). [CFG+] §7 reports a Rust implementation; if it is
  published it is the oracle (D-GRP-9 pin-and-oracle
  discipline, license-permitting, vectors only). Otherwise the
  vectors are geryon's own, generated by the reviewed glue and
  frozen only after the [CFG+] revision pin. The standard
  ML-DSA verifier is an oracle for every KAT signature
  regardless (see below). HKDF / AEAD per existing core/
  requirements.
- KR-ML-DSA KATs (both sets, EVERY built backend):
  deterministic base keygen from a fixed seed (vk_b, sk_b
  bytes); RandVK for fixed (vk_b, rho) (vk_r bytes); RandSK then
  sign with a fixed rnd over a fixed (msg, ctx) (signature
  bytes); rho_A bytes per set. Cross-backend agreement on vk_r
  and on the fixed-rnd signature bytes is itself a test (the
  backends must be interchangeable on every public output).
  Every KAT signature must ALSO verify under
  `gy_mldsa<set>_verify` for vk_r: that check ties the bespoke
  signer to the standard verifier with no shared code.
- Negative matrix: a base key with a foreign rho field rejected
  by RandVK / RandSK; a signature under vk_psdn(rho) rejected
  under vk_psdn(rho') and under vk_b; tampered core signature;
  appendix line signed under the wrong pseudonym; rollback
  (stale vMaj / vMin) rejection; gap detection; wrong-suite and
  wrong-type structures rejected; garbage mct surfaced as
  structured errors; fetch-token mismatch; join-queue
  tampering; a removed member's old pseudonym rejected after
  rotation; attempt-cap exhaustion surfaced as GY_ERR_CRYPTO
  (forced via a test seam).
- Benchmarks (gate before wire formats freeze): per-operation
  sign / verify time at both tiers on mobile-class hardware,
  RandSK cost, and the AddMember / RemoveMember / Fetch wire
  sizes at n in {10, 50, 1000} for comparison with [CFG+] §7.
- Constant-time: fetch-token compare, the rho_A policy compare,
  and all KDF / AEAD paths under geryon's dudect harness; the
  KR-ML-DSA glue's secret-dependent arithmetic is liboqs code
  and is NOT re-timed (D-PQ-4), but the glue's own control flow
  is reviewed for public-only branching (§3.3 timing note).
  The dudect targets covering geryon's own composition over
  secret QSPGS / KR-ML-DSA data (SEC-v1.5.0 LOW-5, tests/timing/
  targets_qspgs.c) are: `krmldsa_randsk_{44,87}` (fixed-vs-random
  base key; the rerandomizer rho held fixed so liboqs ExpandS is
  common-mode, leaving only geryon's constant-time poly add and
  key packing under test), `qspgs_member_open_{44,87}` (the Fetch
  member-entry AEAD open + parse, secret = group key ek, libsodium
  AEAD common-mode), and `qspgs_token_check` (the bearer-token /
  C_UID `gy_const_memcmp` equality, secret = stored token). Each
  is a fixed-vs-random-in-the-secret test (D-GEN-10). The
  KR-ML-DSA SIGN hot loop is deliberately NOT a dudect target: its
  secret-dependent arithmetic is entirely liboqs (D-PQ-4, not
  re-timed) and its rejection-loop iteration count is a FIPS 204
  §5.5 public quantity that standard ML-DSA varies identically, so
  a fixed-vs-random-key sign target would measure that liboqs loop
  rather than geryon glue; geryon's sign orchestration is
  fixed-time given the loop count and is covered by the §3.3
  public-only-branching review.
- liboqs pin: the core/pqinit.c `_Static_assert` is the guard
  for the internal-symbol dependency; a liboqs bump is a
  deliberate event that re-runs every KAT above.
- Consolidation and freeze timing (2026-09-14): the
  KAT set is captured and green across both tiers, all built
  backends: the key hierarchy plus the §6.5 fet / send tokens
  (qspgs_keys_kat.h), the group-structure wire (C_UID, H(vkpsdn),
  core TBS, and the suite-independent appendix-line TBS,
  qspgs_wire_kat.h), and the storage-record framing (byte-exact
  in test_qspgs_store.c). The negative matrix (above) is
  consolidated in test_qspgs_negatives.c with the signature-based
  cases in test_qspgs_ops.
- Vector freeze: FROZEN at the v1.5.0
  close-out. The worked example ran end to end on both
  hybrid tiers without forcing a byte-level change, so no re-cut
  was needed; the vectors are pinned to geryon's own reading of
  the [CFG+] 2026/453 preprint then in force (no authors' reference
  exists). The KAT headers (krmldsa_kat.h, qspgs_keys_kat.h,
  qspgs_wire_kat.h) carry the FROZEN note and are no longer
  regenerated on refactor. A later [CFG+] revision is a D-QGS-12
  format_version bump with a deliberate re-cut, not a silent one.

---

## 13. References

1. [CFG+] docs/references/signal/2026-453.pdf, eprint 2026/453
   (normative basis; revision pin at D-QGS-10;
   Signal-affiliated authorship)
2. GROUP_SPEC.md ([CPZ] system; the parallel CLASSICAL group
   type; §1.2 register relationship)
3. [CPZ] docs/references/signal/2019-1416.pdf (basis of the
   classical type; pinned per D-GRP-9)
4. NIST FIPS 204 (ML-DSA; base of the normative §3.3
   KR-ML-DSA instantiation: ExpandS, Power2Round, the packers,
   Algorithm 2 hedged signing)
5. docs/decisions/qsgroups.md (D-QGS register; D-QGS-11 for the
   KR-ML-DSA instantiation) and docs/decisions/ (D-GEN-3/4/6;
   D-GRP-2/3/7 precedent shapes; D-PQ-1/2/4 for the liboqs
   posture)
6. liboqs 0.16.0, src/sig/ml_dsa/ (mldsa-native backends,
   sig_ml_dsa_<set>.c dispatch wrappers; the internal routines
   §3.3 composes)
7. HYBRID_SPEC.md (pairwise protocol; gk delivery rides the
   pairwise messaging sessions; join-PKE KEM conventions)
8. Fleischhacker, Krupp, Malavolta, Schneider, Schroeder,
   Simkin, "Efficient Unlinkable Sanitizable Signatures from
   Signatures with Re-randomizable Keys" (the [11] KRS
   definition [CFG+] builds on; informative)

---

## 14. Implementation inventory (input to the implementation plan)

What exists, what is new, and what depends on what, so an
implementation plan can be sequenced by build dependency.

**Exists (reused unchanged):** core/ AEAD, HKDF, RNG,
custody seam (D-CUST-1), `gy_mldsa44` / `gy_mldsa87` public
verifiers, the hybrid identity and pairwise sessions for gk
delivery, the classical geryon_group / geryon_groups_server
targets as the structural precedent (D-GRP-2, 3, 7 shapes;
gy_group_store pattern), the liboqs ExternalProject build with
GERYON_OQS_DIST.

**New, primitive layer (Layer 1, core/):**

1. KR-ML-DSA glue per §3.3: draft present, uncompiled
   (src/core/krmldsa/krmldsa_impl.c, krmldsa44.{c,h},
   krmldsa87.{c,h}, cmake/krmldsa.cmake). Work: compile on
   every backend, dudect review of the glue's control flow,
   KATs per §12 (needs a deterministic-rnd test seam in the
   sign path, GY_TEST_HOOKS style), cross-backend and
   public-verifier checks. No other work depends on anything
   beyond this compiling and passing KATs.

**New, group vertical (own targets, per the groups-separate-
target precedent; Layer 5 API surface):**

2. Key hierarchy (§2.2): muk / uk / acq / expKey / gk / ek /
   rrs / rho derivations with the §2.3 label registry; skbase
   generation at hybrid-identity creation and its custody slot
   (§9). Depends on 1 for skbase / vkbase sizes only.
3. Group data structure (§4) encode / decode / validate:
   header, member entry, vk-lst (with the H(vkpsdn)
   optimization), core signature coverage, appendix lines,
   invite queue. Depends on 2. Wire freeze gated on D-QGS-7.
4. Operations (§5): one geryon call per [CFG+] protocol
   message, client side, including core re-signing under
   skpsdn and gk rotation on RemoveMember. The inventory
   includes the geryon-specific calls the paper folds into other
   flows (D-QGS-13 E8.8): Consolidate (the admin appendix fold,
   Fig. 18), AcceptInvitation as the INVITEE's own call (E3), and
   fetch-after-leave (the leaver's retained fetch token, §6.5).
   Depends on 1, 2, 3.
5. Server side (§7, D-QGS-6): stateless verification set
   (core signature and admin-line check, appendix-line check,
   fetch-token compare, invite / join-slot handling, send
   tokens). Depends on 3; uses only public verifiers.
6. Storage / zeroization (§9, D-QGS-8): the QSPGS analogue of
   gy_group_store; skpsdn never persisted. Depends on 2, 3.
7. KATs, negative matrix, benchmarks (§12, D-QGS-10) per
   component as each lands; the benchmark gate precedes the
   D-QGS-7 wire freeze.

**Decisions:** DECIDED end to end as of the v1.5.0 close-out.
D-QGS-7 (item 3's byte layouts,
context-string registry, C_UID encoding, H(vkpsdn) bytes) frozen
2026-09-13; D-QGS-8 (item 6) 2026-09-14;
D-QGS-10 (oracle choice, KATs, benchmarks, vector freeze) resolved
across the KAT and benchmark work, with the vector freeze executed at close-out;
D-QGS-12 (format epoch) 2026-09-14. D-QGS-6 (item 5,
skpers, tokens, versioning) and D-QGS-11 items 5 to 9 are decided
as of 2026-09-12.

---

## Open items

- `[RESOLVED 2026-09-12]` REVERSAL (D-QGS-1 / D-QGS-4
  amendments, D-QGS-11): authentication is KR-ML-DSA over
  liboqs internals with the public verifier; the voleith
  membership layer is withdrawn from this type (§1.4, §3, §6;
  see the project's design history for the measurements).
  D-QGS-11 items 1 to 9 ratified, including the full-t base
  key layout (§3.3). The 2026-07-08 entries below are retained
  as the record.
- `[RESOLVED 2026-07-08]` ADOPTION (D-QGS-1): QSPGS is geryon's
  SECOND group type, side by side with the classical [CPZ]
  type; hybrid suites get this type (voleith-only), classical
  suites keep the [CPZ] type with its roadmap unchanged
  (EncodeToG work item included); KR-ML-DSA not implemented;
  both registers active (§1.2; docs/decisions/qsgroups.md).
- `[RESOLVED 2026-07-08]` D-QGS-2 tier parameters: sk 16/32
  bytes by tier, independent of all classical key material;
  Hirose + grostl256_fixed on the 25519 tier, grostl512 +
  grostl512_fixed on the 448 tier; nullifier widths 16/32 per
  the library policy; grostl256 contingency; KDF-CTR/CMAC nodes
  rejected (§2.1; docs/decisions/qsgroups.md).
- `[RESOLVED 2026-07-08]` D-QGS-4 standalone-PQ posture: hybrid
  suites' membership layer is voleith-only, no classical
  companion; residual construction/implementation risks
  accepted by name with mitigations (§3.4;
  docs/decisions/qsgroups.md).
- `[RESOLVED 2026-07-08]` D-QGS-5 attribution and credentials:
  registered V2 nullifiers (scope = suite-tagged group_id ||
  epoch, mapping in the encrypted entry); V3 role/expiry
  predicates; V4 recovery claims; rate limiting via one-time
  scopes and spent-sets; V5 opener and V6 key evolution
  reserved as upgrade paths; suite string prefixed into m (§6;
  docs/decisions/qsgroups.md).
- `[RESOLVED 2026-07-08]` D-QGS-9 deniability regression:
  accepted and documented, V5 the improvement path (§10.2;
  docs/decisions/qsgroups.md).
- `[PARTIAL 2026-07-08]` D-QGS-3 leaf layout and conventions:
  DECIDED: gid = 12-byte truncated hash of suite_string ||
  group id; roles = 8 reserved single-byte V3 fields,
  EQ-provable individually, all-zero = plain member (no packed
  bitfield, no new BITMASK predicate); leaf OWFs are exactly
  grostl256_fixed / grostl512_fixed. UNDER REVISIT (user
  deliberating): the 25519 field-width budget (candidate 60/64
  with a 4-byte counter; nothing freezes until closed). Still
  open: label registry, commitment instantiation,
  expiry-vs-re-basing (§2.3; docs/decisions/qsgroups.md).
- `[SUPERSEDED 2026-09-12]` the D-QGS-2, D-QGS-3, and D-QGS-5
  resolutions above (voleith tier parameters, leaf layout,
  nullifier attribution) and the V5 improvement path under
  D-QGS-9; see the register status lines.
- `[RESOLVED 2026-09-12]` D-QGS-6 server side: D-GRP-2 shape;
  skpers = the hybrid identity's signing capability per [CFG+]
  footnote 7 (CLAUDE.md exception recorded); H(vkpsdn) storage;
  expKey-derived send / fetch tokens; no server-side content
  validation; compare-and-swap versioning (§7, §2.2;
  docs/decisions/qsgroups.md).
- `[RESOLVED 2026-09-13]` D-QGS-7 wire formats, msg_type
  allocation, gk delivery duty; H(vkpsdn) storage; context-string
  registry; C_UID encoding (§8; wire freeze, gated on
  the KR-ML-DSA benchmark).
- `[RESOLVED 2026-09-14]` D-QGS-8 storage/zeroization confirmation
  (D-GRP-7 carry-over; adds skbase / vkbase to the store model;
  skpsdn never persisted) (§9).
- `[RESOLVED 2026-09-16]` D-QGS-10 test-vector and oracle plan
  (KR-ML-DSA KATs on every backend, public-verifier cross-check;
  no authors' reference, self-generated posture recorded in
  TEST_ORACLES.md); sign / verify benchmarks (both tiers); the
  [CFG+] revision pin and vector freeze executed at the
  v1.5.0 close-out (§12).
- Section transcriptions (§4, §5 full protocol figures, App. B
  extended operations).
