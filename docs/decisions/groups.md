# Private Group System Decisions (M8/M9; GROUP_SPEC.md)

**Scope:** the geryon private group system (GROUP_SPEC.md), based
normatively on [CPZ] (docs/references/signal/2019-1416.pdf).
Register conventions and the full index live in
[README.md](README.md).

**Publication (v1.4.0):** this register is public with the M8
classical group release. References below to qsgroups.md /
QSPGS_SPEC.md (the M9 quantum-safe QSPGS type) are forward
references to a companion document published with a later release.

**Relationship to qsgroups.md (2026-07-08, D-QGS-1):** geryon
ships TWO group types side by side. This register governs the
CLASSICAL [CPZ] type (classical suites, M8) and remains fully
ACTIVE, including the libtalos_schnorr EncodeToG work item
(D-GRP-1). The quantum-safe QSPGS type (hybrid suites, M9) is
governed by [qsgroups.md](qsgroups.md) / QSPGS_SPEC.md; D-GRP-2,
3, and 7 additionally serve as precedent shapes there. Scope
effects on planned entries: D-GRP-10 is CLOSED AS WITHDRAWN and
D-GRP-11 is DECIDED as documentation posture (both 2026-07-10,
entries below); the suite rescope this implies is recorded as
dated amendments on D-GRP-3, D-GRP-4, and D-GRP-5. D-GRP-6
landed 2026-07-10; the register is COMPLETE (all planned entries
decided, D-GRP-10 withdrawn).

### D-GRP-1: Library boundary (all group operations in libtalos_schnorr)

- **Spec gap:** [CPZ] §6 requires group-element operations
  (HashToG, EncodeToG with candidate decoding, generic-linear
  Schnorr NIZKs) beyond what any single existing provider exposes;
  the paper's own implementation modified curve25519-dalek to add
  the Elligator-inverse EncodeToG.
- **Decision (2026-07-07, user directive):** ALL group-element
  operations live in libtalos_schnorr: Ristretto255 and Decaf448
  arithmetic, HashToG, EncodeToG, and the generic-linear NIZK
  engine (commit/challenge/respond split API and the Fiat-Shamir
  wrapper). geryon composes the protocol layer (MAC, credentials,
  verifiable encryption, group operations) clean-room over that
  API and implements NO group operation in-house: the
  XEdDSA-over-libsodium shape. Gaps found in libtalos_schnorr are
  fixed THERE, never worked around in geryon. Known work items
  this places on libtalos_schnorr before M8: EncodeToG for both
  tiers (reversible Elligator-inverse encoding, candidate decoding
  per [CPZ] §6: the provider returns the full profile-key
  candidate list directly, up to 64 on the 255 tier and 8 on
  448); further items are appended here as the GROUP_SPEC
  transcription surfaces them. Its examples/signal_kvac_demo.c
  covers [CPZ] §3.1-3.2 only (MAC, issuance proof, presentation
  over the HashToG attribute) and is a kernel demo, not the
  system.
- **EncodeToG work items (investigation 2026-07-07;
  implementation handoff: libtalos_schnorr
  docs/ENCODE_TO_GROUP.md):**
  1. API, both tiers, three primitive families: (a) padded
     16-byte encode with self-disambiguating decode (the Lizard
     method: hash-derived padding embedded in the field element
     identifies the unique Elligator preimage among the up to 8
     returned by the inverse map); (b) raw near-field-size encode
     (253 bits on the 255 tier) with CANDIDATE-LIST decode: the
     provider enumerates every preimage internally (including the
     +p field-overflow representatives) and returns the full
     [CPZ] §6 candidate list to the caller (up to 64 on the 255
     tier, up to 8 on 448), because disambiguation is the protocol
     layer's MAC check; (c) HashToG1, a single-Elligator
     hash-to-group on a HASH_BYTES field element (32 bytes on the
     255 tier; the provider primitive talos_hash_to_g1_<t>),
     realizing the M3 attribute and its profile-key candidate test
     ([CPZ] §6; the existing two-map RFC 9496 hash_to_group used
     for M1 stays).
  2. Provider: libsodium cannot host the 255-tier work (no public
     field arithmetic, no inverse map). The vendored
     ed448goldilocks tree already generates
     invert_elligator_nonuniform/uniform for BOTH curves (MIT,
     exercised by its constant-time test). Route the new
     functions to decaf_255, or port the MIT lizard module to C;
     confirm decaf-static compiles the curve25519 sources.
  3. Byte-compatibility gate (255 tier): encode is deterministic,
     so zkgroup oracle compat requires exact equality of the
     forward single-Elligator map (decaf_255 vs dalek / RFC 9496
     MAP) and of the padding scheme; preimage enumeration order
     is immaterial. The vendored decaf tree carries no RFC 9496
     vectors today: add decaf_255 / libsodium / RFC 9496
     cross-check tests.
  4. 448 tier: no upstream precedent (Signal is
     ristretto255-only). The padding layout over the ~446-bit
     field is defined by libtalos_schnorr (ENCODE_TO_GROUP.md,
     normative for the encoding; amended 2026-07-07, user
     directive: schnorr-specific design lives in schnorr, the
     same ownership as the 255 tier where the layout is Lizard's,
     fixed provider-side). geryon pins the schnorr version and
     states requirements only: 16-byte AND 32-byte inputs,
     deterministic encode, self-disambiguating decode, length
     unambiguity across the two input sizes, CT decode. Validated
     by provider self-KATs, frozen once first vectors publish.
     Both input sizes fit a single Decaf448 element with padding,
     so the raw candidate path may be unnecessary on that tier.
     This moves the 448 padding-digest choice out of D-GRP-4's
     scope.
  5. Constant time: decode operates on secret plaintexts (members
     decrypt membership entries with GroupSecretParams): fixed
     candidate count, no secret-dependent early exit,
     constant-time padding compare. Policy registered as
     D-GRP-8.
  6. Licensing: the lizard module in signalapp/curve25519-dalek
     (branch lizard2) is MIT (Bas Westerbaan, 2019) inside a
     BSD-3-Clause fork: permissive, may be read or ported.
     zkgroup/poksho stay GPL vector-only oracles; parameters the
     paper leaves open (e.g. the Lizard padding digest) are
     established from the MIT module and black-box oracle
     vectors, never from zkgroup source (D-GEN-6 / D-XED-11
     discipline).
- **Rationale:** library-first crypto (project policy); one audited
  provider for the proof group across the talos ecosystem; the
  demo already validates the composition shape.
- **Validation:** M8 gate: libtalos_schnorr EncodeToG completion
  (plus its permissive relicense) before M8 ticket execution;
  round-trip and candidate-decoding KATs land with the schnorr
  work; geryon review asserts no group arithmetic outside schnorr
  calls.

### D-GRP-2: Server side (ship all server crypto, stateless, separate target)

- **Spec gap:** KVAC is keyed verification: issuer and verifier
  are the same party (the server, holding ServerSecretParams).
  [CPZ] specifies the server's cryptographic operations but not
  whether a client library ships them, their statefulness, or
  their packaging.
- **Decision (2026-07-07):**
  1. geryon SHIPS all five server-side cryptographic operations:
     (i) ServerSecretParams generation + ServerPublicParams
     derivation ([CPZ] §5.8); (ii) AuthCredential issuance, MAC +
     issuance proof pi_I (§5.9); (iii) ProfileKeyCredentialRequest
     verification + blind issuance, pi_BR verify and (S1, S2,
     pi_BI) (§5.10); (iv) AuthCredentialPresentation verification,
     Z recomputation + pi_A (§5.12); (v)
     ProfileKeyCredentialPresentation verification, pi_P (§5.13).
     This is exactly the set requiring ServerSecretParams.
  2. The operations are STATELESS pure functions:
     (params, input objects) to (output objects / accept /
     reject). No store callbacks, no state machine. Group storage,
     ProfileKeyCommitment storage, role enforcement, rate
     limiting, and channel handling belong to the deploying server
     application ([CPZ] §5.5: roles are server-enforced access
     control, not cryptography).
  3. Packaging: a SEPARATE static build target
     (geryon_groups_server) over the same groups/ internals as the
     client target. Client binaries never contain issuance code or
     any ServerSecretParams-touching path; the role split is
     structural, not documentary.
  4. Constant-time discipline applies in full: ServerSecretParams
     are long-lived secret keys; issuance and the Z recomputation
     are secret-keyed and get timing targets like any other
     secret-keyed code.
  5. Architecture rider: groups/ is a PARALLEL VERTICAL over
     core/ plus libtalos_schnorr. It consumes neither kex/ nor
     ratchet/ nor session/, and nothing in M0-M7 consumes it; the
     client and server targets are two facades over shared
     groups/ internals. The strict one-layer-down rule extends
     accordingly (the project layering amendment lands at M8).
- **Rationale:** every client operation is only testable against a
  real verifier, so the code must exist in-tree regardless;
  shipping decides only whether deployers link it or reimplement
  KVAC verification math (the failure mode to avoid). Signal's
  zkgroup ships both roles in one library, FFI'd by their server:
  a proven shape, improved here by the separate-target split
  (least surface on endpoints). Statelessness spares a server
  persistence interface and matches the paper's
  server-as-blind-reference-monitor trust model: untrusted for
  privacy (cannot decrypt entries, cannot link actions to UIDs,
  cannot forge entries without GroupSecretParams), trusted as the
  consistency point and access-control enforcer.
- **Validation:** client-vs-server round-trip tests for every
  operation pair; a link-time check that the client target
  exports no server symbols and contains no
  ServerSecretParams-consuming code; timing targets on issuance
  and presentation verification; the trust matrix transcribed in
  GROUP_SPEC §11.

### D-GRP-3: Tier pairing and suite binding (full suite_id, FS OtherInfo)

- **Spec gap:** [CPZ] specifies a single group G (its implementation
  is ristretto255-only); geryon has two proof-group tiers and four
  suites and must decide how group objects bind to suites. RFC 8235
  leaves OtherInfo contents to the protocol but requires that its
  format "must be fixed and explicitly defined in the protocol
  specification".
- **Decision (2026-07-07, user confirmed):**
  1. Tier pairing: Ristretto255 is the proof group for the 25519
     suites (geryon_c25519, geryon_h25519_512); Decaf448 for the
     448 suites (geryon_c448, geryon_h448_1024). geryon-side HKDF
     derivations use the tier hash (SHA-256 on 25519 tiers,
     SHA-512 on 448) per the suite-table discipline (curve and
     hash move together); libtalos_schnorr's internal FS challenge
     is the provider's curve-native per-tier choice (SHA-512 on
     255, SHAKE256 on 448; corrected by the D-GRP-4 amendment of
     2026-09-01, which supersedes the "SHA-512 on both tiers"
     wording originally here).
  2. FULL suite_id binding (user call): group objects bind
     app_id || protocol_version || suite_id (D-GEN-3), not the
     curve tier. geryon_c25519 and geryon_h25519_512 identities
     produce mutually incompatible group objects despite sharing
     Ristretto255. Deliberate: the group-layer analogue of
     cross-suite handshake rejection; those identities cannot
     message pairwise anyway (suites pinned per identity, mixed
     deployments require distinct identities), and it gives M9 a
     clean seam (hybridized-proof suites bind differently by
     construction; the version story is D-GRP-10).
  3. FS OtherInfo format, fixed here per RFC 8235: two
     length-prefixed subitems per the RFC's subitem rule:
     (a) the D-GEN-3 suite-binding string; (b) a proof-type label
     (pi_I, pi_A, pi_BR, pi_BI, pi_P; exact strings fixed at the
     GROUP_SPEC §5 transcription), making cross-protocol proof
     reuse structurally impossible rather than incidentally so
     (statement shape k/m and generators are already
     transcript-bound, but two proof types could share a shape).
  4. UserID rider: schnorr's challenge API requires a non-empty
     UserID (RFC 8235's prover identifier); presentation provers
     are ANONYMOUS, so UserID carries fixed role strings only
     (server / member role labels, exact strings at §5), never a
     real user identity, in every proof type.
  5. Uniformity: the same suite string feeds the HKDF labels
     (D-GRP-4), the NUMS generator-derivation seeds (D-GRP-5:
     structurally distinct generator sets per suite), and the
     wire tags (D-GRP-6). Suite binding never depends on
     incidental structure such as point sizes (D-GEN-3
     discipline).
- **Rationale:** D-GEN-3 extended verbatim to the group vertical;
  the no-mixing philosophy (suite pinned per identity, never
  negotiated) applied at the group layer; RFC 8235's OtherInfo is
  designed exactly for this contextual binding.
- **Validation:** cross-suite negative tests: proofs and group
  objects generated under one suite fail verification under every
  other, INCLUDING the same-curve classical/hybrid pair;
  wrong-proof-type entries in the §12 negative matrix (pi_A
  presented as pi_P, etc.); a check that no UID bytes ever appear
  in a UserID field.
- **Amendment (2026-07-10, D-QGS-1 follow-through):** the suite
  scope of item 1 narrows to the CLASSICAL suites: Ristretto255
  serves geryon_c25519 and Decaf448 serves geryon_c448 only. The
  hybrid suites use the QSPGS group type (qsgroups.md /
  QSPGS_SPEC.md) and hold NO objects of this system, so the
  same-curve classical/hybrid incompatibility of item 2 is now
  structural rather than a binding property, and item 2's "clean
  seam for M9 hybridized-proof suites" rationale is superseded
  (D-GRP-10 withdrawn). Everything else stands: full suite_id
  binding, the OtherInfo format, the UserID rider, and the
  cross-suite negative tests, which now also assert that
  classical group objects presented under a hybrid-suite identity
  fail (cross-TYPE rejection).

### D-GRP-4: Hash conventions (RFC 8235 FS challenge, HKDF derivations, no SHO)

- **Spec gap:** [CPZ]'s normative body models every hash (HashToG,
  HashToZq, Derive) as a random oracle over "a cryptographic hash
  function" and prescribes no instantiation; HMAC-SHA256 inside
  the "stateful hash object" (SHO) construction appears only in
  the implementation section ([CPZ] §6) and is described there as
  new, i.e. zkgroup engineering, not part of the analyzed scheme.
  RFC 8235 (docs/references/standards/rfc8235.txt) DOES prescribe
  the Fiat-Shamir challenge: H SHALL be a secure cryptographic
  hash (SHA-256/384/512, SHA3 family), output length at least the
  subgroup order, minimum input
  c = H(g || V || A || UserID || OtherInfo), clear item
  boundaries with RECOMMENDED 4-byte length prefixes.
- **Decision (2026-07-07, user confirmed):**
  1. FS challenge: libtalos_schnorr's existing
     gen_compute_challenge_ex family, both tiers: one-shot
     SHA-512 over a 4-byte-length-prefixed transcript (k/m
     dimension binding, the m x k generator matrix, all V
     commitments, all P targets, UserID, OtherInfo), reduced to a
     canonical scalar. This is RFC 8235's construction
     generalized to the generic-linear setting; SHA-512 is on the
     RFC's list and its output exceeds both tiers' orders (~253
     and ~446 bits). No SHO, no poksho-compat mode.
  2. Design posture (user directive, generalizing D-GEN-6):
     geryon is 100% SPEC compliant; where a spec leaves
     implementation open, geryon makes its own choice and does
     NOT chase application-level compatibility with
     libsignal/zkgroup ("if all I wanted was to be compliant with
     libsignal, I'd just modify libsignal"). Consequence:
     protocol-level zkgroup byte-compat is dropped. The group
     protocol layer is validated by GROUP_SPEC-derived self-KATs
     plus per-component oracles, the same validation model the
     hybrid suites use. Feeds D-GRP-9: encoding vectors can come
     from the MIT dalek lizard2 harness, so the GPL zkgroup
     oracle is likely unnecessary entirely.
  3. geryon-side derivations (group master key to
     (a1, a2, b1, b2), ServerSecretParams expansion, HashToZq,
     HashToG input expansion, hedged proof nonces): core/
     HKDF/HMAC with domain-separated info strings per D-GEN-3; no
     SHO-like stateful abstraction. The exact label set lands
     with D-GRP-5 and the GROUP_SPEC §5 transcription.
  4. Hash-to-tier pairing for the geryon-side derivations follows
     D-GRP-3; libtalos_schnorr's internal SHA-512 on both tiers
     is the provider's RFC-conformant choice and stays.
- **Rationale:** the specs settle it: [CPZ] prescribes no hash,
  RFC 8235 prescribes the FS shape, and schnorr already conforms
  to RFC 8235 including the length-prefix recommendation.
  Replicating poksho's SHO would be exactly the compat
  parameterization D-GEN-6 forbids, with no permissive reference
  to build from (SHO exists only in GPL poksho; black-box
  reconstruction of a stateful ratcheting hash protocol is
  impractical and clean-room-hostile). Without SHO even the
  system parameters differ, so zkgroup byte-compat is
  all-or-nothing, and no wire-interop goal exists with Signal
  groups (own wire format D-GRP-6, a 448 tier Signal lacks, M9
  hybridization).
- **Validation:** RFC 8235 conformance asserted in schnorr's test
  suite (transcript composition, length prefixes, challenge
  reduction); geryon derivation labels freeze at first published
  KAT vectors; the §12 negative matrix includes
  transcript-malleability checks (item reordering or boundary
  shifts must change the challenge).
- **Amendment (2026-07-10):** the rationale's closing list cited
  "M9 hybridization" among the reasons no wire-interop goal
  exists with Signal groups; that plan is withdrawn (D-GRP-10).
  The argument stands unchanged on the remaining grounds (own
  wire format D-GRP-6, a 448 tier Signal lacks).
- **Amendment (2026-09-01): the FS challenge hash is per-tier, NOT
  SHA-512 on both tiers.** Decision items 1 and 4 above (and the
  D-GRP-3 decision-1 parenthetical, line ~189) state that
  libtalos_schnorr's internal Fiat-Shamir challenge is "SHA-512 on
  both tiers." That is inaccurate as built; the as-built provider
  (verified in talos_schnorr_{255,448}.c) uses the curve-native
  hash on each tier:
    - 255 (Ristretto255): SHA-512 over the length-prefixed
      transcript, reduced by crypto_core_ristretto255_scalar_reduce
      to a 32-byte scalar. (As originally stated.)
    - 448 (Decaf448): SHAKE256 with a 114-byte squeeze, reduced by
      decaf_448_scalar_decode_long to a 56-byte scalar.
  This CORRECTS items 1 and 4, and supersedes the "internal SHA-512
  FS challenge on both tiers" clause of D-GRP-3 decision 1. It does
  NOT change the security posture or any of D-GRP-4's actual
  decisions: SHAKE256 is on RFC 8235's permitted list (the SHA-3/
  XOF family is explicitly allowed), its 114-byte output far
  exceeds the ~446-bit 448 order, and it is the natural Ed448/
  Decaf448 choice (RFC 8032 Ed448 is SHAKE256-based), so the
  "curve and hash move together" suite-table discipline is in fact
  BETTER honored than a forced SHA-512. The FS transcript SHAPE
  (k/m dimension binding, 4-byte length prefixes, the generator
  matrix, all V, all P, UserID, OtherInfo) and the reduce-to-
  canonical-scalar step are identical across tiers; only the hash
  primitive and its reduction differ. RFC 8235 conformance, the
  no-SHO rule, and the D-GEN-6 no-compat posture all stand
  unchanged. Separately, the geryon-SIDE HKDF derivation hash
  pairing of D-GRP-3 decision 1 (SHA-256 on 25519, SHA-512 on 448)
  is a DIFFERENT mechanism (geryon's own Derive in group_params.c,
  not the schnorr FS challenge) and is unaffected by this
  correction. Surfaced while building the 448 half of the
  independent group KVAC verify-equation oracle (tools/oracles/
  group_kvac), which reconstructs the 448 transcript and so had to
  reproduce SHAKE256/decode_long exactly.

### D-GRP-5: System and server parameters (named NUMS seeds, paper-shaped Derive, random server keys)

- **Spec gap:** [CPZ] fixes the generator inventory (§3.1 MAC set,
  n = 4 per §5.9-5.10; §5.8 system additions) and illustrates NUMS
  derivation ("e.g., G_m1 = HashToG('m1')") but leaves the seed
  strings open. §4.1 defines Derive : {0,1}^2k -> (Zq)^2 as a
  SINGLE hash call (master key in, key tuple out) but does not
  instantiate it. §3.1 KeyGen prescribes MAC secret keys as
  randomly-chosen scalars.
- **Decision (2026-07-07, user confirmed; posture: as faithful to
  [CPZ] as possible):**
  1. Generator set, per suite: G is the standard basepoint
     (RFC 9496; schnorr's default), plus 20 NUMS generators: the
     full §3.1 MAC set at n = 4 (G_w, G_wprime, G_x0, G_x1,
     G_y1..G_y4, G_m1..G_m4, G_V; the three unused G_mi are kept
     for scheme fidelity and M9 room) and the §5.8 system
     additions (G_a1, G_a2, G_b1, G_b2, G_j1, G_j2, G_j3).
  2. Seed structure (Option A, the paper's own convention): one
     named seed per generator,
     G_<name> = hash_to_group(suite_string || "sysparams" ||
     <name>), index 0. Full name/seed table in GROUP_SPEC §2.2.
     The suite string is the full D-GRP-3 descriptor, so every
     suite gets a structurally distinct generator set.
  3. GroupSecretParams: GroupMasterKey is {0,1}^2k per tier
     (32 bytes on the 25519 tiers, 56 bytes on 448). Derive is
     instantiated as one HKDF expansion per encryption scheme,
     two domain-separated purposes (uid encryption -> (a1, a2);
     profile-key encryption -> (b1, b2)), okm partitioned into
     per-scalar wide segments reduced to canonical scalars via
     schnorr hash_to_scalar-equivalent reduction. Per-object
     expansion is the PAPER's shape (Derive is one hash call),
     not an implementation preference.
  4. ServerSecretParams: all 16 MAC scalars (w, wprime, x0, x1,
     y1..y4, for each of iparams_A and iparams_P) are RANDOM
     (core/ rng.c), per §3.1 KeyGen. No production
     seed-derivation path exists (zkgroup's seed expansion is
     implementation convenience, rejected per the D-GRP-4
     posture); deterministic KATs use the GY_TEST_HOOKS derand
     seam (D-PQ-3 precedent).
  5. Label registry (small, frozen at first published KATs):
     20 generator seeds + 2 Derive purposes + HashToG/HashToZq
     purpose prefixes (M1, M3, j3: distinct random oracles get
     distinct domain prefixes, within faithful RO instantiation)
     + hedged proof-nonce labels (the paper requires only random
     nonces; hedging is D-PQ-1-style hardening). Exact strings
     fixed in the GROUP_SPEC §2.2 and §5 tables.
  6. Library boundary rider: everything above is [CPZ]-protocol
     material and lives in geryon (GROUP_SPEC), NOT
     libtalos_schnorr. Schnorr's role is the primitives, all of
     which it already ships: hash_to_group (generator seeds,
     HashToG), scalar_random (server keys, nonces),
     hash_to_scalar (Derive reduction, HashToZq; public on both
     tiers). No new schnorr work item arises from D-GRP-5.
- **Rationale:** paper-faithful throughout (user directive:
  100% spec compliant, no libsignal application-compliance).
  Named seeds are the paper's illustrated convention and D-GEN-3
  explicit-label discipline; per-object Derive and random server
  keys are prescribed, not chosen.
- **Validation:** NUMS transparency KATs recompute every
  generator from its published seed string; sanity checks
  (pairwise distinct, none the identity or basepoint);
  per-tier Derive KATs; cross-suite generator disjointness test;
  review check that no ServerSecretParams seed path exists
  outside GY_TEST_HOOKS.
- **Amendment (2026-07-10):** item 1's "M9 room" motivation for
  the three unused G_mi is withdrawn with D-GRP-10; they are kept
  for scheme fidelity alone. The generator set is unchanged.

### D-GRP-6: Wire formats and envelope integration (canonical encodings, one msg_type, day-aligned dates)

- **Spec gap:** [CPZ] defines every object mathematically (group
  elements, scalars, tuples) and gives Table 1 sizes, but
  prescribes zero bytes-on-the-wire: no serialization, no
  framing, no distribution mechanism, no timestamp encoding.
  zkgroup's serialization is GPL engineering and no compliance
  target (D-GRP-4), so the entire wire layer is implementer
  territory.
- **Decision (2026-07-10, user confirmed):**
  1. Surface split: geryon defines canonical byte encodings for
     the client-server group objects (every GROUP_SPEC §3
     object; required for KATs and for a geryon client against a
     geryon-based server) but NO transport or RPC framing, which
     belongs to the deploying server per D-GRP-2 statelessness.
     The only group data that crosses pairwise sessions is
     GroupMasterKey distribution (item 4). Server API framing is
     explicitly out of scope.
  2. Encoding convention: the M0 wire-helper conventions,
     unchanged: fixed-layout concatenation of canonical
     primitives, RFC 9496 element encodings (32/56 bytes by
     tier), fixed-width big-endian scalars and integers, no TLV,
     no protobuf. Variable length occurs in exactly one place,
     member-entry lists, with a 2-byte BE count bounded by
     GY_GROUP_MAX_ENTRIES (D-GRP-7). Parsing is strict:
     non-canonical element encodings, wrong lengths, and
     trailing bytes are rejected.
  3. Object header: every top-level object carries object-type
     byte || group-wire-version byte (0x01) || compact suite_id
     tag; nested objects are untagged. The tag is identification
     only: cryptographic suite binding lives in the KDF and FS
     transcript layer (D-GRP-3 item 5), never in incidental wire
     structure, so a forged tag changes nothing verifiable.
  4. Envelope integration: exactly ONE new msg_type in the
     D-GEN-1 typed envelope, GROUP_KEY_DISTRIBUTION, payload =
     header + GroupMasterKey and nothing else; the receiver
     rederives GroupSecretParams / GroupPublicParams (D-GRP-7),
     so shipping derived values would only create a consistency
     question. Duty split per D-SES-1: the library defines the
     format, encode/decode, and validation; the application
     decides when to send and whether to accept. Credentials and
     presentations never ride the pairwise envelope.
  5. Versioning: the group subsystem carries its own wire
     version byte (0x01), independent of the pairwise
     protocol_version (it is a parallel vertical, D-GRP-2
     rider); encodings freeze at first published KATs, the same
     rule as the label registry.
  6. Redemption date: uint64 big-endian seconds since the Unix
     epoch, MUST be a multiple of 86400 (a 00:00 UTC day
     boundary), enforced at issuance AND verification: a
     non-aligned value is rejected, never rounded. The
     redemption date is a REVEALED attribute (the server sees it
     at issuance and presentation); second-level precision would
     be a near-unique per-user tag, so day granularity is what
     keeps the per-day anonymity bucket large, matching [CPZ]
     §5.9's daily-credential model. The M3 attribute encoding is
     the canonical scalar reduction of the unsigned value.
     Signed int64 was considered (Unix time_t precedent, user
     question) and rejected: pre-1970 values are never valid in
     this field, so signedness only adds an always-invalid
     representable range plus a two's-complement question in the
     scalar mapping; an int64 with a non-negativity rule is
     functionally a capped uint64 stated less simply. The
     signed-prekey timestamp was reviewed under the same
     question and deliberately stays uint64, unchanged.
- **Rationale:** convention reuse over invention (the M0 wire
  discipline already satisfies the project's versioned-from-day-one
  invariant); strict parsing follows the negative-matrix posture
  (D-GRP-9); the single-msg_type envelope footprint keeps the
  group vertical out of the pairwise stack except at the one
  point the paper requires ([CPZ] §2.5 master-key sharing).
- **Validation:** encode/decode round-trip KATs for every §3
  object; strict-parsing negative tests (non-canonical element
  encodings, truncated and trailing bytes, oversized entry
  counts, non-day-aligned redemption dates, unknown
  version/type/suite tags); GROUP_KEY_DISTRIBUTION integration
  test including rederivation on receipt; [CPZ] Table 1 size
  cross-checks (D-GRP-9).

### D-GRP-7: State, storage, and roles (rederive from GroupMasterKey, no caching)

- **Spec gap:** [CPZ] prescribes only fragments of client state
  handling: users "store an AuthCredential" and "store a
  ProfileKeyCredential" after verifying issuance proofs (§5.6),
  GroupSecretParams are derived from the shared GroupMasterKey
  (§5.5), the UidCiphertext is recomputed per operation (§5.7
  AuthAsGroupMember), the server is the authoritative holder of
  group state (GroupPublicParams plus entry tuples), and Role is
  "enforced by the server, not by a cryptographic mechanism" with
  specific roles out of scope (§5.5). Storage shape, caching,
  credential lifetimes, zeroization points, and role plumbing are
  implementer territory.
- **Decision (user-confirmed 2026-07-08, with the strengthening
  that NOTHING derived is cached):**
  1. Group record: the store callback holds exactly one secret
     per group, the GroupMasterKey (2 kappa = 32/56 bytes,
     D-GRP-5). No derived value is cached, in the store or in
     memory across operations: GroupSecretParams and
     GroupPublicParams are rederived on demand (one HKDF
     expansion per D-GRP-5, cheap) and derived secrets are
     zeroized after each operation. Local lookup key: a GroupID
     in the D-SES-3 style, the suite hash over suite_id ||
     GroupPublicParams encoding, truncated, local-only, never on
     the wire.
  2. Membership state is never stored or cached by the library.
     FetchGroupMembers results pass through the API: the library
     decrypts entries, distinguishes full from invited members
     (missing ProfileKeyCiphertext), and surfaces malformed or
     inconsistent ciphertexts (the §1 malicious-server corruption
     case) as structured errors, never crashes. Plaintext caching
     is application territory, documented as such. Compile-time
     input bound in the D-SES-4 style: at most
     GY_GROUP_MAX_ENTRIES (default 1024) entries processed per
     fetch; applications may lower, not raise.
  3. Credentials are secret key material under D-GEN-4 (a stolen
     AuthCredential authenticates the thief as that
     UidCiphertext): at rest through store callbacks with the
     AEAD-under-stretched-key rule, plaintext copies zeroized.
     AuthCredential is stored with its redemption date; the API
     exposes validity and the library refuses to build a
     presentation from an expired credential (error, application
     re-acquires; no silent reuse). ProfileKeyCredential is
     stored per target UID and replaced, old one zeroized, when a
     newer credential for that UID is acquired (UpdateProfileKey
     obsoletes credentials over the old ProfileKey).
  4. ProfileKeys: the user's own ProfileKey is library-generated
     ([CPZ] §5.6 CommitToProfileKey step 1) and persists through
     a store callback (it must stay consistent with the
     server-side commitment). Contacts' ProfileKeys enter geryon
     as call arguments to AddGroupMember / GetProfileKeyCredential;
     the library defines no contact database (D-SES-1 boundary:
     the application owns the contact model).
  5. Zeroization points: (a) derived GroupSecretParams scalars
     after every operation; (b) on group leave, eviction, or
     local delete: the group record and group-scoped credentials,
     with the documented §5.5 caveat that this is device hygiene,
     not revocation (a departed member may retain the key; rekey
     posture is D-GRP-11); (c) expired AuthCredentials on
     replacement or first detected expiry; (d) all staged
     material on any operation failure: group operations are
     transactional per the D-SES-10 pattern, staging mutations
     and committing through callbacks only at the single success
     point.
  6. Roles: geryon carries the ACCESS ROLE as an opaque
     fixed-size value through AddGroupMember and returns it from
     fetch decryption; it never interprets it. The
     geryon_groups_server target verifies presentations and hands
     the deployer the authenticated UidCiphertext plus the stored
     role; authorization policy is the deployer's (D-GRP-2).
     "Access role" is the API term, kept distinct from D-GRP-3's
     fixed protocol-role strings (pi_A etc.) used as FS UserID
     labels; the two are unrelated.
- **Rationale:** rederive-only matches the paper's own data flow
  (share the master key, derive the params) and keeps exactly one
  long-lived secret at rest per group, eliminating any
  master-key/params consistency question; the user explicitly
  rejected caching GroupSecretParams. The library-never-caches
  membership line follows D-SES-1 (geryon never talks to a
  network; the server is authoritative). Credential-as-secret
  follows from the anonymity design itself.
- **Validation:** rederivation determinism KAT (same
  GroupMasterKey always yields identical params); zeroization
  checks on operation exit, group delete, and credential
  replacement; expired-credential refusal test; oversized-fetch
  rejection at GY_GROUP_MAX_ENTRIES; fault-injection transactional
  tests in the D-SES-10 style (fail every group operation at every
  step, assert store equality with the pre-operation snapshot).

### D-GRP-8: Group-path constant-time boundary (provider owns primitive CT, geryon owns composition CT)

- **Spec gap:** [CPZ] §6 describes profile-key candidate decoding
  (up to 64 candidates on the 255 tier) but says nothing about timing
  discipline. The project's constant-time requirements are
  unconditional but predate the D-GRP-1 split (all group-element
  operations in libtalos_schnorr). Open: where CT responsibility
  sits for group operations.
- **Decision (2026-07-08, user confirmed; reshaped from
  "EncodeToG constant-time policy" per user directive: primitive
  CT is the crypto libraries' job, geryon composes):**
  1. Primitive CT is libtalos_schnorr's contract, already fixed
     in its ENCODE_TO_GROUP.md §6 (fixed 8-preimage decode, CT
     padding compare, CT candidate select, CT forward map, all in
     schnorr's timing harness). geryon relies on the version pin
     and does not restate or re-own those rules beyond the
     GROUP_SPEC §6.1 requirements list.
  2. geryon owns CT only in its own composition code. Concretely
     the [CPZ] §6 profile-key candidate-test loop on the 255 tier
     (schnorr returns the full raw-decode candidate list directly,
     up to TALOS_ENCODE_255_MAX_CANDIDATES = 64 on the 255 tier
     and 8 on 448; geryon tests each returned candidate via
     EB1 == HashToG1(ProfileKey_c, UID)^b1): fixed iteration count over ALL
     MAX_CANDIDATES slots, no early exit on match, const_memcmp for
     every comparison, constant-time select of the winning
     plaintext. The standing rules (no secret-dependent branches,
     no secret-indexed access) apply to credential and
     presentation glue as elsewhere.
  3. Verification stays with geryon under the existing
     linked-library policy: schnorr-backed group paths join
     geryon's timing tests exactly as libsodium/liboqs paths do
     (CT discipline applies equally to linked-library
     primitives).
- **Rationale:** implementation responsibility follows the code
  (D-GRP-1 boundary); avoids duplicated normative CT text
  drifting across two repos; keeps geryon's verification bar
  intact (a library's CT claim is checked, not trusted).
- **Validation:** timing-harness runs over decode and the
  candidate loop with fixed vs varying secret inputs; review
  check that the candidate loop has no data-dependent break or
  early return; ENCODE_TO_GROUP.md version pin checked at vendor
  update time.

### D-GRP-9: Normative text pin and oracle scope (no GPL zkgroup oracle for M8)

- **Spec gap:** the register needs an external-oracle pin for the
  group system (D-GEN-6 discipline), and the normative basis is a
  2019 paper; open question (user, 2026-07-08) whether Signal has
  since published a spec or adopted a newer reference.
- **Findings (checked 2026-07-08):** signal.org/docs lists six
  specifications (XEdDSA, X3DH, PQXDH, Double Ratchet, Sesame,
  ML-KEM Braid), none for groups; Signal self-hosts the [CPZ]
  paper (signal.org/blog/pdfs/signal_private_group_system.pdf),
  which IS Signal's reference. eprint 2019/1416: received
  2019-12-09, five revisions, last 2020-11-10 (the full version
  of the CCS'20 publication, DOI 10.1145/3372297.3417887). The
  checked-in docs/references/signal/2019-1416.pdf is dated
  "Draft - November 9, 2020", exactly that final revision; no
  newer text exists. libsignal's zkgroup/zkcredential cite only
  [CPZ]; Signal's later additions (expiring, receipt, and
  call-link credentials; group send endorsements) are unpublished
  engineering extensions living only in GPL code, categorically
  out of scope per the D-GRP-4 posture (no spec, no compliance
  target).
- **Decision (2026-07-08, user confirmed; posture: stick to the
  paper):**
  1. Normative basis pinned: [CPZ] = eprint 2019/1416, final
     revision of 2020-11-10 ("Draft - November 9, 2020"), the
     checked-in docs/references/signal/2019-1416.pdf. Any
     re-download must match this revision.
  2. NO GPL zkgroup/poksho oracle is required for M8. The group
     protocol validates per D-GRP-4 (GROUP_SPEC-derived self-KATs
     plus per-component oracles, the hybrid-suite model); the
     255-tier encoding vectors come from the MIT dalek lizard2
     branch run as a permissive harness (ENCODE_TO_GROUP.md §8).
  3. zkgroup black-box vector generation remains a named FALLBACK
     only, invoked solely if the lizard2 harness proves
     insufficient for the 255 encoding layer; if ever invoked it
     enters docs/TEST_ORACLES.md (name, version, license,
     generation command) at that time, not before.
  4. Informative M9 reading item: eprint 2026/453 ("A
     Quantum-Safe Private Group System for Signal from Key
     Rerandomizable Signatures"; Signal Messenger + IBM Research
     authorship, Signal's own proposed [CPZ] successor; the
     original "third-party" wording here was a recorded error,
     corrected 2026-07-08): informative only under THIS register
     entry; its evaluation as a candidate system is
     QSPGS_SPEC.md.
- **Rationale:** D-GRP-4 dropped protocol byte-compat, which
  removed the only job a GPL protocol oracle had; the encoding
  layer has a permissive authoritative source (MIT lizard);
  pinning the paper revision makes the normative text itself
  checkable (D-GEN-6 pin discipline applied to a spec rather
  than an oracle).
- **Validation:** [CPZ] Table 1 size cross-checks against the
  implementation; the GROUP_SPEC §12 negative matrix; a
  TEST_ORACLES.md entry exists ONLY if the fallback fires.

### D-GRP-10: M9 transcript forward-compatibility (CLOSED AS WITHDRAWN)

- **Original scope (planned):** bound what the old M9
  (hybridizing this system's proofs via the two-stage Fiat-Shamir
  split, Schnorr + VOLEitH over one shared transcript) could and
  could not change, and keep M8 proof transcripts
  single-prover-agnostic so that split would compose without
  rework (the old GROUP_SPEC §12).
- **Decision (2026-07-10, user confirmed): WITHDRAWN.** D-QGS-1
  replanned M9: the hybrid suites get the separate QSPGS group
  type (qsgroups.md / QSPGS_SPEC.md) instead of hybridized [CPZ]
  proofs, so no future prover shares these transcripts and the
  forward-compatibility constraint buys nothing. No constraint on
  classical proof transcripts is registered; they follow
  D-GRP-3/4 alone. GROUP_SPEC §12 was retained briefly as a
  tombstone and removed in the 2026-07-10 spec cleanup pass; the
  old §13/§14 are renumbered §12/§13.
- **Rider:** the FS-split machinery itself is NOT dead: ROADMAP
  M10 (pairwise first-flight deniable PQ auth, TENTATIVE) still
  plans the Schnorr + VOLEitH two-stage split, sourced directly
  from libtalos_schnorr / libtalos_voleith rather than from group
  work. Nothing in this register constrains it.
- **Validation:** none (no behavior); the §12 negative matrix is
  unaffected.

### D-GRP-11: Harvest-now-decrypt-later posture (documentation, classical type)

- **Spec gap / origin:** promoted out of the M9 footnotes at user
  direction (2026-07-08): HNDL is a first-class concern (forward
  secrecy is a hard requirement in many modern deployments, e.g.
  payments), so the group system needs an explicit stored-state
  exposure posture, not an aside.
- **Structural answer (D-QGS-1):** the question "how does the
  group system resist HNDL?" is answered by TYPE SELECTION: the
  QSPGS type is HNDL-safe by construction and serves the hybrid
  suites; this classical type carries no PQ claims of any kind,
  exactly like the classical pairwise suites.
- **Decision (2026-07-10, user confirmed): what remains here is
  documentation posture, fixed as follows.** GROUP_SPEC §11 and
  the public API documentation for the classical group subsystem
  MUST state plainly:
  1. HNDL exposure: every confidentiality and anonymity property
     of this subsystem rests on discrete-log assumptions in the
     proof group. Server-stored membership ciphertexts and
     recorded presentations are harvestable today and offer no
     protection against a later discrete-log (quantum) adversary;
     deterministic encryption makes candidate-UID and profile-key
     confirmation direct once the group structure falls.
  2. The GroupMasterKey is long-lived and [CPZ] defines no rekey;
     departed members may retain it (D-GRP-7 leave zeroization is
     device hygiene, not revocation). Group-state exposure is
     therefore indefinite in time.
  3. Scope statement: the classical group type provides NO PQ
     confidentiality or anonymity, and no PQ retrofit of this
     type is planned (D-GRP-10 withdrawn). Deployments with HNDL
     requirements use a hybrid suite, which carries the QSPGS
     group type.
- **Rationale:** honest scoping over false comfort; mirrors the
  the project rule that classical suites exist purely for
  size/bandwidth-constrained deployments, provide no PQ
  confidentiality, and must say so in API docs.
- **Validation:** review check at M8 close-out that GROUP_SPEC
  §11.1 and the public-header documentation carry the three
  statements; no code behavior.

### D-GRP-12: Group format versioning (capability epoch pinned at creation)

- **Spec gap / origin:** raised at M8 close-out (2026-09-03) while
  reviewing the strict member-list role check (the GER LOW-1 fix):
  how does adding a future member role, or any versioned feature,
  avoid breaking existing groups for the clients already in them?
  A global strict check makes role-addition a fail-closed wire
  event across all groups; the cleaner answer is a per-group
  capability epoch.
- **Decision (2026-09-03, user confirmed, GER-GRPVER §11 all six
  points):** every group carries a 2-byte big-endian
  format_version, CHOSEN AT CREATION, IMMUTABLE for the life of
  the group, BOUND into the GroupID (the suite hash includes it),
  and carried in the master-key record and the
  GROUP_KEY_DISTRIBUTION envelope. CreateGroup mints at
  GY_GROUP_FORMAT_VERSION; install/load refuse a version outside
  [MIN, MAX] supported with GY_ERR_UNSUPPORTED. There is no
  in-place upgrade (new features mean a new group).
- **Why now:** v1.4.0 is the first public release, so the GroupID,
  envelope, and master-key record formats freeze here. Binding the
  version is a one-way door; the foundation must land in v1.4.0
  even though only version 1 exists.
- **Enforcement split:** the stateless server stays
  version-agnostic (it carries the global role set structurally,
  D-GRP-1/2); per-group feature restriction (an adder must not use
  a role the group's version does not define; a reader rejects an
  out-of-range role) is the client's, keyed on the pinned version.
  With one version this collapses to the global check.
- **Scope:** v1.4.0 lands the foundation only (the version field,
  its binding, and the support check). The per-version role table
  and a versioned-create API are DEFERRED to the release that adds
  a v2 feature; both are additive (no ABI break) when they land.
- **Rationale:** immutability gives old-client stability (an
  existing group's feature set cannot change under it);
  refuse-unsupported gives clean, explicit cross-version behavior
  instead of a silent mis-parse; two bytes so the epoch space is
  not boxed in at 255. The strict role bound (LOW-1) remains the
  structural floor beneath this principled mechanism.
- **Validation:** test_group_state (version reads back, an
  out-of-window version is refused with nothing stored, and a
  flipped bound-version byte fails the load integrity check),
  test_group_wire (envelope BE16 carriage and footprints).
  GROUP_SPEC §10.1.

### D-GRP-13: Rejected - classical group with hybrid (PQ) message transport

- **Origin:** raised 2026-09-03 - could a group allow post-quantum
  messaging between members while its credential/roster layer stays
  classical?
- **Analysis:** architecturally coherent - the group-metadata layer
  (classical KVAC over the proof group) and the 1:1 message
  transport (pairwise sessions, hybridizable) are orthogonal, and
  message content rides the transport, not the GroupMasterKey. But
  a classical group's membership metadata is broken by a discrete-
  log (quantum) adversary from PUBLIC values (A, B, presentations,
  server-stored ciphertexts) regardless of transport, so such a
  tier is honestly "PQ content, classical membership metadata."
- **Decision (2026-09-03, user):** REJECTED. The next release (M9)
  is the QSPGS post-quantum group; a classical-group-plus-hybrid-
  transport tier would be a strictly-weaker interim, dead on arrival
  once M9 ships, at the cost of a mixed mode that cuts against the
  one-suite-no-mixing discipline. Not built.
- **Consequence:** the tiering stays crisp - classical group implies
  classical transport; post-quantum implies the M9 QSPGS group over
  hybrid transport. group_guard continues to reject a hybrid
  custodian (GY_ERR_UNSUPPORTED via a NULL group tier). GER-GRPVER
  reserves nothing for tier/transport decoupling.
