# Quantum-Safe Private Group System Decisions (D-QGS; QSPGS_SPEC.md)

**Scope:** the geryon quantum-safe private group system
(QSPGS_SPEC.md), based normatively on [CFG+] (eprint 2026/453,
docs/references/signal/2026-453.pdf). Register conventions and the
full index live in [README.md](README.md). QSPGS_SPEC.md is the
normative text; where it and this register disagree, the register
is corrected first, spec second.

Namespace note: D-QGS-1..10 were reserved by QSPGS_SPEC.md while
the system was under evaluation. Adoption was confirmed 2026-07-08
and entries now land as decided. D-QGS-4 is REPURPOSED: its
reserved topic (hybrid KRS combiner) became moot when the hybrid
suites went voleith-only; it now records that posture decision.
D-QGS-3 is PARTIAL: mechanisms decided 2026-07-08, the 25519
leaf field-width budget is UNDER REVISIT by the user, and the
label registry / commitment items remain open. Still planned:
D-QGS-6 (server-side operation set), D-QGS-7 (wire formats),
D-QGS-8 (storage/zeroization confirmation), D-QGS-10 (test
vectors and benchmarks).

**AMENDMENT 2026-09-12 (authentication primitive reversed).**
The membership-authentication primitive is now KR-ML-DSA
([CFG+] Section 2, Figures 3 and 4) implemented over liboqs'
mldsa-native internals, NOT the libtalos_voleith ring-signature
layer. The reversal and its evidence are recorded as amendments
under D-QGS-1 and D-QGS-4 and as the new entry D-QGS-11
(provider boundary and instantiation). Scope effects on the
other entries, each also carrying a dated status line:
D-QGS-2, D-QGS-3, and D-QGS-5 (voleith tier parameters, leaf
layout, nullifier attribution) are SUPERSEDED as written and
retained as the record of the rejected design; their subjects
are re-decided at D-QGS-11 in KR-ML-DSA terms where they still
exist (tier mapping, pseudonym-key attribution). D-QGS-9
(deniability regression) STANDS unchanged: [CFG+] loses
membership deniability in exactly the same way. D-QGS-6 is
DECIDED (2026-09-12); D-QGS-7 is DECIDED (2026-09-13,
spec §8); D-QGS-8 and D-QGS-10 carry reserved stubs and
remain planned, now against the [CFG+] protocol as written
rather than a voleith transcription. QSPGS_SPEC.md §3 (KR-ML-DSA
"informative, not implemented") and §6 (voleith membership
layer) must be flipped to match; until then the register wins.
Working design record: docs/plans/QSPGS_DESIGN.md §12.

### D-QGS-1: New group type (side by side), suite mapping, and provider boundary

- **Context:** two group-system designs were evaluated: [CPZ]
  (GROUP_SPEC.md) and [CFG+] (QSPGS_SPEC.md, Signal's own
  proposed successor). [CPZ] is HNDL-exposed by design
  (ElGamal-encrypted membership, no key rotation), which is
  unacceptable for the hybrid suites' PQ-confidentiality claims
  but consistent with the classical suites' documented scope
  (no PQ claims anywhere).
- **Decision (user-confirmed 2026-07-08):**
  1. geryon ships TWO group types SIDE BY SIDE. The classical
     [CPZ] type (GROUP_SPEC.md, D-GRP register) serves the
     CLASSICAL suites; its roadmap (M8) continues unchanged,
     including the libtalos_schnorr EncodeToG work item. The
     quantum-safe QSPGS type specified by QSPGS_SPEC.md serves
     the HYBRID suites (M9, replacing the old
     hybridize-the-[CPZ]-proofs plan).
  2. The QSPGS type: the [CFG+] symmetric group data structure
     (AEAD-encrypted member list under a rotatable group key,
     admin-signed core, member appendix, invite queue,
     client-side validation) with the libtalos_voleith
     membership layer as its ONLY authentication and
     attribution mechanism (voleith-only; posture at D-QGS-4).
  3. Group types are suite-pinned like everything else: hybrid
     identities use the QSPGS type, classical identities the
     [CPZ] type; no negotiation, no cross-type or cross-suite
     group membership.
  4. Provider boundary for the QSPGS type: libtalos_voleith
     (shipped V1-V4 composable ring-signature stack) provides
     the membership layer; core/ provides AEAD/KDF/RNG; the
     join PKE is the suite KEM hybrid per HYBRID_SPEC
     conventions. libtalos_schnorr plays NO role in this type
     (its group work items belong to the classical type,
     D-GRP-1). Rerandomizable ML-DSA (KR-ML-DSA, [CFG+] §2) is
     NOT implemented; recorded as an alternative considered and
     rejected (in-house constant-time lattice sign path with no
     library seam, and it carries the lattice-newness risk the
     voleith layer avoids).
  5. Register relationship: BOTH registers remain active.
     D-GRP-2, 3, and 7 serve as precedent shapes for the QSPGS
     analogues (server statelessness/packaging, tier and suite
     binding, rederive-only storage); D-GRP-9's pin-and-oracle
     discipline recurs at D-QGS-10. Scope effects on planned
     D-GRP entries (10 moot as scoped, 11 largely answered
     structurally) are recorded in the groups.md header note.
- **Rationale:** the hybrid suites need HNDL-safe group state
  and PQ authentication; retrofitting either onto [CPZ]
  (encryption hybridization plus proof hybridization) is more
  work and more risk than adopting the successor design Signal
  itself proposes, instantiated with libraries the user owns
  and whose circuits already ship. The classical suites keep
  the smallest-wire [CPZ] design, consistent with their
  size/bandwidth purpose. Two systems maintained side by side
  is a deliberate, accepted cost: the types serve disjoint
  suite scopes and share the pairwise-messaging boundary. Costs
  accepted for the QSPGS type: [CFG+] is two months old with no
  independent review (KATs stay unfrozen until a revision pin,
  D-QGS-10); client-side validation admits attributable garbage
  entries (mitigation: rate limiting and admin cleanup);
  membership deniability regresses relative to [CPZ] (D-QGS-9).
- **Validation:** [CFG+] revision pin at spec freeze; QSPGS_SPEC
  KAT and benchmark plan (D-QGS-10); cross-references verified
  in GROUP_SPEC.md, ROADMAP.md M8/M9, and the register index.
- **AMENDMENT (user-confirmed 2026-09-12): items 2 and 4
  reversed.** Item 2 now reads: the QSPGS type is the [CFG+]
  group data structure with [CFG+]'s OWN authentication and
  attribution mechanism, key-rerandomizable ML-DSA (KR-ML-DSA),
  adopted as written (per-user base key, per-group pseudonym
  key via RandSK/RandVK, admin-signed core, per-line pseudonym
  signatures). Item 4 now reads: the provider boundary is
  liboqs. Verification is the UNMODIFIED public liboqs ML-DSA
  verifier ([CFG+] Section 2.2 keeps the standard verifier and
  absorbs the +beta into the SelfTargetMSIS bound, under 1 bit
  of loss). Base keygen, RandVK, RandSK, and the 2*beta signing
  loop are geryon composition glue over liboqs' mldsa-native
  INTERNAL routines (polynomial arithmetic, NTT, samplers,
  packers, SHAKE), reached by symbol and never reimplemented;
  detail at D-QGS-11. libtalos_voleith plays NO role in the
  baseline QSPGS type; it remains the recorded path for the
  tangential anonymous-credential uses [CFG+] Section 6 leaves
  open (liveness checks, registration proofs) and for the v2
  first-flight messaging auth. Items 1, 3, and 5 stand.
  Superseding rationale (replaces the item-4 rejection text):
  the 2026-07-08 rejection assumed KR-ML-DSA meant an in-house
  constant-time lattice signer with no library seam. That
  assumption failed on inspection of the pinned liboqs 0.16.0:
  it ships mldsa-native, whose internals are one source tree
  compiled per backend under distinct namespace prefixes, so
  the KR delta is a few hundred lines of glue and inherits
  liboqs' AVX2 / NEON backends and constant-time discipline.
  Against that, the voleith design was MEASURED (2026-09-12,
  this machine, the pre-built voleith depth-12 KVAC example):
  845 KB proof, 1.24 s prove, 0.90 s verify per group operation
  at the 128-bit tier (depth 12 membership + depth 12
  revocation, Grøstl-256 T27, em_128f). Every optimistic
  correction the user identified (Hirose inodes, the planned
  25 percent AES S-box witness cut, dropping the revocation
  branch, em_128s) still leaves 130 to 400 KB and roughly
  0.3 to 0.6 s per operation, versus 7.5 KB and about 2 ms for
  a KR-ML-DSA AddMember. The server verifies every mutating
  operation and every fetching member re-verifies, so that gap
  is the product. The 448 tier was decisive on its own: 256-bit
  CR forces grostl512_fixed inodes (5,376 slots per level) and
  the 256-bit parameter set, giving multi-megabyte proofs, while
  KR-ML-DSA-87 is a 4.6 KB signature. The assumption-diversity
  argument for voleith was withdrawn: ML-KEM already rests on
  MLWE, so a break of MLWE reduces the hybrid suites to
  classical security regardless; a group layer on MLWE is
  exactly as PQ-safe as the messages it manages. Costs newly
  accepted: a non-standard ML-DSA parameterization (doubled
  beta, uncompressed base t) with no ACVP coverage, so geryon
  owns its KATs (D-QGS-10); reliance on liboqs internal symbols
  pinned per liboqs tag (D-QGS-11); about 5x slower signing
  from the squared rejection count (management path only).
- **Validation (amended):** register cross-references updated
  at D-QGS-4, 11; QSPGS_SPEC §3 / §6 flip tracked in
  QSPGS_DESIGN.md §12.7; the measured voleith numbers are kept
  in QSPGS_DESIGN.md §12.1 so the decision can be re-audited.

### D-QGS-2: Tier parameters (sk sizes, hash pairings, nullifier widths, parameter sets)

- **Context:** the voleith membership layer needs per-tier
  choices for the member secret (sk), the Merkle/IMT node hash,
  the leaf OWF, the nullifier width, and the proof parameter
  set. The project's strength-move-together rule applies: curve, signature, hash, and KEM
  strength move together per suite.
- **Decision (user-confirmed 2026-07-08):**
  1. 25519 hybrid tier (geryon_h25519_512): sk = 16 bytes,
     uniformly random (core/ rng.c). tree_hash =
     hirose-aes-256 (32-byte nodes, 2^128 CR); owf_hash =
     grostl256_fixed (64-byte single-compression capacity;
     leaf preimage carries sk, uid, group binding, join
     counter, and role/expiry attributes). Nullifier: 16 bytes,
     raw AES-CMAC (the library's width policy at 128-bit-CR
     trees). Proof parameters: the 128-bit set
     (FAEST-EM-128f class).
  2. 448 hybrid tier (geryon_h448_1024): sk = 32 bytes.
     tree_hash = grostl512 (2^256 CR); owf_hash =
     grostl512_fixed (128-byte capacity). Nullifier: 32 bytes
     via the SP 800-108 KDF-CTR-CMAC wide path. Proof
     parameters: the 256-bit set.
  3. grostl256 is the recorded CONTINGENCY tree hash for the
     25519 tier: structurally independent of Hirose
     (permutation-based vs cipher-based) in case ideal-cipher
     quantum collision attacks improve. The current Hirose use
     is not free-start, so known improvements do not apply.
  4. KDF-CTR/AES-CMAC node hashing is REJECTED for trees: its
     128-bit internal state gives 2^64 collision resistance,
     and a node-hash collision in a membership tree is
     forgery-grade (two member sets, one root). This is the
     recorded reason the old PQ-KVAC draft's node hash was
     replaced.
  5. sk INDEPENDENCE INVARIANT: the membership sk is fresh
     randomness, never derived from any classical key material.
     Deriving it from a curve private key would be quantum-dead
     (Shor recovers the scalar from the public key, making the
     derivation computable by the attacker).
  6. sk sizing rationale is tier-anchored: 16 bytes = the NIST
     Level 1 floor (AES-128 key search, Grover priced in),
     matching ML-KEM-512 / ML-DSA-44 and the 128-bit proof
     envelope on that tier (a larger sk buys nothing inside a
     128-bit-soundness proof system); 32 bytes matches the
     Level 5 posture of the 448 tier. Multi-target discounts
     are mitigated by per-member salting inside the leaf
     preimage (uid and attributes make each leaf a distinct
     target).
- **Rationale:** the asymmetric OWF/tree pairing exists because
  attribute-carrying leaves exceed hirose_fixed32's 32-byte
  single-compression capacity (sk 16 + uid 16 alone fill it);
  grostl256_fixed's 64-byte capacity fits the full preimage.
  Both pairings satisfy the library validator's invariants
  (equal node_bytes; owf cr_bits >= tree cr_bits). Note the
  validator rule is load-bearing here beyond preimage strength:
  with attributes in the leaf, OWF COLLISION resistance is
  security-relevant (a member who finds two preimages of their
  own leaf could equivocate its role bits).
- **Validation:** cfg_fingerprint KATs pin the vt names and all
  widths; config validation at the API boundary; composed-
  circuit benchmarks (proof size, prover time, both tiers) are
  a D-QGS-10 gate before wire formats freeze.
- **Status 2026-09-12: SUPERSEDED** by the D-QGS-1 amendment.
  Retained as the record of the voleith tier parameters. Item 5
  (the sk independence invariant) carries over in spirit to
  D-QGS-11: the KR-ML-DSA base key is fresh randomness, never
  derived from classical key material. Tier mapping is
  re-decided at D-QGS-11 item 1.

### D-QGS-3: Leaf layout, role fields, and derivation conventions (PARTIAL; 25519 budget under revisit)

- **Context:** the leaf preimage OWF(sk || attributes) must carry
  identity binding, group binding, re-add freshness, roles, and
  possibly expiry within the fixed single-compression capacities
  of D-QGS-2's OWFs (64 bytes via grostl256_fixed on the 25519
  tier, 128 via grostl512_fixed on 448). Predicate cost model
  (upstream library): EQ against a public byte is FREE (a linear
  constraint in QuickSilver); RANGE costs 3 mul gates per bit
  (the shared comparison routine), public bounds or not; no
  BITMASK predicate exists in the shipped set.
- **Decision (user-confirmed 2026-07-08; MECHANISMS only, field
  widths under revisit below):**
  1. gid (group binding): 12 bytes, a truncated hash of
     suite_string || group id. Not a soundness parameter: a
     collision breaks no proof (proofs bind the per-group roots
     regardless); what it carries is a linkability-grinding
     bound (2^96 to forge a colliding group binding, whose only
     payoff is cross-group leaf linkage), and the suite_string
     input bakes suite domain separation into the leaf. Width
     set by the user at 12 bytes.
  2. Roles: one byte PER role flag via the V3 multi-field
     schema. Eight single-byte fields reserved up front, each
     valued 0x00/0x01, all-zero = plain member, combinations by
     setting multiple fields. Proving a capability is
     EQ(role_i, 0x01): zero mul gates, and every other role
     field carries predicate NONE and stays hidden. Rejected
     alternatives: a packed bitfield byte with full-byte EQ
     (reveals the prover's exact role combination, shrinking
     anonymity sets in anonymous flows and under a future V5
     opener) and a new BITMASK predicate in libtalos_voleith
     (the 8-16 mul gates were never the issue; the new library
     surface was: implementation, KATs, cfg-fingerprint
     change). All 8 fields are reserved NOW because schema
     changes alter the cfg fingerprint and therefore the wire
     format; meanings are assigned over time in the label
     registry.
  3. Leaf OWF options are exactly grostl256_fixed (25519) and
     grostl512_fixed (448): hirose_fixed32's 32-byte capacity
     cannot hold any attribute-carrying preimage. The D-QGS-2
     tree/inode split is unchanged (Hirose-AES-256 remains the
     25519 TREE hash; the leaf OWF is the once-per-proof cost,
     the inodes the 24-per-proof cost).
- **REVISIT (open; user deliberating, nothing freezes):** the
  25519 field-width allocation within the 64-byte capacity.
  Candidate layout: sk 16 + uid 16 + gid 12 + join counter 4 +
  role flags 8 + expiry 4 = 60 of 64, leaving 4 spare bytes; an
  8-byte join counter lands exactly on 64/64 with zero slack
  forever. Interacts with the expiry keep-or-drop question
  below. NO leaf-layout KAT, cfg fingerprint, or wire format may
  freeze until this closes. (448 tier is uncontended: 76/128
  with the candidate widths.)
- **Still open under this entry:** the label registry (gid
  derivation string, scope encoding, role-field name
  assignments, fs_seed m-prefix convention, KDF labels per
  D-GEN-3); commitment instantiation for any C_UID-analogue
  surviving transcription; whether epoch re-basing subsumes the
  expiry attribute (re-base already implements liveness).
- **Rationale:** the multi-field role design achieves bitfield
  semantics (combinable roles, selective disclosure) entirely
  with shipped machinery at zero gate cost, trading preimage
  bytes for library stability; the gid width is the smallest
  size whose grinding bound is decisively out of reach (the
  user's 96-bit GCM-nonce anchor); capacity forces the
  asymmetric OWF/tree pairing rather than taste.
- **Validation:** per-tier leaf-layout KATs and schema
  cfg-fingerprint KATs once widths freeze; review check that no
  proof constrains (and therefore reveals) role fields beyond
  those the operation requires.
- **Status 2026-09-12: SUPERSEDED / MOOT** by the D-QGS-1
  amendment. There is no leaf preimage, no attribute schema,
  and no depth budget in the KR-ML-DSA design: roles are the
  [CFG+] server-visible admin flag plus member-list fields,
  and group binding is the per-group rerandomizer rho =
  H(UID, rrs). The REVISIT is closed as moot. The label registry
  item migrates to D-QGS-11 (rho_A label, rho derivation string,
  context strings).

### D-QGS-4: Standalone-PQ posture for the voleith membership layer (repurposed entry)

- **Context:** originally reserved for the hybrid KRS combiner
  rule, moot once the hybrid suites went voleith-only. Project policy
  requires hybrid (classical + PQ) for public-key primitives;
  that rule was written for lattice newness (ML-KEM / ML-DSA).
  The voleith membership layer is geryon's first component with
  NO classical companion, which requires an explicit posture
  decision, not drift.
- **Decision (user-confirmed 2026-07-08):** the hybrid suites'
  group authentication layer is voleith-only. No Schnorr rider,
  no KR-ML-DSA. Justification: VOLEitH soundness rests on AES as
  PRG/OWF, SHAKE as random oracle, and an information-theoretic
  core (QuickSilver); these are the oldest assumptions in the
  stack, and a break of AES ends far more than group membership
  privacy. The original hybrid motivation (Kyber/Dilithium
  newness) does not apply to symmetric-assumption constructions;
  BSI precedent permits SPHINCS+/XMSS standalone on the same
  grounds. Residual risks accepted BY NAME: (a) construction
  maturity (the FAEST family is a NIST Round 2 additional-
  signatures candidate; VOLE-in-the-Head + QuickSilver is more
  intricate than plain hash trees and ZK systems have a history
  of construction-level soundness bugs); (b) implementation
  maturity (new library, custom circuits beyond FAEST's
  scrutiny). Mitigations: faest-ref cross-validation KATs,
  shipped fuzz harnesses on attacker-facing parsers, the
  linked-library timing-test policy, and unfrozen geryon KATs
  until the [CFG+]/spec pin.
- **Rationale:** hybrid layers protect against three failure
  modes: primitive breaks (disposed of by the assumption
  argument), construction flaws, and implementation bugs. The
  user weighed the residual (b)/(c) risks against the cost and
  complexity of a companion layer and chose standalone, with the
  mitigations above. This entry is the project posture
  deviation record.
- **Validation:** the mitigations are testable artifacts (KAT
  suites, fuzzers, timing harness) checked at integration.
- **AMENDMENT (user-confirmed 2026-09-12): posture reversed.**
  The hybrid suites' group authentication layer is KR-ML-DSA,
  standalone (no voleith rider, no Schnorr rider). The
  assumption is MLWE / SelfTargetMSIS, the same assumption the
  hybrid suites already rest on for ML-KEM and the ML-DSA
  prekey signatures. The standalone posture is justified by
  that shared dependence rather than by the symmetric-only
  argument above: a hybrid companion for the group layer would
  protect nothing the messaging layer does not already lose in
  the same event. Residual risks accepted BY NAME: (a) a
  bespoke parameterization of a standardized scheme (doubled
  beta in signing, uncompressed base t, fixed public A),
  security argued in a preprint ([CFG+] Section 2.2, Theorems 1
  and 2) with no independent review yet; (b) reliance on liboqs
  internal (non-API) symbols, mitigated by the existing liboqs
  tag pin (D-PQ-2 / D-GEN-5 _Static_assert) plus KATs that fail
  loudly on a bump; (c) no ACVP vectors cover keygen or signing
  at 2*beta, so the KAT oracle must be geryon's own or the
  [CFG+] authors' implementation. The FAEST / voleith maturity
  risks (a)/(b) above no longer apply to this type. The
  symmetric-only reasoning above stays valid for the v2
  first-flight messaging auth, where voleith remains the plan.
- **Validation (amended):** D-QGS-10 KATs for base keygen,
  RandVK, RandSK, and rerandomized signing at both tiers,
  cross-checked by verifying every KAT signature with the
  unmodified public liboqs verifier; the liboqs pin assert in
  core/pqinit.c covers the internal-symbol dependency.

### D-QGS-5: Attribution and credential mechanisms (registered nullifiers; V3/V4 modules; V5/V6 reserved)

- **Context:** [CFG+]'s KRS pseudonym keys give the server
  per-line authorization and give members full attribution.
  The voleith layer must reproduce those semantics from
  symmetric primitives; the library's composable ring-signature
  modules (V2 nullifier, V3 predicates, V4 claims, shipped
  1.8.0) are the toolkit.
- **Decision (user-confirmed 2026-07-08):**
  1. Attribution: REGISTERED V2 NULLIFIERS. T = AES-CMAC(sk,
     scope) with scope = suite-tagged group_id || epoch; T is
     published inside the member's AEAD-encrypted entry at
     join. The server sees a stable opaque per-member tag for
     line-level authorization; members attribute operations by
     looking T up in the decrypted member list; outsiders and
     the server get no cross-group or cross-epoch linkage
     (epoch is in the scope, so rotation re-scopes every tag).
  2. Roles and expiry: V3 predicates over leaf attributes (role
     as EQ, expiry as RANGE with per-signature public bounds,
     so validity is checked against a verifier-supplied current
     date with no re-issuance). Open at D-QGS-3: whether epoch
     re-basing subsumes the expiry attribute entirely (members
     not re-enrolled at a re-base drop out, which is a liveness
     mechanism in itself).
  3. Recovery / re-registration: V4 claimable commitments
     (claim_produce / claim_verify; non-transferable via the
     fs_seed binding of C).
  4. Rate limiting: V2 one-time scopes with application
     seen-sets, and the in-circuit spent-set module where the
     deployer wants it. Seen-set state and policy live with the
     deployer (the D-GRP-2 statelessness carry-over); geryon
     ships the extractor and constant-time comparison only.
  5. Reserved upgrade paths, designed for from day one: V5
     designated opener (attribution-on-dispute instead of
     always-on tags; improves the D-QGS-9 posture; the
     commit_id_bytes sharing in the library already anticipates
     it) and V6 forward-secure key evolution (the spec reserves
     an sk-per-epoch derivation slot so V6 lands as a parameter
     change, not a format break). V7 threshold signatures noted
     as future work for destructive admin operations.
  6. Suite binding: the D-GEN-3 suite string enters every proof
     as a length-prefixed prefix of the signed message m (and
     group-scoped values like scope carry the group binding);
     no voleith API change is required. The exact conventions
     freeze at D-QGS-3/D-QGS-7.
- **Rationale:** registered nullifiers reconstruct [CFG+]
  vkpsdn semantics exactly (stable per-line tag for the server,
  identity mapping for members, re-scoped on rotation) from AES
  alone, eliminating the KR-ML-DSA implementation and its
  lattice assumption. Scope being a per-signature public input
  lets one membership config serve both the attribution scope
  (reuse expected) and one-time rate-limit scopes.
- **Validation:** nullifier and fs_seed KATs (library KATs pin
  the constructions; geryon adds suite-string-prefix KATs);
  attribution integration tests (member maps T to identity;
  server never sees the mapping) at D-QGS-10.
- **Status 2026-09-12: SUPERSEDED** by the D-QGS-1 amendment.
  Attribution is now [CFG+]'s own: the per-group pseudonym
  verifying key vk_psdn = RandVK(vk_base, H(UID, rrs)) gives the
  server per-line authorization and gives members attribution
  (they recompute every vk_psdn from the group's rrs); the
  server sees an unlinkable-across-groups key, not a nullifier.
  Items 2 to 5 (V3 / V4 / V5 / V6 modules) are moot for this
  type. Item 6 (suite string in every signed message) carries
  over as the ML-DSA context string convention at D-QGS-11.
  Rate limiting reverts to [CFG+] Section 6's symmetric send
  tokens derived from expKey, to be designed at D-QGS-6.

### D-QGS-6: Server-side operation set, registration signing key, tokens, and admission (DECIDED 2026-09-12)

- **Context:** QSPGS_SPEC §7 was a `[TODO]` stub inheriting the
  D-GRP-2 shape. With the authentication primitive settled
  (D-QGS-11), the server side is [CFG+] Section 4 as written
  plus the implementer choices the paper leaves open: how
  vk_pers is instantiated, how pseudonym keys are stored, the
  send / fetch token construction, admission control against
  attributable garbage, and concurrent admin updates.
- **Decision (user-confirmed 2026-09-12):**
  1. Server target shape: as the classical type (D-GRP-2).
     Stateless pure verification functions in a separate
     `geryon_qsgroups_server` library; storage, policy, and
     channel handling live with the deploying application. The
     server holds NO secret parameters for the core system.
  2. Registration signing key sk_pers: FOLLOW THE PAPER. [CFG+]
     Figure 7 generates a standard signature pair
     (vk_pers, sk_pers) registered with an idealized PKI, and
     footnote 7 instantiates that PKI with the messaging
     system's user verification keys. In geryon, sk_pers IS the
     hybrid identity's signing capability (XEdDSA + ML-DSA, both
     must verify, exactly the prekey-signing discipline) under
     dedicated QSPGS context strings; no new key. It signs
     exactly the two objects the paper signs with it:
     (vk_base, acq) at RegisterUser and (UID, uk, GID) inside
     the PKE-encrypted invite acceptance. Every member verifies
     those signatures against the UID's identity key on fetch
     (`GetPseudoVkBase`, `IsCorrectUserKey`, `AcceptedInvite`,
     [CFG+] Appendix B.1), which is what gives attribution
     correctness against a corrupt admin: an admin cannot add an
     entry that names one UID but carries another user's base
     key or user key. This is a recorded, narrow EXCEPTION to
     the project rule that identity keys sign published prekeys
     only (CLAUDE.md Goals): neither object is a transcript,
     messaging deniability is untouched, and the added
     non-repudiable statement ("this identity owns this base
     key") is the D-QGS-9 regression extended to the base-key
     binding. Alternatives rejected: a fresh per-user signing
     key (no trust anchor but the server, defeating the
     fetch-time check); delivering vk_base over pairwise
     sessions instead of via the signed server record (serves
     only the adder; unacquainted members could not validate
     new entries, blocking via Refresh would lose its reference
     tag, and the UC argument would no longer apply as written).
  3. Pseudonym key storage: the server stores H(vk_psdn) per
     line ([CFG+] Section 3.2 optimization for the PQ tier);
     a member sends the full vk_psdn with its first signature
     under that pseudonym, and the server checks the hash before
     verifying. Hash = the tier hash, D-GEN-3 labeled (D-QGS-7
     fixes the bytes).
  4. Send and fetch tokens: symmetric bearer tokens per [CFG+]
     Section 6.5, derived from expKey with a D-GEN-3 label over
     (GID, period); the server compares with gy_const_memcmp
     against the value deposited when the member was added
     (fet for Fetch is the paper's own per-major-version bearer
     token). Period length and per-token quotas are deployer
     knobs; counters and seen-state live with the deployer.
  5. Admission control against attributable garbage: none
     server-side (content is AEAD-encrypted by design; D-QGS-1
     accepted this). Mitigation is item 4 rate limiting plus
     admin cleanup at reconciliation; deployer-facing docs state
     it plainly.
  6. Concurrent admin updates: the server enforces strictly
     increasing (vMaj, vMin) with compare-and-swap on the
     version the client claims to be extending; a losing writer
     gets a structured conflict error and re-fetches. Never
     merge server-side.
  7. Register hygiene: D-QGS-7, D-QGS-8, and D-QGS-10 carry
     reserved stubs below so the numbers are visible in this
     file, not only in the header note.
- **Rationale:** items 1, 3, 5, 6 are the paper's design or the
  classical precedent applied unchanged; item 2 is the paper's
  own instantiation advice, adopted after the pairwise-session
  alternative was examined and found to remove a load-bearing
  check; item 4 is the only symmetric mechanism available once
  nullifier scopes went with the voleith layer.
- **Validation:** D-QGS-10 negative matrix (forged base-key
  binding rejected on fetch; invite acceptance under the wrong
  identity rejected; hash / key mismatch on first pseudonym use
  rejected; stale-version write rejected; token mismatch
  rejected), plus the CLAUDE.md exception text and the
  QSPGS_SPEC §7 / §2.2 wording.

### D-QGS-7: Wire formats (DECIDED 2026-09-13; spec §8)

- Topic: byte encodings for the §4 structure and every §5
  message; msg_type allocation under D-GEN-1; gk delivery
  duty; H(vk_psdn) bytes; the context-string registry; C_UID
  encoding; the acquaintance record carrying vk_base. Fixed
  already by D-QGS-11 item 6: vk_b / sk_b / vk_r / signature
  layouts and the 64-byte rho. Gated on the D-QGS-10 benchmark.
- **Decision (the benchmark gate satisfied):** the §4 group data structure wire is frozen and
  recorded in QSPGS_SPEC.md §8, implemented in
  src/qspgs/qspgs_wire.{c,h} and src/qspgs/qspgs_join.{c,h}:
  1. Framing mirrors the classical vertical (GROUP_SPEC §9): one
     D-GEN-1 msg_type (GY_QSPGS_MSG 0x04) and a 3-byte per-object
     header (obj_type || GY_QSPGS_WIRE_VERSION || suite_id). The
     object-type registry (HEADER/MEMBER_LIST/VK_LST/CORE_SIG/
     APPENDIX/INVITE_QUEUE = 0x01..0x06) is append-never-renumber;
     integers big-endian; lists BE16-counted; decode strict.
  2. Encrypted / opaque fields (settings+attributes ct, mct, join
     slot, appendix payloads, invite entries) are length-prefixed
     opaque blobs; their AEAD-internal layout stays a §5
     matter, not frozen by the structure grammar. GID,
     fet, versions, and the two tier-hash fields are fixed-width.
  3. C_UID = H(gy_info("qspgs-cuid") || r_c || UID) (hash-based,
     computationally hiding, the §2.3 item 3 deviation). H(vkpsdn)
     = H(gy_info("qspgs-vkhash") || vkr), the FULL tier hash
     (32 / 64), D-GEN-3 labeled (this fixes the D-QGS-6 item 3
     bytes). The admin core signature is over the canonical TBS
     (signer_index || header || member-list || vk-lst || vMaj ||
     last_vMin) under the qspgs-core context; appendix lines are
     signed over (line_type || author_index || payload) under the
     single qspgs-appendix context.
  4. The join keypair (ipk, isk) (the deferred D-QGS-2 item) is a
     single group-wide keypair rederived from gk via two
     INDEPENDENT domain-separated HKDF branches (qspgs-join-ec /
     qspgs-join-mlkem), so a quantum break of one primitive does
     not reveal the other (the hybrid guarantee holds at the key
     level, not just the per-seal fusion). Its PKE is the suite
     KEM hybrid (ECDH + ML-KEM, no classical-only primitive,
     §10.1), sealed PQ-first (qspgs-join-kem) with
     ChaCha20-Poly1305; ciphertext = eph_curve_pk || mlkem_ct ||
     (aead ct || tag). This required promoting the deterministic
     ML-KEM keygen (gy_mlkem{512,1024}_keypair_derand) to the
     production core/ API.
  5. Still §5, NOT this freeze: the acquaintance
     record carrying vk_base, the per-operation context-string
     registry, and gk delivery over pairwise sessions. The [CFG+]
     §3.3 Falcon dispute-optimization is out of scope.
- **Vectors:** the deterministic wire bytes (C_UID, H(vkpsdn),
  the core TBS) are captured in tests/qspgs/qspgs_wire_kat.h via
  the --dump / SKIP-77 mechanism, UNFROZEN until the [CFG+]
  revision pin (D-QGS-10). Signatures over the TBS are randomized
  and covered by the round-trip tests, not KAT-frozen.

### D-QGS-8: State, storage, and zeroization (DECIDED 2026-09-14; spec §9)

- Topic: the D-GRP-7 rederive-only model applied to muk,
  sk_base / vk_base, gk; sk_psdn never persisted (D-QGS-11
  item 7); zeroization points. Gated on D-QGS-7.
- DECIDED (2026-09-14): the `gy_qspgs_store` `*_stored`
  wrappers (`src/qspgs/qspgs_store.c`) over the keyed-blob
  trio (record kinds MUK, BASE_KEY = skbase || vkbase, GROUP_KEY).
  Each record is ver(0x01) || format_version(BE16) || payload with a
  per-record format-version window (MIN/MAX = 1), mirroring
  `gy_group_format_version_load`. Only the three at-rest secrets are
  written; `gy_qspgs_member_ctx_open_stored` loads gk + the base
  pair and REDERIVES the working set (ek, rrs, rho, sk_psdn, vkr),
  the `gy_group_load` analogue - nothing derived is stored, sk_psdn
  and the sk_r blob never serialized. Zeroization audited client-wide
  (every transient + teardown clear + the sk_r blob via the backend
  rsk_clear); storage-framing KAT + zeroization sweep on both tiers.
  Also lands the §6.5 symmetric token derivation (task 5): fet =
  KDF(gk, "qspgs-fet"), send = KDF(gk, "qspgs-send"), rederived and
  never persisted, the derived fet accepted by
  `gy_qspgs_server_fetch_check`; symmetric derivation + compare only,
  rate limiting stays the deployer's.
- AMENDED (2026-09-16, GER-M9E-05 E6): a FOURTH at-rest secret is
  added, the ONE exception to "only muk, base pair, gk": the static
  join-link secret jls, record kind `GY_QREC_JOIN_LINK` keyed on GID
  (`gy_qspgs_joinlink_secret_store` / `_load` / `_delete`,
  `src/qspgs/qspgs_store.c`). It is required because the join link must
  survive group-key rotation (App. B.8): the creator-admin re-seals
  (gk_new, fet_new) into the rotated core's slot under jls rather than
  mint a fresh secret. Same framing (ver || format_version || 32-byte
  payload), sealed under the custodian KEK, zeroized after use;
  `toggle_join_link` writes it on enable and removes it on disable, and
  `gy_qspgs_group_delete_stored` now drops it with gk. An admin without
  jls that rotates a linked group drops the slot and the public call
  returns the positive `GY_QSGROUP_JOIN_LINK_DROPPED` (not an error).

### D-QGS-10: Test vectors, oracle, and benchmarks (DECIDED end to end; vector freeze EXECUTED at the v1.5.0 close-out; spec §12)

- Topic: KR-ML-DSA KATs on every built backend with the
  public-verifier cross-check; oracle choice ([CFG+] authors'
  implementation vs reviewed self-generated vectors); [CFG+]
  revision pin; sign / verify benchmarks at both tiers before
  the D-QGS-7 freeze.
- Oracle approach (DECIDED 2026-09-12): investigate whether the
  [CFG+] authors published a reference implementation; if one
  exists and is acceptably licensed, use it as a KAT oracle
  (D-GRP-9, docs/TEST_ORACLES.md entry); otherwise reviewed
  self-generated vectors checked against the [CFG+] Figure 3/4
  equations, unfrozen until the revision pin. Low risk either
  way: the arithmetic is vetted liboqs mldsa-native, not a
  from-scratch Dilithium, and the glue is thin (§3.3 item 2).
  The remaining sub-items (revision pin, benchmark numbers)
  stay reserved. The M9 plan (docs/plans/M9.md)
  carries this into the KAT tickets.
- Oracle investigation OUTCOME (2026-09-12): NO
  public authors' reference implementation. The ePrint 2026/453
  landing page ([CFG+]: Connell, Faller, Günther, Hesse,
  Lyubashevsky, Schmidt) links no code repository, artifact, or
  "code available at" statement, and no third-party KR-ML-DSA
  implementation surfaced in search (only stock ML-DSA / FIPS
  204 code such as pq-code-package/mldsa-native, which geryon
  already links via liboqs). Therefore the self-generated branch
  is IN EFFECT: the KR-ML-DSA KATs are reviewed self-generated
  vectors checked against [CFG+] Figures 3 and 4, with every KAT
  signature cross-verified by the unmodified public liboqs
  verifier, UNFROZEN until the [CFG+] revision pin. NO
  TEST_ORACLES.md entry is added for KR-ML-DSA (the recorded
  self-generated posture stands instead). Re-check on any [CFG+]
  revision: if the authors publish acceptably licensed code
  later, revisit this and switch to the oracle branch. The
  conditional oracle wording at D-QGS-4 (validation) and D-QGS-11
  (validation / item "Oracle") resolves to this self-generated
  branch.
- KAT set consolidated (2026-09-14): the frozen-when-pinned
  vector set spans, both tiers, all built backends: the key hierarchy
  (uk / acq / expKey / ek / rrs / rho, plus the §6.5 fet / send tokens) in
  qspgs_keys_kat.h; the group-structure wire (C_UID, H(vkpsdn), the core TBS,
  and the suite-independent appendix-line TBS) in qspgs_wire_kat.h; the
  storage-record framing is byte-exact in test_qspgs_store.c (store_kat). All
  are captured via --dump / SKIP-77 and self-check green today, but remain
  UNFROZEN (see freeze timing below).
- Benchmarks (RECORDED): KR-ML-DSA sign / verify at both tiers in
  QSPGS_DESIGN.md §12.1.1, and the [CFG+] §7 AddMember /
  RemoveMember operation costs in §12.1.2 - both cross-checked
  against the model and confirmed (AddMember flat in n, RemoveMember linear).
- Revision-pin / freeze timing (DECIDED 2026-09-14): the
  self-generated vectors stay UNFROZEN through the rest of M9 and are FROZEN as
  part of the v1.5.0 close-out, AFTER the worked example has run
  end-to-end without surfacing a byte-level change. Rationale: there is no
  authors' reference to converge on (oracle outcome above), so the pin is to
  geryon's own interpretation of the current [CFG+] preprint; the worked example
  is the last place a real end-to-end flow could still expose an encoding /
  derivation adjustment, so freezing before it would risk enshrining a value we
  then re-cut. The D-QGS-12 format epoch makes this low-cost either way: a later
  [CFG+] revision is a format_version bump (new groups new epoch, old groups
  deprecated), not a silent vector change. Freeze trigger, to execute at v1.5.0
  close-out: pin the [CFG+] revision then in force, flip each *_KAT_ header's
  UNFROZEN note to FROZEN, and stop regenerating on refactor.
- Vector freeze EXECUTED (2026-09-16): the worked example
  (geryon_qsgroup_demo / geryon_qsgroup_h448_demo) ran end to end on both hybrid
  tiers, full classical-parity lifecycle, without surfacing a byte-level change,
  so no re-cut was needed. The vectors are now FROZEN, pinned to geryon's reading
  of the [CFG+] 2026/453 preprint in force at this date. The three KAT headers
  (tests/core_hooks/krmldsa_kat.h, tests/qspgs/qspgs_keys_kat.h,
  tests/qspgs/qspgs_wire_kat.h) carry the FROZEN note and are no longer
  regenerated on refactor; a later [CFG+] revision is a D-QGS-12 format_version
  bump with a deliberate re-cut. D-QGS-10 is now DECIDED with nothing open.

### D-QGS-9: Membership deniability regression (accepted; V5 is the improvement path)

- **Context:** [CPZ] group membership is deniable (only the
  server verifies anything; entries are simulatable). In the
  QSPGS design, signatures/proofs are publicly verifiable and
  attribution tags are registered, so an insider can hand
  (proof, T mapping, group key, group state) to an outsider and
  PROVE another member's activity ([CFG+] §3.3 "On
  deniability"). geryon's identity statement ("offline
  deniability preserved in ALL suites") governs the MESSAGING
  protocol; group-membership provability is a distinct property.
- **Decision (user-confirmed 2026-07-08, implied by the D-QGS-5
  attribution choice and recorded explicitly here):** the
  regression is ACCEPTED and documented, for the QSPGS type
  only (the classical [CPZ] type keeps its deniability). API
  documentation and QSPGS_SPEC §10 must state plainly that in
  QSPGS groups, membership and group actions are provable to
  outsiders by any insider. The V5 designated-opener
  upgrade (D-QGS-5 item 5) is the recorded improvement path:
  routine operations become anonymous even in-group, with
  de-anonymization held by an opener quorum, narrowing
  provability to disputes.
- **Rationale:** attribution and deniability are in direct
  tension; the system needs attribution (misbehavior tracing is
  a design goal carried from [CFG+]). Accepting the regression
  with a named, already-architected improvement path is more
  honest than implying the messaging-layer deniability extends
  to the group layer.
- **Validation:** documentation review at M8 ticket time; the
  §10 security-considerations text exists and names the
  regression.
- **Status 2026-09-12: STANDS.** [CFG+] Section 3.3 records the
  identical loss for KR-ML-DSA pseudonym signatures (an insider
  reveals sigma_psdn, vk_base, gk, and the list). The V5
  improvement path no longer applies to this type; no
  replacement improvement path is recorded.

### D-QGS-11: KR-ML-DSA provider boundary and instantiation

- **Context:** the D-QGS-1 / D-QGS-4 amendments adopt [CFG+]'s
  KR-ML-DSA. Its four deltas from FIPS 204 (fixed public A,
  uncompressed base t, RandSK / RandVK, doubled beta in the
  signing rejection bounds) all sit BELOW the public liboqs
  ML-DSA API (beta and the rounding step are compile-time inside
  keygen and sign), so no public-API composition exists. The
  pinned liboqs 0.16.0 ships mldsa-native (pq-code-package) for
  ML-DSA: one source tree compiled three times, as
  `mldsa-native_ml-dsa-<set>_{ref,x86_64,aarch64}`, each under
  the namespace prefix `PQCP_MLDSA_NATIVE_MLDSA<set>_{C,X86_64,
  AARCH64}_`, with identical internal function signatures and
  struct layouts across the three; liboqs dispatches among them
  at the top-level `OQS_SIG_ml_dsa_<set>_*` entry points using
  `OQS_CPU_has_extension` (AVX2 + BMI2 + POPCNT on x86_64, NEON
  on aarch64) when `OQS_DIST_BUILD` is on. The internals are
  non-static, namespaced symbols without installed headers;
  geryon links liboqs statically, so hidden visibility does not
  restrict them.
- **Decision (user-confirmed 2026-09-12 for items 1 to 4; items
  5 to 9 are the drafted instantiation, PROPOSED and awaiting
  ratification):**
  1. Tier mapping: geryon_h25519_512 uses KR-ML-DSA-44 (eta 2,
     beta 78, signing bound 2*beta = 156, about 18 expected
     attempts per [CFG+] Table 1); geryon_h448_1024 uses
     KR-ML-DSA-87 (eta 2, beta 120, bound 240, about 15). Same
     ML-DSA levels the suites already carry; no new level is
     introduced.
  2. Provider boundary: verification is `gy_mldsa44_verify` /
     `gy_mldsa87_verify`, i.e. the unmodified public liboqs
     verifier over a byte-standard verifying key and signature.
     Base keygen, RandVK, RandSK, and rerandomized signing are
     geryon glue calling mldsa-native internals by symbol
     (matrix expansion, eta / gamma1 samplers, NTT, pointwise
     products, power2round, the t1 / t0 / eta / z / w1 packers,
     hint packing, SHAKE via liboqs' fips202 shim). No
     polynomial arithmetic is written in geryon.
  3. Backend dispatch: the glue is compiled ONCE PER BACKEND
     against that backend's header tree with the identical
     `-DMLD_CONFIG_PARAMETER_SET` / `-DMLD_CONFIG_FILE` and
     target flags liboqs used for it, so layouts and symbols
     match the archive; a per-set dispatcher caches a
     function-table pointer on first call using the SAME CPU
     predicate liboqs uses, guarded by the same
     `OQS_ENABLE_SIG_ml_dsa_<set>_<arch>` / `OQS_DIST_BUILD`
     macros, so the KR signer always runs on the backend liboqs
     itself would pick. Which backends are built follows
     GERYON_OQS_DIST exactly as LIBOQS_BACKEND_ARGS does. The
     probe is liboqs' public `OQS_CPU_has_extension`, not
     libtalos_ichor's dispatcher (a new dependency for one
     branch was judged not worth it).
  4. Pinning: the liboqs tag pin (`_Static_assert` on
     OQS_VERSION_* in core/pqinit.c) is the guard for the
     internal-symbol dependency; a bump is a deliberate event
     that re-runs the KR KATs, and a renamed or restructured
     internal fails the build, never a test.
  5. (PROPOSED) Fixed A seed per set: rho_A = SHAKE256-32 of
     the label `"geryon-QSPGS-KR-ML-DSA-<set>-v1"`, mirroring
     [CFG+]'s `H("PQ-Private-Groups-RerandSig-ML-DSA-65-v1")`.
     Every base and rerandomized key carries rho_A in its rho
     field; RandVK / RandSK reject a base key whose rho field
     is not rho_A (policy check, constant-time compare).
  6. (PROPOSED) Wire layouts. Base verifying key vk_b = rho_A
     (32) || t1 (K x 320, standard t1 packer) || t0 (K x 416,
     standard t0 packer): 2,976 bytes at 44, 5,920 at 87; the
     full t is recoverable as t1 * 2^d + t0 with no new packer.
     Base signing key sk_b = s1 (L x 96, eta packer) || s2
     (K x 96) || K (32): 800 bytes at 44, 1,472 at 87.
     Rerandomized verifying key vk_r: byte-standard ML-DSA pk
     (1,312 / 2,592). Signatures: byte-standard (2,420 / 4,627).
     The [CFG+] Section 3.2 hash-of-vk_psdn storage optimization
     is a D-QGS-7 item.
  7. (PROPOSED) Rerandomized signing key sk_r is IN-MEMORY ONLY
     and BACKEND-AFFINE: it holds s1_r, s2_r, t0_r in NTT domain
     (the shape mldsa-native unpacks to), plus rho_A, tr = H(vk_r),
     and K_r. It is never serialized: (a) s_r coefficients reach
     2*eta, beyond the standard eta packer's width; (b) the
     native NTT backends keep polynomials in a backend-specific
     coefficient order, so a blob from one backend is meaningless
     to another. RandSK is cheap (one matrix product) and is
     re-run from (sk_b, vk_b, rho) whenever needed. The
     dispatcher's fixed-after-first-call backend is what makes
     in-memory holding safe.
  8. (PROPOSED) Derivations left open by [CFG+] Figure 4:
     ExpandS(rho) is FIPS 204's ExpandS (eta sampler, nonces
     0..L+K-1) over the 64-byte rho = H(UID, rrs); the signing
     seed K is carried UNCHANGED from the base key into sk_r,
     exactly as [CFG+] Fig. 4 line 39 (a prior geryon variant
     derived K_r = SHAKE256-32(K_b || rho); reverted in v1.5.0 as
     an unproven divergence, since the hedged nonce rho' =
     H(K || rnd || mu) is already pseudonym-specific via mu / tr =
     H(vk_r)); base keygen derives (rhoprime, K_b) from a 32-byte
     seed as FIPS 204 keygen does but ignores the per-key rho (A is
     fixed). Signing is hedged (FIPS 204 default, D-PQ-1) with the
     context string as a parameter; the D-GEN-3 suite string rides
     the context string exactly as for prekey signatures (carries
     over D-QGS-5 item 6).
  9. (PROPOSED) Attempt cap: 4,096 signing attempts (mldsa-
     native's 814 floor is sized for 4.25 expected attempts;
     with 18 / 15 expected, 4,096 gives failure probability
     below e^-227 / e^-273). Exhaustion is GY_ERR_CRYPTO.
- **Rationale:** liboqs internals over a vendored PQClean /
  mldsa-native fork because the fork would drop the AVX2 / NEON
  backends or force duplicating them (the user's stated
  reason); one-source-per-backend over hand-written per-backend
  copies because mldsa-native's uniform internal API makes the
  copies unnecessary; the public verifier because [CFG+]
  explicitly keeps it and it puts the server and every fetching
  member on the public API. The in-memory sk_r rule turns the
  two facts that make it non-portable into a non-issue rather
  than inventing a wider packer and a canonical-order transform.
- **Validation:** D-QGS-10 KATs: deterministic base keygen from
  seed, RandVK, RandSK-then-sign with a fixed rnd, at both sets
  and on every built backend, with every KAT signature also
  verified by the public liboqs verifier (cross-backend
  agreement on vk_r and on the signature bytes for a fixed rnd
  is itself a test); a negative test that a base key with a
  foreign rho is rejected; the liboqs pin assert. Oracle: the
  [CFG+] authors' Rust implementation if published, else
  geryon's own frozen vectors after review.
- **Implementation note:** a first draft of this instantiation
  exists as src/core/krmldsa/krmldsa_impl.c (per-backend glue),
  src/core/krmldsa44.{c,h} / krmldsa87.{c,h} (dispatch and
  public wrappers), and cmake/krmldsa.cmake (per-backend object
  libraries folded into geryon_core). It is UNCOMPILED and
  UNTESTED; it is the reference for items 5 to 9, not their
  authority.

### D-QGS-12: Format / capability epoch (DECIDED 2026-09-14; spec §4, §8)

- Topic: a per-group FORMAT / capability version, separate from
  the state version (vMaj, vMin), so a future [CFG+] format
  revision can be adopted as a new epoch while old groups keep
  theirs and are deprecated on a schedule. The QSPGS analogue of
  the classical group `format_version`.
- Problem it closes: before this, QSPGS carried only the state
  version (vMaj/vMin, wire + core-signed) and the M9-06 at-rest
  storage `format_version`; there was no wire-carried, tamper-
  evident, window-checked capability epoch. vMaj could not double
  as one (it advances on every membership / key edit and a decoder
  treats it as opaque state).
- DECIDED (2026-09-14):
  1. `format_version` (BE16) is a new stable field of
     `struct gy_qspgs_core`, chosen at Create and IMMUTABLE for the
     group's life; distinct from vMaj.
  2. It rides the HEADER object (after GID, before vMaj), so it is
     inside the core TBS and therefore covered by the admin core
     signature. Because the QSPGS GID is opaque / caller-supplied
     (not a derived hash like the classical GroupID), the epoch
     cannot be GID-bound; signature coverage is the substitute, and
     every QSPGS core is admin-signed, so tamper-evidence is
     equivalent. Confirmed with a tamper test (flip format_version
     -> core-sig verify fails).
  3. Decode refuses an epoch outside [MIN, MAX] with
     GY_ERR_UNSUPPORTED, before consuming any state.
  4. The window constants (GY_QSPGS_FORMAT_VERSION,
     GY_QSPGS_MIN/MAX_SUPPORTED_FORMAT_VERSION) are defined ONCE in
     qspgs_wire.h and reused by the gy_qspgs_store records (§9), so
     a group's at-rest and on-wire epoch are one value. Window opens
     at 1 (nothing to migrate).
  5. No GY_QSPGS_WIRE_VERSION bump: nothing has shipped or been
     KAT-frozen publicly, so epoch 1's wire layout simply includes
     the field and the (unfrozen, D-QGS-10) wire vectors were
     re-cut. The WIRE_VERSION byte remains reserved for a future
     hard framing break.
- Migration model: a [CFG+] revision -> implement the new layout
  under format_version = 2, raise MAX to 2; new groups mint at 2,
  groups at 1 keep decoding while 1 >= MIN; deprecate by raising
  MIN past 1.

### D-QGS-13: [CFG+] transcription errata (DECIDED 2026-09-16; spec §3.3, §5, §7.3, §8, §9, §10.2)

- Topic: findings of the 2026-09-16 compliance review of the whole
  QSPGS vertical (every change since ff77796, the v1.4.0 merge)
  against [CFG+] Figures 3 to 20 and Appendix B. The review
  confirmed the bulk of the transcription faithful (KR-ML-DSA
  Figs. 3/4, the Fig. 6 hierarchy, the Fig. 5 structure and core-
  signature coverage, RemoveMember rotation, the H(vkpsdn)
  optimization, the C_UID check, the hybrid invite PKE, CAS
  versioning; see docs/plans/M9-errata.md "what the review
  confirmed"). Eight items diverged; each is decided below. The
  implementation plan is docs/plans/M9-errata.md (tickets
  GER-M9E-00..07); this entry is the authority, the plan the work
  breakdown.
- Cross-cutting freeze decision (DECIDED, user 2026-09-16):
  NOTHING is frozen yet (v1.5.0 untagged; no QSPGS group exists
  outside the test suite and the demo), so the wire and at-rest
  layouts are changed FREELY to be spec-true at format_version 1.
  Version 1 is DEFINED to be the correct, post-errata format; there
  is no epoch bump and no "keep decoding the old bytes" obligation,
  because nothing consumed them. The affected KAT vectors are
  re-cut once, deliberately, through the --dump generator (generator
  and header byte-identical), the FROZEN note flipped for the one
  regen and the re-cut recorded under D-QGS-10. The [CFG+] revision
  pin is unchanged: these are geryon transcription errors, not a
  paper revision. This supersedes the M9E-00 "epoch 1 vs epoch 2"
  option in favor of epoch 1.
- E1 (HIGH, FIX; [CFG+] Fig. 12 / Fig. 16; GER-M9E-01): the
  appendix-line signature omitted the appendix header. [CFG+] signs
  sigma_psdn = Sgn(apx-hdr, line) with apx-hdr = (GID, vMaj, vMin);
  geryon signed line_type || author_index || payload only
  (gy_qspgs_apx_line_tbs). The pseudonym key is per gk so cross-
  group replay was already blocked, but gk survives every non-
  rotating major and every minor version, so a corrupt server could
  re-append an old signed line at a later (vMaj, vMin): an old
  refresh rolls a member's uk back, an old modAttr reverts
  attributes, an old leave/addUser re-fires. This is the rollback
  class the paper's model excludes. DECISION: bind the header. TBS
  becomes GID(16) || vMaj(BE32) || vMin(BE32) || line_type(1) ||
  author_index(BE32) || payload, single qspgs-appendix context.
  Validation: negatives (both tiers) that a line signed at
  (vMaj, vMin) fails at (vMaj, vMin+1), (vMaj+1, vMin), and under a
  foreign GID, plus an empty-payload Leave line so the header-only
  coverage is exercised; the appendix-line TBS vector re-cut.
- E2 (HIGH, FIX; [CFG+] Fig. 11 / Fig. 15; GER-M9E-02): admin
  lineage was not enforced. The server admn gate read the admn flag
  from the SUBMITTED core (gy_qspgs_server_core_check), so a non-
  admin could sign a core flipping its own admn bit and the server
  accepted it; the client fetch had no prior-version input, checked
  no admn flag, and recomputed only the signer's pseudonym hash, so
  a malicious admin could plant foreign vk hashes undetected (E5,
  folded here). DECISION, three parts:
  1. Server takes prior (stored) + next (submitted) cores; the admn
     gate for signer_index ALWAYS reads the PRIOR mem-lst (Fig. 11 /
     17 / 19 / 20 all abort on admn_i' from the stored record), the
     TBS is built from the NEXT objects; Create (prior NULL) gates on
     the submitted list and requires n_members == 1, vMaj == 1.
  2. vk-lst is bounded per the paper's PER-OPERATION rule, driven by
     an operation-kind field added to the submission wire (free per
     the freeze decision). Reading the actual figures (Fig. 11
     AddMember, Fig. 17 RemoveMember, Fig. 19 ChangeSettings, Fig. 20
     RotateGroupKey, App. B.5 SetAdminRights), the server's vk-lst
     transition and the source of the signer's own vkpsdn reduce to
     exactly four categories:
       - CREATE (Create): no prior; vk-lst = submitted, n==1, vMaj==1;
         signer vkpsdn resolved from the SUBMITTED vk-lst.
       - UNCHANGED (SetAdminRights, ChangeSettings, ChangeAttr,
         ToggleJoinLink): the submitted vk-lst MUST equal the prior
         vk-lst byte for byte; signer vkpsdn from the PRIOR vk-lst.
       - APPEND_ONE (AddMember, UserAdd, Invite): the submitted vk-lst
         MUST equal the prior vk-lst with exactly one newcomer hash
         appended (prior is a prefix, length +1); signer vkpsdn from
         the PRIOR vk-lst (gk unchanged, the admin's key is not
         rerandomized) - Fig. 11 "vkpsdn <- (vk-lst')_i,
         vk-lst <- vk-lst' += vk_UID'".
       - REPLACE (RemoveMember, RotateGroupKey): any submitted vk-lst
         is accepted, because rotation rerandomizes every key with the
         new rrs = KDF(gk, "SUB-KEY") and the server holds no gk;
         signer vkpsdn from the SUBMITTED vk-lst (Fig. 20
         "vkpsdn <- (vk-lst)_i", no prime). RemoveMember is delete-one
         then rotate, so as the server sees it, it is a REPLACE with
         one fewer entry.
     This is a transcription of the paper's per-endpoint behavior into
     geryon's single core-check endpoint; the operation-kind is how
     that one endpoint learns which of the four rules applies. The
     earlier "additive vs replacement" wording in this item was
     under-specified: it could not express UNCHANGED (SetAdminRights
     appends no newcomer, so an "additive = prior + newcomer" rule
     would wrongly reject it) and it missed the prior-vs-submitted
     source of the signer key. The rejected "accept any admin-signed
     vk-lst" alternative rested only on the existing code, which is
     not a valid basis. The server derivation is defense in depth; the
     client recompute (part 3, E5) is the actual guarantee.
  3. Client fetch takes the caller's last-seen (vMaj, vMin) and
     retained prior member view (NULL for a first fetch). The signer
     must be an admin in the FETCHED roster. (open_current, the edit
     helper, only re-verifies that the current core is authentically
     admin-signed; the E5 all-member recompute is a FETCH property,
     not an edit one, and must not run there because that helper also
     backs a non-admin member appending an appendix line, which holds
     only its own and acquaintance base keys. A rotation rebuilds and
     recomputes the whole vk-lst in its own path.) With
     a prior view the fetched version must PROGRESS, never roll back,
     by lexicographic (vMaj, core-sig last_vMin). CORRECTION (D-QGS-14
     E11, 2026-09-17): the original text here claimed "a SKIP FORWARD
     past missed versions is ALLOWED" and attributed that to [CFG+]
     Fig. 15 as monotonicity, "NOT exactly +1". That attribution is
     WRONG. Fig. 15 UsrVfyUpdate has an explicit second abort,
     "if vMaj' > vMaj + 1: HandleError // version skipped", so the
     paper requires EXACTLY the next major, and a third abort,
     "if vMaj' > vMaj AND v != vMin: HandleError // min version
     skipped", that geryon never implemented (the new major's core-sig
     version must equal the appendix vMin the client last saw). The
     paper-faithful lineage rule is decided in D-QGS-14 E11 and
     SUPERSEDES this paragraph; only when the fetch is the next major
     (vMaj == prior + 1) does the incremental admin-in-prior check
     apply. After decrypting every member the client recomputes
     rho_j / vkr_j / H(vkr_j) from each member's base key and requires
     the received vk-lst to match entry for entry, with
     n_vk == n_members (E5). This client recompute is the ACTUAL
     security guarantee (the server is the adversary); the server-side
     derivation is defense in depth that rejects a planted vk-lst at
     CAS time and does not replace it.
  Base-key resolution for E5 is [CFG+] Fig. 16 GetPseudoVkBase: the
  caller's own pair, else an acquaintance record, else a caller-
  supplied server-served ACCT (the fetch takes an ACCT-ref array,
  brought forward from GER-M9E-04 because the spec's fetch
  verification needs it; the ACCT's identity-signature and acq-tag
  check remain GER-M9E-04). A member resolvable by none is
  GY_ERR_NOT_FOUND. The library keeps no membership state (D-QGS-8):
  the prior view is the caller's. A deployer that passes NULL on
  every fetch forfeits the anti-rollback property; stated in §10.2.
  Validation: the self-promotion negative fails on the pre-errata
  server and passes after (server side); client lineage negatives for
  rollback, progress/skip accepted, and non-admin-in-prior signer on
  an exact +1 (test_qsgroup_lifecycle). E5 positive coverage is every
  multi-member fetch (all members recomputed); the malicious-admin
  negative (an admin signing a FOREIGN vk-lst hash for a non-signer,
  which a valid signature cannot catch but E5 does) needs a low-level
  signing seam the public facade does not expose, so it is built in
  GER-M9E-06 (task 9), which stands up that forged-signed-object harness
  under GY_TEST_HOOKS for its CheckAppendixLine invalid-line tests and
  reuses it to sign the malicious core; the fetch-time E5 recompute
  landed in GER-M9E-02 is what the negative exercises.
- E3 (HIGH, FIX; [CFG+] App. B.7, Fig. 12, Fig. 15 AcceptedInvite;
  GER-M9E-03): the invite acceptance was inverted, contradicting
  THIS register's D-QGS-6 item 2. The paper has the admin add a
  PENDING line (C_UID, Enc_ek(UID, r, uk absent, gk), admn = 0) and
  the INVITEE accept by signing (UID, uk, GID) with its OWN skpers,
  sealing to ipk, uploading to the invite queue; fetching members
  treat the invitee as a member once a valid acceptance is queued
  (verified against the INVITEE's PKI key), and Consolidate writes
  the accepted uk into the main list. geryon had the INVITER mint a
  random uk, sign as the inviter, and seal; the opener verified the
  inviter; the demo added the member before the invitee opened
  anything. JoinViaLink independently minted a random uk where
  Fig. 12 derives uk = KDF(muk, "uk@" || ep). Consequences: no
  invitee consent, the invitee's uk unrelated to its muk (so acq /
  expKey are wrong for that group), uk shipped out of band. The
  "voucher" design this reflected is recorded in NO document.
  RESOLUTION OF THE D-QGS-6 ITEM 2 CONTRADICTION (user 2026-09-16):
  the SPEC (and register, and paper) WIN over the code; the code is
  corrected, not reconciled. DECISION: the invitee signs the
  acceptance with its own identity, uk = KDF(muk, "uk@" || ep); the
  admin emits a pending member entry (mct plaintext gains a form
  flag: uk present vs pending, a pending entry carrying gk' so later
  rotations can still derive the isk the acceptance was sealed to);
  a new client call AcceptInvitation signs uidlen || UID || uk || GID
  under qspgs-invaccept through the custodian identity seam and
  seals to ipk; opening takes the INVITED UID's identity keys and
  returns (uid, uk); ApproveJoin/Consolidate writes the accepted uk
  into the pending entry and re-signs; JoinViaLink derives uk from
  muk. No random uk anywhere in the vertical after GER-M9E-03.
  Validation: acceptance signed by a non-invited identity rejected,
  wrong-GID acceptance rejected, a queued acceptance with no pending
  entry ignored, a pending entry with no acceptance stays pending.
  OUTCOME (CLOSED 2026-09-16): implemented across ops/field, facade,
  header, and the worked example. The mct plaintext gained a form
  byte (GY_QSPGS_MEMBER_FORM_PRESENT / _PENDING); a PENDING entry
  carries gk' in its key slot (gy_qspgs_member_ct_seal_pending /
  gy_qspgs_member_build_pending), decrypts to a view flagged pending
  (uk_len 0). gy_custodian_qsgroup_invite is now an admin core edit
  that resolves the invitee base key (acquaintance / caller ACCT),
  mints gk', appends the pending entry, and outputs gk'.
  AcceptInvitation is the INVITEE's call (own identity signs
  (UID, uk, GID), uk = KDF(muk, "uk@" || ep), sealed to ipk from
  gk'). A new OpenInvitation verifies against the INVITED UID's
  identity keys. ApproveJoin re-seals the pending entry PRESENT with
  the accepted uk (admn and vk-lst unchanged, an UNCHANGED core
  write). RevokeInvitation, since queue entries are opaque PKE
  ciphertexts (spec section 8, no cleartext UID), now takes the
  current core and opens entries with the isk from the target's
  pending gk' to identify them. JoinViaLink derives uk from muk.
  No random uk remains. Validated by test_qsgroup_lifecycle
  (invite_flow_roundtrip: pending fetch shows uk_len 0, invitee
  accepts, open verifies vs the invitee and rejects a non-invitee
  identity, revoke drops the pending invitee's queued acceptance,
  approve settles it) and the worked example's phase-D
  invite/accept/open/approve choreography over the pairwise session.
  CARRIED FORWARD (as the ticket scoped): the FETCH-time treatment
  of a pending entry with a matching verified queue acceptance
  (reported as a settled member) and Consolidate draining the queue
  need the invite-queue object as a fetch input, so they land with
  GER-M9E-06; the complete_invitation / approve_join naming split is
  GER-M9E-07 item 6. Until M9E-06, ApproveJoin trusts the uk the
  caller passes from a verified OpenInvitation; the fetch-time
  re-verification of the queued acceptance against the invitee's
  identity is the M9E-06 guarantee.
- E4 (MEDIUM, FIX; [CFG+] Fig. 8, Fig. 15 IsCorrectUserKey;
  GER-M9E-04): the acquaintance tag acq was derived and stored but
  never compared to any uk. GrantAcquaintance accept verified the
  identity signature and stored acq, but accept_acquaintance never
  received uk, and add_member loaded acq and discarded it, so the
  "authorized addition" property and the fetch-time member consist-
  ency check were unimplemented. DECISION: accept_acquaintance takes
  the granter's uk, derives acq = KDF(uk, "ACQ-Tag"), const-time
  compares to the ACCT's acq, and stores (UID, uk, vkbase) as the
  paper's AcqRec (GY_QREC_ACQUAINTANCE gains uk); add_member takes
  new_uid only and reads uk from the record (the out-of-band uk
  param is removed); Fetch runs IsCorrectUserKey for any member
  without an AcqRec against a caller-supplied ACCT, failing the
  version (GY_ERR_VERIFY, offending index) on mismatch. Whether the
  store record bumps format_version within the D-QGS-8 window or the
  record kind is versioned is settled in GER-M9E-04. Validation: a
  granter ACCT whose uk does not open acq rejected at accept; a
  fetched member whose uk mismatches its ACCT acq fails the version.
  OUTCOME (CLOSED 2026-09-16): implemented across facade, store, the
  public header, unit tests, and the demo. accept_acquaintance takes
  the granter's uk, derives acq and const-time compares to the ACCT
  acq before sealing the AcqRec (UID, uk, vkbase); the record now
  carries uk (ep || vkbase || acq || uk). add_member dropped its uk
  param and loads uk from the record; a granter uk that does not open
  acq is rejected (GY_ERR_VERIFY). gy_qsgroup_acct_ref gained the
  member's hybrid identity public keys (curve_pk / mldsa_pk), and
  Fetch runs IsCorrectUserKey (check_user_key) for every settled
  member with no AcqRec: the matching ACCT's identity signature must
  verify AND acq == KDF(uk) on the decrypted roster uk, else
  GY_ERR_VERIFY; pending invites (E3, no uk) are skipped; members with
  an AcqRec were checked at accept time. gy_custodian_qsgroup_export_-
  user_key was added so a granter can produce its own uk to convey.
  The conveyance channel is the pairwise Double Ratchet session
  (QSPGS_SPEC.md section 5): the demo stands one up per pair at
  acquaintance and reuses it for the group-key delivery. The store
  record was extended in place (no format_version bump; v1.5.0
  untagged, nothing frozen). Test fetch_iscorrect_userkey drives the
  ACCT-path positive plus the epoch-mismatch and missing-id-keys
  negatives; accept-time acq mismatch is covered in register_and_-
  accept_roundtrip. Carried forward: nothing (E4 fully closed).
- E5 (MEDIUM, FIX; folded into E2 part 3; GER-M9E-02): fetch
  recomputed only the signer's vkpsdn hash. Decided with E2.
- E6 (MEDIUM, FIX; [CFG+] Fig. 20, App. B.8; GER-M9E-05): the join
  slot was carried forward unchanged on gk rotation, so a link
  holder recovered the retired gk and failed at fetch; the demo
  worked around it by re-linking with a new secret. The paper re-
  seals c_join = Enc_jk(gk_new, fet_new) under the STATIC join key on
  rotation, and the link must not change (rotation happens on every
  removal). DECISION: store the join-link secret per group (new
  record kind GY_QREC_JOIN_LINK keyed on GID, the ONE at-rest
  exception to "only muk, base pair, gk", recorded in §9); rebuild_
  and_emit re-seals (gk_new, fet_new) under the stored jlk when the
  caller holds it; a non-creator admin without the secret gets a
  distinct return code and the slot is dropped (recommended over
  refusing the rotation, since refusing a removal for a missing link
  secret is the wrong failure mode; the alternative "share jls with
  the other admins" step is the paper's own requirement and stays a
  documented deployer option). ToggleJoinLink gains a disable path.
  Validation: rotate a group with an open link, the OLD secret opens
  the NEW slot and yields gk_new, old slot bytes gone.
- E7 (MEDIUM, FIX; [CFG+] Fig. 10, 15, 16, 18; GER-M9E-06): the
  library emitted appendix lines but nothing consumed them (no
  CheckAppendixLine, no settings gating, no Consolidate, no fetch-
  after-leave), and the demo never submitted one. SCOPE DECISION
  (user 2026-09-16): LIBRARY scope, maximally. Everything that can
  live in the library does: CheckAppendixLine (per-line signature
  under the recomputed vkpsdn, b_add/b_attr gating, c_join-present
  for join, commitment check on new-member lines), the UsrVfyUpdate
  roster application in the paper's kind order (join/addUser,
  refresh, modAttr, leave), and the Consolidate helper (fold valid
  lines, drain the invite queue, rotate gk if any leave folded, bump
  vMaj, set last_vMin = |apx-lst|). RATIONALE: leaving these to
  callers lets any deployer reintroduce exactly the holes this
  errata closes. Only durable storage, ordering/rate-limiting, and
  delivery of appendix lines stay deployer scope. This requires a
  minimal FROZEN settings prefix in the HEADER field plaintext
  (flags(1) = b_add | b_attr<<1 | b_adm<<2, then opaque attributes)
  so the gating bits are readable, and adds the APPENDIX and
  INVITE_QUEUE objects as Fetch inputs. Fetch-after-leave adds
  Sgn_skpsdn(GID, k) (client) verified under vk-lst_k (server).
  Validation: a lifecycle test over all five line kinds, one invalid
  line of each kind, the paper's ordering (a refresh and a leave for
  one member in one appendix), and consolidation reproducing the
  roster Fetch computed.
- E8 (LOW, MIXED; various; GER-M9E-07):
  1. fet derived from gk is refreshed only on rotation while the
     paper samples fet_new on every major version. KEEP (the
     deviation), recording in §6.5 that a leaver retains fetch until
     the next rotation, which Consolidate-with-leave now forces
     (E7). Reason: rotation on every folded leave bounds the window.
  2. Self-removal: the paper allows an admin to remove itself
     (Fig. 17 note); gy_custodian_qsgroup_remove_member returns
     GY_ERR_ARG on a self target. DECIDED (2026-09-17): DOC ONLY, no
     functional gap. A geryon core edit is self-signed and the signer
     must remain in the emitted roster (rebuild_and_emit rejects an
     absent signer with GY_ERR_STATE), so a direct-edit self-removal
     would emit an unverifiable core; the refusal is structural, not
     policy. Self-removal is ALREADY available the spec-faithful way:
     a LEAVE appendix line (gy_custodian_qsgroup_appendix_leave, self-
     signed while still a member) folded by another admin at
     Consolidate, which rotates gk on the folded leave. The paper's
     permission is met; geryon_qspgs.h now documents remove_member's
     refusal and points at the LEAVE path. A last-admin guard in
     Consolidate (refuse to orphan the group) is a separate opt-in
     hardening, NOT required by this item and not taken here.
  3. expKey: the paper's Fetch output is (expKey, UID); the roster
     exposed raw uk. FIXED (2026-09-17): added
     gy_custodian_qsgroup_export_key(c, uk, uk_len, out, out_len), a
     derive call that applies the spec-defined expKey = KDF(uk,
     "EXP-Key") (§2.2 / §6.5) so applications never derive from uk
     themselves; the roster wire is unchanged (additive API only).
  4. n_vk vs n_members: FIXED by E2 part 3; close.
  5. JoinViaLink installed the recovered gk without verifying the
     core signature. FIXED (2026-09-17): gy_custodian_qsgroup_join_-
     via_link now takes signer_acct / signer_acct_len and verifies
     the current core's admin signature (signature-only against that
     caller-supplied ACCT, since the joiner has no acquaintance
     records yet) BEFORE the recovered gk is stored; a forged or
     tampered core is rejected GY_ERR_VERIFY with no state written.
     Full ACCT dual-signature verification remains accept_-
     acquaintance's job, and the E5 all-member recompute runs at the
     joiner's first Fetch.
  6. Naming: geryon's approve_join is the paper's invite completion;
     the paper's ApproveJoin is admin approval of a link joiner when
     b_adm is set. FIXED (2026-09-17): renamed
     gy_custodian_qsgroup_approve_join ->
     gy_custodian_qsgroup_complete_invitation; the approve_join name
     is reserved for the paper's gated join-line approval, which is
     reconciled inside Consolidate / Fetch.
  7. KR-ML-DSA doc precision (DOC ONLY, no code change, vectors
     unaffected): §3.3 item 8 framed K_r = SHAKE256-32(K_b || rho)
     as filling a gap the paper leaves open, but Fig. 4 line 39
     carries K unchanged into sk_r; record it as a DELIBERATE geryon
     choice (a per-pseudonym signing seed), not a gap. The same item
     said the base seed expansion is "exactly as FIPS 204 KeyGen";
     FIPS 204 / Fig. 3 line 02 take rho_s from bytes [32, 96) of
     H(seed || K || L) after a 32-byte rho slot, while geryon
     squeezes rhoprime = bytes [0, 64) and K_b = [64, 96) with NO
     rho slot (A is fixed, so no rho is needed). State the actual
     slicing. DONE: §3.3 item 8 states both as deliberate choices
     with the actual slicing (rhoprime [0, 64), K_b [64, 96)).
  8. Inventory precision (DOC ONLY): §14 item 4 ("one geryon call
     per [CFG+] protocol message") and §5's operation inventory did
     not name the geryon-specific calls the paper folds into other
     flows. FIXED (2026-09-17): both now list Consolidate (the admin
     appendix fold, Fig. 18), AcceptInvitation as the invitee's own
     call (E3), and fetch-after-leave (§6.5).
- Validation (whole entry): every HIGH finding gets a negative test
  that fails on the pre-errata code and passes after, or is
  explicitly accepted here with the consequence stated in §10.2; the
  worked example runs end to end on both hybrid tiers and now
  exercises the appendix path and the invitee-signed acceptance; the
  affected vectors are re-cut once and re-frozen. v1.5.0 is tagged
  only after this closes (or the accepted-deviation subset is
  documented), since E1 to E3 change what §10.2 claims.

### D-QGS-14: [CFG+] transcription errata, second pass (DECIDED 2026-09-17; spec §4, §5, §8, §10.2)

- Topic: findings of the 2026-09-17 compliance review of the whole
  QSPGS vertical (every change from bec10bd, the GER-M9-08 close-out
  merge, to HEAD of branch 122-ger-m9e-07) against [CFG+] Figures 5 to
  22 and Appendix B. The first-pass review (D-QGS-13) confirmed the
  bulk faithful and fixed eight items; this pass found six residual
  divergences, E9 to E14, decided below. The implementation plan is
  docs/plans/M9-errata-2.md (tickets GER-M9E2-00..05); this entry is
  the authority, the plan the work breakdown. The cross-cutting freeze
  decision of D-QGS-13 still holds: v1.5.0 is untagged and no QSPGS
  group exists outside the test suite and the demo, so wire and at-rest
  layouts are changed FREELY to be spec-true at format_version 1. All
  six are FIX, following the paper as closely as it allows (the user's
  standing instruction, 2026-09-17). E11 additionally corrects a
  factual misattribution in D-QGS-13 E2 part 3 (see that item).
- E9 (MEDIUM, FIX; [CFG+] App. B.8, Fig. 22 JvL.3 / JvL.4 / AJ.3;
  GER-M9E2-01): b_adm is defined (GY_QSGROUP_SETTING_ADM) and sealed
  into the header flags byte (§8), but never enforced. A valid JOIN
  line becomes a member at every honest fetch and is folded by any
  Consolidate, with no admin having approved it; a group configured to
  require approval has open joins. App. B.8: with b_adm set, joiners
  from links are NOT interpreted as members until an admin writes them
  in (ApproveJoin, Fig. 22 AJ.3). DECISION: with b_adm set, a JOIN line
  is still verified (signature, open link) and still reported, but is
  NOT applied to the effective roster at Fetch and is NOT folded by
  Consolidate unless an admin approves it. Fetch reports the line with
  a pending-approval outcome; Consolidate takes a caller-supplied array
  of approved appendix-line indices and folds only those. This is the
  paper's ApproveJoin, for which the D-QGS-13 E8.6 rename reserved the
  name. With b_adm clear, behavior is unchanged. Validation: with
  b_adm set, a valid JOIN line is reported pending-approval and absent
  from the Fetch roster, Consolidate without approval leaves the joiner
  out and with approval folds it (both tiers); the b_adm-clear
  appendix_fold_and_consolidate behavior unchanged.
- E10 (MEDIUM, FIX; [CFG+] App. B.7, Fig. 17, Fig. 22 IG.3(d);
  GER-M9E2-02): RevokeInvitation scrubbed the invite queue only and
  left the pending member entry in the core, so the invitee (holding
  gk' from invite time) could call AcceptInvitation again and be
  settled at the next Fetch or Consolidate; revocation was undone by
  the invitee. App. B.7: the admin revokes by removing the
  (C_UID, mct, 0) line, "similar as in RemoveMember (cf. Figure 17)".
  DECISION: RevokeInvitation becomes an admin core edit that drops the
  pending entry (and its vk-lst hash) and re-signs; the queue scrub
  stays as the second half of the same call. Following Fig. 17
  literally, the revoke rotates gk via the RemoveMember path
  (rebuild_and_emit). The server classifies the result as a REPLACE
  (the existing op-kind, DECIDED 2026-09-17 over a new REMOVE_ONE
  op-kind: a removal is a REPLACE with one fewer entry, matching how
  RemoveMember is already handled, so no new server surface). Once the
  entry is gone, Fetch's settle_one ignores a stray acceptance for the
  revoked UID (already true). Validation: revoke, then the invitee
  re-accepts and the acceptance is deposited; Fetch reports no such
  member and Consolidate does not settle it (both tiers); on the
  pre-fix code the same sequence settles the member.
- E11 (MEDIUM, FIX; [CFG+] Fig. 15, Fig. 21 FG.2; GER-M9E2-03):
  Fetch accepted a skip forward past missed major versions and never
  implemented Fig. 15's "min version skipped" check; D-QGS-13 E2 part 3
  misquoted Fig. 15 as permitting the skip (corrected in that item).
  Fig. 15 UsrVfyUpdate aborts on "vMaj' > vMaj + 1 // version skipped"
  and on "vMaj' > vMaj AND v != vMin // min version skipped", and
  Fig. 21 FG.2 serves exactly the next version. DECISION (follow the
  paper, the user's standing instruction): when a prior is supplied,
  reject vMaj' < prior (rollback) and vMaj' > prior + 1 (skip); on
  vMaj' == prior + 1 require the new major's core-sig version to equal
  the appendix vMin the client last saw (a new prior_apx_vmin fetch
  input, free per the freeze) and the signer to be an admin in the
  prior view; on vMaj' == prior accept the same-major refetch when the
  core-sig last_vMin is unchanged. That same-major acceptance is the
  ONE interpretive call: Fig. 15's rollback line ("vMaj' <= vMaj //
  attempted rollback") would bar a same-major refetch that Fig. 10
  explicitly serves to a leave-fetch-token holder, an internal
  inconsistency in the paper resolved in favor of Fig. 10. A deployer
  that keeps no prior still forfeits all of this (§10.2 item 4).
  Validation: skip forward by two majors rejected; an exact next major
  whose core-sig version is one short of the appendix the client saw
  rejected (an admin consolidated from a hidden shorter appendix); the
  existing rollback and admin-in-prior negatives unchanged; the
  "skip accepted" assertion in TEST(create_and_fetch_roundtrip) flips
  to "skip rejected".
- E12 (LOW-MEDIUM, FIX; [CFG+] Fig. 15 "Check new acquaintances";
  GER-M9E2-04): IsCorrectUserKey ran once per core entry in the decrypt
  loop BEFORE the appendix was applied, and its AcqRec branch returned
  success on a UID match without comparing the stored uk to the roster
  uk. Fig. 15 runs the check AFTER the appendix over all (UID', uk') in
  members with no (AcqRec, UID', uk') record: it covers the effective
  roster (refreshed uks, addUser / join newcomers, settled invitees)
  and exempts a member only on a (UID, uk) match, not UID alone. Result
  was a consistency gap (wrong expKey / sending token for an
  unchecked member; a planted uk on an acquainted member undetected),
  not a confidentiality hole. DECISION: move the check after the
  appendix and queue passes, run it over the effective roster, and make
  the AcqRec exemption a const-time (UID, uk) match; on a uk mismatch
  fall through to the ACCT check. Settled invitees stay exempt because
  their uk is bound by the invitee's own identity signature (Fig. 15
  AcceptedInvite), stronger than IsCorrectUserKey; recorded here.
  Validation: an acquainted member whose roster uk was planted (forge
  harness, a validly-signed core with a wrong uk in the member's mct)
  fails the version; a refresh line whose new uk does not open the
  member's new-epoch ACCT acq fails; the existing
  fetch_iscorrect_userkey positives unchanged.
- E13 (LOW, FIX; [CFG+] Fig. 11 hdr <- (GID, vMaj+1, ...); GER-M9E2-05):
  QSPGS_SPEC.md §7.3 item 4 (added by GER-M9E-02) claims the server
  requires a submitted core to advance vMaj by exactly one over the
  stored prior, but gy_qspgs_server_core_check never compared next->vmaj
  to prior->vmaj (gy_qspgs_server_version_check enforced only strictly
  increasing (vMaj, vMin)). DECISION: FIX in code, one check in the
  non-CREATE path (next->vmaj != prior->vmaj + 1 is GY_ERR_VERIFY), so
  the §7.3 item 4 sentence becomes true. This is server-side defense in
  depth alongside the client E11 lineage. Validation: a next core at
  prior vMaj + 2 rejected, at prior vMaj rejected (test_qspgs_server.c,
  test_qspgs_ops.c); §7.3 item 4 text unchanged.
- E14 (LOW, FIX; [CFG+] Fig. 5, Fig. 12, Fig. 16; GER-M9E2-05): the
  JOIN appendix line carried the mct alone, with no cleartext C_UID'
  commitment, so Fig. 16's commitment check for a join line was a
  no-op (addUser carries cuid(hash_len) || mct and is checked;
  join_via_link framed the payload as mct only). Consolidate re-commits
  every folded member with a fresh r_c, so the omission was structural,
  not a hole. DECISION (follow the paper): align the JOIN payload wire
  to cuid(hash_len) || mct like addUser and have CheckAppendixLine
  check the commitment; one code path across the two newcomer kinds and
  a spec-true Fig. 5. Free layout change: no vector covers the JOIN
  payload (the appendix-line TBS vector uses an opaque payload), the
  demo's phase-I JOIN line is regenerated by the same call. Validation:
  a JOIN line whose C_UID' does not open is reported invalid (forge
  harness, as adduser_bad_commitment).
- Register placement (DECIDED 2026-09-17): opened as D-QGS-14, leaving
  D-QGS-13 as the first-pass record.
- Validation (whole entry): each finding gets a negative test that
  fails on HEAD 96adfc3 and passes after, or is explicitly accepted
  here with the consequence stated in §10.2; the worked example runs
  end to end on both hybrid tiers. v1.5.0 is tagged only after this
  entry closes, since E9 to E11 change what §10.2 claims.
- CLOSE-OUT: exit criteria met. E9 to E14 each landed with
  their negative tests, the SECURITY_REVIEW_v1.5.0 pass closed every
  code-level finding (HIGH-1 through LOW-6, all FIXED) with negatives on
  both tiers, the QSPGS / KR-ML-DSA dudect targets (LOW-5) pass on x86_64
  and arm64 (all |t| well under the 10 threshold), and the worked example
  runs end to end on both hybrid tiers. This entry is CLOSED and v1.5.0 is
  clear to tag.
