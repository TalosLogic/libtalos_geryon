# Double Ratchet Decisions

**Spec:** Signal's Double Ratchet specification, "The Double Ratchet
Algorithm", Revision 4 (2025-11-04). See the References section of
DESIGN.md for the full citation. Revision 4 also adds optional
post-quantum ratcheting sections (§5 Sparse Post-Quantum Ratchet, §6
Triple Ratchet); the classical suites do not use them (D-DR-12).
**Module:** ratchet/ (double_ratchet.c, header.c).
Register conventions and the full index live in [README.md](README.md);
cross-referenced D-GEN/D-X3DH/D-SES IDs live in sibling files.

### D-DR-1: KDF_RK

- **Spec gap:** §3.1 defines KDF_RK abstractly; §7.2 recommends HKDF
  with the root key as salt.
- **Decision:** HKDF-HASH, salt = rk, IKM = the DH output, info per
  D-GEN-3, L = 64 (32-byte new root key + 32-byte chain key).
  Extended by D-DR-14 for protocol v1: the shipped root KDF is the
  HE variant with L = 96 (a 32-byte next header key appended); the
  L = 64 form never appears on a v1 wire.
- **Rationale:** follows the spec recommendation.
- **Validation:** RFC 5869 vectors; protocol KATs.

### D-DR-2: KDF_CK

- **Spec gap:** §3.1 defines KDF_CK abstractly; §7.2 recommends HMAC
  with single-byte constants (0x01 message key, 0x02 next chain key)
  but leaves the construction to the implementer.
- **Decision:** NIST SP 800-108r1 (upd1) KDF in Counter Mode, PRF =
  HMAC-HASH, Label = INFO("dr.msg") / INFO("dr.chain"), single-block
  output. The fixed-input byte layout is pinned (SP 800-108 permits
  variations, so KATs need one exact form):
  [i]_32BE || Label || 0x00 || Context || [L]_32BE, counter starting
  at 1, L in BITS. The Context field sits between the 0x00 separator
  and L, and is empty for dr.msg/dr.chain. The Label uses the
  info-string convention (D-GEN-3) rather than a fixed ASCII context,
  so the suite binding is carried into symmetric derivations.
- **Rationale:** NIST-specified construction with official test
  vectors; Label-based domain separation carries the suite binding
  into symmetric derivations.
- **Validation impact:** deliberate divergence from the DR spec's
  recommendation means libsignal chain/message keys never match
  byte-for-byte, and per D-GEN-6 no compat parameterization is
  built to force a match. KDF_CK validates against SP 800-108 official
  vectors and spec-derived protocol KATs.

### D-DR-3: AEAD scheme and nonce handling

- **Spec gap:** §3.1 requires an AEAD keyed by the message key and
  explicitly enumerates nonce options (fixed constant; derived from
  mk alongside an independent AEAD key; extra KDF_CK output; random
  and transmitted). §7.2 recommends CBC+HMAC or SIV for
  misuse-resistance.
- **Decision:** classical suites use ChaCha20-Poly1305 (the
  mandatory-to-implement default) with a 32-byte key, pinned as
  aead_id = 0x01. There is no runtime AEAD selection in classical
  suites: classical signed_data has no flags field (D-X3DH-4) and
  classical AD is the spec form exactly (D-X3DH-6), so there is no
  carrier for a choice. Per-message key and nonce derive from MK via
  SP 800-108 KDF-CTR: Label = INFO("dr.aead"),
  Context = aead_id || n_be32, L = 32 + 12 (key + ChaCha20-Poly1305
  nonce). aead_id stays in the dr.aead and he.aead KDF Contexts even
  when pinned, so derivation code is suite-uniform. One aead_id
  governs the whole session, header and message encryption alike
  (D-DR-15).
- **Rationale:** MK is unique per message so derived nonces are too,
  and derivation keeps nonce handling stateless; suite security is
  set by the key exchange, not AEAD key length. This is the "derived
  from mk alongside an independent AEAD encryption key" option that
  §3.1 enumerates. Geryon deliberately declines §7.2's CBC+HMAC/SIV
  recommendation: mk is single-use by construction and the
  per-message KDF-CTR derivation leaves no nonce-misuse path for SIV
  to defend against, while ChaCha20-Poly1305 is faster, smaller on
  the wire, and already in libsodium. Binding aead_id into the Context
  means the same mk can never feed two algorithms with related
  key/nonce material.
- **Validation:** libsodium/RFC vectors for ChaCha20-Poly1305;
  out-of-set aead_id negative test; nonce-uniqueness property test.

### D-DR-4: MAX_SKIP and skipped-key handling

- **Spec gap:** §3.1 requires a MAX_SKIP constant; §8.4 recommends
  "e.g. 1000" and leaves storage, eviction, and DoS handling open.
- **Decision:** MAX_SKIP = 1000; pn/n jumps checked against MAX_SKIP
  before any key derivation; skipped keys indexed by (ratchet-key
  PKID, message number); commit-after-verify: no state mutation of
  any kind until the AEAD tag verifies; zeroize on use or eviction.
  Two store details: entries hold mk ONLY (key and nonce are
  re-derived at use time from the Context inputs (aead_id, n) that are
  available then, keeping entries smaller and single-purpose); PKID
  collisions in the store are candidate-scanned (every (PKID, n) match
  is a candidate, the AEAD tag is the arbiter, and an entry is
  consumed only on successful decryption). The tag plays the role
  D-GEN-2's full-key fallback plays elsewhere. NOTE: the (ratchet-key
  PKID, n) index describes the non-HE form; the shipped v1 wire is HE
  and indexes skipped keys by (header key, n) per D-DR-17, which also
  dissolves the PKID-collision case (header keys are full 32-byte
  values).
- **Rationale:** bounds memory and CPU under adversarial pn/n; the
  ordering rule converts every malformed message into a no-op.
- **Why commit-after-verify:** running SkipMessageKeys and the full DH
  ratchet (root-key advance, ratchet-keypair replacement, DHr update)
  on the LIVE session before AEAD verification, deferring only the
  chain-key/counter update, is unsafe: one forged header carrying a
  novel ratchet public key then corrupts the root key and remote-key
  state with no rollback. Every subsequent genuine message ratchets
  from the corrupted root and the session is permanently desynced,
  with no key knowledge required. Geryon's ordering rule exists
  precisely to make that message a no-op.
- **Validation:** MAX_SKIP overflow tests; state-unchanged-on-failure
  tests, including the forged-new-ratchet-key header case above;
  PKID-collision candidate-scan test.

### D-DR-5: Header integer encoding and CONCAT

- **Spec gap:** header integer encoding is unspecified; §3.1 CONCAT
  requires (ad, header) to parse as an unambiguous pair, with a
  length prefix "if ad is not guaranteed to be a parseable byte
  sequence".
- **Decision:** pn and n are u32 big-endian; flags u32 big-endian with
  curve_type in the low byte. CONCAT is plain ad || header with no
  length prefix: AD length is fixed per suite (two encoded identity
  keys) and the header layout is fixed, so the pair is already
  unambiguous.
- **Rationale:** 64-bit counters are unreachable in a session's
  lifetime given MAX_SKIP; u32 keeps headers compact; fixed-length
  AD makes the length prefix dead weight. Fixed lengths also mean
  CONCAT runs in a stack buffer: geryon has no app-supplied AD
  (D-X3DH-12) and no dynamic allocation in hot paths, so the
  ad || header buffer is a per-suite constant size rather than a
  per-message heap allocation.
- **Validation:** encode/decode round-trip; CONCAT ambiguity is
  structurally excluded (fixed lengths asserted in tests).

### D-DR-6: Header encryption

- **Spec gap:** §4 defines the HE variant as optional; §4.4 requires
  "additional shared secrets" to seed the initial header keys and
  leaves their derivation to the key agreement; §4.1 puts
  message-to-session association outside the spec's scope.
- **Decision:** REQUIRED in protocol v1 for all suites; version/suite
  bytes stay outer; the HE mechanics are pinned normatively in
  D-DR-13..17 below. The initial header keys (shared_hka, shared_nhkb)
  derive from the X3DH SK by KDF expansion with distinct INFO purposes
  (D-GEN-3), mirroring the expansion pattern §7.1 of the spec itself
  uses for the Triple Ratchet's SKec/SKscka split; the exact
  construction is pinned in D-DR-13. Session association is Sesame
  scope (sesame.md).
- **Rationale:** metadata protection; doing it before Sesame avoids
  retrofitting session routing; doing it up front avoids a later wire
  migration; deriving header keys from SK adds no wire bytes to the
  handshake.
- **Validation:** self-vectors (Signal does not deploy HE; no oracle).

### D-DR-7: Initialization mapping from X3DH

- **Spec point (confirms earlier decisions):** §3.3 initializes
  Bob's root key directly from SK and notes Bob-sends-first would
  need extra chain-key seeding, which the spec declines to specify;
  §7.1 maps the key agreement onto the ratchet: SK becomes the DR
  init input, the X3DH AD becomes the ratchet AD, and Bob's signed
  prekey becomes his initial ratchet key pair. §7.1 also recommends
  re-sending the X3DH initial message prepended to every ratchet
  message until the first reply arrives.
- **Decision:** adopted exactly, all suites: RatchetInitAlice /
  RatchetInitBob per §3.3, SPK_B is Bob's initial ratchet key.
  Alice-first only: geryon does not implement the responder-sends-first
  variant; the responder cannot send until it has processed an initial
  message. The §7.1 re-send pattern is adopted at the session layer;
  repeated initial messages carry the same (IK_A, EK_A) and route to
  the existing session via base-key dedupe (D-X3DH-3), so the pattern
  and the replay defense are the same mechanism.
- **Rationale:** exact conformance to the §3.3/§7.1 init mapping;
  SPK-as-ratchet-key is what makes DH1/DH3 bind the handshake
  to the first ratchet epoch.
- **Alice's initial ratchet key (fresh DHs, not EK_A):** Alice
  generates a fresh ratchet key pair at init per §3.3 rather than
  reusing her ephemeral EK_A. Reusing EK_A would (1) extend the
  ephemeral key's life past the X3DH §3.3 deletion point (D-X3DH-13);
  (2) make the first root-KDF input DH3 of the handshake recomputed,
  giving Alice's initial sending chain zero entropy beyond SK, whereas
  a fresh DHs gives it an independent DH; and (3) diverge from the
  DR Rev 4 §3.3 init, one of the few spec-prescriptive points that
  D-GEN-6 anchors validation to.
- **Validation:** init-mapping KATs (Bob's initial RK is SK per
  §3.3, a prescriptive point); re-send convergence test (N copies
  of the initial message yield one session, one plaintext).

### D-DR-8: Skipped-key aging and eviction

- **Spec gap:** §8.4 says skipped keys should also be deleted "after
  an appropriate interval", by timer or event count, and leaves the
  policy to the implementer; §8.7 advises deterministic,
  event-based deletion to avoid implementation fingerprinting.
- **Decision:** event-based only, never wall-clock: a skipped key is
  evicted after 1000 subsequent successfully decrypted messages in
  the session, the store is capped at MAX_SKIP (1000) entries per
  session with oldest-first eviction, and all skipped keys zeroize
  on session archive/teardown. Constants are per-protocol-version,
  not per-app tunables.
- **Rationale:** bounds the §8.4 record-now-compromise-later window
  and the storage DoS with one mechanism; determinism follows §8.7
  and keeps behavior reproducible in vectors.
- **Validation:** eviction-order KATs; zeroization on eviction and
  teardown.

### D-DR-9: No deferred ratchet key generation

- **Spec gap:** §8.5 describes deferring new ratchet key generation
  until the next send as an optional hardening (shorter ratchet-key
  lifetime, more complexity).
- **Decision:** not in v1; geryon follows the §3.5 receive path
  exactly (generate the new pair during the DH ratchet step). The
  derived key schedule is identical either way, so this can be
  revisited later without a wire or vector change.
- **Rationale:** simplicity and exact §3.5 conformance first.
- **Validation:** none needed beyond existing KATs (schedule is
  unchanged).

### D-DR-10: No authentication tag truncation

- **Spec gap:** §8.6 permits truncating CBC+HMAC tags to 128 bits
  and cautions against truncation for other ENCRYPT constructions.
- **Decision:** never truncate. The AEAD's full 16-byte
  ChaCha20-Poly1305 tag ships as defined.
- **Rationale:** §8.6's own advice is that non-CBC+HMAC truncation
  "is not recommended"; geryon uses none of the constructions the
  carve-out applies to.
- **Validation:** wire-size KATs pin the tag length.

### D-DR-11: Implementation fingerprinting discipline

- **Spec gap:** §8.7 advises that anonymous-setting deployments
  follow §3/§4 precisely, with identical skipped-key limits and
  deterministic deletion policies.
- **Decision:** geryon behaves identically across builds of the same
  protocol version by construction: MAX_SKIP, aging constants
  (D-DR-8), and AEAD/nonce derivation are compile-time
  per-protocol-version constants; deletion is event-based; no
  timing-based or configurable protocol-visible behavior exists.
  The only protocol-visible variability is the suite the wire already
  declares (aead_id is pinned in classical suites).
- **Rationale:** geryon cannot know if an application is
  anonymity-sensitive, so the safe posture is the default one.
- **Validation:** cross-build vector equality (same inputs, same
  bytes).

### D-DR-12: Revision 4 post-quantum ratcheting not used (classical suites)

- **Spec point:** Revision 4 adds §5 (Sparse Post-Quantum Ratchet)
  and §6 (Triple Ratchet hybridization) as Signal's optional PQ
  ratcheting design.
- **Decision:** the classical suites provide no post-quantum ratcheting
  and do not implement §5/§6. This is recorded so the Rev 4 additions
  are not mistaken for an unimplemented TODO in the classical register.
- **Validation:** n/a (out of scope for the classical suites).

### D-DR-13: Initial secret expansion (SKdr, shared_hka, shared_nhkb)

- **Spec gap:** the HE variant's §4.4/§4.5 initialization takes SK
  plus "additional shared secrets" shared_hka and shared_nhkb from
  the key agreement and leaves their derivation to it. §7.1 shows
  the spec's own pattern for the analogous Triple Ratchet case:
  "the SK output ... should be expanded into two 32-byte keys SKec
  and SKscka using a key derivation function"; the spec expands SK
  into ALL consumers rather than using it raw for one of them.
- **Decision:** the X3DH SK (hash_len bytes, D-X3DH-7) is never
  used directly by the ratchet. kex/ expands it, immediately after
  derivation, into exactly three 32-byte outputs via three
  HKDF-Expand calls (PRK = SK, tier hash, D-GEN-3 info strings):

  ```
  SKdr        = HKDF-Expand(SK, INFO("dr.sk"),   32)
  shared_hka  = HKDF-Expand(SK, INFO("he.hka"),  32)
  shared_nhkb = HKDF-Expand(SK, INFO("he.nhkb"), 32)
  ```

  then zeroizes SK (extending the D-X3DH-13 deletion schedule).
  SKdr is the DR initialization input everywhere the DR spec says
  "SK" (Bob's initial root key = SKdr). The header-key mapping
  follows §4.5 exactly: Alice sets HKs = shared_hka and NHKr =
  shared_nhkb; Bob sets NHKr = shared_hka and NHKs = shared_nhkb
  (Bob's HKs starts None). Applies to ALL suites: protocol v1
  requires HE everywhere (D-DR-6), so the expansion is
  unconditional. All three outputs are 32 bytes in both tiers:
  header keys are AEAD keys (32 bytes in every geryon AEAD; §4
  defines 32-byte header keys), and SKdr at 32 gives the root key a
  single length from step zero in both tiers (D-DR-1's KDF_RK already
  outputs a 32-byte root key, so without this the 448 tier's RK would
  be 64 bytes at init and 32 thereafter).
- **Rationale:** three labeled expansions rather than one
  positional split follow the spec's SKec/SKscka pattern and
  D-GEN-3's rule that the info string, not position or length, is
  the load-bearing separator; raw SK never serves two roles (root
  key AND header-key PRK), so there is no cross-construction
  interaction to argue about; per-label outputs are independently
  KAT-able, and a future additional output is a new purpose, not a
  layout change. The split lands in the handshake (kex emits the
  triple, DR init consumes SKdr) so the HE mechanics attach without
  touching the handshake-to-ratchet interface.
- **Validation impact:** the init-mapping KAT reads "Bob's initial
  RK equals SKdr" (the §3.3 mapping is preserved with SKdr playing
  the spec's SK role). D-GEN-6 oracle scope is unchanged: the
  prescriptive X3DH composition is validated on SK itself; the
  expansion is implementer choice, covered by RFC 5869 vectors and
  self-KATs. Expansion KATs pin all three outputs
  from a known SK; a purpose-swap test asserts the outputs are
  pairwise distinct and label-dependent; zeroization checks cover
  SK immediately after expansion.

### D-DR-14: KDF_RK_HE output layout (single root KDF, L = 96)

- **Spec gap:** §4.5 defines KDF_RK_HE returning (root key, chain
  key, next header key) but leaves construction, output width, and
  ordering to the implementer; §7.2's HKDF recommendation covers
  only the plain KDF_RK.
- **Decision:** protocol v1 has exactly ONE root KDF, the HE
  variant: KDF_RK_HE(rk, dh) = HKDF-HASH(salt = rk, IKM = the
  DH output, info = INFO("dr.root"), L = 96), split
  new_rk = out[0..31], ck = out[32..63], nhk = out[64..95],
  matching the spec's (RK, CK, NHK) tuple order and extending
  D-DR-1's RK || CK split by appending NHK. The "dr.root" purpose
  is reused, not forked: HE is mandatory in v1 (D-DR-6), so no
  L = 64 variant coexists on any wire and there is nothing to
  domain-separate from. L = 96 is implemented from the start (the
  D-DR-13 fold-in pattern), so the root KDF has a single shape.
- **Rationale:** every degree of freedom is forced: 32-byte
  outputs by D-DR-1/D-DR-13 sizing (header keys are 32-byte AEAD
  keys), order by the spec tuple, construction by D-DR-1, purpose
  reuse by v1's single-variant reality. Positional splitting here
  (vs D-DR-13's labeled expansions) keeps the spec's own KDF_RK
  output shape: spec-shaped KDFs keep the spec's shape (D-DR-1
  precedent); labeled expansions are for geryon-invented
  derivations.
- **Validation:** RFC 5869 vectors through the L = 96 path;
  init/step KATs pin all three outputs.

### D-DR-15: HENCRYPT construction (derived key+nonce, transmitted salt)

- **Spec gap:** §4.2 requires HENCRYPT's nonce to be "either a
  stateful non-repeating value, or ... a random non-repeating value
  transmitted with the ciphertext", and leaves the AEAD and any
  associated data open. The mk pattern (D-DR-3) cannot transfer
  verbatim: hk is reused across a whole sending epoch, and the
  per-message variability (n) sits INSIDE the encrypted header, so
  a receiver cannot rebuild an n-based KDF context before
  decrypting the header.
- **Decision:** headers encrypt under the SESSION's aead_id (the same
  algorithm as message encryption; classical suites pin 0x01,
  ChaCha20-Poly1305; one AEAD choice is honored everywhere, no
  separate header knob). Per header: hdr_salt = 16 fresh random
  bytes, transmitted in the clear;

  ```
  key ‖ nonce = KDF-CTR(K_in = hk, Label = INFO("he.aead"),
                        Context = aead_id ‖ hdr_salt,
                        L = 32 + nonce_len(aead_id))
  ```

  HENCRYPT AD = the message's outer version ‖ suite_id bytes. hk
  never keys an AEAD directly. This implements the spec's
  transmitted-random-value option with the value routed through
  the PRF rather than used as the raw nonce. The stateful-counter
  option is rejected: out-of-order delivery would force trial
  decryption across a counter window per header key.
- **Rationale:** structural mirror of D-DR-3's mk derivation (one
  derivation shape for message and header keys); each header gets
  a fresh AEAD key, so batch/multi-target attacks against an
  epoch-lived header key disappear and (key, nonce) reuse requires
  a 128-bit salt collision (birthday 2^64 per epoch, vs 2^48 for a
  raw 96-bit nonce); a fixed 16-byte wire field is uniform and
  compact; binding the outer bytes as AD makes cross-version/suite
  header confusion cryptographically impossible, not just
  parse-rejected. Cost is one KDF-CTR per header operation; trials
  are bounded (D-DR-17).
- **Validation:** self-vectors only (Signal does not deploy HE;
  D-GEN-6): derivation-layout KATs; salt-tamper, AD-tamper, and
  cross-suite-AD negatives; salt-uniqueness property test across a
  simulated epoch.

### D-DR-16: DR message wire layout under HE (protocol v1)

- **Spec gap:** the spec never defines a wire format; §4.5/§4.6
  treat enc_header as an opaque unit and bind it into the payload
  AD via CONCAT(AD, enc_header).
- **Decision:** the v1 DR message is

  ```
  version ‖ suite_id ‖ hdr_salt(16) ‖ enc_header_len_be16 ‖
  enc_header ‖ payload (AEAD ct ‖ tag, to end of envelope)
  ```

  enc_header = HENCRYPT output (header ct ‖ tag). In classical
  suites the enc_header length is fixed (the 44-byte header per
  D-DR-5 plus the 16-byte AEAD tag); the length field keeps the
  frame shape uniform across suites. It is be16 for headroom: the
  header is protocol-defined material with compile-time maxima, so
  65535 is structurally unreachable; be32 was considered and
  rejected as two dead bytes on every message. D-X3DH-15's
  ciphertext_len_be32 is not a counterexample: that field frames
  the entire embedded first-DR-message, whose payload is unbounded
  application data. Receivers reject enc_header_len outside the
  suite's valid set before any derivation. The length field leaks
  nothing beyond already-observable envelope lengths (no padding,
  D-GEN-1). The payload AD is CONCAT(ad, hdr_salt ‖ enc_header_len ‖
  enc_header): the full header wire unit plays the spec's enc_header
  role in CONCAT, so header/payload cross-splicing between messages
  fails the payload tag. D-DR-5's stack-buffer property holds. The
  first-DR-message embedded in the X3DH initial message (D-X3DH-15)
  is a COMPLETE frame of this layout, own version/suite bytes
  included: two duplicated bytes buy a single DR parser and an
  identical HENCRYPT AD everywhere. HE applies from message one:
  Alice's HKs = shared_hka exists at init (D-DR-13), and Bob's first
  header decrypts via the NHKr path, triggering his first DH ratchet
  exactly per §4.6.
- **Rationale:** one frame shape for every DR message in every
  suite and every position (standalone or embedded); all fields
  before enc_header are exactly what a receiver needs to run
  D-DR-15's derivation during trial decryption.
- **Validation:** parse round-trips; truncation matrix at every
  field boundary; header/payload cross-splice negative;
  embedded-frame reuse test (same parser, same bytes).

### D-DR-17: HE receive path - trial order, skipped-key indexing, bounds

- **Spec gap:** §4.6 gives the reference receive algorithm
  (TrySkippedMessageKeysHE, then HKr, then NHKr) and stores
  MKSKIPPED under (header key, n), but leaves storage layout,
  iteration cost, and eviction to §8.4's general advice.
- **Decision:** follow §4.6's order exactly: (1) skipped-key
  trials: one header trial per DISTINCT stored hk (derive per
  D-DR-15 with the received hdr_salt, attempt HDECRYPT; on
  header.n matching a stored entry, consume that mk), (2) HKr,
  (3) NHKr, whose success triggers the DH ratchet step. The
  skipped store is re-keyed from D-DR-4's (ratchet-key PKID, n)
  to (hk, n): header keys live once per epoch in a small epoch
  table, entries hold (epoch ref, n, mk), and an epoch's hk is
  zeroized when its last entry is consumed or evicted. Everything
  else in D-DR-4/D-DR-8 carries over unchanged:
  commit-after-verify staging, MAX_SKIP-before-derivation, the
  1000-entry cap, oldest-first and aging eviction, zeroization.
  Per-message trial cost = (distinct stored hks) + 2 header
  decryptions, bounded by the entry cap and in practice by the
  number of epochs represented; NO new constant is introduced
  (the existing cap and aging are the bound). Multi-session
  routing bounds remain D-SES-6 scope.
- **Rationale:** the §4.6 algorithm is the spec's reference shape;
  deviating from its trial order would change observable behavior
  (D-DR-11). Per-epoch hk storage avoids duplicating 32 bytes per
  entry and makes "trials per distinct hk" the natural iteration.
  The (hk, n) index removes D-DR-4's PKID-collision handling: hk
  is a full 32-byte key, and header.n plus the payload tag remain
  the arbiters.
- **Validation:** out-of-order and cross-epoch delivery under HE;
  trial-count assertions via test-build counters (exactly
  distinct-hk + k trials); forged-header no-op test unchanged;
  epoch-hk zeroization on last-entry consumption, eviction, and
  teardown.

### D-DR-18: DR decrypt tag-rejection timing target framing

- **Spec gap:** the natural timing target to reach for is a "DR
  decrypt tag rejection (valid-vs-corrupt tag through the full
  staged decrypt path)" dudect target with the standard |t| < 10
  bound. Implementing it literally is unsound: commit-after-verify
  (D-DR-4) makes the ACCEPTING path do strictly more work than the
  rejecting path (the `*st = stage` commit plus store aging), so a
  valid-vs-corrupt comparison measures a class-dependent difference
  on a PUBLIC input (was the tag valid) rather than a
  secret-dependent leak, and fails the bound by correct design.
- **Decision:** the `dr_tag_reject` target compares two FORGED
  messages that differ only in the flipped tag-byte position (class
  A the first tag byte, class B the last). Both take the identical
  staged-and-rejected path, so the target isolates the only
  security-relevant property at this layer: that tag rejection does
  not leak WHICH tag byte mismatched (a padding-oracle-style leak).
  The accept-vs-reject work asymmetry is intentional and is not a
  leak (the initiator learns accept/reject from the response
  regardless), so it is deliberately excluded from the measured
  differential. libsodium's constant-time tag compare is
  additionally covered directly by the Layer 1 `aead_tag_reject`
  target; `dr_tag_reject` wraps the full staged DR path around it.
- **Rationale:** dudect flags any class-dependent timing, whether
  or not the distinguishing input is secret; framing the two
  classes as equal-work forgeries keeps the differential meaningful.
- **Validation:** the `dr_tag_reject` timing target,
  built under -DGERYON_BUILD_TIMING=ON; |t| < 10 over the standard
  sample budget. The forged decrypts leave Bob's state unmutated
  (D-DR-4), which the `forged_message_is_noop` functional test
  already asserts.

### D-DR-19: HE timing target framing

- **Spec gap:** the natural HE timing target is a receive
  trial-loop target "comparing a match at an early vs late
  trial position." Implemented literally against the D-DR-17
  loop it is unsound: the loop breaks on the epoch that decrypts the
  header (D-DR-17), so an early-match runs strictly fewer HDECRYPT
  trials than a late-match. That is a class-dependent difference on
  the matching epoch's TABLE POSITION (a function of delivery order,
  not a secret) rather than a secret-dependent leak, and it fails
  the |t| < 10 bound by correct design, exactly the D-DR-18
  accept-vs-reject pattern one layer up.
- **Decision:** two forgery-vs-forgery targets, per D-GEN-10 and by
  analogy to D-DR-18. `he_tag_reject` wraps HDECRYPT
  (`gy_he_decrypt`) on a forged `enc_header`; `he_recv_trials` wraps
  the full `gy_dr_decrypt` receive with a FIXED number of live
  stored epoch header keys, so the skipped-trial loop runs a
  constant HDECRYPT count on both classes before the forged payload
  tag rejects. The two classes differ only in which tag byte is
  flipped, so both take the identical constant-count rejected path;
  any |t| is a "which byte mismatched" leak, never an
  early-vs-late-position or accept-vs-reject asymmetry.
- **Rationale:** the constant-trial-count invariant this target
  wants to probe is a control-flow property, better asserted directly
  by the test-build op counters (`gy_dr_he_ctr`) than by
  timing; the timing targets are left to prove the per-trial
  HDECRYPT and the staged reject do not leak tag structure.
- **Validation:** the `he_tag_reject` and `he_recv_trials` timing
  targets, built under -DGERYON_BUILD_TIMING=ON; |t| < 10
  over the standard budget. The constant per-receive trial count is
  asserted by `receive_trial_counts` (tests/ratchet/test_skipped.c);
  the forged decrypts leave Bob byte-identical, asserted by
  `forged_message_is_noop` and `dr_frame_tamper_matrix`.
