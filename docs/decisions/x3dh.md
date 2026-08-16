# X3DH Decisions

**Spec:** Signal's X3DH specification, "The X3DH Key Agreement Protocol",
Revision 1 (2016-11-04). See the References section of DESIGN.md for the
full citation.
**Module:** kex/ (x3dh.c, prekeys.c).
Register conventions and the full index live in [README.md](README.md);
cross-referenced D-GEN/D-DR/D-SES IDs live in sibling files.

### D-X3DH-1: EncodeEC

- **Spec gap:** X3DH §2.1 requires an encoding function but only
  recommends "a single-byte constant + little-endian u-coordinate";
  the byte values are implementer-defined.
- **Decision:** a single curve_type byte whose value is the curve key
  length (0x20 = X25519, 0x38 = X448) followed by raw key bytes.
- **Rationale:** length-valued type bytes are self-documenting and
  give pairwise-disjoint encodings across curves for free (the spec's
  disjointness requirement).
- **Validation:** encode/decode round-trip and cross-curve rejection
  tests.

### D-X3DH-2: Info parameter

- **Decision and rationale:** see D-GEN-3.

### D-X3DH-3: Replay mitigation for OPK-less initial messages

- **Spec gap:** X3DH §4.2 describes the replay risk and explicitly
  leaves mitigation ("blacklist of observed messages, or replacing
  old signed prekeys more rapidly") to the implementer.
- **Decision:** base-key dedupe, REQUIRED: session records store the
  initiator ephemeral key; a repeated (IK_A, EK_A) routes to the
  existing session where forward-secrecy key deletion makes the
  replayed message undecryptable. Bounded overall by SPK private-key
  retention. No separate replay cache.
- **Rationale:** dedupe on IK alone would break Sesame re-initiation
  (state loss, racing, new devices); the base key is exactly the
  freshness witness. Reuses state the session layer already needs.
- **Validation:** replay negative tests; fresh-EK re-initiation
  accepted while sessions exist.

### D-X3DH-4: Signed prekey signed bytes

- **Spec gap:** X3DH signs Encode(SPK) only; timestamps and policy
  metadata are not covered by the spec's signature.
- **Decision:** signed_data = encoded_public_key || timestamp_be64
  (no flags field is defined for classical suites yet; if one becomes
  necessary it uses the same layout). The ENCODED public key is signed
  (33 bytes for X25519: the D-X3DH-1 curve_type byte plus the raw key),
  never the bare key bytes.
- **Timestamp semantics:** unsigned 64-bit seconds since the Unix
  epoch, UTC, set by the key owner at SPK creation, big-endian both in
  the signed bytes and on the wire. The library never calls time(); the
  timestamp comes through the application clock callback (the same clock
  as D-SES-7). The timestamp is informational: age/skew enforcement is
  application policy (D-X3DH-5). What the signature buys is that a
  malicious server cannot make old prekeys look fresh or fresh ones
  look old; whether staleness is rejected stays a policy knob.
- **Rationale:** an unsigned timestamp lets a malicious server serve
  stale prekeys as fresh; unsigned policy bounds would let it widen
  them. Signing metadata closes both.
- **Validation:** signature-over-metadata tampering tests.

### D-X3DH-5: Prekey rotation and retention

- **Spec gap:** X3DH suggests rotation "e.g. once a week or once a
  month" and leaves retention of old private keys open.
- **Decision:** rotation cadence and the deletion grace period are
  application policy, exposed through the store callbacks; the library
  enforces deletion mechanics (zeroization) and refuses initial
  messages referencing SPKs whose private keys are gone. OPK
  replenishment is application-driven; the library provides batch
  generation. The per-batch cap is a configurable limit with a
  default of 100; it is an operational bound (server load, upload
  size), not security-bearing, and applications may tune it. Decided
  2026-07-04; may be revisited.
- **Rationale:** the library cannot know deployment message-latency
  distributions; it can only make deletion safe and timely once
  policy fires. Matches the standard client/library division of labor.
- **Validation:** expiry negative tests (initial message against a
  deleted SPK aborts cleanly).

### D-X3DH-6: Associated data contents

- **Spec gap:** X3DH §3.3 defines AD = Encode(IK_A) || Encode(IK_B)
  and permits appending additional identifying information.
- **Decision:** AD is exactly the spec form, Encode(IK_A) ||
  Encode(IK_B), with no appended information.
- **Rationale:** full identity-key binding with no extension surface;
  identity misbinding is countered by fingerprint verification
  (D-X3DH-11).
- **Validation:** AD-mismatch decryption failures.

### D-X3DH-7: Parameter instantiation and the F prefix

- **Spec point (registered against drift):** §2.1 makes curve, hash,
  and info application decisions; §2.2 fixes the KDF input as
  KM prefixed by F (32 bytes 0xFF for X25519, 57 bytes 0xFF for
  X448) for domain separation against XEdDSA.
- **Decision:** curve and hash come from the suite table (SHA-256 in
  the 25519 tier, SHA-512 in the 448 tier); info per D-GEN-3. The
  F prefix is kept in every suite, sized by the curve: HKDF IKM =
  F || DH1..DHn.
- **HKDF realization:** libsodium's incremental HKDF API
  (crypto_kdf_hkdf_sha256 / _sha512: extract_init / extract_update /
  extract_final + expand; requires libsodium >= 1.0.19, and the
  third_party/ submodule is pinned at 1.0.22). The multi-input
  extract feeds F and each DH output without a concatenation
  buffer. Salt is an explicit zeros(hash_len) buffer. geryon uses the
  library HKDF directly rather than hand-rolling HKDF over HMAC
  (library-first: no reimplemented primitive where the library
  provides one).
- **Rationale:** F exists so no XEdDSA hash input can collide with a
  KDF input; F is invariant across suites.
- **Validation:** KATs include F; a vector with F omitted must fail
  to match (guards against a wrapper silently dropping it); RFC 5869
  vectors through the libsodium wrapper.

### D-X3DH-8: DH output validation (contributory behavior)

- **Spec gap:** the spec says DH() is "the X25519 or X448 function
  from RFC 7748"; RFC 7748 makes rejecting the all-zero shared
  secret optional ("MAY check").
- **Decision:** every DH in geryon rejects an all-zero output: all
  X3DH DH computations and every DR ratchet DH. libsodium
  (crypto_scalarmult returns -1) and libdecaf (DECAF_FAILURE)
  already enforce this; geryon propagates the error as a handshake
  or ratchet-step abort, never a fallback.
- **Rationale:** unconditional rejection of small-order/identity
  contributions costs one check and removes an entire class of
  contributory-behavior games; matches the constant-time rule's
  spirit of not depending on peer honesty.
- **Cross-check (DR Rev 4):** the DR spec's §3.1 explicitly permits a
  DH function that "rejects invalid public keys" and terminates
  processing, even though its §7.2 says checking is not needed;
  geryon's rejection is therefore spec-sanctioned behavior in the
  ratchet too, not a divergence.
- **Validation:** negative tests feeding the known small-order
  X25519/X448 public keys at every DH position.

### D-X3DH-9: Use of SK and the initial ciphertext

- **Spec gap:** §3.3 allows the initial ciphertext key to be "either
  SK or the output from some cryptographic PRF keyed by SK"; §4.3
  requires the post-X3DH protocol to randomize Bob's sending key.
- **Decision:** SK is never used directly as an encryption key. SK
  is exclusively the Double Ratchet seed (root key input at DR
  init), and the initial ciphertext IS the first DR message,
  carrying a fresh ratchet key. There is no pre-DR encryption mode.
- **Rationale:** one code path; DR's first responder step satisfies
  §4.3's MUST-randomize automatically; SK exposure surface is one
  KDF call.
- **Confirmed by DR Rev 4:** §3.3/§7.1 specify exactly this wiring:
  SK is the DR initialization input (Bob's initial root key IS SK),
  the X3DH AD is the ratchet AD, and the initial ciphertext is the
  first ratchet message. The full mapping, including SPK_B as Bob's
  initial ratchet key and the initial-message re-send pattern, is
  registered as D-DR-7.
- **Validation:** protocol KATs derive the first message key through
  the full DR init; no API exists to encrypt under raw SK (absence
  checked at review).

### D-X3DH-10: One-time prekey lifecycle and batching

- **Spec gap:** §3.2 leaves upload cadence open; §3.3 has the server
  hand out and delete OPKs; §3.4 has Bob delete the private key
  after successful decryption; §4.7 raises drain/rate-limit concerns
  and leaves them to the server.
- **Decision:** geryon is client-side only. The library generates
  OPK batches (configurable cap, default 100, D-X3DH-5) with PKIDs;
  upload scheduling, server handout, server-side deletion, and rate
  limiting are application/server scope. Batch generation enforces
  store-local PKID uniqueness (regenerate on collision) because the
  initial message references OPKs by PKID alone (see D-GEN-2). An
  initial message referencing an unknown or already-consumed PKID
  aborts with the same error as any other handshake failure. The OPK
  private key is deleted only AFTER the initial ciphertext decrypts
  successfully (spec §3.4 ordering, consistent with
  commit-after-verify, D-DR-4); a garbage message referencing an
  OPK does not burn it.
- **Rationale:** deletion-on-success means an attacker cannot spend
  a victim's OPKs with junk traffic; uniform abort errors avoid
  giving a sender an oracle for which prekeys exist.
- **Validation:** consumed-OPK replay test; junk-message
  OPK-retention test; batch-uniqueness test.

### D-X3DH-11: Identity fingerprints

- **Spec gap:** §4.1 puts fingerprint comparison "outside the scope
  of this document"; §4.8 suggests hashing more identifying
  information into the fingerprint.
- **Decision:** the library exposes a fingerprint function: the
  suite hash over the encoded identity public key. Display encoding,
  comparison channel, and UX are application scope.
- **Rationale:** a stable, independently-recomputable identifier over
  the full encoded identity key; hashing the whole encoded identity
  (rather than a sub-field) closes component-swap misbinding for free.
- **Validation:** fingerprint-mismatch test when the identity key
  differs.

### D-X3DH-12: No AD extension point in v1

- **Spec gap:** §3.3 permits appending "additional information" to
  AD (usernames, certificates); §4.8 discusses the identity-binding
  trade-offs and leaves them open.
- **Decision:** no application-supplied AD extension in protocol v1.
  AD is exactly the spec form. Adding an extension point later is a
  versioned wire change (D-GEN-1), not a runtime option.
- **Rationale:** keeps AD exactly the spec form (D-GEN-6 rules out
  chasing byte-for-byte compatibility with other implementations
  anyway); identity misbinding is countered by fingerprint
  verification (D-X3DH-11); an open-ended AD hook invites
  application-dependent interop failures.
- **Validation:** AD-form KATs; AD-mismatch decryption failures
  (D-X3DH-6) cover tampering.

### D-X3DH-13: Deletion points (recorded conformance)

- **Spec point (registered because ordering is easy to get wrong):**
  §3.3/§3.4 fix the deletion schedule: Alice deletes her ephemeral
  private key and DH outputs after computing SK; Bob deletes DH
  outputs after computing SK, deletes SK on decryption failure, and
  deletes the used OPK private key on success.
- **Decision:** followed exactly, via secure_zero. Deletion is
  protocol behavior, not cleanup (a geryon invariant).
- **Validation:** zeroization checks at each deletion point,
  including the failure paths.

### D-X3DH-14: Bundle validation ordering (validate before use)

- **Spec gap:** §3.3 says only "Alice verifies the prekey signature
  and aborts the protocol if verification fails"; it does not order
  validation against key use or say what else to check.
- **Decision:** the complete bundle is validated before ANY
  private-key operation (no DH, no state allocation until the bundle
  passes). Checks, in order: every present key's curve_type matches
  the identity's pinned suite (cross-suite abort, D-GEN-1); every
  present key's PKID is non-zero and matches recomputation (D-GEN-2);
  the SPK signature verifies over the full signed_data (D-X3DH-4);
  OPK checks only if present (zero sentinel). The suite-consistency
  check is geryon's addition to the standard validate-before-use
  ordering.
- **Rationale:** the handshake-side analog of commit-after-verify
  (D-DR-4): a bad bundle costs zero secret-key operations and
  leaves zero state; PKID recomputation before signature checking
  also means the signature is only ever checked over
  self-consistent input.
- **Validation:** bundle-tampering matrix (each field mutated
  individually must abort before any DH is attempted; asserted via
  operation counters in the test build).

### D-X3DH-15: Initial message layout

- **Spec gap:** §3.3 lists the initial message's contents
  (identity key, ephemeral key, prekey identifiers, ciphertext) but
  no layout; the wire format is entirely implementer-defined.
- **Decision:** the initial message layout is:
  version || suite_id || ik (pkid || curve_type || curve_pk) ||
  ek (pkid || curve_type || curve_pk) || ik_id || spk_id ||
  opk_id || ciphertext_len_be32 || first-DR-message. ik_id, spk_id,
  opk_id are BOB's key PKIDs: the identity Alice encrypted to, the
  SPK used, and the OPK used (zeros if none, D-GEN-2 sentinel).
  PKIDs embedded in fully-carried keys (ik, ek) are never trusted:
  the receiver recomputes and aborts on mismatch. The receiver also
  checks ik_id against its own identity PKID and aborts on mismatch
  (a stale reference after identity replacement fails fast instead
  of failing in DH2).
- **Rationale:** one layout shape across suites keeps the parser
  generic (the suite-descriptor discipline, D-GEN-7); Bob-side PKIDs are
  how the receiver selects private keys (D-GEN-2); carrying pkid
  inside full keys costs 8 bytes but keeps the key structure
  identical everywhere it appears (bundle, message, store), which
  generic key-structure accessors made worth it.
- **Validation:** parse round-trip; embedded-PKID tamper test
  (mismatch aborts); wrong-ik_id abort test; no oracle comparison
  of the wire format (implementer-defined, D-GEN-6).
