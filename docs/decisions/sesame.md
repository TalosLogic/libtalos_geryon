# Sesame Decisions

**Spec:** Signal's Sesame specification, "The Sesame Algorithm",
Revision 2 (2017-04-14). See the References section of DESIGN.md for the
full citation.
**Module:** session/ (session.c, store.c).
Register conventions and the full index live in [README.md](README.md);
cross-referenced D-GEN/D-X3DH/D-DR IDs live in sibling files.

### D-SES-1: Library/application scope split

- **Spec gap:** Sesame assumes a server, per-device mailboxes, a
  UserID/DeviceID namespace, and message fetching, and puts fetching
  (§3.4), server architecture (§5.1), and server-link protection
  (§6.3) out of scope.
- **Decision:** geryon implements the device-side algorithm only:
  UserRecords/DeviceRecords/sessions, the state operations of §3.2,
  and the send/receive processing of §3.3/§3.4. UserID and DeviceID
  are opaque byte strings supplied by the application. The server
  round-trips inside the §3.3 send loop (accept/reject, stale
  UserID, old/new DeviceID lists) surface as structured API results
  the application feeds back in; the library never talks to a
  network. The §6.5 bounded-send-loop counter is application
  territory and is documented as a REQUIRED integration rule
  (suggested default: 8 iterations per recipient). Fan-out to the
  sender's own other devices is ordinary Sesame (own UserRecord,
  §3.1), nothing special-cased.
- **Rationale:** matches the store-callback architecture (the
  session layer) and keeps geryon transport-agnostic; the OPK scope
  decision (D-X3DH-10) already set this boundary.
- **Validation:** state-machine tests drive the send loop through
  scripted server responses, including the §3.3 restart path.

### D-SES-2: Per-device identity keys

- **Spec gap:** §3.1 supports per-user or per-device identity keys.
- **Decision:** per-device identity keys only. geryon provides no
  mechanism to move an identity private key between devices, and
  per-user mode is not implemented. Compromise recovery (Sesame
  §6.2, DR Rev 4 §8.2 "must replace them immediately") follows
  §3.1's replacement rule: the device is logically deleted and
  re-added with a new DeviceID and identity key pair; the library's
  part is deleting the old device's records and sessions with
  zeroization, after which correspondents see an ordinary identity
  key change (D-SES-9).
- **Rationale:** per-user keys require exporting the identity
  private key to every linked device, an operation geryon's key
  handling deliberately lacks (D-GEN-4). Per-device keys keep
  compromise blast radius to one device and match suite pinning
  being per identity.
- **Validation:** API review (no export path); multi-device tests
  use distinct identities.

### D-SES-3: SessionID

- **Spec gap:** §2.2 requires "some SessionID which uniquely
  identifies each session" and leaves its form open.
- **Decision:** SessionID is local-only (it never appears on the
  wire) and deterministic: the first 4 bytes of the suite hash over
  suite_id || IK_A || EK_A, the session's creating base key, held
  as a uint32 like a PKID (D-GEN-2). Uniqueness within a device's
  store is enforced at insertion (the base key already uniquely
  names the creating handshake per D-X3DH-3).
- **Rationale:** derivable from state both parties already hold,
  one-instruction comparison on lookup, and never security-bearing.
- **Validation:** insertion-collision test; determinism KAT.

### D-SES-4: Storage bounds

- **Spec gap:** §3.2 allows deleting inactive sessions "from the
  tail end"; §6.5 recommends limits on DeviceRecords per UserRecord
  and sessions per DeviceRecord without giving numbers.
- **Decision:** inactive sessions are capped at 40 per DeviceRecord
  (matching libsignal's archived-state bound), tail-evicted and
  zeroized; DeviceRecords are capped at 32 per UserRecord (oldest
  stale evicted first, error if all are fresh). Compile-time
  defaults; an application may lower but not raise them via store
  policy. Skipped-key bounds are D-DR-8.
- **Rationale:** bounds both storage and, once header encryption
  lands, the trial-decryption work per received message; 40 matches
  the only deployed reference point; 32 devices is far above any
  realistic multi-device deployment.
- **Validation:** eviction-order and zeroize-on-evict tests;
  trial-decryption cost test at the caps.

### D-SES-5: Activation semantics (racing convergence)

- **Spec point (adopted exactly):** §3.2 insert makes the new
  session active and pushes the previous active to the head of the
  inactive list; §3.4(4) activates the session that successfully
  decrypted if it was inactive. This is the entire convergence
  mechanism for simultaneous initiation: both sides keep decrypting
  on whichever matching session the peer used and re-activate it,
  so both converge on one session pair (§6.2 notes convergence may
  take a few messages).
- **Decision:** implemented as specified, no deviation; geryon adds
  only the zeroized eviction from D-SES-4.
- **Validation:** simultaneous-initiation property test: two
  crossing initiations converge to a single session pair within the
  spec's expected message count, no plaintext loss.

### D-SES-6: Receive path, session-not-found, and HE association

- **Spec gap/points:** §3.4(1) creates a session from an initiation
  message only when no existing session can decrypt it; §3.4(2)
  discards the message AND all state changes when nothing decrypts;
  message-to-session association under header encryption is outside
  both this spec and DR Rev 4 §4.1.
- **Decision:**
  1. Initiation detection is structural (outer version/type byte,
     D-GEN-1), and "a session that can decrypt it" is decided by
     base-key dedupe (D-X3DH-3/D-DR-7): a repeated (IK_A, EK_A)
     routes to the existing session instead of creating one. This
     realizes §3.4(1) deterministically and absorbs the D-DR-7
     initial-message re-send pattern.
  2. Session-not-found: uniform error to the application, message
     discarded, zero state mutation (transactional rule, D-SES-10).
     No error detail distinguishes "no session" from "bad tag"
     beyond what the app needs for retry policy.
  3. Under header encryption, association within the sender's
     DeviceRecord is trial decryption of the encrypted header
     (finalized 2026-07-05): the active session first, then
     inactive sessions in list order, running D-DR-17's full
     per-session procedure (skipped-epoch hks, then HKr, then
     NHKr, the §4.6 order) to completion on each session before
     moving to the next. Header keys are full-entropy 32-byte
     keys, so a header realistically decrypts under exactly one
     candidate; iteration shape is a cost choice, not a
     correctness one, and the single-loop shape keeps §4.6 intact
     per session.
  4. Bounds (finalized 2026-07-05): the existing caps ARE the
     bound; no new constant. Worst-case header trials per message
     = sum over the DeviceRecord's sessions (1 active + at most
     40 inactive, D-SES-4) of (distinct skipped epochs + 2)
     (per-session skipped bounds, D-DR-8/17); reaching that worst
     case requires the peer to have legitimately established
     those sessions and epochs.
  5. Skipped-key stores and their per-epoch hk tables are strictly
     per-session: never shared, merged, or searched across
     sessions (D-DR-4/17 scope).
  6. Rejected alternatives (2026-07-05): any cleartext key
     identifier on the wire (a PKID of hk, or a precomputable
     recognition tag KDF(hk, const)) is a constant per-epoch
     value and restores exactly the message linkability HE
     removes; a salt-bound tag KDF(hk, hdr_salt) preserves
     unlinkability but must be recomputed against every candidate
     hk per message (the salt is fresh per message), costing what
     trial decryption costs since the KDF dominates and the
     small-header AEAD open is nearly free; an identifier inside
     the encrypted header cannot route (decryption is the trial).
- **Rationale:** deterministic association where possible (dedupe),
  bounded work where not (capped trial decryption); uniform errors
  avoid a decryption oracle; no wire-side routing aid is admissible
  under HE (item 6), so bounded trials are the only shape left.
- **Validation:** session-not-found state-unchanged test; replayed
  and re-sent initiation tests; HE association cost test at caps
  with test-build trial counters asserting the exact per-session
  D-DR-17 counts and session order; review check that no wire
  field correlates across messages within an epoch beyond
  version/suite/type bytes.

### D-SES-7: Session expiration and stale-record deletion

- **Spec gap:** §4.2 (optional) defines MAXSEND/MAXRECV expiration
  with MAXRECV > MAXSEND + 2(MAXLATENCY); §3.1 recommends deleting
  stale records once older than MAXLATENCY; §6.4 warns about clock
  manipulation and suggests combining time with event checks.
- **Decision:** the library implements the mechanics (session
  timestamps, stale-marked timestamps, expiration state transitions,
  the §4.2 activation refusal) but owns no clock: time enters only
  through an application callback, and MAXLATENCY/MAXSEND/MAXRECV
  are application policy constants. The library validates
  MAXRECV > MAXSEND + 2(MAXLATENCY) at configuration and refuses
  otherwise. Expiration is off until the application supplies
  constants. Deletion always zeroizes.
- **Rationale:** same division as SPK rotation (D-X3DH-5): the
  library cannot know deployment latency, but it can make the
  transitions safe and enforce the spec's inequality; the clock
  callback keeps vectors deterministic and honors §6.4.
- **Validation:** expiration state-machine tests with a mock clock,
  including the §4.2 no-activation rule and clock-rollback cases.

### D-SES-8: No MessageRecords, retry requests, or delivery receipts

- **Spec gap:** §4.1 is optional and requires the sender to retain
  plaintext in MessageRecords; §6.2 notes an attacker who steals a
  device's keys "can probably also steal... any plaintext in
  MessageRecords".
- **Decision:** not implemented in the library. Retaining plaintext
  contradicts geryon's deletion posture (D-X3DH-13 and the
  zeroization invariant), so retry/resend is application scope. The
  library supports an application-level implementation with:
  undecryptable-message errors carrying sender identifiers, and an
  explicit re-initiate operation implementing §4.1(3d)'s
  orphaned-session escape (create and insert a fresh initiating
  session for a DeviceRecord on demand). The §4.1 resend bound and
  MessageRecord retention become the application's, and the
  documentation says so.
- **Rationale:** plaintext caching is a per-product tradeoff no
  crypto library should hardcode; the orphan-escape operation is
  the one piece only the library can provide.
- **Validation:** orphan-recovery integration test using the
  re-initiate operation.

### D-SES-9: Identity key change handling

- **Spec gap:** §6.1 says users "must repeat the authentication
  process" on key change and that a device "may wish to pause (or
  abort)" send/receive/resend, continuing only on user
  acknowledgment; the conditional update otherwise silently
  replaces records (§3.2).
- **Decision:** fail closed by default: a conditional update that
  would replace an existing identity public key does not proceed
  silently; it returns a distinct key-changed result carrying old
  and new fingerprints (D-X3DH-11), and the operation resumes only
  when the application explicitly accepts the new key (which then
  performs the §3.2 replacement). Trust-on-first-use for unknown
  keys is unchanged. The application chooses whether acceptance is
  automatic or user-confirmed.
- **Rationale:** the spec's own warning; silent replacement would
  let a malicious server rotate identities under an established
  relationship without any surfaced signal.
- **Validation:** key-change tests on all three paths (send,
  receive, re-initiate); no state mutation before acceptance.

### D-SES-10: Transactional state updates

- **Spec point (adopted and strengthened):** §3.3 discards all
  changes to a UserRecord on any send error; §3.4 discards all
  state changes on any receive error; §6.7 generalizes: any error
  terminates the process and discards changes that would leave the
  device inconsistent.
- **Decision:** every Sesame operation stages record and session
  mutations in memory and commits through the store callbacks only
  at the single success point; any failure zeroizes staged key
  material and leaves the store untouched. This is the record-level
  extension of commit-after-verify (D-DR-4), and it shapes the
  store API: callbacks receive complete post-operation records, not
  incremental mutations.
- **Rationale:** §6.7's consistency requirement, made structural
  instead of disciplinary; also makes power-loss behavior
  well-defined for free.
- **Validation:** fault-injection tests failing every operation at
  every step and asserting store equality with the pre-operation
  snapshot.

### D-SES-11: Session records are separately-keyed store blobs

- **Context (2026-08-06):** a persisted session embeds a
  full Double Ratchet state, which is dominated by the fixed
  GY_MAX_SKIP (D-DR-8) skipped-key and epoch tables (~88 KB in
  memory). Nesting 1 active + 40 inactive sessions (D-SES-4) inline
  in a DeviceRecord would make one DeviceRecord ~3.6 MB and force
  the whole record to be rewritten on every ratchet step, defeating
  practical close-and-resume persistence.
- **Decision:** the store has three opaque blob types, not two:
  UserRecord (keyed by UserID), DeviceRecord (keyed by DeviceID),
  and SessionRecord (keyed by SessionID, D-SES-3). A DeviceRecord
  holds its device identity plus an ORDERED list of SessionIDs
  (active marked first, then inactive in list order) and does NOT
  embed the sessions; each session (metadata + DR state) is its own
  blob loaded and stored independently. A UserRecord holds an
  ordered list of DeviceIDs, not embedded DeviceRecords. Encryption
  at rest of any blob is the application's (D-GEN-4), unchanged by
  this split.
- **Rationale:** per-session write granularity (a ratchet step
  rewrites one small session blob, not a multi-megabyte device
  blob); lean in-memory records so the D-SES-10 staging arena stays
  bounded without holding every session of every device; the
  store's SessionID key space directly enforces the D-SES-3
  insertion-uniqueness check; and durable suspend/resume falls out
  because every blob is a complete post-operation record (D-SES-10).
  The cost is one additional store-callback family (session
  load/store/delete by SessionID) and that the receive-path HE
  association (D-SES-6.3) loads a candidate device's session blobs
  in list order (bounded at 1 + 40).
- **Validation:** blob round-trip for all three record types
  including full-capacity records; SessionID-keyed insertion
  collision; DeviceRecord SessionID-list ordering after
  insert/activate/evict; the D-SES-6 association test loads session
  blobs in the asserted order.

### D-SES-12: DeviceRecords are keyed per (UserID, DeviceID)

- **Spec gap:** Sesame nests DeviceRecords inside a UserRecord (a
  device belongs to a user); DeviceIDs are namespaced per user, not
  global (mirroring Signal, where device numbers 1, 2, 3 repeat
  across accounts). D-SES-11 recorded the store split as "DeviceRecord
  keyed by DeviceID" and D-SES-1 declared UserID/DeviceID opaque
  application byte strings with no format constraint. Nothing forces
  DeviceIDs to be globally unique, yet the store keyed a DeviceRecord
  by its DeviceID alone.
- **Problem surfaced (example application):** two peers that happen to
  supply the same DeviceID byte string collide into ONE DeviceRecord (the record
  carries no owning UserID). The second write clobbers the first's
  identity key and SessionID list: silent cross-user record
  corruption and mis-delivery, not a clean error. The fan-out
  self-exclusion had the same root: it dropped any peer device whose
  DeviceID equalled the sender's own self_device_id, regardless of
  user. The example, which reused "device-1" for both
  clients, never reached the GY_FANOUT_MESSAGE steady-state path at
  all (every send fell through to re-initiate).
- **Decision:** a DeviceRecord's identity is the PAIR (UserID,
  DeviceID), matching the public API, which addresses every peer
  device as a (user_id, device_id) pair. The change is at the STORE
  KEY only: the DeviceRecord blob body is unchanged (it does not gain
  a UserID field), and the key is derived at each call site from the
  (user_id, device_id) that site already holds (gy_devrec_key), then
  passed to load/put/delete. The key is a fixed 64-byte,
  domain-separated hash of the length-prefixed pair:
  SHA-512("geryon-devrec-key" || be32(user_id_len) || user_id ||
  be32(device_id_len) || device_id), GY_DEVKEY_LEN = 64. SHA-512 is
  used UNCONDITIONALLY and suite-INDEPENDENTLY (gy_devrec_key takes no
  suite_id/desc and calls gy_sha512 directly, consistent with the
  gy_suite_desc() core-calls already made from the session layer): the
  derivation does not vary by suite, so a uniform 64-byte key needs one
  hash, and the 25519 tier's SHA-256 could not fill 64 bytes anyway.
  One hash, one size, no per-suite branch, and no suite_id threading
  into the internal helpers. The 64-byte key sits exactly at the
  <= GY_USER_ID_MAX (64) envelope existing UserRecord keys already
  require, so no store-callback contract change. Security margin is
  not the driver: this is a non-secret lookup key whose only relevant
  property is collision resistance (a collision is a functional bug,
  not a break), already far beyond any need at SHA-256's 128 bits -
  uniformity is the reason for the wider hash, not a Grover argument
  (Grover halves PREIMAGE, not collision resistance). be32 length
  prefixes match the codebase's canonical integer encoding and
  disambiguate the variable-length pair (SessionID needs no such
  prefix only because its EC-key inputs are fixed-width). The fan-out
  self-exclusion (gy_send_ctx) compares the full (self UserID, self
  DeviceID) pair; gy_send_ctx gains a self_user_id. This scopes ONLY
  the device-key derivation; a system-wide move to SHA-512 for
  classical suites is a separate, larger decision (the suite table
  picks SHA-256 for the 25519 tier deliberately, for output size). SessionRecords are
  UNCHANGED: SessionID is derived from the base keys (D-SES-3 /
  D-SES-6.1) and is already globally unique, so sessions never
  collided. The fan-out self-exclusion (gy_send_ctx) compares the
  full (self UserID, self DeviceID) pair; gy_send_ctx gains a
  self_user_id. DeviceIDs are therefore unique only per UserID; the
  application carries NO global-uniqueness burden. This refines
  D-SES-11 ("keyed by DeviceID" -> "keyed by the (UserID, DeviceID)
  hash") and D-SES-1 (the opaque IDs are per-user-namespaced).
- **Rationale:** the alternative (declare DeviceIDs globally unique
  and document it) contradicts the (user_id, device_id) addressing the
  whole API is built on, is unenforceable at the call boundary, and
  fails as silent wrong-crypto rather than a rejected call. Per-user
  namespacing is the Sesame/Signal model and makes the collision class
  impossible by construction. Landed before the v1.0.0 tag so the
  changed DeviceRecord store-key derivation and blob layout are locked
  by the freeze in their corrected form (no released data to migrate).
- **Validation:** two distinct users sharing one DeviceID byte string
  keep independent DeviceRecords, sessions, and identity keys with no
  cross-talk; a purge of (userA, dev) leaves (userB, dev) intact;
  the fan-out to a peer whose DeviceID equals the sender's own
  self_device_id (but a different UserID) yields GY_FANOUT_MESSAGE,
  not an empty descriptor; DeviceRecord blob round-trip with the
  UserID field at full capacity; and the example gives its
  two clients distinct DeviceIDs and asserts the steady-state
  GY_FANOUT_MESSAGE path.
