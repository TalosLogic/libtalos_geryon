# geryon system design

This is the durable, whole-system design overview. It is deliberately terse and
points at the authoritative documents rather than restating them:

- `docs/CUSTODY_SPEC.md` - design for the key-custody layer (the `gy_custodian`
  public API as of v1.0.0; decisions in D-CUST-1).
- `docs/decisions/` - the per-module implementer decision register (D-GEN,
  D-XED, D-X3DH, D-DR, D-SES, D-CUST, and D-GRP for the group vertical); every
  "D-*" tag below resolves there.
- `CHANGELOG.md` - broad strokes per release.

## What geryon is

A clean-room C17 implementation of the Signal protocol (X3DH, Double Ratchet,
Sesame, XEdDSA), in classical suites and post-quantum-hybrid suites. In the
hybrid suites every classical asymmetric operation gets an ML-KEM/ML-DSA
counterpart, so session security holds if EITHER the ECDH or the KEM assumption
survives, while offline deniability is preserved (no transcript signatures).
The hybrid construction is geryon's own, not Signal's PQXDH, and is specified
normatively in [HYBRID_SPEC.md](HYBRID_SPEC.md). Protocol code is clean-room
from specifications; primitives come from permissively-licensed libraries by
preference. The core public API is the installed header `include/geryon.h`; two
opt-in private-group verticals (classical and quantum-safe) each add two further
public headers (see Private groups and Quantum-safe private groups, below).

## Cipher suites

One suite is pinned per identity and never negotiated at runtime; it is bound
into every KDF info string, so a message under one suite cannot complete a
handshake under another (this kills downgrade attacks - there is no fallback
path in code). Curve, signature scheme, hash, and KEM strength move together.

| Suite | ID | KEX | Signatures | Hash |
|-------|----|-----|------------|------|
| `geryon_c25519` | 0x01 | X25519 | XEdDSA | SHA-256 |
| `geryon_h25519_512` | 0x02 | X25519 + ML-KEM-512 | XEdDSA + ML-DSA-44 | SHA-256 |
| `geryon_c448` | 0x03 | X448 | XEd448 | SHA-512 |
| `geryon_h448_1024` | 0x04 | X448 + ML-KEM-1024 | XEd448 + ML-DSA-87 | SHA-512 |

The classical suite `geryon_c25519` provides no post-quantum confidentiality
(the installed header says so plainly); it exists for size/bandwidth-constrained
deployments. The hybrid suite `geryon_h25519_512` fuses an ML-KEM-512 secret
into each X3DH DH and each Double Ratchet root-key step (PQ-first,
`HASH(kem_ss || dh_out)`), dual-signs prekeys with XEdDSA and ML-DSA, and adds
deniable KEM-based initiator authentication (the `gy_pq_pending` state). A
classical identity never completes a hybrid handshake or vice versa; the
handshake, ratchet, and custody paths are suite-agnostic and dispatch on the
suite byte the wire objects carry. The `geryon_c448` and `geryon_h448_1024`
suites mirror the 25519 pair at the 448 tier (ML-KEM-1024 + ML-DSA-87, SHA-512,
CNSA 2.0-aligned). Suite byte 0x00 and any unassigned byte are rejected before
any cryptographic processing. HYBRID_SPEC.md governs all hybrid behavior.

## Strict layering

Each layer calls only the layer below it; violations are build bugs, enforced at
review and by `scripts/layer_audit.sh` (include-direction check, a `nm`-based
proof that Layer 5 references no ratchet/core symbol, and a `geryon.h`
standalone C++ compile). The allowlist is empty.

- **Layer 1 `core/`** - primitives: thin wrappers over libsodium (X25519,
  Ed25519, SHA-2, HKDF/HMAC, AEAD, RNG), liboqs (ML-KEM-512/1024 and
  ML-DSA-44/87 for the hybrid suites), and monocypher (the XEdDSA verify map),
  plus in-house
  crypto only where no acceptable library exists (the XEdDSA composition, and
  XEd448 over libdecaf for the 448 tier) held to the constant-time + clean-room
  bar.
- **Layer 2 `kex/`** - X3DH and prekey generation/signing; the hybrid variant
  encapsulates an ML-KEM secret per DH and dual-signs prekeys (XEdDSA + ML-DSA).
- **Layer 3 `ratchet/`** - the Double Ratchet, header encryption (D-DR-16 wire
  frame), and the bounded skipped-key store (D-DR-8/17); the hybrid variant
  mixes a fresh ML-KEM secret into each root-key step and carries the deniable
  KEM-confirmation state machine.
- **Layer 4 `session/`** - Sesame: the record model, the staging engine, the
  lifecycle state machine, and the send/receive paths (below).
- **Layer 5 `proto/`** - the typed wire envelope, the prekey-bundle format, and
  the `include/geryon.h` public API. proto/ does no cryptography and holds no
  key material; it moves bytes between the session API and the wire.

The Layer 4/5 boundary is the abstraction seam: proto/ never touches ratchet or
key material directly (it reaches the few primitives it needs - suite lookup,
key generation, fingerprint, secure-zero - through session-layer facades).

## Session model (Sesame)

### Records (D-SES-11)

Three separately-keyed opaque store blobs, so a ratchet step rewrites one small
session blob rather than a multi-megabyte device blob:

- **SessionRecord** (keyed by a 4-byte local SessionID, D-SES-3) - the Double
  Ratchet state plus session metadata and the fixed X3DH associated data.
- **DeviceRecord** (keyed per (UserID, DeviceID), D-SES-12) - the peer device
  identity and an ORDERED list of its SessionIDs (active first, then inactive),
  not the sessions.
- **UserRecord** (keyed by UserID) - an ordered DeviceID index.

Identity keys are per-device (D-SES-2). Storage is bounded (D-SES-4: 40 inactive
sessions/device, 32 devices/user) with zeroizing eviction. The application owns
storage and at-rest protection (D-GEN-4); the library caches no records.

### Transactional staging (D-SES-10)

Every operation stages record and session mutations in memory and commits them
through the store callbacks at a single success point; any failure zeroizes the
stage and leaves the store untouched. Commit order is pinned - all record STOREs
first, then deferred deletions and OPK consumptions - so a crash between phases
replays safely (an unconsumed OPK is caught by base-key dedupe; an undeleted
record is harmless). The staging engine adds read-your-writes so lifecycle
operations compose within one uncommitted transaction. A debug-build re-entrancy
guard (D-GEN-8) trips if a callback re-enters the engine.

### Send path

A message fans out to one INDEPENDENT ciphertext per recipient device (each
device has its own session; nothing is shared). The API is therefore
per-session: `gy_prepare` enumerates the fan-out (message / needs-bundle / stale
per device), `gy_encrypt` runs one device's ratchet step, `gy_initiate` starts a
session from a fetched bundle and emits the initial message (X3DH prefix with the
complete first DR frame, D-X3DH-15). The whole fan-out stages until the
application confirms server accept, then commits (or rolls back). Output buffers
use the OpenSSL size-query convention. The Sesame bounded send-retry loop is
a REQUIRED application responsibility.

### Receive path (D-SES-6)

The security-critical operation. An initiation message is deduped by base key
(D-SES-6.1) before any handshake, so a re-send routes to the existing session
instead of forking one; a fresh base key runs X3DH respond, creates the session,
and decrypts the embedded first frame, deferring OPK consumption until that frame
verifies (D-X3DH-10). A Double Ratchet message is associated by trial-decrypting
the encrypted header against the sender DeviceRecord's sessions in list order
(active first, then inactive), each running the full D-DR-17 procedure; the first
session whose header opens owns the message, and a payload failure there is a
hard error, never a continue-to-next-session (which would be a padding-oracle
shaped search). Under header encryption the wire carries no routing aid
(D-SES-6.6). Every mutation stages and reaches the store only on a verified
payload; any rejection aborts to a single uniform error (D-SES-6.2), so no
decryption oracle is exposed. A peer identity-key change surfaces distinctly as
`GY_ERR_KEY_CHANGED` with fingerprints, fail-closed until explicit accept
(D-SES-9).

## Security invariants (summary)

Load-bearing points: suite binding into the KDF; no transcript signatures ever
(offline deniability, in the hybrid suites as much as the classical ones - PQ
authentication is KEM-based, never a signature over the transcript); message
keys deleted immediately after use and skipped-key storage bounded by MAX_SKIP;
zeroization treated as part of the protocol, not cleanup; constant-time
discipline unconditional, software fallbacks included. In the hybrid suites no
KEM secret is ever optional (handshake or ratchet) and hybrid signature
verification requires both XEdDSA and ML-DSA to pass.

## Private groups (opt-in vertical)

A classical private group system (the [CPZ] design; normative in
[GROUP_SPEC.md](GROUP_SPEC.md), decisions in D-GRP), added in v1.4.0 as a
separate set of libraries (all `EXCLUDE_FROM_ALL`, so a deployment that does not
use groups links none of it), layered like the messaging library over `core/`
and the vendored `libtalos_schnorr` proof engine.

- **Two roles, split at link time (D-GRP-1/2).** The CLIENT
  (`include/geryon_group.h`) extends a custodian: group secret state seals into
  the custodian's store and nothing derived is cached (D-GRP-7). The SERVER
  (`include/geryon_group_server.h`) is a separate, stateless target holding only
  the service keys; it issues and verifies credentials and never touches the
  messaging custodian. A `nm` scope audit proves the client archive carries no
  ServerSecretParams-consuming (issuance) symbol.
- **Anonymous credentials.** Membership is proven with keyed-verification
  credentials: an algebraic MAC over hidden attributes (UID, ProfileKey) plus
  Schnorr conjunction NIZKs, with verifiable ElGamal-style encryption of the UID
  and ProfileKey so the server learns neither. Deniable (the proofs are NIZKs,
  not transferable signatures). Classical only: the guarantees rest on
  discrete-log, so no PQ confidentiality or anonymity (D-GRP-11); the
  quantum-safe group system (QSPGS, below) is a distinct type that ships side by
  side, not a retrofit of this one.
- **No group ratchet.** Group messages fan out over the 1:1 sessions above; the
  GroupMasterKey reaches a new member inside a 1:1 session (a
  `GROUP_KEY_DISTRIBUTION` envelope, D-GRP-6). GroupSecretParams are rederived
  from the GroupMasterKey on demand and zeroized after use.
- **Group format version (D-GRP-12).** Each group is created at an immutable
  capability epoch, a 2-byte value bound into the GroupID, so an existing group's
  feature set cannot change under the clients in it, and a client that lacks a
  newer version declines to join rather than mishandle it.

## Quantum-safe private groups (opt-in vertical)

A quantum-safe private group system (QSPGS; normative in
[QSPGS_SPEC.md](QSPGS_SPEC.md)), added in v1.5.0 as a second group vertical
alongside the classical one. It is a separate set of libraries (all
`EXCLUDE_FROM_ALL`), layered like the messaging library over `core/`, and shares
no code with the classical group type; a deployment uses either, both, or
neither. Group authentication is post-quantum throughout.

- **Two roles, split at link time.** The CLIENT (`include/geryon_qspgs.h`)
  extends a custodian: all group secret state (the group key, per-epoch user
  keys, the member's rerandomizable signing key) seals into the custodian's store
  and nothing derived is cached. The SERVER
  (`include/geryon_qsgroups_server.h`) is a separate, stateless target holding
  only the service keys; it verifies cores, appendix lines, and bearer tokens and
  never touches the messaging custodian. An `nm` scope audit proves the client
  archive carries no server-side check symbol.
- **Unlinkable membership via rerandomizable ML-DSA (KR-ML-DSA).** Each member
  presents under a per-version rerandomized ML-DSA verification key derived from
  its base key, so the server and other members cannot link a member's actions
  across group versions or to its long-term identity. The identity key certifies
  the member's base verification key and its per-epoch user key, binding
  membership to the custodied identity with no transcript signature (deniability
  of membership is the one documented regression, since these two registration
  objects are identity-signed).
- **Versioned symmetric state with an appendix log.** The member list is
  AEAD-encrypted under a rotatable group key. A group advances through
  admin-signed cores (the authoritative snapshot) and member-appended lines
  (joins, leaves, key refreshes, attribute changes) that an admin later folds
  into a new core. Harvested group state exposes nothing to a later quantum
  adversary. Rotating edits stage the new group key and commit only on server
  acceptance, so a rejected write never strands the admin.
- **Immutable per-group epoch and field AEAD.** Each group is created at an
  immutable format epoch and field-AEAD choice (ChaCha20-Poly1305 default or
  AEGIS-256), both bound into the signed header, so there is no downgrade path
  and an existing group never changes shape under the clients in it. Member UIDs
  are a fixed 16 bytes, so a corrupt server learns no per-entry length class.

## Public API

`include/geryon.h` is the core installed header (the opt-in classical group
vertical adds `geryon_group.h` / `geryon_group_server.h`, and the quantum-safe
group vertical adds `geryon_qspgs.h` / `geryon_qsgroups_server.h`); every
exported symbol starts
`gy_`. A `gy_custodian` is the public entry object (D-CUST-1; design in
docs/CUSTODY_SPEC.md): `gy_custodian_create` mints it from a suite id, the
store callback table, an unlock credential, this device's ids, an optional
clock callback, and optional expiration config, and `gy_custodian_open`
reopens it from the store and the credential alone. The `gy_custodian` object
itself - not just its KEK - is allocated in guarded
(`sodium_malloc`/`mlock`'d) memory (CUSTODY_SPEC section 15): it embeds the
unlocked identity, signed-prekey, one-time-prekey, and application-signing-key
(SAK) private material directly, so the whole object, not a sub-field, carries
the guarantee. It never returns cleartext private key bytes across the API;
every other protocol call (`gy_encrypt`/`gy_receive`/`gy_initiate`/...) takes
the custodian in place of the former `gy_ctx`. It is not thread-safe or
re-entrant (D-GEN-8): one custodian per thread, no re-entry from store
callbacks. ABI FROZEN as of v1.0.0 (D-GEN-9, the key-custody release): the
public struct layouts, the wire format (protocol_version 0x01), and
stored-blob formats are stable, and later suites arrive additively as minor
bumps.

## Licensing boundaries

geryon's code is AGPL-3.0-only. Everything linked into the library or vendored
must be permissively licensed so the combined work is redistributable under the
AGPL; copyleft/source-available code (libsignal) is confined to test-vector
oracle tooling that is never linked, copied, or translated. Runtime dependencies:
libsodium (ISC), liboqs (MIT, the ML-KEM/ML-DSA provider for the hybrid suites),
libdecaf (MIT, the X448 and 448 field/scalar/point provider for the 448-tier
suites), and monocypher (BSD-2/CC0).

## References

The Signal protocol specifications (the normative basis for the clean-room
protocol implementation):

- Signal, "The X3DH Key Agreement Protocol", Revision 1 (2016-11-04).
- Signal, "The Double Ratchet Algorithm", Revision 4 (2025-11-04).
- Signal, "The Sesame Algorithm", Revision 2 (2017-04-14).
- Signal, "The XEdDSA and VXEdDSA Signature Schemes", Revision 1 (2016-10-20).

Standards for the primitives and their known-answer vectors:

- RFC 7748 - Elliptic Curves for Security (X25519, X448).
- RFC 8032 - Edwards-Curve Digital Signature Algorithm (Ed25519, Ed448).
- RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 2104 / RFC 4231 - HMAC and its test vectors.
- NIST SP 800-108r1 - Recommendation for Key Derivation Using Pseudorandom
  Functions (KDF in Counter Mode).
- NIST FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
- NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard (ML-DSA).

geryon's hybrid design and its rationale against Signal's PQ approach are
in [HYBRID_SPEC.md](HYBRID_SPEC.md) and [PQ_COMPARISON.md](PQ_COMPARISON.md);
the ProVerif models are under [formal/](../formal/README.md).
