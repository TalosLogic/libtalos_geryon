# geryon system design

This is the durable, whole-system design overview. It is deliberately terse and
points at the authoritative documents rather than restating them:

- `docs/CUSTODY_SPEC.md` - design for the key-custody layer (the `gy_custodian`
  public API as of v1.0.0; decisions in D-CUST-1).
- `docs/decisions/` - the per-module implementer decision register (D-GEN,
  D-XED, D-X3DH, D-DR, D-SES, D-CUST); every "D-*" tag below resolves there.
- `CHANGELOG.md` - broad strokes per release.

## What geryon is

A clean-room C17 implementation of the Signal protocol (X3DH, Double Ratchet,
Sesame, XEdDSA), in a classical suite and a post-quantum-hybrid suite. In the
hybrid suite every classical asymmetric operation gets an ML-KEM/ML-DSA
counterpart, so session security holds if EITHER the ECDH or the KEM assumption
survives, while offline deniability is preserved (no transcript signatures).
The hybrid construction is geryon's own, not Signal's PQXDH, and is specified
normatively in [HYBRID_SPEC.md](HYBRID_SPEC.md). Protocol code is clean-room
from specifications; primitives come from permissively-licensed libraries by
preference. The public API is the single installed header `include/geryon.h`.

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
| (reserved) | 0x04 | | | |

The classical suite `geryon_c25519` provides no post-quantum confidentiality
(the installed header says so plainly); it exists for size/bandwidth-constrained
deployments. The hybrid suite `geryon_h25519_512` fuses an ML-KEM-512 secret
into each X3DH DH and each Double Ratchet root-key step (PQ-first,
`HASH(kem_ss || dh_out)`), dual-signs prekeys with XEdDSA and ML-DSA, and adds
deniable KEM-based initiator authentication (the `gy_pq_pending` state). A
classical identity never completes a hybrid handshake or vice versa; the
handshake, ratchet, and custody paths are suite-agnostic and dispatch on the
suite byte the wire objects carry. Suite ID 0x04 (`geryon_h448_1024`) is
reserved for a future 448-tier suite and is rejected before any cryptographic
processing. HYBRID_SPEC.md governs all hybrid behavior.

## Strict layering

Each layer calls only the layer below it; violations are build bugs, enforced at
review and by `scripts/layer_audit.sh` (include-direction check, a `nm`-based
proof that Layer 5 references no ratchet/core symbol, and a `geryon.h`
standalone C++ compile). The allowlist is empty.

- **Layer 1 `core/`** - primitives: thin wrappers over libsodium (X25519,
  Ed25519, SHA-2, HKDF/HMAC, AEAD, RNG), liboqs (ML-KEM-512 and ML-DSA-44 for
  the hybrid suite), and monocypher (the XEdDSA verify map), plus in-house
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
(offline deniability, in the hybrid suite as much as the classical one - PQ
authentication is KEM-based, never a signature over the transcript); message
keys deleted immediately after use and skipped-key storage bounded by MAX_SKIP;
zeroization treated as part of the protocol, not cleanup; constant-time
discipline unconditional, software fallbacks included. In the hybrid suite no
KEM secret is ever optional (handshake or ratchet) and hybrid signature
verification requires both XEdDSA and ML-DSA to pass.

## Public API

`include/geryon.h` is the only installed header; every exported symbol starts
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
libsodium (ISC), liboqs (MIT, the ML-KEM/ML-DSA provider for the hybrid suite),
and monocypher (BSD-2/CC0) today; libdecaf (MIT) joins with the X448 suite.

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

The hybrid suite's own design and its rationale against Signal's PQ approach are
in [HYBRID_SPEC.md](HYBRID_SPEC.md) and [PQ_COMPARISON.md](PQ_COMPARISON.md);
the ProVerif models are under [formal/](../formal/README.md).
