# Changelog

Broad strokes per release. Architecture and rationale live in
[docs/DESIGN.md](docs/DESIGN.md).

## [1.1.0] [2026-08-20]

The hybrid flagship suite. Adds `geryon_h25519_512` (X25519 + ML-KEM-512,
XEdDSA + ML-DSA-44), geryon's own PQ-hybrid design: session security holds if
EITHER the ECDH or the KEM assumption survives. Every change is additive over
v1.0.0; the frozen v1.0.0 ABI, wire format (`protocol_version` 0x01), and
stored-blob formats are unchanged. A classical `geryon_c25519` identity and a
hybrid `geryon_h25519_512` identity never interoperate: the suite is pinned per
identity and there is no downgrade path. liboqs (ML-KEM-512, ML-DSA-44) joins
libsodium as a runtime dependency.

- **Hybrid key agreement and ratchet.** Hybrid X3DH mixes an ML-KEM
  encapsulation into every classical DH (identity, signed prekey, one-time
  prekey), and the Double Ratchet mixes a fresh ML-KEM secret into each ratchet
  step's root KDF. Per-pair fusion is PQ-first (`HASH(kem_ss || dh_out)`); no
  KEM secret is ever optional within the suite. Prekeys carry BOTH an XEdDSA and
  an ML-DSA signature and verification requires both.

- **Deniable PQ authentication.** The responder's first reply encapsulates to
  the initiator's identity ML-KEM key; the initiator is PQ-pending
  (classical-only authentication) until its first valid message after that
  confirmation. `gy_pq_pending` now reports `GY_PQ_PENDING`/`GY_PQ_CONFIRMED`
  for hybrid peers. No transcript signatures: offline deniability is preserved
  in the hybrid suite exactly as in the classical one.

- **Suite-agnostic public surface, hybrid throughout.** No public signature
  changed. Every wire object self-describes via its suite byte, and each public
  entry point dispatches internally. The custodian-less directory helpers
  (`gy_bundle_assemble`, `gy_opk_batch_count`/`_get`,
  `gy_registration_identity_pub`, `gy_bundle_fingerprint`), the SAK cluster
  (`gy_custodian_sign`/`_generate_appkey`/`_rotate_appkey`/`_export_appkey_cert`
  and `gy_appkey_verify`), prekey deletion, and one-time-prekey delete-on-use
  all handle hybrid identities. The hybrid SAK is dual-scheme (XEdDSA + ML-DSA),
  both-or-abort.

- **Hybrid worked example.** The `examples/` driver runs the full lifecycle
  under `geryon_h25519_512`, with the PQ-pending transition and ratchet KEM
  refresh exercised alongside every phase the classical example covers.

- **Security fix (low risk).** One-time-prekey delete-on-use now propagates the
  sealed-idmat re-seal result instead of discarding it, so a receive whose OPK
  consumption cannot be made durable fails closed. Previously a persist failure
  was swallowed: the spent key was wiped in memory but remained in the last
  sealed blob, so a crash and reopen could restore it and permit OPK reuse. The
  in-memory wipe is unaffected. This corrects the classical delete-on-use path
  present since v1.0.0 as well as its hybrid counterpart.

The v1.1.0 materials (`docs/HYBRID_SPEC.md`, the formal models, the hybrid
decision registers) are published with this release.

## [1.0.0] [2026-08-16]

Initial release: a clean-room C17 implementation of the classical Signal
protocol (X3DH, Double Ratchet, Sesame, XEdDSA) with library-custodied keys,
behind the single `include/geryon.h` public API. Public struct layouts, the
wire format (`protocol_version` 0x01), and stored-blob formats are stable from
this release; additional cipher suites arrive additively as later minor
versions.

- **Protocol (`geryon_c25519`: X25519 + XEdDSA, SHA-256).** X3DH key
  agreement, the Double Ratchet with mandatory header encryption, and Sesame
  session management, clean-room from the Signal specifications. The suite is
  pinned per identity and bound into every KDF; it is never negotiated at
  runtime and there is no downgrade path.

- **Session management (Layer 4).** The three separately-keyed store blobs
  (User/Device/Session), the transactional staging engine, the lifecycle
  state machine, and the send/receive paths (base-key dedupe, header-encrypted
  trial association, uniform failure). DeviceRecords are keyed per
  `(UserID, DeviceID)`, matching the public API's addressing and the
  Sesame/Signal per-account device model, so two contacts sharing a DeviceID
  byte string never collide into one record; DeviceIDs need only be unique per
  user.

- **Wire format and public API (Layer 5).** The typed envelope, the
  prekey-bundle format, and `include/geryon.h` as the only installed header,
  under the concurrency, storage, and send-loop contracts.
  `scripts/layer_audit.sh` enforces the strict layering in CI.

- **Key custody.** The public entry object is `gy_custodian`: the library, not
  the application, custodies every private key it generates. Handle-based API
  (`gy_custodian_create`/`_open`/`_close`/`_reset`/`_change_credential`) over a
  type-tagged slot table; no public entry point returns cleartext private key
  material. Envelope hierarchy: a per-custodian KEK (self-describing AEGIS-256
  default, or explicit XChaCha20-Poly1305) protected by an Argon2id-derived
  credential wrap, so every identity/prekey/record blob a store callback sees
  is already library-sealed opaque bytes. The custodian object itself, not just
  its KEK, lives in guarded (`sodium_malloc`/`mlock`'d) memory and embeds every
  unlocked private key directly.

- **Prekey lifecycle and directory helpers.** SPK rotation with bounded,
  zeroizing history (an in-flight session against a superseded SPK still
  resolves); OPK replenishment, pool stats, and granular publish
  (registration-only, OPK-batch-only, or full bundle). One-time prekeys are
  genuinely one-time: the emitting path reserves each OPK it hands out (minting
  a fresh one if the pool is spent), and an OPK's private key is deleted the
  moment it is used to establish a session. The one-shot full-bundle publish
  and the granular directory publish are distinct paths and must not be mixed
  on one identity (they draw one pool). Custodian-free helpers let an untrusted
  directory serve keys without holding any private material:
  `gy_bundle_assemble` builds a fetch bundle from a published registration plus
  one OPK, `gy_opk_batch_count`/`gy_opk_batch_get` enumerate a published OPK
  batch, `gy_registration_identity_pub` pins a client's raw identity key, and
  `gy_bundle_fingerprint` renders a peer's safety number from a fetched bundle
  or registration (byte-identical to that peer's own `gy_self_fingerprint`).

- **Application signing key (SAK).** A dedicated, domain-separated
  request-signing subkey (`gy_custodian_sign`/`_generate_appkey`/
  `_rotate_appkey`/`_export_appkey_cert`), verified by the custodian-less
  `gy_appkey_verify`. Deliberately non-repudiable and deliberately never used
  for protocol message content, so it cannot erode Double Ratchet deniability.

- **Worked example (`examples/`).** A multi-process end-to-end example over
  `include/geryon.h` only (an untrusted relay plus per-client sealed stores)
  that drives the full lifecycle and doubles as a deterministic pass/fail smoke
  test: both publish models side by side, an explicit no-OPK handshake
  (reduced forward secrecy), peer removal and re-add, a store credential change
  folded into a restart, session expiration, and SAK rotation within the
  retained-history window.

The classical `geryon_c25519` suite provides no post-quantum confidentiality;
the installed header says so plainly.
