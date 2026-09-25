# Changelog

Broad strokes per release. Architecture and rationale live in
[docs/DESIGN.md](docs/DESIGN.md).

## [1.5.0] [2026-09-24]

Adds an opt-in quantum-safe private group system (QSPGS, the [CFG+] design),
geryon's post-quantum group vertical. Like the classical group system it is a
separate set of libraries (all `EXCLUDE_FROM_ALL`) and two new public headers
(`include/geryon_qspgs.h`, `include/geryon_qsgroups_server.h`), so the messaging
library and the classical group system are behaviorally unchanged and a
deployment that does not use quantum-safe groups links none of it. It ships side
by side with the classical group system, not as a replacement. All group
authentication is post-quantum: KR-ML-DSA (rerandomizable ML-DSA) at the two
hybrid tiers (ML-DSA-44 and ML-DSA-87). See
[docs/QSPGS_SPEC.md](docs/QSPGS_SPEC.md).

- **Unlinkable post-quantum group membership.** Members present under
  per-version rerandomized verification keys, so the server and other members
  cannot link a member's actions across group versions or to its long-term key.
  Rerandomizable ML-DSA (KR-ML-DSA) provides the unlinkable signatures; the
  identity key certifies each member's base verification key and per-epoch user
  key, binding membership to the existing custodied identity without a transcript
  signature.

- **Client extends the custodian; server is separate and stateless.** The client
  API (`include/geryon_qspgs.h`) seals all group state into the existing
  custodian store and caches nothing derived. The server API
  (`include/geryon_qsgroups_server.h`) holds only the service keys and verifies
  cores, appendix lines, and bearer tokens; the client/server split is enforced
  at link time (a client binary cannot carry server-side check code).

- **Versioned group state with an appendix log.** A group advances through
  admin-signed cores (the authoritative membership snapshot) and member-appended
  lines (joins, leaves, key refreshes, attribute changes) that an admin folds
  into a later core. Each group is created at an immutable format epoch and AEAD
  choice bound into its signed header, so an existing group never changes shape
  under the clients already in it. Rotating edits stage the new group key and
  commit only on server acceptance, so a rejected write never strands the admin.

- **Field encryption pinned per group.** The admin pins the group's field AEAD at
  creation: ChaCha20-Poly1305 (default) or AEGIS-256. The choice is immutable
  across every edit, so there is no downgrade path, mirroring messaging's
  pin-at-establishment.

- **Fixed-width member identities.** Member UIDs are a fixed 16 bytes, so a
  corrupt server learns member indices and activity but never a per-entry length
  class it could intersect with the public account directory.

- **New dependency.** The KR-ML-DSA layer composes liboqs ML-DSA; no new
  third-party dependency is added beyond the liboqs already carried for the
  hybrid messaging suites.

The messaging suites, the classical group system, the wire format
(`protocol_version` 0x01), and the messaging stored-blob formats are unchanged;
this release is additive over v1.4.0.

## [1.4.0] [2026-09-10]

Adds an opt-in classical private group system (the [CPZ] design), geryon's first
group vertical. It is a separate set of libraries (all `EXCLUDE_FROM_ALL`) and
two new public headers, so the messaging library is behaviorally unchanged and a
deployment that does not use groups links none of it. All group cryptography is
classical (the 25519 and 448 proof-group tiers); a post-quantum group system is a
planned follow-on, not a retrofit of this type. See
[docs/GROUP_SPEC.md](docs/GROUP_SPEC.md).

- **Anonymous group membership.** Keyed-verification credentials (an algebraic
  MAC over hidden attributes plus Schnorr conjunction NIZKs) let a member prove
  membership and present its profile without revealing its UID or ProfileKey to
  the server, with verifiable encryption of both. Deniable throughout (the proofs
  are NIZKs, never transferable signatures).

- **Client extends the custodian; server is separate and stateless.** The client
  API (`include/geryon_group.h`) seals group state into the existing custodian
  store and caches nothing derived. The server API
  (`include/geryon_group_server.h`) holds only the service keys and is a distinct
  target; the client/server split is enforced at link time (a client binary
  cannot carry issuance code).

- **No group ratchet.** Group messages fan out over the existing pairwise
  sessions; the GroupMasterKey is distributed to a new member inside a 1:1
  session (a `GROUP_KEY_DISTRIBUTION` envelope).

- **Group format version.** Each group is created at an immutable capability
  epoch bound into its GroupID, so an existing group never changes shape under
  the clients already in it, and a client that lacks a newer version declines to
  join it cleanly rather than mishandle it.

- **New dependency.** Vendors `libtalos_schnorr` (the Schnorr / decaf
  conjunction-proof engine) as a pinned submodule under `third_party/`, wired in
  only for the group vertical.

The messaging suites, the wire format (`protocol_version` 0x01), and the
stored-blob formats are unchanged; this release is additive over v1.3.0.

## [1.3.0] [2026-09-03]

The complete library: adds the fourth and highest suite `geryon_h448_1024`
(X448 + ML-KEM-1024, XEd448 + ML-DSA-87, SHA-512), so all four suites ship.
This is geryon's highest security tier: category-5 post-quantum material paired
with X448 so no component falls below X448's ~224-bit classical strength, CNSA
2.0-aligned. Every change is additive over v1.2.0; the frozen ABI, wire format
(`protocol_version` 0x01), and stored-blob formats are unchanged. As with every
suite, a `geryon_h448_1024` identity never interoperates with any other suite:
the suite is pinned per identity and there is no downgrade path.

- **The h448_1024 hybrid tier.** ML-KEM-1024 and ML-DSA-87 (via liboqs) over the
  X448 + XEd448 curve tier: X3DH mixes an ML-KEM-1024 secret into every DH, the
  Double Ratchet mixes a fresh ML-KEM secret into each step, and prekeys are
  dual-signed with XEd448 and ML-DSA-87 (both must verify). No protocol code is
  suite-specific; the tier is a descriptor row plus the ML-KEM-1024 / ML-DSA-87
  wrappers, validated against FIPS 203/204 ACVP vectors and the HYBRID_SPEC §11
  known-answer suite instantiated at 448.

- **Full 4x4 cross-suite rejection.** Every suite's bundle and initial message,
  presented to every other suite's identity, is rejected before any
  cryptographic processing, at the public API and at the parse seam, covering
  the classical/hybrid boundary in both directions.

- **Public buffer-size bounds for fixed-buffer consumers.** `include/geryon.h`
  now exposes the sizes an application needs to size fixed buffers without the
  runtime size-query: store buffers (`GY_STORE_IDENTITY_BLOB_MAX_{CLASSICAL,
  HYBRID}`, `GY_STORE_RECORD_BLOB_MAX`), which have no size-query at all, and
  the wire buffers (`GY_BUNDLE_MAX_*`, `GY_REGISTRATION_MAX_*`,
  `GY_APPKEY_CERT_MAX_*`, `GY_APPKEY_SIG_MAX_*`, `GY_OPK_WIRE_MAX_*` with
  `GY_OPK_BATCH_HDR`, `GY_MESSAGE_OVERHEAD_MAX_*`). They split classical vs
  hybrid so a size/bandwidth-constrained classical deployment allocates far
  less; the `_HYBRID` bound covers both hybrid tiers. Build-time and test-time
  checks keep them ahead of the internal record model and wire formulas. A
  supported suite now needs no custom store sizing; the reference in-memory
  store and the worked example size themselves from these constants.

## [1.2.0] [2026-08-28]

The classical high-security tier. Adds `geryon_c448` (X448 + XEd448, SHA-512):
a CNSA-aligned classical suite for deployments that want a larger classical
security margin without post-quantum material. Every change is additive over
v1.0.0; the frozen v1.0.0 ABI, wire format (`protocol_version` 0x01), and
stored-blob formats are unchanged. As with every suite, a `geryon_c448`
identity never interoperates with any other suite: the suite is pinned per
identity and there is no downgrade path. libdecaf (ed448-goldilocks, MIT) joins
libsodium as a runtime dependency, providing the 448 field, scalar, and point
primitives.

- **Classical 448 key agreement and ratchet.** X3DH, the Double Ratchet with
  mandatory header encryption, and Sesame session management all run at the 448
  tier through the suite descriptor: 56-byte X448 keys, 114-byte XEd448
  signatures, SHA-512 KDF chains. No protocol code is 448-specific; the tier is
  a descriptor row plus the two new primitive wrappers.

- **In-house XEd448, library primitives.** X448 wraps libdecaf's RFC 7748
  ladder. XEd448 sign AND verify are geryon's own spec composition (XEdDSA
  specification §6, the birationally-equivalent curve) over libdecaf's field,
  scalar, and point primitives; RFC 8032 Ed448 (SHAKE256, the 4-isogenous
  curve) is a different scheme and is never used in production, only as a
  validation-gate oracle. The vendored libdecaf 448 slice is direct-compiled
  under geryon's build, so no C++ runtime is linked.

- **Custody, prekeys, SAK, and delete-on-use at 448.** The custodian, sealed
  identity material, prekey lifecycle (SPK rotation with history, OPK
  replenish/publish), the signed application-key cluster (XEd448), and
  one-time-prekey delete-on-use all handle `geryon_c448` identities. No public
  signature changed; every wire object self-describes via its suite byte.

- **Worked example.** The `examples/` driver runs the full lifecycle under
  `geryon_c448`, one tier up from the classical `geryon_c25519` example.

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
