# Key-Custody Decisions

**Scope:** the HSM-style key-custody layer. geryon becomes the custodian
of all long-lived private key material; the application never receives
cleartext private keys. This area has no Signal-spec basis: the specs are
silent on key storage (see [general.md](general.md) D-GEN-4, which this
register extends). Register conventions and the full index live in
[README.md](README.md).

**Status:** the v1.0.0 ABI-freeze release (D-GEN-9): key custody becomes
the public API and all existing gy_* entry points route behind it.
Building custody first means later key material is built behind handles
from the start (no retrofit) and the stored-blob format is finalized once
(no second break of a frozen format). It is orthogonal to the protocol; it
wraps the existing surface rather than changing protocol behavior.
In-scope release scope: the handle API, the in-memory keystore, and
Stage-1 at-rest sealing. Deferred to later increments (v1.0.x / v1.1.x):
Stage 2 hardware backends and the backup / export formats. D-CUST-2+ (the
concrete handle API surface, the backup format, and the export/wrap format)
are reserved for those.

**Public object and design doc:** the custody API is the `gy_custodian` object
(`gy_custodian_*`), which replaces `gy_ctx` as the public entry point; its design
is docs/CUSTODY_SPEC.md (Accepted 2026-08-11). This register
governs the decisions; CUSTODY_SPEC.md governs the API shape.

**Spec accepted (2026-08-11):** CUSTODY_SPEC.md was confirmed against this
register (agrees on every decision item) and flipped to Accepted; the four
API-shape judgment calls (SAK naming, `gy_appkey_verify` as a free function,
the SAK certificate shape, `gy_custodian_reset` semantics) are decided and
recorded there.

### D-CUST-1: HSM-style key custody, envelope hierarchy, two-stage root of trust

- **Context / gap:** the specs do not address key storage. Today
  (D-GEN-4, D-SES-8) the library generates identity and prekey material
  internally but hands it to the application's `store_identity` /
  `store_record` callbacks as a serialized blob whose private bytes are
  in the clear; the application is told to seal that blob at rest. So the
  private key bytes transit the consumer's process and rest in the
  consumer's storage in cleartext, wrapped only in a format the consumer
  is not invited to parse. The goal of this decision is a stronger
  contract: the library manages ALL private key material, and the API
  emits only (a) opaque handles, (b) public keys, or (c) library-
  encrypted private data. Cleartext private key bytes never cross the API
  boundary to the consumer.

- **Decision:**

  1. **API contract (HSM-style).** Every public entry point that would
     otherwise expose a private key returns a handle, a public key, or
     wrapped (AEAD-sealed) private data instead. Normal protocol
     operations resolve a handle internally; backup and export are
     library-mediated and produce only sealed bytes. A handle is a
     process-local, non-forgeable reference into the unlocked in-memory
     keystore; the durable cross-process reference is a stable persisted
     key id, and re-opening a keystore requires an unlock (Stage 1:
     passphrase; Stage 2: hardware). This is distinct from D-GEN-4's
     current "hand out a cleartext-bearing opaque blob" behavior and
     supersedes it where custody is in effect.

  2. **Envelope hierarchy (three tiers).**

     ```
     password --Argon2id--> PDK --AEAD-wrap--> KEK --AEAD-wrap--> key material
                                    (stored)          (stored per key/record)
     ```

     - The password tier is a memory-hard hash, Argon2id via libsodium
       `crypto_pwhash` (a new `core/` primitive; geryon's `hash.c` has
       SHA-2/HMAC/HKDF but no password hash today). The Argon2id salt and
       parameters (opslimit, memlimit, algorithm/version) are stored
       alongside the wrapped KEK so the PDK can be re-derived and the
       parameters can be raised over time.
     - A single randomly generated KEK wraps the actual private key
       material and the persisted records. The PDK wraps only the KEK.
     - This indirection buys the two target properties: a password change
       re-derives the PDK and re-wraps only the KEK (key material
       untouched), and hardware migration (Stage 2) replaces only the top
       tier.

  3. **Two-stage root of trust.** The top tier is an explicit
     KEK-protector seam from Stage 1, even though Stage 1 is only a
     passphrase: an interface that can `wrap(KEK) -> blob` and
     `unwrap(blob) -> KEK`.
     - **Stage 1 (build first):** passphrase-derived. Argon2id -> PDK,
       PDK AEAD-wraps the KEK.
     - **Stage 2 (later):** an OS keychain / TPM / Secure Enclave / HSM
       implements the same seam; the passphrase tier becomes a
       hardware-protected key protecting the KEK. Everything from the KEK
       down is byte-identical. Building the seam in Stage 1 is what makes
       "only the top tier changes" literally true in code rather than a
       refactor.
     - **Boundary:** this seam assumes `unwrap` returns the KEK into
       geryon's process so the custody AEAD runs in software. That holds
       for passphrase, TPM, and enclave (which unseal into memory). A
       strict HSM that never releases key material would require the
       wrapping itself to run in hardware, which is beyond "swap the top
       tier" and is out of scope for the two-stage plan.

  4. **Wrapping AEAD, self-describing, caller-selectable.** AEGIS-256 is
     the default wrap cipher; XChaCha20-Poly1305 is available as an
     explicit alternative the caller selects, not an automatic hardware
     fallback. **Corrected 2026-08-11:** unlike
     AES-256-GCM, this project's libsodium exposes no
     `crypto_aead_aegis256_is_available()`, and AEGIS-256 always has a
     working constant-time software implementation (`aegis256_soft.c`,
     silently upgraded to AES-NI / ARM-crypto when present) - there is no
     hardware-absent condition to detect or gate on. Each
     wrapped blob stores a one-byte **algorithm ID** in its header, so
     unwrap uses whatever algorithm the blob was wrapped with and never
     has to re-detect or take the caller's word for it. The algorithm ID
     is echoed into the AEAD associated data (below) so it cannot be
     silently altered. This custody AEAD choice is independent of the
     per-session message AEAD (D-DR-3); the two are unrelated.
     - **Portability note (corrected):** because AEGIS-256's software path
       is constant-time and always present, an AEGIS-256 blob decrypts on
       ANY host, not only AES-capable ones - only speed differs. The
       original claim that a portable export needs XChaCha20-Poly1305 to
       restore on non-AES hardware does not hold; XChaCha20-Poly1305
       remains offered as a caller preference (for example, a policy that
       avoids AES entirely, or a simpler cipher on a constrained target),
       not a portability requirement. See the revised sub-decision 3
       below.

  5. **Associated-data binding.** Every wrap authenticates, in its AD: a
     format version byte, the algorithm ID, the key id / handle, the key
     type (identity vs which prekey vs which suite / record kind), and a
     tier label ("PDK-wrap-of-KEK" vs "KEK-wrap-of-material"). This stops
     blob substitution across keys and tier confusion, and pins the
     self-describing algorithm ID against downgrade.

  6. **Password change vs KEK rotation are two operations; rotation is
     DEFERRED (v1.0.x).** A password change re-wraps only the KEK and is
     cheap; it does NOT recover from a compromised password (an adversary
     holding the old wrapped-KEK blob and the old password already holds
     the KEK). True recovery from KEK compromise is **KEK rotation** (mint
     a fresh KEK, re-wrap all material and records), which must visit every
     persisted record. The store-callback model has no enumeration, so
     rotation needs a KEK-epoch plus lazy-re-wrap design and is deferred to
     a later increment; because the credential-derived key protects the
     KEK, a password change never triggers a rotation, so rotation is rare.
     Password change is the in-scope re-keying operation; nobody may assume
     it equals recovery-from-compromise.

  7. **Export is a re-wrap, not the at-rest blob.** The at-rest blob is
     KEK-wrapped and only the KEK opens it. An export or backup must
     cross the KEK boundary, so it is unwrap-under-KEK then re-wrap-under-
     export-target (an export passphrase, or a recipient device's public
     key for provisioning), performed inside the library with cleartext
     never crossing the API. "Encrypted private key data" out of the API
     therefore has two flavors, at-rest (KEK) and portable (export
     target), and they are not the same bytes.

  8. **Format versioning and memory hygiene.** Every wrapped blob and the
     backup bundle carry a version byte from day one (the D-GEN-1 "wire
     format versioned from day one" ethos applied to storage). The KEK
     and any unwrapped material live in `sodium_malloc` / mlock'd pages
     and are zeroized on handle close (consistent with the secure_zero
     discipline; D-GEN-4).

  9. **Custody scope.** Custody covers the long-lived identity and prekey
     material and the persisted records. The Double Ratchet's ephemeral
     and derived key material lives in geryon's process by necessity and
     is the custodian's own; that is consistent with the model (geryon IS
     the custodian) and does not need handle indirection, since it never
     crosses the API to the consumer.

- **Rationale:** standard envelope encryption with a wrapped data key.
  The three-tier hierarchy relocates the "sensitive bytes" problem from
  every stored blob and every API return to a single KEK, which is the
  one thing to protect and back up. The KEK-protector seam is what lets
  the same code serve "passphrase on a Linux server" and "Secure Enclave
  on iOS" by swapping one implementation. Building entirely on libsodium
  (Argon2id, AEGIS-256 / XChaCha20-Poly1305, `sodium_malloc`) keeps it
  within the permissive-license and library-first rules and adds no new
  dependency; it is standard sealing, not protocol crypto, so it does not
  engage the clean-room bar the way a primitive would. It is orthogonal
  to deniability and forward secrecy; it wraps stored key material and
  changes no protocol behavior.

- **Resolved (2026-08-11): custody is the DEFAULT public surface, not an
  opt-in mode.** It is the v1.0.0 breaking change itself, so
  `store_identity` / `store_record` blobs become library-sealed and the
  API is handle-based for everyone; there is no cleartext-blob
  compatibility mode. This is what makes the "consumer never sees
  cleartext key bytes" guarantee unconditional rather than opt-in. (The
  earlier "changing a frozen interface is v2 territory" concern is moot:
  custody *is* the release that establishes the frozen interface.)
- **Resolved (2026-08-13): a custodian-free peer-fingerprint call,
  `gy_bundle_fingerprint`.** Surfaced by the example-application
  feedback loop (identity verification), exactly as
  `gy_registration_identity_pub` was surfaced by the same effort. The custody
  API let an identity fingerprint ITS OWN key (`gy_self_fingerprint`) and
  exposed a PEER's fingerprint only as a side effect of a key change
  (`gy_keychange` on `GY_ERR_KEY_CHANGED`); there was no way to render a
  peer's safety number on demand from public bytes the app already holds,
  which is the core of every messaging app's verify-identity screen. The
  fix is a FREE function (no custodian, no secret, like `gy_bundle_assemble`
  / `gy_registration_identity_pub`) that fingerprints the IK inside a
  fetched bundle or a published registration; its output is byte-identical
  to that peer's own `gy_self_fingerprint` and to `gy_keychange.new_fp`, so
  the two sides compare and match. Purely ADDITIVE to the v1.0.0 surface (a
  new exported function, no struct-layout or wire change), so it is
  minor-bump-compatible and does not reopen the ABI freeze; it is public-key
  math over already-public material, so it engages no deniability or
  forward-secrecy concern. Note the residual limit recorded for the demo: it
  fingerprints the IK the relay delivered, so it detects a tampered/mismatched
  published fingerprint, not a substituted identity key the app never
  independently pinned; pinning is the app's TOFU responsibility (D-SES-9,
  `gy_accept_identity`).

- **Resolved (2026-08-13): one-time prekeys are genuinely one-time -
  delete-on-use plus reserve-on-export.** Surfaced by analysis of
  `gy_publish_bundle` while building the example application. Two coupled changes, both in
  `src/proto/custodian.c`:
  1. **Delete-on-use.** When an OPK is consumed to ESTABLISH a session
     (`tr_consume_opk`, which fires only after the first frame verifies),
     its private key is now wiped and its slot freed, and the idmat is
     re-sealed so a reopen never restores it. A second initiation with a
     different base key that tries to reuse the same OPK cannot find the
     key and fails closed. This **reverses** the earlier note that a
     consumed OPK is retained and that base-key dedupe (D-SES-6.1) is the
     *sole* reuse defense: dedupe still routes legitimate retransmits of the
     *same* initial message to the established session (it never re-touches
     an OPK, verified in `recv_init`), but genuine reuse is now made
     impossible, not merely flagged. The wipe is safe mid-receive because
     `c->recv.opks` is the same array by pointer (no `cust_reinit_recv`
     needed, which would rebuild the on-stack recv context); durability is
     best-effort within the call and reconciled on the next idmat write on
     the rare seal failure.
  2. **Reserve-on-export.** `gy_publish_bundle` (the directory-less one-shot
     path) is no longer read-only: it marks the OPK it emits as exported
     (`opk_consumed`), minting a fresh one via the shared `cust_replenish_opks`
     helper if the pool is spent, and persists - so two calls never hand out
     the same one-time key and a later `publish_opk_batch` never re-exports
     it. The private key is retained until the peer uses the bundle, when
     delete-on-use destroys it. The granular directory model
     (`publish_registration` + `publish_opk_batch`, server assembles and
     deletes per fetch) is unchanged and remains the correct production
     directory; the two models must not be mixed for one identity, since both
     draw the one pool. Public-surface impact is additive/behavioral only (no
     new exported function; `gy_publish_bundle` and the `consume_opk` callback
     docs updated in `include/geryon.h`), within the v1.0.0 freeze.

- **Open sub-decisions (gate only the deferred D-CUST-2 backup/export
  work; none block the Stage-1 custody release):**
  1. **Export target model.** Passphrase-wrapped portable backup, a
     recipient device's public key for provisioning, or both.
  2. **KEK-protector provider shape.** Whether Stage 2 is a fixed set of
     platform backends or a pluggable KEK-provider callback (mirroring
     the storage-callback delegation), and the exact `wrap`/`unwrap`
     signatures.
  3. **Portable-export cipher pin.** Whether portable exports/backups use
     the same caller-selectable AEGIS-256 default as at-rest blobs, or pin
     XChaCha20-Poly1305. **Corrected 2026-08-11:** the original
     hardware-portability rationale for pinning XChaCha here does not
     hold - AEGIS-256's software path is constant-time and decrypts on any
     host regardless of AES hardware (item 4, above) - so if this is
     decided in favor of XChaCha at all, it is a caller-preference
     question, not a correctness one.

- **Validation (when built):** KAT round-trips for each wrap cipher; the
  self-describing unwrap opens both AEGIS-256 and XChaCha20-Poly1305
  blobs by their stored algorithm ID; AD-tamper rejection (flipping the
  algorithm-ID, key-type, or tier byte fails authentication); password
  change preserves all key material and leaves records openable; KEK
  rotation re-wraps every blob and old wrapped-KEK blobs no longer open
  new material; wrong-password unlock fails with a uniform error; a blob
  sealed under either cipher restores on any host (AEGIS-256's software
  path is constant-time and always present; sub-decision 3 governs only
  which cipher an export pins, not whether it restores); zeroization on
  handle close and on keystore lock.
