# geryon key-custody design (the custodian API)

**Date:** 2026-08-11 (Accepted 2026-08-11)
**Status:** Accepted. Design for key custody; the v1.0.0 public API.
No implementation work starts against a section still marked open.
**Normative decisions:** docs/decisions/custody.md (D-CUST-1) is the decision
record; this document is the design elaboration and governs the public API
contract. Where the two disagree, D-CUST-1 wins on the decisions it states and
this document wins on API shape. Referenced by docs/DESIGN.md.

**Confirmed:** this document agrees with D-CUST-1 on every
decision item (1-9), the "custody is the default surface" resolution, and the
three open sub-decisions (all of which gate only the deferred D-CUST-2
backup/export work, none of which block this release).

**API-shape judgment calls, decided:**

1. **SAK naming is `appkey`, not `authkey`.** The key names what it is (an
   application-level signing delegate), not what any one caller uses it for;
   "authkey" would suggest it participates in an authentication protocol,
   which it does not (it just signs bytes the app hands it). `authkey` was
   considered and rejected on that basis. Reflected throughout section 10 and
   the `gy_custodian_generate_appkey` / `gy_appkey_verify` / `"appkey-cert"` /
   `"appkey"` naming already in this document.
2. **`gy_appkey_verify` is a free function**, not a custodian method: a
   verifying server has no private key material and must not need a
   custodian object (or a store, a clock callback, or any lifecycle state)
   just to check a signature. Section 10, section 12.
3. **The SAK certificate carries the identity PKID, not the identity public
   key.** The verifier pins the identity public key out of band (or TOFU) and
   uses the PKID only to select which pinned identity the cert claims to be
   under; shipping the public key inside the cert would let an unpinned
   verifier accept any self-certified identity, defeating the pin. Section 10.
4. **`gy_custodian_reset` wipes this identity's own material** (zeroize and
   delete everything the custodian holds, return to absent) and is a
   distinct operation from `gy_purge_device` / `gy_purge_user`, which remove
   PEER records only. Conflating the two would make a peer-cleanup call
   capable of destroying the caller's own identity. Section 7.

These four are now fixed API shape for the code tickets, not open choices.

This is the design for geryon's key-custody layer, exposed as the `gy_custodian`
object. It establishes the frozen v1.0.0 public API (D-GEN-9): every existing
`gy_*` entry point routes behind the custodian, and the library becomes the sole
holder of private key material.

## 1. Purpose and guarantee

The custodian makes geryon the custodian of all long-lived private key material.
The guarantee it adds over the pre-1.0.0 API:

> No cleartext private key bytes cross the public API. The application receives
> only opaque handles, public keys, or library-encrypted (wrapped) private data.

Today (v0.1.x, D-GEN-4) the library generates identity and prekey material but
hands it to `store_identity` / `store_record` as a serialized blob whose private
bytes are in the clear; the application is merely told to seal that blob at rest.
Under the custodian, the library seals the blob itself before it leaves, holds
the unlocked material in guarded memory for the duration of a session, and never
returns a private scalar, decapsulation key, or signing key through the API.

## 2. Threat model

In scope (what the custodian defends):
- An adversary who reads the application's at-rest storage (the sealed blobs the
  store callbacks persist) learns nothing without the unlock credential.
- An adversary who reads the store *medium* in transit (the blob bytes passing
  through the store callbacks) sees only sealed data.
- An application-integration mistake that logs, serializes, or transmits "the key
  blob" cannot leak a usable private key, because the blob is sealed and the API
  never hands out cleartext key material to mishandle.

Out of scope (stated plainly, not defended):
- In-process memory disclosure while the custodian is unlocked (a debugger, a
  core dump, ptrace, or root on the host). The Stage-1 KEK and any key material
  in active use necessarily exist in the process address space; `mlock` and
  zeroization reduce the window but do not eliminate this.
- The Double Ratchet's ephemeral and derived key material, which lives in the
  process by necessity (it is minted and consumed per message). This is the
  custodian's own material and is consistent with the model; it is not handle-
  addressable by the application and never crosses the API.
- Passphrase strength (Stage 1). Argon2id raises the cost of an offline guess but
  a weak passphrase remains the weak link; Stage 2 replaces the passphrase tier
  with a hardware-protected key.

## 3. Object model and vocabulary

- **custodian** (`gy_custodian`): the top-level public object, holding ONE
  identity's material: the unlocked private key material, the wrapping KEK, this
  device's identifiers, and the application's store and clock callbacks. It is
  created and unlocked with a credential (Stage 1: a passphrase) and is the object
  every protocol operation takes. It subsumes the role of today's `gy_ctx`
  (section 4). One custodian is one identity: multiple identities or personas mean
  multiple custodians, each with its own credential; there is no global keystore
  of many identities.
- **handle** (`gy_key_handle`): an opaque, process-local, non-forgeable reference
  to a key object held by the custodian. A handle is a flat integer whose value
  carries no meaning - the key type is stored in the custodian's slot, never
  packed into handle bits - with 0 reserved as the invalid handle (matching the
  PKID zero-sentinel, D-GEN-2). Handles are meaningless across processes; the
  durable cross-process reference is a stable persisted key id, and re-opening
  requires an unlock. Handles are the mechanism by which the library holds keys
  and the application names them without touching bytes.
- **key object:** a unit of private material the custodian owns and seals:
  - the identity key (IK): the curve secret;
  - signed prekeys and one-time prekeys (each an ECDH secret), with the
    lifecycle of section 9;
  - the application signing key (SAK): an optional identity-certified delegate for
    authenticating application data (section 10);
  - session and ratchet state (custodian-owned; section 8).
- **peer address** (`user_id`, `device_id`): the opaque, application-defined
  identifiers naming a user and one of their devices (Sesame UserID/DeviceID, up
  to `GY_USER_ID_MAX` / `GY_DEVICE_ID_MAX` bytes). They are the addressing
  primitive for every send/receive operation and are DISTINCT from the identity
  key and its PKID: the address is stable and assigned by the application's
  service namespace, while the identity key is per-device cryptographic material
  (D-SES-2) that can change under the same address (rotation, re-registration).
  The library binds a peer's address to their identity public key in the
  DeviceRecord (learned from their published bundle) and detects/verifies changes
  by PKID/fingerprint (D-X3DH-11, `GY_ERR_KEY_CHANGED`); the PKID is a key
  identifier, never the address.

Handles are not an everyday burden on the application. The common send/receive
path addresses peers by `(user_id, device_id)` and the local identity is implicit
in the custodian, so the application passes the custodian and no handle. Explicit
handles surface only where a specific local key must be named: prekey operations,
the SAK, and (deferred) export.

## 4. The custodian as the public entry object

The custodian subsumes today's `gy_ctx`. Where the current API creates a context
from a suite id, the store callbacks, this device's identifiers, and optional
clock/expiry config, the 1.0.0 API creates a custodian from the same inputs plus
an unlock credential, and the custodian additionally owns the key material that
`gy_ctx` previously pushed out as cleartext blobs. Every protocol operation
(`gy_encrypt`, `gy_receive`, `gy_initiate`, `gy_publish_bundle`, the send-staging
calls, identity-change acceptance) takes a `gy_custodian *` where it previously
took a `gy_ctx *`. There is no separate context object; one unlocked custodian is
the unit of use, under the same concurrency contract as `gy_ctx` (D-GEN-8: not
thread-safe, not re-entrant, one per thread or caller-serialized).

## 5. Envelope hierarchy and wrap format

The sealing follows D-CUST-1's three-tier envelope:

```
credential --Argon2id--> PDK --AEAD-wrap--> KEK --AEAD-wrap--> key material / records
                                  (stored)          (stored per object)
```

- The credential tier (Stage 1) is Argon2id via libsodium `crypto_pwhash`; its
  salt and parameters (opslimit, memlimit, algorithm/version) are stored beside
  the wrapped KEK so the PDK can be re-derived and the parameters raised later.
- A single random KEK wraps every key object and record. The PDK wraps only the
  KEK, so a credential change re-wraps one blob (section 7).

**Wrap format (every sealed blob):**

```
version(1) || alg_id(1) || nonce(alg) || ciphertext || tag
```

with associated data (authenticated, not encrypted) binding, per D-CUST-1:
the format version, `alg_id`, the key id / handle, the key type (identity /
which prekey / suite / record kind), and the tier label ("PDK-wrap-of-KEK" vs
"KEK-wrap-of-material"). Binding `alg_id` into the AD pins the self-describing
selector against downgrade.

**Wrap ciphers:** AEGIS-256 is the default; XChaCha20-Poly1305 is available as an
explicit caller-selected alternative, not an automatic hardware fallback -
unlike AES-256-GCM, this project's libsodium exposes no
`crypto_aead_aegis256_is_available()`, and AEGIS-256 always has a working
constant-time software implementation (silently upgraded to AES-NI / ARM-crypto
when present), matching the existing D-DR-3 treatment of AEGIS-256 as always
available. `alg_id` records which cipher was used, so unwrap is self-describing
and never re-detects or takes the caller's word for it. This is independent of
the per-session message AEAD (D-DR-3). Because AEGIS-256's software path is
constant-time and always present, a blob sealed under either cipher decrypts on
any host - only speed differs, not correctness (D-CUST-1 item 4, corrected
2026-08-11).

## 6. Root-of-trust seam (two stages)

The top tier is an explicit **KEK-protector seam** from Stage 1: an internal
interface that can `wrap(KEK) -> blob` and `unwrap(blob) -> KEK`.

- **Stage 1 (this release):** the passphrase implementation. Argon2id derives
  the PDK; the PDK AEAD-wraps the KEK.
- **Stage 2 (deferred, v1.0.x / v1.1.x):** an OS keychain / TPM / Secure Enclave
  / HSM implements the same seam; the passphrase tier becomes a hardware-protected
  key protecting the KEK. Everything from the KEK down is byte-identical.

Building the seam in Stage 1, even though Stage 1 is only a passphrase, is what
makes "only the top tier changes" literally true rather than a later refactor.
Boundary: the seam returns the KEK into process memory so the custodian's AEAD
runs in software; this holds for passphrase, TPM, and enclave (which unseal into
memory). A strict HSM that never releases key material would require the wrapping
itself to run in hardware, which is beyond "swap the top tier" and out of scope.

## 7. Lifecycle and state machine

States: **absent** (no keystore) -> **locked** (sealed blobs exist, KEK not in
memory) -> **unlocked** (KEK and needed material in guarded memory) -> **locked**
(on close) -> **absent** (on reset).

- **create:** generate the identity (and initial prekeys), mint the KEK, seal
  everything, persist the sealed blobs through the store callbacks.
- **open / unlock:** derive the PDK from the credential, unwrap the KEK, and make
  the custodian usable. A wrong credential fails with a single uniform error.
- **operate:** all protocol operations run against the unlocked custodian;
  material is unsealed on demand and re-sealed on mutation.
- **lock / close:** zeroize the KEK and all unlocked material (`sodium_memzero`),
  drop to locked.
- **credential change:** re-derive the PDK, unwrap and re-wrap the KEK. Key
  material and records are untouched. Cheap, but NOT recovery from a compromised
  credential (D-CUST-1): an adversary holding the old wrapped-KEK blob and the old
  credential already has the KEK.
- **KEK rotation (deferred to a later increment, v1.0.x):** minting a fresh KEK
  and re-wrapping every key object and record is the true recovery from a KEK
  compromise, but it must visit every persisted record, which the store-callback
  model (load/store by key, no enumeration) cannot drive without a KEK-epoch plus
  lazy-re-wrap design. It is deferred. Because the credential-derived key protects
  the KEK, a credential change never requires a rotation, so rotation is rare;
  credential change is the in-scope re-keying operation.
- **reset / destroy:** zeroize and delete all custodied material for this identity
  and return to absent. This is distinct from `gy_purge_device` /
  `gy_purge_user`, which remove PEER records; reset removes the LOCAL identity
  and its keys.

**Immutable configuration (HSM pattern).** Security-relevant limits (the D-SES-4
store maxima, the SPK-history and OPK-pool bounds, and an Argon2id parameter
floor) are fixed at create/open and are not runtime-mutable, so a running
custodian cannot be silently weakened. Changing them requires a fresh create.

## 8. Storage integration

The custodian does not replace the storage split (D-GEN-4): the application still
owns the medium and implements `gy_store_callbacks`; the custodian persists sealed
blobs through those same callbacks. What changes is the content: the identity,
prekey, and record blobs handed to `store_identity` / `store_record` are now
sealed (section 5), so the application is no longer asked to seal them and can no
longer read them. Session and ratchet records are custodian-owned key material and
are sealed under the KEK like any other object. Finalizing this blob format at
the ABI freeze is deliberate: later key material is written into the final
sealed format, not into one that would break a second time.

## 9. Prekey lifecycle

Signed prekeys and one-time prekeys are consumed and must be refreshed over the
life of an identity; the custodian owns this. The pre-custodian API generated them
once at identity creation with no way to rotate or replenish; the custodian adds
the full rotation and replenishment lifecycle.

- **Signed prekey rotation:** mint a new signed prekey (identity-signed, timestamped
  per D-X3DH-4/5), keeping a bounded history of superseded SPKs so in-flight
  sessions that referenced an older SPK still resolve. History depth is a fixed
  maximum (D-SES-4 style bound), not a runtime knob.
- **One-time prekey replenishment:** generate additional OPKs into the pool at any
  time, up to the batch cap, without regenerating the identity.
- **Pool observability:** query the OPK pool (total / used / unused) so the
  application knows when to replenish; consumption is driven by the existing
  `consume_opk` store callback and the receive path (D-X3DH-10).
- **Granular publish / export:** publish the identity+SPK registration and upload
  OPK public batches independently, matching how a real server is provisioned
  (register once, top up OPKs periodically). Public material only, under the
  D-GEN-1 versioned framing and the size-query convention. The untrusted server
  stores the registration and the OPK pool and assembles a per-fetch bundle
  (IK + SPK + one popped OPK) with the free function `gy_bundle_assemble` (no
  custodian, like `gy_appkey_verify`); the fetcher feeds the result to
  `gy_initiate`. These server-side free functions (`gy_bundle_assemble`,
  `gy_opk_batch_count` / `_get`, `gy_registration_identity_pub`,
  `gy_bundle_fingerprint`) are suite-agnostic: they dispatch on the
  self-describing suite byte and never deserialize private material, so a hybrid
  identity uses the same directory path (its registration is bundle-shaped and
  its OPK entries carry the ML-KEM key; HYBRID_SPEC §5.4).
- **PKID discovery and deletion:** map a server-reported PKID (a consumed OPK, an
  expired SPK) back to the local key so the application can prune it; delete
  individual or batches of prekeys with zeroization.

All of this is public-key output or internal bookkeeping; no private prekey
material leaves the custodian.

## 10. Application signing key (SAK)

The custodian optionally holds an application signing key: an identity-certified
delegate the application uses to authenticate its own data (for example, signing
REST API requests so a server can verify they come from identity X without session
tokens - anonymous but authenticatable). This is the clearest expression of the
custodian's purpose: it signs on the application's behalf and never releases the
key.

- **Certified subkey, not the identity key.** The SAK is its own keypair, signed
  by the identity key into a small certificate:
  `{SAK public key, issuance timestamp, optional expiry, identity signature,
  identity PKID}`. A verifier pins identity X out of band (or TOFU), checks the
  certificate once, then verifies per-request signatures with the SAK. The identity
  key is never used for request signing, and the SAK is rotatable and revocable
  (bounded history for in-flight tolerance) without touching the identity.
  Certifying the SAK is the same category of act as signing a prekey (the identity
  publishes a key); it is NOT a transcript signature and does not affect messaging
  deniability. Because it is the same category as signing a prekey, in a HYBRID
  suite the SAK follows the prekey rule: dual-scheme (see Scheme below), so no
  identity-signed artifact drops to classical-only PQ authentication.
- **Domain-separated signing.** The library frames every SAK signature as
  `sign(SAK, purpose_label || app_context || message)` (D-GEN-3 domain
  separation), so a SAK signature can never be confused with a protocol signature,
  another application's, or replayed into a different context. This is a deliberate
  improvement over the predecessor, which signed raw caller bytes with no domain
  separation.
- **Freshness is the application's responsibility (REQUIRED).** The library signs
  the bytes it is given; it does not invent anti-replay state. The signed payload
  MUST carry a server challenge or a timestamp+nonce, or requests are replayable.
  A convenience entry may frame a caller-supplied `(nonce, timestamp, message)`,
  but the freshness policy stays with the application (the same shape as the
  REQUIRED bounded send-retry loop). The predecessor did not bind freshness
  either; there it was entirely implicit in the caller's message.
- **Deniability caveat, stated plainly.** SAK signatures are NON-repudiable by
  design - that is the point for authentication. The SAK must never sign message
  content or protocol transcripts: doing so creates permanent proof that identity X
  authored that content, destroying deniability for it. The SAK is domain-separated
  from every protocol key, so messaging deniability (offline, all suites) is fully
  preserved; the SAK is an opt-in capability beside the protocol, not inside it.
- **Scheme.** In a classical suite the SAK is XEdDSA. In a hybrid suite the SAK
  is dual-scheme, exactly mirroring hybrid prekey signing (HYBRID_SPEC): the SAK
  keypair is an XEdDSA key AND an ML-DSA key, the identity certifies it under
  BOTH schemes, and per-request signatures carry both; verification requires
  every signature of each pair to pass (no single-scheme acceptance, no
  downgrade). The certified data binds both SAK public keys
  (`curve_type || curve_pk || mldsa_pk`), the identity PKID is the hybrid
  identity's, and the pinned `identity_pub` a verifier supplies is the full
  hybrid identity encoding (`curve_type || curve_pk || mlkem_ek || mldsa_pk`,
  the same bytes the safety-number fingerprint hashes). The SAK keypair carries
  no ML-KEM component: it signs, it never performs key agreement. The XEdDSA
  half is framed identically to the classical SAK (a domain-separation label
  prefix), and the ML-DSA half signs the same bytes under the FIPS 204 context
  string set to that same label, so the two suites share one canonicalization.

## 11. Custody design posture

The custody layer sits above Sesame and deliberately keeps these properties:

- **No global singleton.** geryon is object-based with no global mutable state
  (D-GEN-8); the custodian is an object, one per identity, not a process-global
  keystore.
- **No session handles.** Sessions stay hidden behind Sesame: peers are addressed
  by `(user_id, device_id)`, routing and fan-out are internal, and the custodian
  exposes no session handle. Many concurrent sessions are still tracked, without
  app-held handles: the three-record model (D-SES-11, UserRecord ->
  DeviceRecord -> SessionRecords) lives in the application's store, keyed there
  through the callbacks, so the count is bounded only by the app's storage and
  persists across restarts. A 4-byte SessionID (D-SES-3) keys each session blob in
  the store but is never an operation argument; the library resolves
  `(user_id, device_id)` to the active session internally, including the
  multiple-sessions-per-device cases (active/archived, racing convergence) that
  raw handles would push onto the application.
- **Uniform verify failure.** The receive path keeps the single uniform
  `GY_ERR_VERIFY` (D-SES-6.2) to deny a decryption oracle. The custodian adds
  lifecycle error codes (bad credential, handle not found, custodian locked, slots
  exhausted) but keeps them off the crypto-verify path, and a wrong credential
  fails uniformly (section 15).
- **AEAD and MAX_SKIP are not config knobs.** AEAD is selected per session at
  runtime (D-DR-3) and MAX_SKIP is fixed per protocol version (D-DR-11); neither
  is custodian configuration.
- **Generic serialization.** The suite-descriptor genericity and versioned
  framing (D-GEN-1) cover storage with a handful of generic publish/export
  operations rather than per-object serialize/deserialize sprawl.

Design choices carried in: opaque integer handles with the type in the slot (not
in handle bits) and 0 as invalid; the full prekey lifecycle (section 9); the
identity-certified application signing key (section 10); and the immutable-config
plus explicit-reset HSM pattern (sections 7, 15).

## 12. Public API shape (illustrative)

Signatures are illustrative and frozen at implementation, not here. The shape:

```c
/* create + open + destroy */
int gy_custodian_create(gy_custodian **out, uint8_t suite_id,
                        const gy_store_callbacks *store,
                        const uint8_t *cred, size_t cred_len,
                        const uint8_t *self_uid, size_t self_uid_len,
                        const uint8_t *self_did, size_t self_did_len,
                        gy_clock_fn clock, void *clock_ctx,
                        const gy_config *cfg);
int  gy_custodian_open(gy_custodian **out, const gy_store_callbacks *store,
                       const uint8_t *cred, size_t cred_len);
void gy_custodian_close(gy_custodian *c);          /* lock + zeroize */
int  gy_custodian_reset(gy_custodian *c);          /* wipe this identity */

/* credential management (full KEK rotation deferred to v1.0.x, section 16) */
int gy_custodian_change_credential(gy_custodian *c,
                                   const uint8_t *new_cred, size_t new_len);

/* identity + publish (public/handle only, never private bytes) */
int gy_custodian_generate_identity(gy_custodian *c, uint64_t spk_ts,
                                   size_t n_opk);
gy_key_handle gy_custodian_identity(gy_custodian *c);
int gy_custodian_publish_bundle(gy_custodian *c, uint8_t *out, size_t *out_len);
int gy_self_fingerprint(gy_custodian *c, uint8_t *out, size_t *out_len);

/* prekey lifecycle (section 9) */
int gy_custodian_rotate_signed_prekey(gy_custodian *c, uint64_t spk_ts);
int gy_custodian_generate_onetime_prekeys(gy_custodian *c, size_t count);
int gy_custodian_opk_stats(gy_custodian *c,
                           size_t *total, size_t *used, size_t *unused);
int gy_custodian_publish_opk_batch(gy_custodian *c, uint8_t *out, size_t *out_len);
gy_key_handle gy_custodian_find_prekey(gy_custodian *c, int kind, uint32_t pkid);
int gy_custodian_delete_prekey(gy_custodian *c, gy_key_handle h);

/* server-side bundle assembly: a FREE function, no custodian (like
 * gy_appkey_verify). Combines a published IK+SPK registration with one OPK public
 * into the serialized bundle gy_initiate consumes. */
int gy_bundle_assemble(const uint8_t *registration, size_t reg_len,
                       const uint8_t *opk_pub, size_t opk_len,
                       uint8_t *out, size_t *out_len);

/* application signing key (section 10) */
int gy_custodian_generate_appkey(gy_custodian *c, uint64_t expiry,
                                 gy_key_handle *out);
int gy_custodian_rotate_appkey(gy_custodian *c, uint64_t expiry,
                               gy_key_handle *out);
int gy_custodian_export_appkey_cert(gy_custodian *c, gy_key_handle sak,
                                    uint8_t *out, size_t *out_len);
int gy_custodian_sign(gy_custodian *c, gy_key_handle sak,
                      const uint8_t *app_ctx, size_t app_ctx_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len);
/* verify is a free function: the server pins identity_pub out of band, the cert
 * carries the SAK public key + identity signature + expiry. */
int gy_appkey_verify(const uint8_t *identity_pub, size_t identity_pub_len,
                     const uint8_t *cert, size_t cert_len,
                     const uint8_t *app_ctx, size_t app_ctx_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len, uint64_t now);

/* protocol operations take the custodian (formerly gy_ctx) */
int gy_encrypt(gy_custodian *c, const uint8_t *uid, size_t uid_len,
               const uint8_t *did, size_t did_len,
               const uint8_t *pt, size_t pt_len, uint8_t *out, size_t *out_len);
int gy_receive(gy_custodian *c, ...);
int gy_initiate(gy_custodian *c, ...);
/* ... send-staging (gy_send_*), gy_accept_identity, gy_purge_device ... */
```

No function returns a private key. `gy_custodian_publish_bundle` /
`_publish_opk_batch` return public bytes; identity/prekey access returns handles;
`gy_custodian_sign` signs without releasing the SAK; export (which would return
*wrapped* private data) is deferred (section 16).

## 13. Migration from v0.1.1

The v0.1.1 -> v1.0.0 change is deliberate and breaking (D-GEN-9):
- `gy_ctx` becomes `gy_custodian`; `gy_init` splits into `gy_custodian_create`
  (first run, generates and seals) and `gy_custodian_open` (subsequent runs,
  unlocks) with the added credential.
- The store callbacks are unchanged in signature; the blobs they carry become
  sealed. An application upgrading in place must migrate existing cleartext blobs
  once (re-seal under a new custodian), or start fresh.
- Every `gy_*` protocol call takes `gy_custodian *` in place of `gy_ctx *`.
- The wire format (`protocol_version` 0x01) does NOT change; this is an API/ABI
  change, not a wire change.

## 14. Layering placement

Custody spans two layers and adds one core primitive, respecting the one-layer-
down rule:
- **Layer 1 `core/`** gains the Argon2id wrapper (libsodium `crypto_pwhash`); the
  wrap ciphers (AEGIS-256, XChaCha20-Poly1305) are already present in `aead.c`,
  and SAK signing reuses the suite's existing XEdDSA. The KEK-protector seam and
  the wrap/unwrap of blobs are core-level sealing over these primitives.
- **Layer 5 `proto/` + the public API** own the `gy_custodian` object: it holds
  what `gy_ctx` held, drives create/open/lock/close/reset, and seals records at
  the same points the session/proto layers already serialize them. proto/ still
  does no protocol cryptography; the sealing and SAK certification are
  key-management, reached through the same session-layer facades that expose suite
  lookup, key generation, and secure-zero today.

The custodian adds no cross-layer calls: it sits at the API layer and reaches
sealing/signing through core, exactly as the rest of proto/ reaches its few
primitives.

## 15. Constant-time and memory hygiene

- Credential verification is a uniform pass/fail: a wrong credential yields one
  error, with the unwrap authentication-tag check (constant-time, libsodium) as
  the sole discriminator; no distinct "bad password" vs "corrupt blob" oracle.
- The custodian's non-crypto lifecycle errors (handle not found, locked, slots
  exhausted) are kept off the receive/verify path, which retains the single
  uniform `GY_ERR_VERIFY` (D-SES-6.2).
- The KEK and all unlocked material live in `sodium_malloc` / `mlock`'d pages and
  are zeroized on lock, close, reset, and mutation (secure_zero; D-GEN-4).
- Argon2id parameters are stored per blob so they can be raised over time without
  a format change.
- SAK signing is domain-separated (section 10) and uses the suite's constant-time
  XEdDSA; the wrap ciphers inherit libsodium's constant-time guarantee (geryon's
  CT authority); geryon's sealing/signing glue adds no secret-dependent
  branch, length, or index.

## 16. Deferred scope and open sub-decisions

Deferred to later increments (v1.0.x / v1.1.x), NOT in this release:
- Stage 2 hardware backends (OS keychain / TPM / Secure Enclave / HSM) behind the
  KEK-protector seam.
- Full KEK rotation (re-wrap every record under a fresh KEK): needs a KEK-epoch
  plus lazy-re-wrap design to work against the no-enumeration store model.
  Credential change (re-wrap the KEK only) is in scope; rotation is rare (a
  credential change never triggers it) and deferred.
- Backup and export (`gy_custodian_export_*`): a re-wrap under an export target
  (an export passphrase, or a recipient device's public key for provisioning),
  performed inside the library so cleartext never crosses the API.

Open sub-decisions (D-CUST-1; gate only the deferred export/backup work, not this
release): the export target model; the KEK-protector provider shape (fixed
backends vs a pluggable provider callback); and whether portable exports pin
XChaCha20-Poly1305 or use the same caller-selectable AEGIS-256 default as
at-rest blobs (the original hardware-portability rationale for pinning
XChaCha here does not hold, per section 5; if decided in favor of XChaCha at
all, it is a caller-preference question, not a correctness one).

## 17. Validation

Per D-CUST-1, at the API level:
- AEAD KAT round-trips for each wrap cipher; self-describing unwrap opens both
  AEGIS-256 and XChaCha20-Poly1305 blobs by their stored `alg_id`.
- AD-tamper rejection: flipping the `alg_id`, key-type, or tier byte fails
  authentication.
- Credential change preserves all key material and leaves records openable
  (full KEK rotation is deferred, section 16).
- Wrong-credential unlock fails with the uniform error; reset zeroizes and leaves
  the store empty.
- Prekey lifecycle: SPK rotation retains bounded history and old-SPK sessions
  still resolve; OPK replenishment and stats track pool consumption; PKID
  discovery maps server-reported PKIDs to the right local key; deletion zeroizes;
  `gy_bundle_assemble` round-trips (assemble from a published registration + one
  OPK, and `gy_initiate` accepts the result).
- SAK: the certificate verifies against the identity key and rejects past expiry;
  domain separation makes a SAK signature fail verification under a different
  purpose/context; a signature over stale freshness data is the application's to
  reject (documented, tested at the integration level).
- Zeroization on close, lock, and reset (teardown checks, D-GEN-4).
- The full existing public-API property/integration suite passes against the
  custodian in place of `gy_ctx` (behavioral equivalence of the protocol paths).
