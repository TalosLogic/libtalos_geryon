<!--
Copyright (c) 2026 Jason Crawford
SPDX-License-Identifier: AGPL-3.0-only
-->

# geryon end-to-end example

A multi-process worked example of the geryon v1.0.0 public API
(`include/geryon.h` only), driving the full messaging lifecycle end to end in
its intended deployment topology: an untrusted relay plus per-client sealed
stores.

This is a **worked example, not a security proof.** The security properties are
established elsewhere by the unit and property test suites. Where the example
touches a security property it *illustrates* it (a visible ciphertext dump, an
opaque store blob); it never asserts or proves it.

## Topology

```
        +-------------+
        | coordinator |   models the UNTRUSTED server:
        |  (no keys)  |   holds no custodian, no private keys; only stores
        +------+------+   published public bundles and relays opaque ciphertext
          pipe | pipe
       +-------+-------+
       |               |
   +---+---+       +---+---+
   | alice |       |  bob  |   each: a gy_custodian + a file-backed sealed store
   +-------+       +-------+
```

The parent process is the coordinator; it forks two clients, Alice and Bob.
**All** traffic goes through the coordinator (there is no direct client-to-client
pipe), so the untrusted-relay property is real and testable. Each client owns a
custodian (the v1.0.0 handle-based key-custody API) and a per-client directory
of library-sealed blobs, so state survives a simulated restart and the
sealed-at-rest property is visible on disk.

## What it demonstrates

The single binary runs the whole lifecycle in phases:

1. **Coordinator + fork + IPC** - length-framed request/response over pipes, a
   `poll` loop, clean fd bookkeeping.
2. **Directory publish/fetch** - `gy_custodian_create` over a file store,
   `gy_custodian_publish_registration` / `_publish_opk_batch`; the coordinator
   slices one OPK with `gy_opk_batch_count` / `gy_opk_batch_get` and assembles a
   bundle with `gy_bundle_assemble`. A printed store blob shows the opaque seal
   envelope.
3. **Identity verification (safety numbers)** - each client prints its own
   `gy_self_fingerprint`, publishes it, and fetches the peer's registration to
   derive the peer's fingerprint locally with `gy_bundle_fingerprint`; the
   derived value must equal the peer's own (the out-of-band comparison a user
   performs by hand). A byte mismatch fails closed. The library makes no trust
   decision here; pinning stays the app's job (`gy_accept_identity`).
4. **One-shot full-bundle publish** - `gy_publish_bundle` emits a complete
   bundle (IK + signed SPK + one OPK) a peer feeds straight to `gy_initiate`
   with no server-side assembly; the relay forwards it verbatim. Shown beside
   the granular directory model (phase 2) so both publish paths are visible.
   Because `gy_publish_bundle` RESERVES an OPK from its own pool, a one-shot
   identity must never also publish through the granular registration+OPK-batch
   path (they would draw from one pool); the phase uses a dedicated throwaway
   identity to honor that. See "Two publish models" below.
5. **X3DH + Double Ratchet messaging** - the fan-out send transaction
   (`gy_send_open` / `gy_prepare` over `gy_target` into `gy_fanout_desc` /
   `gy_encrypt` / `gy_commit`, falling to `gy_initiate` when a target has no
   session), `gy_receive` through the coordinator's mailbox, including a seeded
   out-of-order delivery the recipient recovers via its skip store.
6. **Prekey lifecycle** - OPK depletion via repeated handshakes, replenishment
   (`gy_custodian_generate_onetime_prekeys`) with stats, and SPK rotation
   (`gy_custodian_rotate_signed_prekey`) where the prior SPK still receives.
7. **No-OPK handshake** - a deliberate X3DH handshake against a bundle with NO
   one-time prekey: the coordinator assembles it with `gy_bundle_assemble(...,
   opk_pub == NULL)` and the peer `gy_initiate`s from it. The session is valid
   but has **reduced forward secrecy** (no per-session OPK), so it is clearly
   labeled and not the default. On a dedicated identity so it draws no directory
   OPK and does not touch the main conversation.
8. **SAK-authenticated request + rotation** - `gy_custodian_sign` /
   `gy_appkey_verify`; the custodian-less coordinator pins the client's identity
   key from its published registration (`gy_registration_identity_pub`, TOFU)
   and rejects a forged signature. The SAK signs only the request payload, never
   message content. The phase then rotates the SAK
   (`gy_custodian_rotate_appkey`) and publishes the new cert as active plus the
   retained prior cert: a request signed by the NEW SAK verifies, and one signed
   by the retained PRIOR SAK still verifies within the history window (mirrors
   SPK rotation), while a forged signature is still rejected.
9. **Peer removal** - the initiator purges the peer with `gy_purge_device` and
   then `gy_purge_user` (D-SES-2); after each purge the session and its records
   are zeroized (verified: the peer's fan-out is empty, as for a never-seen
   device), and re-adding the contact is nothing special - an ordinary fresh
   handshake. Runs on the main conversation; each cycle ends in a healthy
   session so the restart phase still resumes.
10. **Session expiration** - an isolated, in-process pair of throwaway
   custodians created with an expiration policy (`gy_config`, D-SES-7; the
   section 4.2 inequality `max_recv > max_send + 2*max_latency` is enforced at
   `gy_custodian_create`). After `max_send` messages the session goes stale:
   `gy_prepare` reports `GY_FANOUT_STALE` and `gy_encrypt` returns
   `GY_ERR_EXPIRED` (never send under a stale device; re-establish instead).
   Expiration is a create-time policy, so this uses dedicated custodians - the
   main alice/bob are created with expiration OFF.
11. **Restart persistence + credential change** - before handing off, the
   client rotates its store passphrase with `gy_custodian_change_credential`
   (only the credential-derived wrap changes; the KEK and all sealed material
   are untouched). It then closes and exits; the coordinator re-forks it with
   fresh pipes; it reopens purely from the sealed store (`gy_custodian_open`, no
   re-handshake) and resumes. Both a clearly-wrong passphrase AND the OLD
   credential are rejected with the same uniform error (no
   bad-credential-vs-corrupt-store oracle), and the NEW credential reopens the
   intact conversation.

## Also available (not demonstrated)

A few public entry points are deliberately left out of this walkthrough to keep
it focused; they are part of the v1.0.0 API and documented in
`include/geryon.h`:

- `gy_pq_pending` - a peer device's PQ-authentication state. In the classical
  `geryon_c25519` suite this always returns `GY_PQ_NOT_APPLICABLE`, so there is
  nothing to show in this binary. The hybrid twin (`geryon_hybrid_demo`, below)
  does exercise it, watching a peer advance `PENDING -> CONFIRMED`.
- `gy_custodian_reset` - a destructive wipe of the LOCAL identity (distinct from
  the peer-record `gy_purge_*` shown in phase 9). Omitted so the demo's stores
  stay intact for the restart phase.
- `gy_custodian_find_prekey` / `gy_custodian_delete_prekey` - advanced
  PKID-level prekey management, below the level this end-to-end walkthrough
  works at (the prekey-lifecycle phase drives replenishment and rotation
  through the higher-level calls instead).

## Two publish models

geryon offers two ways to hand a peer the public material it needs to start a
session, and the demo shows both:

- **Granular directory model** (phase 2): the client publishes a *registration*
  (`gy_custodian_publish_registration`) and an *OPK batch*
  (`gy_custodian_publish_opk_batch`) separately, and an untrusted directory
  server slices ONE OPK per fetch and assembles a bundle itself
  (`gy_bundle_assemble`). This is what a real directory needs: it hands out a
  distinct OPK to each fetcher without the client pre-assembling a bundle per
  OPK. The publishing client does **not** reserve OPKs; the server owns
  one-per-fetch selection.
- **One-shot model** (phase 4): the client calls `gy_publish_bundle` to produce
  a single complete bundle and hands it directly to one peer; the relay forwards
  it as opaque bytes with no assembly. This is simpler when a client hands a
  ready bundle straight to a peer. `gy_publish_bundle` **reserves** the OPK it
  emits from its own pool (and mints a fresh one if the pool is spent), so its
  private key is retained until the peer uses the bundle, at which point
  delete-on-use consumes it.

Because the one-shot path reserves from the same pool the granular path serves,
the two models must **not** be mixed on one identity: reserving an OPK the
directory server still lists would let the server hand out a key the client has
already committed elsewhere. The demo keeps them on separate identities for
exactly this reason (phase 4 uses a dedicated throwaway custodian).

## How to run

```sh
cmake -S . -B build -DGERYON_BUILD_EXAMPLES=ON
cmake --build build
ctest --test-dir build -R demo        # exit 0 = pass
```

Or run the binary directly to watch the phase-by-phase log:

```sh
./build/examples/geryon_demo
```

## Hybrid suite (`geryon_hybrid_demo`)

The same walkthrough ships a second time as `geryon_hybrid_demo`, pinning the
post-quantum-hybrid suite `geryon_h25519_512` (X25519 + ML-KEM-512, XEdDSA +
ML-DSA-44) in place of the classical `geryon_c25519`. This is the whole point of
the pairing: **a consumer selects the suite once, at `gy_custodian_create`, and
every call above it is identical.** The two binaries share `demo_driver.c`,
`client.c`, `coordinator.c`, `filestore.c`, and `demo_ipc.c` byte for byte; they
differ only in the one enum their thin `main` passes. So the entire lifecycle
above - directory publish/fetch, one-shot and no-OPK handshakes, the reordered
ratchet batch, prekey depletion/replenish and SPK rotation, SAK-authenticated
requests, peer removal, expiration, and restart persistence - runs unchanged
under hybrid keys, which also makes the hybrid binary a full regression of the
custody surface under the larger suite.

On top of that it shows the three surfaces the classical suite structurally
cannot:

- **PQ authentication state** (`gy_pq_pending`): the responder watches the
  initiator advance `PENDING -> CONFIRMED`. The responder's first reply
  encapsulates to the initiator's identity ML-KEM key and mixes that secret into
  the root KDF (a deniable KEM confirmation, never a transcript signature); the
  initiator stays classical-strength `PENDING` until its first message after that
  confirmation is received, then reads `CONFIRMED`.
- **Dual-signed prekey bundle**: a hybrid bundle carries both an XEdDSA and an
  ML-DSA signature over the signed prekey, and `gy_initiate` verifies *both* or
  aborts - there is no single-signature acceptance in a hybrid suite. This rides
  the ordinary fetch/initiate path, so it is exercised by the main conversation.
- **ML-KEM refresh boundary**: a long in-process ping-pong drives one session
  past the fixed Double Ratchet ML-KEM refresh interval, so the periodic keypair
  refresh fires mid-conversation and every message still decrypts across it. The
  refresh is internal (the consumer just keeps sending), so this illustrates the
  path rather than asserting on it.

```sh
ctest --test-dir build -R hybrid_demo   # exit 0 = pass
./build/examples/geryon_hybrid_demo     # phase-by-phase log
```

## Determinism and CI-readiness

The demo is a deterministic pass/fail test: it exits nonzero on any plaintext
mismatch, auth failure, or unexpected state; it is non-interactive,
network-free, and bounded in runtime (bounded `poll` waits, no unbounded
blocking). Time enters only through the D-SES-7 clock callback, and message
ordering is fixed by the coordinator's reorder seed (`0x08`, printed at
startup), so a run reproduces. It can be wired into CI unchanged as a regression
test; actually scheduling that is a later decision.

- **Fail-closed check:** `GERYON_DEMO_FAULT=1 ./build/examples/geryon_demo`
  injects a fault (a corrupted derived safety number in the verification phase,
  and a plaintext mismatch in messaging) and the demo exits nonzero. The hybrid
  twin has the same path, wired as the `hybrid_demo_fault` CTest (a `WILL_FAIL`
  test: the injected fault must make the run exit nonzero).
- **Build hygiene:** the `demo_include_check` CTest asserts BOTH examples include
  only `geryon.h` and their own headers (never an internal library header) - one
  check covers every `examples/` source. Build with
  `-DGERYON_SANITIZE=address,undefined` for an ASan/UBSan-clean run; both
  binaries and their CTests join that matrix.

## Release gate

The v1.0.0 public tag is gated on this demo passing (D-GEN-9): the API
is frozen at the key-custody release but is not tagged until this example drives
the full lifecycle end to end. Building it before the tag is deliberate - it
dogfoods the frozen API and surfaces ergonomics gaps while they are cheap. It
already did twice: the SAK-request phase needed a client's raw identity key
with no public accessor, so `gy_registration_identity_pub` was added; and the
identity-verification phase needed a peer's safety number with no public
accessor (only the custodian's own `gy_self_fingerprint` existed), so
`gy_bundle_fingerprint` was added. Both are additive to the frozen API.

# geryon GROUP end-to-end example

A second worked example (`geryon_group_demo`, and its 448-tier twin
`geryon_group_c448_demo`) drives the classical private group system (the [CPZ]
KVAC construction, `include/geryon_group.h` + `include/geryon_group_server.h`)
end to end across **six real processes** (five members plus a second device for
one of them). It reuses the messaging example's
transport verbatim (`demo_ipc.c`, `filestore.c`) and follows the same
methodology: copy the proven call sequences, do not reinvent them. Like the
messaging demo it is a **worked example, not a security proof.**

## What a group is here, and what it is not

Group *messaging* is ordinary pairwise messaging fanned out: there is no group
ratchet. The founder mints a `GroupMasterKey` and hands it to each member
**inside a real 1:1 geryon session** (`gy_initiate` with a
`GROUP_KEY_DISTRIBUTION` envelope as the session's first message), and group
messages are then sent member-to-member over those same pairwise sessions. What
the group *system* adds on top is anonymous, unlinkable membership: KVAC
credentials that let a member prove "I am a member of this group" and enroll an
encrypted UID/ProfileKey in the roster without revealing which member it is.

## Client / server split (an ABI boundary, not just a convention)

- **The client extends the custodian.** Every client operation is a
  `gy_custodian_group_*` call (`include/geryon_group.h`); group secret state
  (the `GroupMasterKey`, credentials, the member's own ProfileKey) seals into
  the custodian's existing sealed store under a reserved record-kind band, right
  alongside the identity/prekey/session records. A group-capable custodian is
  just a custodian whose 16-byte `self_user_id` is the member's account UID.
- **The server is a separate, stateless target.** `geryon_group_server.h`
  depends on **nothing** in `geryon.h`: it holds only the sealed KVAC key
  (`ServerSecretParams`), carries no identity, no prekeys, no sessions, and
  never sees a custodian. A client never links it. So the client/server boundary
  (D-GRP-1/2) is an ABI property, provable by the fact that the two headers share
  no types, not only a symbol-audit convention.
- **The server holds no group secret.** A group's public parameters are deployer
  state the server is *given* per group (`SRV_REGISTER` in the demo); the server
  verifies presentations and issues credentials against them but cannot decrypt
  any UID or ProfileKey. The roster it serves is a list of opaque ciphertexts.

## Topology

```
              +------------------+
              |   coordinator    |  TWO untrusted roles:
              |  group server +  |   - group SERVER: holds ServerSecretParams
              |      relay       |     (geryon_group_server), answers the
              +--+--+--+--+--+---+     section 8.1 RPCs
        pipe  |  |  |  |  |  | pipe    - RELAY: forwards opaque bytes (key
         +----+  |  |  |  |  +----+      distribution + fanned-out group
      +--+--+ +--+-+ ++--+ +--+-+ +--+--+  messages), never parsing them
      | m1  | | m2 | | m3 | | m4 | | m5  | + | m2b |  (m2's 2nd device)
      +-----+ +----+ +----+ +----+ +-----+   +-----+
      founder  member member member invited  companion
```

Five members exercise every role transition: a founder/admin (m1), full members
that self-add (m2, m3, m4), an invited-but-not-joined member (m5), and a
deletion (m4 is removed). One member (m2) additionally runs a **second device**,
"m2b", as a sixth process. Each process has its own file-backed sealed store, so
the persistence and untrusted-relay properties are real.

## Multi-device: membership is per account, delivery is per device

m2's two devices (m2b is the companion) share one 16-byte member UID but have
distinct device ids and separate custodians/stores. That split is the whole
point:

- **Membership is per account.** Only m2's primary performs the KVAC operations
  (credentials, self-add, present, ProfileKey rotation), so the roster holds a
  single entry for m2's UID. The companion performs no group-credential op at
  all.
- **Delivery is per device.** The founder establishes a pairwise session with
  *each* of m2's devices, so both receive the `GroupMasterKey`. Thereafter
  `gy_prepare` over m2's UID naturally returns a descriptor per device, and a
  fanned-out group message is encrypted once per device and relayed to both
  ("m2" and "m2b") in a single send transaction. This is geryon's real Sesame
  fan-out, exercised rather than simulated.

The demo fixes the device topology in `group_demo_proto.h` so every party agrees
without a discovery round trip; a real app learns a peer's device set from the
server (the Sesame device list).

## What it demonstrates

The lifecycle runs in phases, gated by N-party barriers so the roster is in a
known state before any member asserts on it:

1. **Server bring-up and param install** - the server generates
   `ServerSecretParams` (`gy_group_server_create`, sealed under its own KEK) and
   exports `ServerPublicParams` (`gy_group_server_export_public`); every member
   fetches and installs them
   (`gy_custodian_group_install_server_params`, sealed into the custodian).
2. **Group creation + key distribution** - the founder mints the group
   (`gy_custodian_group_create`), registers its public parameters with the
   server (`gy_custodian_group_export_group_public_params`), and distributes the
   `GroupMasterKey` to each member over a fresh 1:1 session
   (`gy_custodian_group_export_key_envelope` carried by `gy_initiate`), and to
   m2's companion device over its own session; each recipient installs it
   (`gy_custodian_group_install_key_envelope`, which returns the 16-byte
   `GroupID`).
3. **Credentials, join, present** - each full member gets an AuthCredential
   (7.1, `gy_custodian_group_receive_auth_credential`) and a blind-issued
   ProfileKeyCredential (7.2/7.3,
   `gy_custodian_group_pk_credential_request` / `_finish`), enrolls its
   encrypted UID+ProfileKey (7.5, `gy_custodian_group_add_member`), and proves
   anonymous membership (7.4, `gy_custodian_group_auth_present`).
4. **ProfileKey rotation** (7.10) - m2 rotates its ProfileKey. This needs a
   FRESH ProfileKeyCredential over the new key (the old one is bound to the old
   key) before presenting; the server replaces only m2's roster entry.
5. **Invite + delete** (7.9 / 7.8) - the founder invites m5 (a UID-only roster
   entry, no ProfileKey yet) and removes m4.
6. **Fetch + decrypt roster** (7.7, `gy_custodian_group_fetch_members`) - every
   surviving member decrypts the roster (3 full + 1 invited) and confirms its
   own entry carries its current ProfileKey (m2's is the rotated one).
7. **Group message fan-out** - the founder sends each surviving member a chain
   of messages over the pairwise sessions; for m2 the chain goes to **both** of
   its devices (one `gy_prepare`/`gy_encrypt` per device). The coordinator
   delivers each chain reordered, so receivers recover it through the ratchet
   skip store (the group analogue of the messaging demo's out-of-order phase).
8. **Identity-key change** (Sesame 3.2) - m3 reinstalls in place: it keeps its
   account UID and device id but creates a fresh identity key on a clean store
   (the real trigger is an app reinstall or a restore onto a wiped device slot,
   not a new device). It re-registers a bundle and signals the founder to
   re-handshake. The founder's `gy_initiate` then fails closed with
   `GY_ERR_KEY_CHANGED`, handing back the old and new fingerprints (the
   safety-number change a real app surfaces for out-of-band re-verification);
   after `gy_accept_identity` the re-initiation succeeds and the conversation
   resumes. Only m1 and m3 take part; the rest proceed to teardown.

## Depth checks (the example doubles as a regression)

Three members carry extra assertions that a real app's tests would want:

- **Tampered presentation rejected** - m3 corrupts one byte of a valid
  AuthCredentialPresentation and confirms the server rejects it as the uniform
  `GY_ERR_VERIFY` (no oracle), the group analogue of the messaging demo's
  forged-request rejection.
- **Sealed group state survives restart** - m3 closes its custodian and reopens
  it from the on-disk store (`gy_custodian_group_open`), then re-presents
  membership using only state recovered from disk (group master secret + stored
  AuthCredential), and later still decrypts the fanned-out message over its
  restored pairwise session.
- **Daily-credential rotation** - m3 rolls its clock forward one day, confirms
  the day-bound AuthCredential is now `GY_ERR_EXPIRED` (spec-true daily model,
  D-GRP-7), then re-issues a fresh credential for the new day and presents it.

## Two patterns worth copying

- **The clock (D-SES-7).** geryon never reads a system clock; time enters only
  through the callback a consumer supplies at `gy_custodian_create`. The demo's
  `demo_clock_now` calls POSIX `time(2)` for real and returns epoch seconds; the
  app owns a small ctx it hands the library by pointer (here it also carries a
  test-only offset the rotation check bumps to move a day forward without
  waiting). A real app wires the callback to its trusted clock and leaves the
  offset out.
- **Reopen for group use.** `gy_custodian_open` (the frozen v1.0.0 custody ABI)
  takes no clock, and messaging never needs one after open. The daily group
  credentials do, so the group vertical adds `gy_custodian_group_open`: same
  parameters plus the clock, calling `gy_custodian_open` internally and
  reinstalling the clock. Reopen a group member with this, not the plain open.

## Scope

The group API is **classical-suite only** (`geryon_c25519`, `geryon_c448`); a
hybrid-suite custodian's group calls return `GY_ERR_UNSUPPORTED`. Post-quantum
groups are a separate construction with their own API, the quantum-safe private
group system (QSPGS), demonstrated below. As with the
messaging demo, building this against the still-unfrozen group API dogfooded it
and surfaced additive gaps (the `gy_custodian_group_open` clock reopen above,
`gy_custodian_group_export_group_public_params`, the server-side
`gy_group_server_member_list_encode` roster assembly, and passing the group
public parameters into the server verify calls).

```sh
ctest --test-dir build -R "group_demo|group_c448_demo"   # exit 0 = pass
./build/examples/geryon_group_demo                        # phase-by-phase log
```

# geryon QUANTUM-SAFE GROUP end-to-end example

A third worked example (`geryon_qsgroup_demo`, and its 448-tier twin
`geryon_qsgroup_h448_demo`) drives the quantum-safe private group system (QSPGS,
the [CFG+] design, `include/geryon_qspgs.h` + `include/geryon_qsgroups_server.h`)
end to end across **five real processes** (a founder/admin plus four members).
Like the other examples it reuses the untrusted-relay topology: the parent is
the coordinator (object store + relay), it forks the members, and all traffic
goes through it with no direct member-to-member path. It is a **worked example,
not a security proof.** The single driver (`qsgroup_demo_run`) is suite-agnostic
across the two hybrid tiers; the two binaries differ only in the
`GY_SUITE_*` value their thin main passes.

## What a quantum-safe group is here, and what it is not

As with the classical group type, group *messaging* is ordinary pairwise
messaging fanned out (no group ratchet): members become acquainted, stand up 1:1
sessions, and the group key rides those sessions. What QSPGS adds is
**unlinkable post-quantum membership**: each member presents under a per-version
rerandomized ML-DSA verification key (KR-ML-DSA), the encrypted member list
advances through admin-signed cores and member-appended appendix lines, and the
server verifies cores, appendix lines, and bearer tokens without holding any
group secret. The identity key certifies each member's base verification key and
per-epoch user key, so membership binds to the custodied identity with no
transcript signature.

## Client / server split

As in the classical example this is an ABI boundary, not just a convention: the
client is `gy_custodian_qsgroup_*` (`include/geryon_qspgs.h`), sealing all group
state (the group key, per-epoch user keys, the member's rerandomizable signing
key) into the existing custodian store; the server
(`include/geryon_qsgroups_server.h`) is a separate, stateless target that holds
only the service keys and verifies submissions. A client binary never links the
server target (`geryon_qsgroups_server`), and an `nm` scope audit backs this.

## What it demonstrates

The lifecycle runs in barrier-gated phases (A, B, D, E, F, G, H, I):

- **A / B - acquaintance and pairwise sessions.** Members exchange registration
  and user keys (the identity-signed reguser / invaccept certifications), verify
  each other, and stand up 1:1 geryon sessions that persist for group-key
  delivery and group messaging.
- **D - group creation and invite.** The founder creates the group
  (`gy_custodian_qsgroup_create`, pinning the format epoch and field AEAD),
  invites each member (a PENDING roster entry), and delivers the group key over
  the pairwise session; each member accepts and settles into the roster.
- **E - rotating edit + removal.** The founder opens a join link, removes a
  member, and rotates the group key; surviving members install the rotated key
  and the removed member confirms its fetch now fails.
- **F - group message fan-out.** The founder fans a chain of group messages out
  over the pairwise sessions; receivers recover the reordered chain through the
  ratchet skip store.
- **G / H - admin operations and appendix lines.** Admin edits end to end, plus
  member-appended appendix lines (refresh, modAttr, addUser) that every member
  folds via Fetch and an admin folds via Consolidate.
- **I - join-link resurrection.** The removed member rejoins through the
  surviving join link (JoinViaLink), which the design keeps valid across the
  key rotation.

## Scope

QSPGS is **hybrid-suite only** (`geryon_h25519_512`, `geryon_h448_1024`); it
composes KR-ML-DSA, which needs the hybrid tier's ML-DSA. It ships side by side
with the classical group type, not as a replacement.

```sh
ctest --test-dir build -R "qsgroup_demo|qsgroup_h448_demo"   # exit 0 = pass
./build/examples/geryon_qsgroup_demo                          # phase-by-phase log
```
