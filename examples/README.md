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
  nothing to show here.
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
  and a plaintext mismatch in messaging) and the demo exits nonzero.
- **Build hygiene:** the `demo_include_check` CTest asserts the example includes
  only `geryon.h` and its own headers (never an internal library header). Build
  with `-DGERYON_SANITIZE=address,undefined` for an ASan/UBSan-clean run.

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
