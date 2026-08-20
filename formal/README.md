<!-- Copyright (c) 2026 Jason Crawford -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# formal/ - ProVerif symbolic models

Symbolic verification of geryon's hybrid protocol (HYBRID_SPEC.md),
following the published PQXDH analysis: Bhargavan, Jacomme, Kiefer,
Schmidt, "Formal verification of the PQXDH post-quantum key agreement
protocol", USENIX Security 2024 (cited as BJKS;
<https://github.com/Inria-Prosecco/pqxdh-analysis>). Modeling decisions
are registered in `../docs/decisions/formal.md` (D-FM-1..7).

## Layout

```
formal/
  lib/geryon.pvl     shared symbolic theory (D-FM-1, D-FM-2); every model -lib's this
  models/            one .pv per property family
  README.md          this file - the authoritative verdict/runtime table (D-FM-7)
```

Every `.pv`/`.pvl` file carries a header recording the HYBRID_SPEC
sections modeled, the register decisions consumed, each query's expected
verdict, and its expected runtime on the CI runner class. Models are
ASCII; concatenation in comments is written `||`.

## Toolchain pin (D-FM-7)

ProVerif is pinned to **2.04**, the version BJKS validated their
methodology on. Proofs are reproducible only relative to a prover
version (resolution-strategy changes across releases can turn `proved`
into `cannot be proved`), so the pin is load-bearing and version bumps
are deliberate events: re-run the full suite and record verdict diffs
before changing it.

ProVerif is GPL tooling used only as an external verifier. It is **never
linked into the library** - the same copyleft carve-out that applies to
the test oracles (the library's licensing boundaries).

### Install (runner provisioning)

```sh
opam pin add proverif 2.04
proverif -help        # banner must report 2.04
```

### Run

```sh
scripts/formal_check.sh            # every model, verdicts checked vs the table below
proverif -lib formal/lib/geryon.pvl formal/models/<model>.pv   # a single model
```

`scripts/formal_check.sh` asserts the pinned version first (fail-fast on
drift), then runs each model under a wall-clock cap of 2x its recorded
budget, parses the `RESULT` lines, and compares each query's verdict to
the **Expected** column below. A mismatch fails, including any `cannot be
proved` (a FAILURE for proof files, never a pass) and any `proved` where
a falsification model expects an attack (the D-FM-5 direction check).
Since `formal/lib/geryon.pvl` exists, the runner passes
`-lib formal/lib/geryon.pvl` to every model; `smoke.pv` ignores it and
stays self-contained.

## Authoritative verdict/runtime table

`scripts/formal_check.sh` parses this table. Each row is one query.
**Expected** is `proved` (secrecy/agreement holds: `RESULT ... is true`)
or `attack` (falsification expected: `RESULT ... is false`). **Budget**
is the expected wall-clock on the CI runner class in seconds; the CI cap
is 2x that. Total suite budget is <= 30 minutes (D-FM-7); it is comfortably
under that today and each new model records its own budget as it lands.

| Model file | Query | Expected | Budget (s) | Config |
|------------|-------|----------|-----------:|--------|
| `formal/models/smoke.pv` | `attacker(s)` secrecy (toolchain smoke) | proved | 5 | default |
| `formal/models/lib_smoke.pv` | `attacker(reached)` non-vacuity witness (honest run reaches Bob's accept) | attack | 10 | default |
| `formal/models/x3dh_secrecy.pv` | SK secrecy: `attacker(skwitness)` unless a curve/KEM key is compromised (directly or via BrokenDH/BrokenKEM) or Bob's ML-DSA identity key forges the prekey sig | proved | 120 | default |
| `formal/models/x3dh_secrecy.pv` | parameter agreement: `ResponderAccepted ==> InitiatorStarted` on (suite, interval, aead, both identities) for an honest initiator, unless `CompromiseCurve(IK_A)`, `CompromiseCurve(SPK_B)`, or `BrokenDH` (the §10.8 flight-1 impersonation set; AD_first-bound params only, prekey ids free) | proved | 120 | default |
| `formal/models/x3dh_secrecy.pv` | reachability: OPK-present branch runs (`attacker(reached_opk)`) | attack | 120 | default |
| `formal/models/x3dh_secrecy.pv` | reachability: OPK-absent branch runs (`attacker(reached_noopk)`) | attack | 120 | default |
| `formal/models/agreement.pv` | post-confirmation agreement: `BobPQConfirmed ==> InitiatorPQConfirmed` unless Alice's IK ML-KEM key is compromised or BrokenKEM (NOT defeated by BrokenDH: the PQ-pending -> PQ_CONFIRMED transition, §8.4; injectivity deferred to M4-05 ratchet model) | proved | 120 | default |
| `formal/models/agreement.pv` | pre-confirmation impersonation (EXPECTED attack): flight-1 `ResponderAccepted ==> InitiatorStarted` with the §10.8 set minus BrokenDH; the omitted BrokenDH is the quantum impersonation trace | attack | 120 | default |
| `formal/models/agreement.pv` | non-vacuity: honest three-flight run reaches Bob's PQ-confirm (`attacker(reached_confirmed)`) | attack | 120 | default |
| `formal/models/agreement.pv` | Alice-authenticates-Bob: `AliceAcceptedBob ==> ResponderConfirmed` unless Bob's IK/SPK ML-KEM key is compromised or BrokenKEM (NOT defeated by BrokenDH: symmetric hybrid win) | proved | 120 | default |
| `formal/models/ek_agreement.pv` | ek agreement (D-FM-4.5): same-session `BobEks ==> AliceEks` (same ML-KEM eks) unless `CompromiseCurve(IK_A)`, `CompromiseCurve(SPK_B)`, or BrokenDH; rides on the dual-signed `(curve_pk, mlkem_ek)` pairing, NOT KEM binding. A FALSE here triggers the D-FM-4.5 fork | proved | 120 | default |
| `formal/models/ratchet.pv` | forward secrecy (epoch-1 message key): `attacker(s1) ==> CState1`; the epoch-1 key falls ONLY to a direct epoch-1 state compromise, never to a later-phase compromise (CState3) nor any DH/KEM break (the secret root chain protects it) - past keys safe under future compromise | proved | 120 | default |
| `formal/models/ratchet.pv` | §9 vulnerable window (epoch-2 message key, EXPECTED attack): `attacker(s2)`; under BrokenDH the epoch-1 state compromise propagates through the REUSED ML-KEM keypair (interval=2) - CState1 with CompromiseKEM(rek1) and CompromiseKEM(ika) yield mk2 before the refresh | attack | 120 | default |
| `formal/models/ratchet.pv` | PCS / post-regeneration (epoch-3 message key): `attacker(s3) ==>` BrokenKEMev or (CompromiseKEM(kk) and HealKEM(kk)) or CState3; the HealKEM conjunction pins kk to the refreshed keypair rek2, so the epoch-1 compromise does NOT reach epoch 3 - secrecy restored by the 2-to-3 refresh (§9, §10.2) | proved | 120 | default |
| `formal/models/ratchet.pv` | HE header-key secrecy (D-FM-6): `attacker(hkw) ==> RevealHK`; nhk1 is a distinct one-way split of the same KDF_RK output as rk1/ck1, so a state compromise leaking rk1/ck1 does NOT reveal it - header keys secret unless explicitly revealed | proved | 120 | default |
| `formal/models/ratchet.pv` | HE no feedback into the root chain (D-FM-6): `attacker(rw3) ==>` BrokenKEMev or (CompromiseKEM(kk) and HealKEM(kk)) or CState3; RevealHK is absent from the epoch-3 root key's defeating set - revealing ALL header keys never feeds the root or message chain | proved | 120 | default |
| `formal/models/ratchet.pv` | non-vacuity: the honest 3-epoch run completes (`attacker(reached_ratchet)`) | attack | 120 | default |
| `formal/models/falsify_classical_quantum.pv` | D-FM-5(i) classical suite, no KEM, under BrokenDH: SK secrecy MUST fall (`attacker(secret_sk)`); documents why the hybrid suites exist - contrast x3dh_secrecy.pv where BrokenDH alone does NOT defeat SK | attack | 120 | default |
| `formal/models/falsify_both_broken.pv` | D-FM-5(ii) hybrid suite with BrokenDH AND BrokenKEM: SK secrecy MUST fall (`attacker(secret_sk)`); attacker-model potency check - the fusion has nothing left when neither leg survives (§10.1 hybrid claim's negative side) | attack | 120 | default |
| `formal/models/falsify_unpaired_kem.pv` | D-FM-5(iii) ek agreement with the paired DH REMOVED from each HDH: ProVerif MUST find the BJKS F4 re-encapsulation attack (`BobEks ==> AliceEks` is false); validates the D-FM-1 non-binding KEM theory grants re-encapsulation - its DH-present mirror ek_agreement.pv proves | attack | 120 | default |

The `lib_smoke.pv` row is a **non-vacuity witness**, not a security
claim: `reached` is a private constant Bob outputs only if the honest
handshake completes, so `attack` (`RESULT ... is false`, i.e. reachable)
is the PASS condition. A library typo that makes any honest step
impossible would flip it to `proved` and fail the gate (the D-FM-2
acceptance guard against vacuous models).

### Archived attack traces

**`agreement.pv`, pre-confirmation impersonation (query 2, EXPECTED
`is false`).** With BrokenDH enabled, the attacker leaks the honest
long-term curve secrets (`BrokenDHev`), computes `DH1 = DH(IK_A, SPK_B)`
from public keys, and forges Alice's first flight to Bob. Bob reaches
`ResponderAccepted` for a registered honest initiator identity with no
corresponding honest `InitiatorStarted`; none of the query's classical
defeating events (`CompromiseCurve(IK_A)`, `CompromiseCurve(SPK_B)`)
fire, so the omitted `BrokenDHev` is the attack. This is the §10.8
flight-1 impersonation and the pre-confirmation half of the PQ-pending
state (§8.4). Its post-confirmation counterpart (query 1, `is true`)
shows the SAME BrokenDH attacker cannot reach a flight-3 forgery,
because that needs `confirm_ss` decapsulated to Alice's IK ML-KEM key:
together they bound PQ-pending exactly as `gy_pq_pending()` reports it.

**`ratchet.pv`, §9 vulnerable window (query 2, EXPECTED `is false`).**
Interval is 2, so epochs 1 and 2 REUSE the receiving ML-KEM ratchet
keypair rek1. Under BrokenDH (all ratchet DH outputs public), the
attacker compromises the epoch-1 session state (`CState1`, leaking rk1),
the epoch-1 receiving dk (`CompromiseKEM(rek1)`, giving kem_ss2), and
Alice's identity dk (`CompromiseKEM(ika)`, giving the §8.3 confirm_ss),
then reconstructs hdh2, the epoch-2 KDF_RK output, ck2, and mk2, and
decrypts s2. The compromise PROPAGATES one refresh interval forward. Its
epoch-3 counterpart (query 3, `is true`) shows the SAME attacker cannot
reach mk3: the 2-to-3 refresh mints rek2, so kem_ss3 is secret and the
root chain re-seals - the §9 window is exactly `interval - 1` steps wide,
and §10.2 PCS is restored from epoch 3. The FS query (query 1, `is true`)
is the other bound: a LATER compromise (CState3) never reaches the
epoch-1 message key.

**Falsification models (D-FM-5).** Three deliberately degraded
models whose attack CI ASSERTS ProVerif finds; a `proved` in any of them
is a gate FAILURE (it would mean the attacker model or the KEM encoding
silently lost a capability - the D-FM-5 vacuous-pass guard).

- **`falsify_classical_quantum.pv` (query, `is false`).** A classical
  suite derives SK from the DH legs alone. BrokenDH publishes every DH
  output, the attacker reconstructs the HKDF input (F is public), derives
  SK, and decrypts the witness. No KEM leg means the quantum attacker
  wins outright - the formal statement of why hybrid suites exist. The
  positive contrast is x3dh_secrecy.pv, where BrokenDH alone leaves SK
  secret because the KEM leg survives.
- **`falsify_both_broken.pv` (query, `is false`).** A hybrid handshake
  with BOTH BrokenDH and BrokenKEM reachable: the attacker recovers the
  DH output and, via the leaked ML-KEM dks, decapsulates both kem_ss, so
  the per-pair HDH fusion and thus SK are fully computable. Confirms the
  attacker wins when neither assumption holds (§10.1's negative side);
  its potency is what makes the single-leg proofs meaningful.
- **`falsify_unpaired_kem.pv` (query, `is false`).** ek_agreement.pv with
  the paired DH removed from each HDH. SK becomes a pure function of the
  KEM secrets, which the non-binding theory (D-FM-1) makes
  attacker-choosable: the attacker impersonates an honest initiator to
  Bob with only Bob's public prekeys (crafts ct_ik/ct_spk by
  re-encapsulating fresh secrets, computes the SK Bob will derive, sends
  a first message), so Bob fires BobEks with no matching honest AliceEks
  and no curve compromise. This is the BJKS F4 re-encapsulation attack.
  It validates that the lib's KEM encoding genuinely grants
  re-encapsulation (a `proved` here would expose a silently-binding
  encoding), and its DH-present mirror ek_agreement.pv proves - so the
  paired DH is exactly geryon's F4 defense.
