# Formal Modeling Decisions (M4)

**Scope:** the ProVerif models in `formal/` (the M4 milestone;
../HYBRID_SPEC.md Open items). These decisions fix what is modeled,
the symbolic theories, the query set, and the toolchain, so the
models never improvise. Register conventions and the full index live
in [README.md](README.md).

Methodology follows the published PQXDH analysis: Bhargavan, Jacomme,
Kiefer, Schmidt, "Formal verification of the PQXDH post-quantum key
agreement protocol for end-to-end secure messaging", USENIX Security
2024; models at <https://github.com/Inria-Prosecco/pqxdh-analysis>.
Cited below as BJKS. Roles per HYBRID_SPEC §1.3: Bob publishes the
prekey bundle, Alice sends the initial message.

Out of scope for M4, restating HYBRID_SPEC Open items: deniability
(paper argument, HYBRID_SPEC §8.5) and CryptoVerif computational
proofs (possible later phase).

### D-FM-1: KEM symbolic theory (PKE-style, non-binding)

- **Spec gap:** symbolic KEM encodings differ in whether the shared
  secret term is bound to the encapsulation key, and the choice
  silently decides whether ML-KEM's internal ek binding
  (ss = G(m ‖ H(ek)), FIPS 203) is credited by every proof.
- **Decision:** model the KEM as public-key encryption of a fresh
  secret, the BJKS encoding:

  ```
  fun kempk(kempriv):kempub.
  fun penc(kempub,bitstring):bitstring.
  fun pdec(kempriv,bitstring):bitstring
  reduc forall sk:kempriv,m:bitstring;
        pdec(sk,penc(kempk(sk),m)) = m.

  letfun pqkem_enc(pk:kempub) = new ss:bitstring; (penc(pk,ss),ss).
  ```

  `penc` is a public constructor, so an attacker who knows an `ss`
  can re-encapsulate it to any key: the model credits the KEM with
  IND-CCA only, no ek or ct binding. No binding variant is a
  deliverable; if one is written for debugging it must not back any
  claimed result.
- **Rationale:** BJKS finding F4 (re-encapsulation, loss of PQPK
  session independence) is only visible under a non-binding theory;
  PQXDH needed Kyber's internal binding, proved separately as a
  bespoke KEM collision-resistance notion, to close it. Geryon must
  not depend on that internal property (D-GEN-3's stance applied to
  the model). The function-style encoding (ss as a function of pk
  and coins) is implicitly binding and would prove ek agreement
  vacuously. FIPS 203 ML-KEM binds ek but not ct (the round-3
  H(ct) KDF input was dropped), so the deployed primitive is
  strictly stronger than the model in one direction and the model
  never over-credits it.
- **Validation:** the D-FM-5 falsification model (iii) must
  reproduce the F4 attack, confirming the theory actually grants
  the re-encapsulation capability.

### D-FM-2: attacker classes (broken-primitive events, single model)

- **Spec gap:** the M4 scope defines the quantum attacker as "all ECDH
  secrets revealed" but leaves the model structure open.
- **Decision:** one model per property family, with primitive
  breakage as attacker processes gated by events (BJKS pattern): a
  `BrokenDH` process reveals the discrete log of any point via a
  `[private]` reduc after emitting `event BrokenDH`; `BrokenKEM`
  likewise for KEM private keys. Queries are event-conditioned
  ("attacker(SK) ==> honest-compromise events or BrokenDH ...") so
  each states exactly which compromise set defeats it. CPP toggles
  (`#ifdef UnbreakableDH` / `UnbreakableKEM`) select the CI
  configurations.
- **Rationale:** event conditioning captures KCI, FS, and hybridity
  in one optimal query per property instead of a matrix of model
  files, and matches the methodology the query set is derived from.
  The quantum attacker is exactly the configuration
  where `BrokenDH` is enabled.
- **Validation:** `formal/README.md` lists every CI configuration
  with its expected verdict; CI runs them all.

### D-FM-3: ratchet bound (3 epochs, two mechanisms)

- **Spec gap:** the M4 scope says "2-3 epochs, one refresh boundary,
  confirmation chain"; the exact bound and its layout are open.
- **Decision:** 3 epochs, where an epoch is one DH ratchet step (one
  KDF_RK application pair, HYBRID_SPEC §7.3). Layout:
  - **Epochs 1-2, PQ-IK confirmation chain:** flight 1 is Alice's
    initial message (PQ-pending: she proves her classical identity
    via DH1 but nothing about her identity ML-KEM key); flight 2 is
    Bob's reply carrying the confirmation encapsulation to Alice's
    identity ML-KEM key (§8.3); flight 3 is Alice's first
    post-confirmation message, where `InitiatorPQConfirmed` fires.
    Bob is never PQ-pending: flight 1 already encapsulates to his
    identity ML-KEM key.
  - **Epoch 2 to 3 boundary, keypair refresh:** the model's
    `mlkem_refresh_interval` is set to 2 so one ML-KEM ratchet
    keypair regeneration falls inside the bound.

  Compromise timing uses ProVerif phases aligned to the epoch
  boundaries.
- **Rationale:** encapsulation is fresh at every ratchet step; the
  interval controls keypair regeneration only (§7.3), so the §9
  vulnerable-window FS/PCS claims are only observable across a
  regeneration boundary. Two epochs would suffice for the
  confirmation chain alone; the third buys the refresh-window
  queries. More epochs add termination risk with no new symbolic
  behavior.
- **Validation:** the FS/PCS queries reference the phase boundaries
  at epochs 1/2 and 2/3.
- **Finding (2026-08-10, ratchet.pv):** the 3-epoch model realizes
  this layout with ProVerif phases 0/1/2 at epochs 1/2/3 and interval=2
  (rek1 reused across epochs 1-2, rek2 minted at the 2->3 boundary). The
  ratchet-step DH contribution is modeled as an OPAQUE per-step shared
  secret rather than an `smul` group element: the agreement-model finding is that
  raw DH exponents across multiple steps plus the commutation equation
  diverge the clause set, and FS/PCS security content is carried by the
  KDF-chain structure and per-step fresh entropy, not DH algebra (each
  step still fuses a fresh dh with a fresh kem_ss via the §3.1 combiner,
  so hybridity holds). The KEM ratchet keypairs stay concrete (the §9
  window is a KEM-keypair-reuse property). The model runs under the
  quantum attacker (BrokenDH on throughout); classical-attacker
  ratchet secrecy is not re-proved here (x3dh_secrecy.pv). No
  manual axioms were needed (D-FM-3 termination expectation met).

### D-FM-4: query set

- **Spec gap:** the M4 scope names the query families; the precise
  properties, events, and expected outcomes are open.
- **Decision:** events `InitiatorStarted`, `ResponderAccepted`,
  `ResponderConfirmed`, `InitiatorPQConfirmed`, each carrying the
  full parameter tuple (suite_id, refresh interval, aead_id, both
  identity keys, the SPK/OPK identifiers used). Queries, all run for
  both OPK-present and OPK-absent handshakes:
  1. **SK secrecy, classical attacker:** compromise-conditioned
     optimal query (BJKS style: the query names the exact
     compromise sets that defeat it).
  2. **SK secrecy under BrokenDH (the hybrid claim):** must hold
     unless the corresponding KEM secrets are also compromised.
  3. **Injective agreement:** Bob authenticates Alice's classical
     identity from flight 1; Alice's PQ identity is authenticated
     only from `InitiatorPQConfirmed`. Initiator impersonation
     under BrokenDH before that event is an EXPECTED attack (the
     PQ-pending state, §8.4, which the API exposes); after it,
     agreement must hold. Alice authenticates Bob from flight 2
     under both attacker classes.
  4. **Parameter agreement:** suite_id, refresh interval, aead_id
     (bound via `AD_first`, §6.6-6.7).
  5. **ek agreement (the F4 class):** if both parties compute the
     same SK they agree on every ML-KEM public key used. Expected
     to follow from per-pair fusion plus the dual-signed pairing
     (same SK implies same HDH values implies same DH values
     implies same curve keys implies, via the signed pairing, same
     KEM eks) WITHOUT crediting KEM binding. This is a result to
     be established, not assumed; it is where geryon's
     per-KEM-paired-DH design should prove stronger than PQXDH's
     lone KEM prekey. Named fallback if disproved: hash the KEM
     cts/eks into the KDF input (BJKS revision-3 proposal P2, a
     spec change with no wire impact), adopted only if forced.

  ct agreement is explicitly NOT a query: it is unprovable under
  D-FM-1 by design (re-encapsulation yields ct' with the same ss).
  The corresponding obligation is a review check, recorded here:
  nothing downstream may key off ciphertext bytes as an identifier
  (§6.8 base-key dedupe uses the base key, not ct - verify this
  stays true through M3/M5 review).
- **Rationale:** items 1-4 are the milestone scope made precise;
  item 5 is the BJKS F4 lesson applied to geryon's own hybrid
  design, and the reason D-FM-1 chooses the non-binding theory.
- **Validation:** each query's expected verdict (proved, or attack
  found where marked EXPECTED) is recorded per file and enforced by
  CI (D-FM-7).
- **Amendment (2026-07-07, tier independence):** the models are
  symbolic and parameter-independent: suite ids, key sizes, and
  KEM/DSA parameter sets appear only as free constants, so the
  proofs cover geryon_h448_1024 exactly as they cover
  geryon_h25519_512. M7 therefore requires NO model re-run or
  re-instantiation; the parameter-agreement queries (item 4)
  already prove suite binding for any suite constant. Recorded so
  M7's plan can cite it instead of re-opening the question.
- **Finding (2026-08-10, parameter agreement):** the
  `x3dh_secrecy.pv` agreement query (item 4) proved only after its
  defeating set was tightened to
  `CompromiseCurve(IK_A) || CompromiseCurve(SPK_B) || BrokenDH`. The
  `SPK_B` disjunct was a defeating set HYBRID_SPEC §10 did not
  acknowledge: compromise of a responder's signed-prekey private key
  lets an attacker forge an initiator's first flight, since
  `DH1 = DH(IK_A, SPK_B)` is the sole initiator-authenticating value
  and either key defeats it. Handled spec-first: HYBRID_SPEC §10.8 now
  states the property (flight-1 impersonation, contained to one flight
  by the §8.3-8.4 confirmation in hybrid suites, unbounded in classical
  suites, OPK-independent). This is the classical, flight-1 instance of
  the D-FM-4.3 pre-confirmation impersonation; the containment bound is
  proved in agreement.pv.
- **Amendment (2026-08-10, injective agreement scope):** D-FM-4.3's
  post-confirmation agreement is proved NON-injectively in agreement.pv.
  The INJECTIVE (replay-free) form moves to
  ratchet.pv: injectivity rests on the §6.8 base-key dedupe and the
  §7.2 ratchet message counters, stateful session-layer defenses.
  ProVerif tables cannot express the atomic test-and-set those need, so
  at the handshake layer a replay yields two responder confirms for one
  initiator - an artifact of unmodeled replay protection, not an attack.
  The stateful ratchet model is the correct home for injective agreement.
- **Resolution (2026-08-10, ratchet.pv):** injective agreement is
  RESOLVED as a documented modeling boundary, NOT mechanized. Confirming
  the above at the ratchet layer: injectivity rests on the §6.8 base-key
  dedupe and §7.2 monotonic message counters, an atomic test-and-set that
  ProVerif's applied-pi fragment cannot express (tables give lookup, not
  atomicity), so a mechanized injective query would report a spurious
  replay the unmodeled counter defeats - a false attack, not a finding.
  ratchet.pv therefore mechanizes the properties that ARE in the fragment
  (secrecy, FS, the §9 window, PCS, HE derivation) and the injective
  property is carried by the prose argument here plus the §8.5
  replay-hardening argument. No third model attempts it.

### D-FM-5: expected-attack (falsification) models

- **Spec gap:** nothing in the milestone scope demands the models be able to
  fail; a model that proves everything may be modeling nothing.
- **Decision:** ship deliberately degraded models where CI asserts
  ProVerif FINDS the attack:
  1. classical suite under BrokenDH (documents why hybrid exists);
  2. hybrid suite with BrokenDH and BrokenKEM both enabled
     (confirms the attacker model is potent enough to win when it
     should);
  3. per-pair fusion with the paired DH removed from the HDH
     computation, which must reproduce the BJKS F4
     re-encapsulation attack (validates the D-FM-1 encoding);
  plus the D-FM-4.3 pre-confirmation initiator impersonation, which
  lives in the main model as an expected-attack query.
- **Rationale:** falsification pins both attacker power and encoding
  fidelity; without it a typo that strips attacker capability
  produces silent vacuous passes.
- **Validation:** CI treats "query is false, attack found" as PASS
  for these files, per the recorded expected verdicts.
- **Finding (2026-08-10, falsification models):** all three falsification models find
  their attacks under 2.04 (formal/models/falsify_classical_quantum.pv,
  falsify_both_broken.pv, falsify_unpaired_kem.pv; each RESULT `is
  false`). Model (iii) additionally surfaced a MODELING bug shared with
  ek_agreement.pv: the refresh interval `iv` had been a restricted
  `new iv`, so the responder's `hflag(=iv,=ae)` check spuriously
  authenticated the session on a secret the attacker could not forge -
  which MASKED the F4 attack (model iii proved instead of breaking) and,
  in ek_agreement.pv, made the ek-agreement proof VACUOUS (Bob's
  handshake was unreachable, `BobEks` never fired). Fix, spec-first: `iv`
  is public policy (signed in the prekey flags §5.3, carried in `hf` on
  the wire §6.6), so both models now `out(pub, iv)`. After the fix model
  (iii) finds the F4 attack (`is false`) and ek_agreement.pv still proves
  (`is true`) NON-vacuously - confirming the D-FM-4.5 result rests on the
  paired DH, not on an accidental `iv` secret. The general lesson (a
  restricted name that stands in for public wire/policy data can silently
  authenticate and hide attacks) is a review check for future models.

### D-FM-6: header encryption scope (derivation only)

- **Spec gap:** HE mechanics land in HYBRID_SPEC §7.8;
  how much of HE the formal model covers is open.
- **Decision:** model header keys only as the third KDF_RK output
  (`nhk`, §7.3, D-DR-14). Queries: header-key compromise must not
  reach message keys or the root key (no feedback path into the
  root chain), and header keys are secret under the same conditions
  as chain keys. Trial decryption, routing, and header privacy as a
  metadata property are out of model scope (argued in prose in the
  spec).
- **Rationale:** this captures the property with security content
  (HE cannot weaken the ratchet) at a fraction of the model
  complexity; routing is Sesame plumbing with no secrecy content.
- **Dependency:** the modeling work depends on the merged
  §7.8 text (available from the start of M2, well before M4).
- **Validation (2026-08-10, ratchet.pv):** both HE queries prove.
  Header-key secrecy (query 4) and the no-feedback property (query 5)
  both rest on the lib's `nhk_split` being a one-way constructor DISJOINT
  from `rk_split`/`ck_split` over the same 96-byte KDF_RK output: leaking
  the header keys (`RevealHK`) never appears in the root/message key
  defeating sets, and leaking the root/chain state (`CState`) never
  reveals the header key. The D-FM-6 review obligation ("no HE feedback
  into the root chain") is thus discharged syntactically, exactly as the
  lib header claims - not merely asserted in prose.

### D-FM-7: toolchain pin and CI gate

- **Spec gap:** the project dependency table lists ProVerif (GPL,
  tooling carve-out) with no pin; CI semantics for formal proofs are
  undefined.
- **Decision:** ProVerif pinned to **2.04**, the version BJKS used,
  installed via `opam pin` in the CI image; the pin, exact
  invocation, and per-file expected runtimes are recorded in
  `formal/README.md` and the project dependency table. ProVerif
  never links into the library (same carve-out as oracle tooling).
  The formal CI job is a **merge-into-master gate**: required on MRs
  targeting master, not run (or advisory only) on feature-branch
  pipelines. A file fails the gate on any verdict other than its
  recorded expected verdict; `cannot be proved` is a FAILURE for
  proof files, never a warning. Version bumps are deliberate
  events: re-run the full suite and record verdict diffs before
  changing the pin.
- **Rationale:** proofs are reproducible only relative to a prover
  version (resolution-strategy changes across releases can turn
  proved into cannot-be-proved); 2.04 is the version the adopted
  methodology was validated on. Master-gating keeps feature
  development unblocked while making unproved models unmergeable,
  per the standing gate (M4 passes before any M5 hybrid
  kex code merges).
- **Validation:** the CI job itself; `formal/README.md` is the
  authoritative verdict/runtime table.
