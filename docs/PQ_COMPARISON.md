# Post-Quantum Signal: Signal's Approach vs. the Talos Hybrid Approach

**Date:** July 2026
**Status:** Analysis / design input for docs/HYBRID_SPEC.md
**Sources reviewed:**

| Side | Document | File |
|------|----------|------|
| Signal | The PQXDH Key Agreement Protocol, rev 3 (2024-01-23) | signal.org/docs |
| Signal | The ML-KEM Braid Protocol, rev 1 (2025-09-26) | signal.org/docs |
| Talos | Hybrid Key Structure Specification v1.0 | archive repo `docs/specs/hybrid_keys.md` |
| Talos | Hybrid X3DH Protocol Specification v1.0 | archive repo `docs/specs/hybrid_x3dh.md` |
| Talos | Hybrid Double Ratchet Specification v1.1 | archive repo `docs/specs/hybrid_double_ratchet.md` |
| Reference | Hybrid key exchange in SSH (mlkem768x25519-sha256) | datatracker.ietf.org (draft-ietf-sshm-mlkem-hybrid-kex) |

The Talos rows cite the predecessor library's specs, which live in
the archive repo (`~/Source/libtalos_signal_archive/`), not in this
repository.

---

## 1. Executive Summary

Signal and Talos both hybridize the Signal protocol with ML-KEM, but they sit at
opposite ends of a bandwidth-vs-immediacy trade-off:

- **Signal** adds the *minimum* post-quantum material needed to defeat
  harvest-now-decrypt-later: one KEM in the handshake (PQXDH), and a *sparse*
  KEM ratchet (ML-KEM Braid) that trickles KEM material across many messages in
  ~32-byte chunks. Per-message overhead is tiny; PQ security arrives slowly and
  authentication remains entirely classical.

- **Talos** hybridizes *everything*: every asymmetric key (identity, signed
  prekey, one-time prekey) is an X25519+ML-KEM pair, prekeys carry dual
  XEdDSA+ML-DSA signatures, and every Double Ratchet step mixes in a fresh KEM
  secret. PQ forward secrecy and post-compromise security are immediate, and
  the responder gets post-quantum implicit authentication - at the cost of
  ~1.1-2.3 KB of overhead on every message and ~6.5 KB initial messages.

Neither is strictly better. Signal optimizes for a billion phones on bad
networks; Talos optimizes for security posture and implementation simplicity.
Section 6 summarizes what geryon should take from each.

> **Note on parameter sets:** the Talos specs (archive repo
> `docs/specs/`) are out of date; the authoritative reference is the
> archived implementation at `~/Source/libtalos_signal_archive/`.
> Confirmed from that code: the hybrid
> modules use **ML-KEM-512 + ML-DSA-44** (800-byte pk, 768-byte ct,
> 2420-byte signatures), the signed-prekey signatures cover
> `encoded_pubkey || timestamp_be64` (both schemes over identical bytes),
> the combiner is the per-key paired construction (matching the spec §4.1,
> classical-first order), the refresh interval travels as a `hybrid_flag`
> in the initial message (range-checked [1,100], reserved bits
> must-be-zero, authenticated via a 68-byte first-message AD), and every
> DR message appends its full encoded header to the AEAD AD. The specs'
> ML-KEM-768/ML-DSA-65 values are historical, and this analysis uses spec
> sizes only when quoting the spec documents themselves. Geryon's pinned
> suites: **ML-KEM-512 + ML-DSA-44** with X25519;
> **ML-KEM-1024 + ML-DSA-87** with X448 (the archive's stated intent was
> ML-KEM-768 for X448; geryon deliberately chose 1024 - see takeaway 7).

---

## 2. What Each Design Actually Does

### 2.1 Signal: PQXDH (handshake)

PQXDH is classical X3DH plus **exactly one KEM encapsulation**:

- Bob publishes, in addition to classical keys: a signed **last-resort** KEM
  prekey (`PQSPK`) and optionally signed **one-time** KEM prekeys (`PQOPK`),
  all signed with the classical identity key via XEdDSA.
- Alice encapsulates once to whichever KEM prekey the server hands her:
  `SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)` - the KEM secret is appended to
  the pooled X3DH input of a single HKDF call.
- The HKDF info string binds all four protocol parameters
  (`info_curve_hash_pqkem`, e.g. `MyProtocol_CURVE25519_SHA-512_CRYSTALS-KYBER-1024`),
  and `EncodeEC`/`EncodeKEM` outputs are required to be pairwise disjoint.
- **Authentication is unchanged**: only XEdDSA over the discrete log problem.
  The spec is explicit (§4.8) that an *active* quantum adversary can
  impersonate either party, and that adding a PQ identity signature key was
  considered and rejected (it would protect Alice but not give mutual
  authentication, and no standardized PQ deniable mutual auth exists).
- Mitigations documented for KEM re-encapsulation attacks (§4.12): Kyber/ML-KEM
  hashes the public key into the shared secret; for generic IND-CCA KEMs the
  KEM public key must be added to the AEAD associated data.
- Formally analyzed in ProVerif and CryptoVerif (§4, refs [11]-[13]).

### 2.2 Signal: ML-KEM Braid / SPQR (ratchet)

The Double Ratchet itself is made post-quantum by a separate **Sparse
Continuous Key Agreement (SCKA)** protocol braided into the root KDF:

- A full ML-KEM ping-pong (keygen → send encapsulation key → encapsulate →
  return ciphertext) is spread across **many messages** using erasure-coded
  chunks (Reed-Solomon over GF(2^16), ~32-byte codewords) piggybacked on
  normal Double Ratchet messages.
- It exploits a **non-standard incremental ML-KEM interface**: `KeyGen` split
  into seed + vector, `Encaps1`/`Encaps2` splitting the ciphertext into `ct1`
  (compressed-public-key part, computable from just the 32-byte seed and the
  key hash) and `ct2` (reconciliation part). This lets `ct1` and the
  encapsulation-key vector travel in *parallel*, cutting round trips.
- Each completed exchange emits an **epoch key** that is mixed into the Double
  Ratchet root chain (the "Triple Ratchet" construction). The classical DH
  ratchet continues to run unmodified alongside.
- An 11-state state machine per party governs the exchange; a ratcheted
  authenticator (HKDF-chained MAC keys) optionally authenticates braid
  messages internally.
- With ML-KEM-768 and 32-byte chunks, one epoch costs ~74 messages
  (3 header + 30 ct1 + 36 ek_vector + 5 ct2, §3.4). The spec's security metric
  is the **vulnerable message set**: how many messages pass between compromise
  and PQ healing. It is explicitly *unbounded* if one party goes silent.
- Formally verified in ProVerif (correctness, FS, PCS, mutual auth of the
  braid itself); design descends from the peer-reviewed Triple Ratchet paper
  (eprint 2025/078).

### 2.3 Talos: hybrid keys, hybrid X3DH, hybrid Double Ratchet

**Keys** (`hybrid_keys.md`): every non-ephemeral key is a paired
X25519+ML-KEM-768 structure (1224 bytes public); identity keys additionally
carry an ML-DSA-65 verification key (3176 bytes public). Keys are addressed by
a 4-byte truncated-SHA-256 PKID.

**Handshake** (`hybrid_x3dh.md`): X3DH's shape is preserved, but Alice performs
**one KEM encapsulation per recipient key** - to Bob's IK, SPK, and OPK - in
addition to the 3-4 classical DH operations. Each DH output is paired with the
KEM secret *from the same recipient key* before pooling:

```
HDH1 = SHA-256(DH1 || KEM_SPK)   HDH3 = SHA-256(DH3 || KEM_SPK)
HDH2 = SHA-256(DH2 || KEM_IK)    HDH4 = SHA-256(DH4 || KEM_OPK)   [if OPK]
SK   = HKDF(salt=0, IKM = F || HDH1 || HDH2 || HDH3 [|| HDH4], info="TalosSignal")
```

The per-pair SHA-256 combiner follows the IETF SSH hybrid draft (§2.3.3/2.4).
Alice's ephemeral key EK stays classical-only to save ~3 KB per initial
message. Signed prekeys carry **dual signatures** (XEdDSA + ML-DSA-65) and
verification requires both to pass, with diagnostic codes distinguishing which
scheme failed. AEAD associated data hashes the *full* hybrid identity keys of
both parties.

**Ratchet** (`hybrid_double_ratchet.md`): the classical Double Ratchet is kept
intact except that every DH ratchet step computes
`hdh = SHA-256(X25519_output || ML-KEM_shared_secret)` and feeds that to the
unchanged `KDF_RK`. Every message header carries the 1088-byte KEM ciphertext
from the last ratchet step; the sender's 1184-byte ML-KEM public key is
included only every `mlkem_refresh_interval` ratchets (default 20), giving
1132-byte compact headers and 2316-byte full headers.

---

## 3. Signal's Approach: Pros and Cons

### Pros

1. **Minimal bandwidth.** PQXDH adds one KEM ciphertext (~1.1-1.6 KB) to the
   initial message; the braid adds ~32-64 bytes per Double Ratchet message.
   Total per-message overhead stays within a few percent of classical Signal.
   This is the only approach viable for Signal's deployment reality (metered
   mobile data, huge group fan-out, linked devices).

2. **Formally verified, peer-reviewed.** PQXDH has ProVerif and CryptoVerif
   analyses; the braid has ProVerif models and derives from a published
   academic construction (Triple Ratchet). For a protocol this subtle, that is
   a major assurance advantage no bespoke design can claim.

3. **Careful KDF hygiene.** The suite (curve, hash, KEM, app id) is bound into
   the HKDF info string; encoding ranges are disjoint; re-encapsulation
   attacks are analyzed with a concrete mitigation. Transcripts from different
   parameterizations cannot collide.

4. **Graceful degradation under loss.** Erasure/fountain coding means braid
   progress survives arbitrary message drops and reordering; any N codewords
   reconstruct the payload. The vulnerable-message-set framing gives an honest,
   measurable security metric.

5. **Deniability preserved by design.** No PQ signatures are introduced
   anywhere; the deniability analysis of X3DH carries over (with a Plaintext
   Awareness caveat for the KEM, discussed in §4.4 of the PQXDH spec).

### Cons

1. **Authentication is entirely classical.** An active quantum adversary can
   impersonate anyone (PQXDH §4.8 says so outright). A quantum-capable
   malicious server can substitute KEM prekeys because they are signed only
   with XEdDSA. Signal accepts this deliberately; it is still a real gap. The
   protection delivered today is confidentiality against
   harvest-now-decrypt-later, nothing more.

2. **Slow PQ healing in the ratchet.** One braid epoch needs ~74 messages
   (ML-KEM-768, 32-byte chunks) and multiple round trips. In asymmetric
   conversations (one quiet party), PQ post-compromise security may never
   arrive - the vulnerable message set is unbounded. Classical PCS still heals
   per round trip via the DH ratchet, but PQ PCS is sparse by construction.

3. **Single KEM in the handshake, often a medium-term key.** When one-time KEM
   prekeys are exhausted, Alice encapsulates to the *last-resort* signed KEM
   prekey, which lives until rotation (weeks). Compromise of that one key -
   plus a quantum computer for the DHs - exposes every session keyed through
   it in that window. All PQ eggs are in one basket per handshake.

4. **Severe implementation complexity.** The braid needs: an 11-state
   distributed state machine, Reed-Solomon (or RaptorQ) codecs over GF(2^16),
   epoch bookkeeping, and - most importantly for geryon - an **incremental
   ML-KEM API (`Encaps1`/`Encaps2`, seed-split keygen) that FIPS 203 does not
   define**. You cannot build it on a stock ML-KEM library boundary; you must
   open up the K-PKE internals. For a clean-room C17 library that wants to
   validate against ACVP vectors, this is a large surface of novel,
   hard-to-validate code (Signal's own implementation is Rust, AGPL - usable
   only as a test oracle here).

5. **KEM material transits in fragments.** Integrity of reassembled keys and
   ciphertexts rests on the SHA3-256 `hek` check plus optional MACs; the
   security argument for chunked, adversarially-reordered delivery is more
   involved than "verify one signed blob."

---

## 4. The Talos Approach: Pros and Cons

### Pros

1. **Immediate, per-step PQ forward secrecy and PCS in the ratchet.** Every DH
   ratchet step carries a fresh ML-KEM encapsulation, so post-quantum healing
   happens at the same cadence as classical healing - one round trip - instead
   of ~74 messages. There is no unbounded vulnerable message set (bounded only
   by the ML-KEM keypair refresh interval, ≤ interval−1 ratchets).

2. **Post-quantum authentication that PQXDH lacks.**
   - Dual XEdDSA+ML-DSA signatures on prekeys (both must verify) stop a
     quantum-capable malicious server from substituting prekeys - precisely
     the attack PQXDH §4.8 concedes.
   - Encapsulating to Bob's *identity* KEM key gives the responder
     post-quantum **implicit** authentication: only the holder of IK_B's
     ML-KEM private key can decapsulate KEM1 and derive SK.
   - (Sender authentication remains classical-only - see Cons.)

3. **Defense in depth per key.** The paired combiner
   `HDH_i = SHA-256(DH_i || KEM_j)` binds each classical operation to the PQ
   operation on the same recipient key, so *every* HDH input to the final KDF
   is individually hybrid. Compromise of one key's classical component doesn't
   even weaken that key's contribution. Compare PQXDH, where the single KEM
   secret is the only PQ input and everything else in the pool is classical.

4. **Dramatically simpler to implement correctly.** The ratchet is the
   textbook Double Ratchet with one substitution (`DH_out → SHA-256(DH || KEM_ss)`);
   KDF_RK, KDF_CK, skipped-key handling are untouched. Standard FIPS 203/204
   APIs suffice - no incremental KEM, no erasure codes, no epoch state
   machine. For a from-scratch C17 clean-room implementation, the difference
   in attack surface and test burden versus SPQR is enormous.

5. **Sensible engineering details.** OPKs are hybrid and single-use (PQ
   forward secrecy for the handshake doesn't depend on a last-resort key when
   OPKs are stocked); the AD binds the *full* hybrid identities (independently
   blocking component-substitution); diagnostic dual-signature failure codes
   give an early-warning signal for whichever scheme breaks first; the KEM
   ciphertext is computed once per ratchet, not per message.

### Cons

1. **Bandwidth. A lot of it.**
   - Prekey bundle: **9,024 B** vs ~1.5-1.8 KB for PQXDH (vs ~0.2 KB classical).
   - Initial message: **6,496 B** vs ~1.3-1.8 KB for PQXDH.
   - Every ratchet message: **1,148-2,332 B** of overhead vs ~56 B classical
     and ~90-120 B with Signal's braid. That is a 20-40× per-message tax,
     dominated by the always-present 1,088-byte KEM ciphertext. Fine for
     desktop/LAN/enterprise; painful for mobile messaging at scale, and it
     also fingerprints the protocol on the wire.

2. **No formal analysis or external review.** The design is plausible and
   follows the IETF combiner pattern, but nothing here has ProVerif/CryptoVerif
   models or academic scrutiny. Subtleties this class of protocol hides (KEM
   binding properties, ratchet state interactions, the OPK-absent path) are
   exactly where bespoke designs get burned. This is the single biggest gap
   versus Signal.

3. **Sender authentication is still classical.** Alice contributes no PQ
   authentication: all KEMs encapsulate *to Bob's* keys (anyone can do that),
   and Alice's ML-DSA identity component is never exercised in the handshake -
   she signs nothing. A quantum adversary who breaks X25519 can impersonate
   *initiators* at will (DH1/DH2 are the only things binding IK_A). Talos
   improves on PQXDH's responder-side story but inherits the initiator-side
   gap; the specs' "dual authentication" framing overstates this slightly.

4. **ML-KEM keypair reuse window in the ratchet.** With the default refresh
   interval of 20, the same ML-KEM ratchet keypair absorbs 20 ratchet steps.
   The spec's own VMS analysis (§7.6) is honest that under the triple
   compromise (X25519 broken + ML-KEM key extracted + root key known) up to 19
   ratchets are exposed. Fresh encapsulations per step mitigate this.
   The implementation (newer than the spec) has the *initiator* choose the
   interval and pin it for the session, with both parties bound to it - which
   solves interoperability, but makes the interval a **negotiated security
   parameter**: the initiator dictates the responder's PQ-healing cadence,
   and unless the field is authenticated (bound into the KDF or AD) a MITM
   can silently raise it. It needs a receiver-side policy ceiling and
   tamper-binding to be safe. Note also the spec's own bandwidth table shows
   hard diminishing returns above 20 (48.6% → 50.6% going from 20 to 100,
   ~46 B/message) while VMS grows linearly (19 → 99), so the useful range is
   really [1, 20]. Signal, by contrast, fixed every such parameter by
   specification.

5. **KDF domain separation is implicit, not explicit.** The HKDF info string
   is a constant `"TalosSignal"` - it does not encode curve, hash, or KEM the
   way PQXDH's `info_curve_hash_pqkem` does. The Talos rationale: the prekey
   bundle's key material physically forces the suite, and every wire message
   (KEM public keys and ciphertexts) identifies the parameter set by length
   alone. That is true, and it makes the design practically safe today. But
   none of those length-distinct bytes ever *enter the KDF* - it ingests only
   the 32/56-byte DH output and the KEM shared secret, which is **32 bytes at
   every ML-KEM level**. Within a curve, separation therefore rests entirely
   on ML-KEM internally hashing the encapsulation key into the shared secret
   (FIPS 203: K is derived from G(m ‖ H(ek))) - a KEM-specific binding
   property, not a protocol property. Signal's braid spec (§3.2) warns
   explicitly that alternate KEMs may lack ML-KEM's binding properties, and
   PQXDH (§4.12) adds the KEM public key to the AD for generic KEMs for the
   same reason. Explicit suite binding costs one constant and makes the
   property unconditional and KEM-agnostic. (Geryon's design policy mandates it;
   a protocol version belongs alongside - see §6.)

6. **Assorted smaller issues.**
   - 4-byte PKIDs are grindable (2³² work to collide); they are mostly
     non-security-critical because signatures and PKID-recomputation cover the
     key material, but any code path trusting a PKID without the fallback full
     comparison is a bug waiting to happen.
   - The spec pseudocode for header encode/decode has minor byte-order
     confusion (comments say little-endian while using `htonl`/`ntohl`) and an
     off-by-omission in the `n` encode path - cosmetic in a spec, fatal in an
     implementation; geryon should re-specify cleanly.
   - Combiner ordering deviates from the cited IETF draft: the draft computes
     `HASH(K_PQ || K_CL)` (PQ first), Talos computes `SHA-256(dh || kem_ss)`
     (classical first). Not a security issue, but the "matches [HYBRID-KEX]"
     claim isn't byte-exact.
   - No header encryption (acknowledged in-spec); Signal's classical DR
     specifies a header-encryption variant, and its absence leaks ratchet
     public keys and message counters to the transport.

---

## 5. Head-to-Head Summary

| Dimension | Signal (PQXDH + ML-KEM Braid) | Talos (Hybrid X3DH + Hybrid DR) |
|---|---|---|
| HNDL (passive quantum) confidentiality | Yes | Yes |
| PQ FS granularity, handshake | 1 KEM; last-resort key when OPKs exhausted | 2-3 KEMs incl. hybrid one-time prekey |
| PQ FS/PCS granularity, ratchet | Per epoch (~74 msgs, multiple RTTs); unbounded if peer silent | Per ratchet step (1 RTT); bounded by refresh interval |
| Responder PQ authentication | None (classical XEdDSA only) | Implicit via KEM-to-IK + ML-DSA prekey signatures |
| Initiator PQ authentication | None | None (classical only) |
| Deniability | Preserved (no PQ sigs) | Essentially preserved (ML-DSA only over prekeys) |
| Initial message size | ~1.3-1.8 KB | ~6.5 KB |
| Prekey bundle size | ~1.5-1.8 KB | ~9.0 KB |
| Per-message ratchet overhead | ~90-120 B | 1,148-2,332 B |
| Implementation complexity | Very high (erasure codes, 11-state SCKA, non-standard incremental ML-KEM internals) | Low (stock FIPS 203/204 APIs, DR structure unchanged) |
| Formal verification | ProVerif + CryptoVerif (PQXDH); ProVerif (braid); peer-reviewed basis | None |
| KDF suite binding | Full parameter string in HKDF info | Fixed `"TalosSignal"` info string |
| Loss/reorder tolerance of PQ material | Excellent (fountain/erasure codes) | Standard DR semantics (KEM ct rides every message) |
| Protocol parameters | Fixed by spec | Initiator-set, session-pinned refresh interval (downgrade surface) |

---

## 6. Takeaways for geryon

Geryon's design is essentially the Talos architecture,
generalized to two tiers. That is a defensible choice - per-step PQ ratcheting
with standard NIST APIs is far more tractable for a clean-room C17 library
than reimplementing SPQR's incremental KEM machinery, and the bandwidth cost
is a stated, deliberate trade (classical suites exist precisely for
constrained deployments). When writing `docs/HYBRID_SPEC.md`, keep the Talos
strengths and adopt Signal's hygiene where Talos is weak:

1. **Bind app id, protocol version, AND suite ID into every KDF info string**
   (`app_id || version || suite_id`). Suite ID and version solve different
   problems - algorithm parameterization vs. protocol/format evolution - so
   include both, not one standing in for the other. "The bundle's keys force
   the suite" is true - wire lengths identify the parameter set, and ML-KEM's
   shared secret internally binds the encapsulation key - but that makes
   separation *contingent on a per-KEM binding property* rather than on the
   protocol itself (the KDF sees only fixed-length secrets; ML-KEM shared
   secrets are 32 bytes at every level). Explicit binding makes it
   unconditional and KEM-agnostic, and turns domain separation into an axiom
   rather than a lemma in any future formal model. Cost is a few info-string
   bytes, nothing on the wire.
2. **Keep the initiator-set refresh interval, but harden it** (resolved
   design direction, July 2026): the bundle owner advertises an acceptable
   [min, max] interval range in the prekey bundle, the initiator picks a
   value within it, and the chosen value is bound into the handshake KDF/AD
   so tampering fails closed. The Talos implementation already
   authenticates all plaintext header fields (public keys, interval, flags)
   as AEAD associated data, so in-session tampering fails closed - and
   PQ-robustly, since the tag key derives from SK's KEM leg. Two items
   remain: (a) the advertised bounds must be covered by the dual prekey
   *signatures*, because the bundle is fetched before any shared key exists
   and AD cannot authenticate it - otherwise a malicious server can widen
   the range undetected; (b) commit-after-verify discipline: no state
   mutation (cached remote ML-KEM key, ratchet advance, interval update,
   skipped-key retention) until the AEAD tag verifies, with MAX_SKIP
   enforced before key derivation.
   No global cap at 20: bandwidth savings plateau there (48.6% vs 50.6% at
   100), but longer intervals also skip ML-KEM *keygens*, which matters for
   CPU/battery on embedded and mobile targets, so the ceiling is per-identity
   policy. (Note the CPU savings are keygen-only: fresh encapsulation and
   decapsulation still run on every ratchet step regardless of interval.)
3. **Initiator authentication resolved** (July 2026): offline deniability is
   a hard geryon requirement, which rules out transcript signatures. Geryon
   adopts **deniable KEM confirmation**: the responder's first reply
   encapsulates to the initiator's *identity* ML-KEM key and mixes the
   secret into the root KDF (one ML-KEM-512 ciphertext, 768 B, once per
   session). Deniability is preserved because both parties know every
   symmetric secret (encapsulator by generation, decapsulator by
   decapsulation), so either can simulate the full transcript - the
   1-out-of-2 property X3DH's deniability rests on. Result: mutual PQ
   implicit authentication after one round trip, persistent (root-chain
   mixed), plus replay hardening. Residual risk to document: a
   quantum-active adversary can forge one initial flight; the session dies
   at the responder's reply, and the API must expose initiator identity as
   "PQ-pending" until confirmation. **First-flight deniable PQ auth has a
   concrete upgrade path**: `libtalos_voleith` (VOLE-in-the-Head ZK,
   clean-room from the FAEST v2.0 spec - a NIST PQC Round 2 additional-
   signatures candidate, so NIST-process-grounded though not yet
   FIPS-approved) provides Merkle-membership ring signatures (RSv1) whose
   security rests on AES/SHAKE only (FIPS 197/202 primitives) - an authentication leg independent of
   the ML-KEM/ML-DSA lattice monoculture - and a two-stage Fiat-Shamir
   transform composing them with Schnorr (ristretto255/decaf448) proofs
   into hybrid membership proofs, mirroring Signal's Schnorr-based zkgroup.
   A 2-member ring over {initiator IK, responder IK} (depth-1 tree) with
   the handshake transcript bound into the fs_seed gives exactly the
   Brendel/Hashimoto deniable-DAKE construction. Before adoption in a
   protocol v2: (a) libtalos_voleith is AGPL-3.0 and must be relicensed or
   dual-licensed permissively for geryon linkage; (b) identities need a
   dedicated ZK component (OWF leaf secret) since the ring proves an OWF
   preimage, not an ML-KEM/ML-DSA key; (c) the two-stage FS composition
   needs a written security argument; (d) proof sizes are 5-17 KB -
   acceptable once per session, but measure the depth-1 case. The
   versioned wire format leaves room for all of this.
4. **Adopt PQXDH's re-encapsulation reasoning**: rely on ML-KEM's
   pk-binding, but state it, and keep KEM public keys in the AD (the Talos AD
   construction already does this - keep it).
5. **Combiner input order resolved** (July 2026): geryon adopts the IETF
   draft ordering, PQ first - `HASH(kem_ss || dh_out)` - removing the Talos
   deviation. HYBRID_SPEC.md must state this normatively; the Talos specs'
   classical-first order is historical.
6. **Plan for no external oracle.** Signal's vectors validate only classical
   suites and raw primitives; hybrid behavior needs HYBRID_SPEC-derived
   known-answer vectors plus per-primitive cross-checks (ACVP for ML-KEM /
   ML-DSA). Signal's formal-verification advantage can be partially closed by
   writing ProVerif models for the geryon hybrid handshake and ratchet -
   worth budgeting for, given both PQXDH and the braid caught real issues that
   way.
7. **Parameter sets are now resolved** (July 2026): geryon_h25519_512 uses
   ML-KEM-512 + ML-DSA-44 (category 1/2, strength-matched, minimizes
   overhead); geryon_h448_1024 uses ML-KEM-1024 + ML-DSA-87 (category 5,
   nothing below X448's 224-bit strength, CNSA 2.0-aligned). ML-KEM-768 for
   the 448 tier was considered and rejected: it would cap the flagship
   suite's PQ strength at 192 bits, below its classical leg, and mismatch
   ML-DSA-87's category. HYBRID_SPEC.md and the KDF suite-ID binding must
   use these exact pairings; the Talos specs' ML-KEM-768/ML-DSA-65 values
   are historical.
