# Hybrid-Suite Decisions

Published with the v1.1.0 hybrid release, alongside HYBRID_SPEC.md,
PQ_COMPARISON.md, pq.md, and formal.md.

This register collects the hybrid/PQ-specific implementer decisions that
were extracted from the per-module classical decision files so each per-module
classical file stays classical-only. Normative hybrid behavior lives in
HYBRID_SPEC.md; this file is its decision-register companion, mirroring
the classical files' "what the spec left open, geryon's decision, why".

Entries are grouped by module and keyed to the classical decision ID they
were split from: the hybrid rider of D-X3DH-4 lives under X3DH here as
"D-X3DH-4 (hybrid)". The classical file holds the classical core of the
same ID; this file holds only the hybrid-suite additions.

---

## X3DH (hybrid riders)

- **D-X3DH-1 (EncodeKEM):** in hybrid suites the ML-KEM and ML-DSA keys
  append their raw FIPS 203/204 encodings after the curve key. The
  encoding-disjointness argument of the classical D-X3DH-1 extends over
  these appended components.

- **D-X3DH-4 (hybrid signed bytes):** signed_data = encoded_public_key ||
  timestamp_be64 || flags_be64, byte-identical under BOTH signature
  schemes (XEdDSA and ML-DSA). flags_be64 carries the hybrid interval and
  AEAD selection; left unsigned it would let a malicious server widen the
  advertised policy bounds, so it is signed alongside the key and
  timestamp.

- **D-X3DH-6 (hybrid AD):** hybrid suites hash the full hybrid identities
  (HYBRID_SPEC §6.7) rather than raw-concatenating them (raw concatenation
  is ~6 KB per message); the first-message AD additionally binds the
  hybrid_flag (interval + AEAD selection), the fail-closed anchor for the
  negotiated session parameters.

- **D-X3DH-7 (hybrid F / HDH):** the F prefix is retained unchanged; in
  hybrid suites HKDF IKM = F || HDH1..HDHn (HYBRID_SPEC §6), where each
  HDH is the per-pair fusion of the classical DH output with the
  corresponding ML-KEM shared secret. Hybrid fusion changes what follows
  F, never F itself.

- **D-X3DH-11 (hybrid fingerprint):** the fingerprint covers ALL identity
  components (curve key, ML-KEM ek, ML-DSA pk). Covering only the curve
  key would let a misbinding attack swap the PQ identity components
  undetected; hashing the full encoded identity closes that for free.

- **D-X3DH-12 (hybrid AD extension):** hybrid AD is HYBRID_SPEC §6.7 plus
  the hybrid_flag binding; like the classical form it has no
  application-supplied extension point in protocol v1.

- **D-X3DH-13 (hybrid deletion):** the D-X3DH-13 deletion schedule extends
  in hybrid suites to KEM shared secrets and HDH intermediates
  (HYBRID_SPEC §6), zeroized at the same points as the classical DH
  outputs.

- **D-X3DH-14 (hybrid bundle validation):** validate-before-use also
  performs no KEM encapsulation until the bundle passes, and the SPK
  signature check requires BOTH signature schemes to verify (never a
  single-signature bundle in a hybrid suite).

- **D-X3DH-15 (hybrid initial message):** the classical layout is the
  hybrid layout of HYBRID_SPEC §6.5 with the KEM fields removed; the
  hybrid layout adds the per-pair ML-KEM ciphertext and ek fields.

---

## XEdDSA / signatures (hybrid riders)

- **D-XED-2 (hybrid identity components):** the ML-KEM and ML-DSA
  identity components are distinct keys with no reuse between DH,
  signing, and KEM roles; the D-XED-2 dual-use modeling gap is the
  classical curve key only. The identity-key dual-use gap is
  explicitly acknowledged by PQXDH §4 as well (HYBRID_SPEC §10.7).

- **D-XED-7 (hybrid signed_data size):** the maximum XEdDSA/ML-DSA
  message length is sized to the largest hybrid signed_data (the
  encoded hybrid prekey + timestamp_be64 + flags_be64), which stays
  under 8 KB in every suite.

- **Signatures in hybrid suites:** prekeys are signed by BOTH XEdDSA
  and ML-DSA, and verification requires both to pass; never a
  single-signature bundle (see also D-X3DH-4 / D-X3DH-14 above). ML-DSA
  signing parameters and provider integration are D-PQ-1..4 (pq.md).

---

## Sesame (hybrid riders)

- **D-SES-1 (PQ-pending peer state):** the session API additionally
  exposes the PQ-pending peer state per HYBRID_SPEC §8.4 (initiator
  identity is classical-only until the responder's KEM confirmation is
  mixed in and the initiator's first valid message arrives).

- **D-SES-2 (hybrid identity material size):** a further reason for
  per-device identity keys is that hybrid identity private material is
  large (ML-KEM dk + ML-DSA sk), which per-user key sharing would have
  to export to every linked device.

---

## Double Ratchet (hybrid riders)

- **D-DR-1 / D-DR-14 (fused IKM):** in hybrid suites the root KDF IKM
  is the per-pair fused DH output: the classical DH output fused with
  the corresponding ML-KEM shared secret (HYBRID_SPEC §6 upstream, §7.3
  in the ratchet). The L 64 -> 96 root-KDF change (D-DR-14) updated
  HYBRID_SPEC §7.3.

- **D-DR-2 (single-block KDF_CK):** KDF_CK single-block output is
  HYBRID_SPEC §7.4.

- **D-DR-3 (three-AEAD advertise/select):** hybrid suites support three
  selectable AEADs (all 32-byte keys): ChaCha20-Poly1305
  (mandatory-to-implement, default), AES-256-GCM (hardware-gated by
  libsodium), AEGIS-256 (always available). The responder advertises
  support in signed-prekey flags; the initiator selects per session;
  the choice is bound into the first-message AD. aead_id feeds the
  dr.aead / he.aead KDF Contexts; nonce_len is 12 for
  ChaCha20-Poly1305/GCM and 32 for AEGIS-256 (HYBRID_SPEC §7.5). The
  advertise/select mechanism is HYBRID-ONLY; classical suites pin
  aead_id = 0x01.

- **D-DR-5 (hybrid CONCAT AD):** the header flags carry curve_type in
  the low byte (HYBRID_SPEC §7.6); the CONCAT AD length is fixed by a
  fixed-size identity hash in hybrid suites (rather than two encoded
  identity keys).

- **D-DR-7 (hybrid SPK):** SPK_B is the full hybrid SPK in hybrid
  suites; HYBRID_SPEC §7.2 matches the init mapping.

- **D-DR-9 (hybrid deferral cost):** deferring ratchet keygen would
  also move ML-KEM keygen into the send path, complicating the
  refresh-interval accounting (HYBRID_SPEC §7.3), for marginal gain.

- **D-DR-11 (refresh interval on the wire):** in hybrid suites the
  refresh interval is protocol-visible (declared on the wire), an
  additional entry in the fingerprinting-discipline variability list.

- **D-DR-12 (SPQR / Triple Ratchet / ML-KEM Braid not implemented):**
  Signal's Rev 4 §5 (Sparse Post-Quantum Ratchet over an SCKA, i.e.
  the ML-KEM Braid) and §6 (Triple Ratchet hybridization), with
  §8.8-§8.11 on SCKA choice, PCS under drops, and HNDL attackers, are
  deliberately NOT implemented. geryon's hybrid suites mix a fresh
  ML-KEM secret into every DR root-key step per HYBRID_SPEC (§7.3-§7.4)
  instead of running a parallel sparse ratchet. PQ_COMPARISON.md
  records the full analysis of the braid design against geryon's, and
  the reasons geryon keeps the latter: per-step KEM mixing at both
  tiers, bandwidth spent via the negotiated refresh interval rather
  than erasure-coded chunking, and no dependence on incremental
  encapsulation APIs liboqs does not expose. HYBRID_SPEC §11 vectors
  validate the chosen construction.

- **D-DR-13 (upstream SK derivation):** hybrid suites change only how
  SK is derived upstream (HYBRID_SPEC §6); the three-way expansion into
  SKdr / shared_hka / shared_nhkb is unchanged.

- **D-DR-16 (hybrid header sizes):** hybrid headers vary (kem_ct
  always, mlkem_ek at refresh, HYBRID_SPEC §7.3), which is why the
  enc_header_len field exists. The be16 width holds against the largest
  case: h448_1024 at ek refresh (44-byte core + ML-KEM-1024 kem_ct 1568
  + mlkem_ek 1568 + AEAD tag 16, plus HYBRID_SPEC framing) is about
  3.2 KiB, and even a hypothetical much larger KEM outside the closed
  suite set (HQC at NIST level 5: 7245 B ek, 14485 B ct) would yield
  only about a 21.8 KiB header, within be16.

- **HE normative home:** the normative text for the HE mechanics
  (D-DR-13..17) is HYBRID_SPEC §7.8.1-§7.8.5; the classical decision
  files carry the same mechanics as their own normative text for the
  classical suites.

---

## General / cross-cutting (hybrid riders)

- **D-GEN-1 (hybrid suite bytes):** 0x02 = geryon_h25519_512 (KDF suite
  name h25519_512), 0x04 = geryon_h448_1024 (h448_1024); these match
  HYBRID_SPEC §2.1 and take the even suite ID bytes. The classical
  register lists them as "reserved".

- **D-GEN-2 (hybrid PKID input):** the encoded public key hashed for a
  hybrid PKID is curve_type || curve_pk || mlkem_ek [|| mldsa_pk]; the
  never-security-bearing / full-key-fallback rules are unchanged.

- **D-GEN-3 (ek-binding independence):** domain separation must never
  rely on ML-KEM's internal ek binding (nor on input lengths); the
  explicit "geryon . version . suite . purpose" binding is
  PQXDH-style parameter binding (HYBRID_SPEC §3.2).

- **D-GEN-7 (KEM/DSA pairing rule and rejected pairings):** the pairing
  rule within a hybrid suite is that the KEM's NIST category strength
  must be >= the strength of every other component (hybrid PQ
  confidentiality rests on the KEM alone once a quantum adversary voids
  the ECDH). X448 sits at ~224-bit classical strength, between
  ML-KEM-768 (category 3, 192) and ML-KEM-1024 (category 5, 256), so
  the rule forces rounding UP to ML-KEM-1024 + ML-DSA-87, which is also
  the only CNSA 2.0-compliant choice.
  - **h448_768 rejected (2026-07-05):** X448 + ML-KEM-768 (+ ML-DSA-65)
    caps quantum-adversary security at 192 bits while the suite
    advertises 224-bit classical strength, inverting the tier's
    purpose; CNSA 2.0 permits only ML-KEM-1024/ML-DSA-87; the byte
    savings are dominated by the tier's ML-DSA-87 signatures anyway;
    and the bandwidth-sensitive deployment already has
    geryon_h25519_512. A "PQ >= vs PQ = classical" policy knob was
    likewise rejected (suite choice IS the knob).
  - **Descriptor hybrid fields:** the gy_suite_desc reserved component
    fields hold, in hybrid rows, the KEM ops (kem_keypair/encap/decap),
    DSA ops (dsa_sign/verify), and hybrid component sizes; the KEM/DSA
    buffer maxima are per HYBRID_SPEC.

- **D-GEN-9 (suite-milestone versions):** M5 v1.1.0,
  M6 v1.2.0, M7 v1.3.0 (complete library, all
  four suites); each suite addition is an additive semver MINOR. The
  library version is independent of the HYBRID_SPEC document version
  (v1.0 Accepted). The M3 API was already shaped around the hybrid
  requirements (PQ-pending placeholder, GY_*_MAX store maxima). The
  first 2.0.0 candidate is M10 (D-GEN-1/7).
