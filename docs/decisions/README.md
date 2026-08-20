# Decision Register

The Signal specifications deliberately leave many choices to the
implementer. This register records every such point, geryon's
decision, the rationale, and the validation impact, so the
implementation never improvises. The per-module files (general, xeddsa,
x3dh, double_ratchet, sesame, custody) are normative for the classical
suites and anything suite-wide; the hybrid-suite riders and the PQ/formal
decisions live in hybrid.md, pq.md, and formal.md.

Entry format: ID, spec reference, what the spec leaves open, geryon's
decision, rationale, validation impact. Decision IDs are unique
across the whole register, so a cross-reference like D-GEN-2 is
unambiguous regardless of which file it appears in.

The Signal specifications themselves are cited by name; see the
References section of ../DESIGN.md for the full bibliography.

## Files

One file per area, matching the module layout of the source tree:

| File | IDs | Spec |
|------|-----|------|
| [general.md](general.md) | D-GEN-1..10 | cross-cutting (all specs) |
| [xeddsa.md](xeddsa.md) | D-XED-1..13 | XEdDSA, Revision 1 (2016-10-20) |
| [x3dh.md](x3dh.md) | D-X3DH-1..15 | X3DH, Revision 1 (2016-11-04) |
| [double_ratchet.md](double_ratchet.md) | D-DR-1..19 | Double Ratchet, Revision 4 (2025-11-04) |
| [sesame.md](sesame.md) | D-SES-1..12 | Sesame, Revision 2 (2017-04-14) |
| [custody.md](custody.md) | D-CUST-1 (D-CUST-2+ reserved) | HSM-style key custody over libsodium; extends D-GEN-4 |
| [hybrid.md](hybrid.md) | hybrid riders on D-X3DH/D-XED/D-SES/D-DR/D-GEN | hybrid-suite additions (HYBRID_SPEC.md companion) |
| [pq.md](pq.md) | D-PQ-1..4 | ML-KEM/ML-DSA primitives (FIPS 203/204, via liboqs) |
| [formal.md](formal.md) | D-FM-1..7 | ProVerif symbolic models of the hybrid protocol |

## Index

**general.md:** D-GEN-1 wire format versioning; D-GEN-2 key
identifiers (PKID); D-GEN-3 KDF info strings / domain separation;
D-GEN-4 private key storage; D-GEN-5 toolchain and test harness;
D-GEN-6 external oracle scope (spec-prescriptive behavior only, no
compat parameterization); D-GEN-7 suite descriptor and closed suite
set; D-GEN-8 thread-safety and re-entrancy contract (thread-compatible,
caller-serialized per object); D-GEN-9 release versioning policy
(v0.1.0, v0.1.1, v1.0.0 at the key-custody release, minors per
suite); D-GEN-10 dudect timing-target methodology.

**xeddsa.md:** D-XED-1 randomness source; D-XED-2 identity key dual
use; D-XED-3 VXEdDSA excluded; D-XED-4 SHA-512 in every suite;
D-XED-5 construction over libsodium, verification strictness;
D-XED-6 calculate_key_pair timing; D-XED-7 no pre-hashing, bounded
message length; D-XED-8 XEd448 constants; D-XED-9 448-tier provider
(libdecaf); D-XED-10 Montgomery key generation and clamping;
D-XED-11 libsignal signature-encoding divergence (spec over reference);
D-XED-12 libdecaf integration, Ed448 validation-gate scope, X448
keygen; D-XED-13 XEd448 construction layer (RESERVED: registered by
a design spike, blocking for the 448-tier implementation).

**x3dh.md:** D-X3DH-1 EncodeEC; D-X3DH-2 info parameter;
D-X3DH-3 replay mitigation (base-key dedupe); D-X3DH-4 signed prekey
signed bytes and timestamp semantics; D-X3DH-5 prekey rotation and
retention; D-X3DH-6 associated data contents; D-X3DH-7 parameter
instantiation, F prefix, HKDF realization; D-X3DH-8 DH output
validation; D-X3DH-9 use of SK / initial ciphertext; D-X3DH-10 OPK
lifecycle and batching; D-X3DH-11 identity fingerprints; D-X3DH-12
no AD extension point; D-X3DH-13 deletion points; D-X3DH-14 bundle
validation ordering; D-X3DH-15 initial message layout.

**double_ratchet.md:** D-DR-1 KDF_RK; D-DR-2 KDF_CK (SP 800-108
KDF-CTR); D-DR-3 AEAD scheme and nonce handling; D-DR-4 MAX_SKIP,
skipped keys, commit-after-verify; D-DR-5 header encoding and
CONCAT; D-DR-6 header encryption; D-DR-7 initialization mapping from
X3DH; D-DR-8 skipped-key aging; D-DR-9 no deferred ratchet keygen;
D-DR-10 no tag truncation; D-DR-11 fingerprinting discipline;
D-DR-12 Revision 4 post-quantum ratcheting not used (classical
suites); D-DR-13 initial secret expansion (SKdr, shared_hka,
shared_nhkb); D-DR-14 KDF_RK_HE output layout (single root KDF,
L = 96); D-DR-15 HENCRYPT construction (derived key+nonce, transmitted
salt); D-DR-16 DR message wire layout under HE; D-DR-17 HE receive
path (trial order, (hk, n) skipped-key indexing, bounds); D-DR-18 DR
decrypt tag-rejection timing target; D-DR-19 HE timing target framing.

**sesame.md:** D-SES-1 library/application scope split; D-SES-2
per-device identity keys; D-SES-3 SessionID; D-SES-4 storage bounds;
D-SES-5 activation semantics (racing convergence); D-SES-6 receive
path, session-not-found, HE association; D-SES-7 session expiration
and stale-record deletion; D-SES-8 no MessageRecords / retry /
receipts; D-SES-9 identity key change handling; D-SES-10
transactional state updates; D-SES-11 three-blob record split
(UserRecord/DeviceRecord/SessionRecord, keyed independently);
D-SES-12 DeviceRecords keyed per (UserID, DeviceID).

**custody.md:** D-CUST-1 the custody model and envelope hierarchy
(the public API emits only handles, public keys, or wrapped private
data; three-tier password -> Argon2id PDK -> KEK -> key material;
AEGIS-256 primary wrap cipher with an XChaCha20-Poly1305 fallback on
hardware without AES acceleration, self-describing via a stored
algorithm ID; the AD binds version/alg/key-id/type/tier; password
change vs KEK rotation distinguished). D-CUST-2+ reserved for the
concrete handle API, backup format, and export/wrap format when they
are built.

**hybrid.md:** the hybrid-suite riders on the classical decisions,
grouped by module and keyed to the classical ID they split from (e.g.
"D-X3DH-4 (hybrid)"): ML-KEM encapsulation per DH and dual prekey
signatures in X3DH, the ML-KEM ratchet mix and KEM-confirmation state
in the Double Ratchet, the hybrid SAK and identity encoding, and the
suite-milestone version policy (D-GEN-9). Normative behavior is in
HYBRID_SPEC.md.

**pq.md:** D-PQ-1 ML-KEM/ML-DSA parameter selection per tier;
D-PQ-2 liboqs backend dispatch (DIST vs pure-C `_ref`);
D-PQ-3 provider integration and error surface; D-PQ-4 PQ timing-harness
policy (what geryon times vs. what liboqs self-validates).

**formal.md:** D-FM-1 non-binding KEM theory; D-FM-2 attacker classes
(single model, broken-primitive events); D-FM-3 ratchet bound
(3 epochs); D-FM-4 query set; D-FM-5 falsification models; D-FM-6
header-encryption modeling scope; D-FM-7 toolchain pin and CI gate.
