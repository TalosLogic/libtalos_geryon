# geryon Private Group System Specification

**Date:** 2026-07-10
**Status:** DRAFT, ready for acceptance review; normative once
accepted. String tables and exact layouts freeze at first
published KATs, not at acceptance.
**Group types (D-QGS-1):** geryon ships two group types side by
side. This document specifies the CLASSICAL type (M8), serving
the classical suites, with no PQ claims of any kind;
QSPGS_SPEC.md specifies the quantum-safe type (M9), serving the
hybrid suites.
**Normative basis:** Chase, Perrin, Zaverucha, "The Signal Private
Group System and Anonymous Credentials Supporting Efficient
Verifiable Encryption", full version draft 2020-11-09
(docs/references/signal/2019-1416.pdf; CCS'20). Cited as [CPZ]
with section numbers.
**Decision register:** docs/decisions/groups.md (D-GRP-*; created
as decisions land, index in docs/decisions/README.md). Where this
document and the register disagree, the register is corrected
first, spec second (same discipline as HYBRID_SPEC).

This specification governs geryon milestone M8, the classical
group type. It is a clean-room protocol
specification derived from [CPZ]; Signal's zkgroup/poksho
implementations are external test oracles only (D-GEN-6), never
consulted for implementation.

---

## 1. Overview

### 1.1. Design summary

- A central server stores group membership as encrypted entries:
  (UidCiphertext, ProfileKeyCiphertext) pairs plus a Role, under a
  group-scoped key derived from a GroupMasterKey shared among
  members ([CPZ] §1, §5).
- Members authenticate to the server anonymously via
  keyed-verification anonymous credentials (KVAC): the server
  learns that the requester corresponds to SOME encrypted entry,
  never which UID ([CPZ] §3, §5.12).
- Encryption of UIDs and profile keys is deterministic,
  verifiable, and unique-ciphertext ([CPZ] §4).
- Group MESSAGING is out of scope: messages fan out over pairwise
  M0-M7 sessions ([CPZ] §2.5). This document specifies membership
  machinery only.

### 1.2. Relationship to [CPZ]

Sections marked "transcription" adopt [CPZ] normatively with
geryon naming and encoding conventions; sections marked "geryon
decision" fill gaps [CPZ] leaves to the implementer, each backed
by a D-GRP register entry.

### 1.3. Roles and naming

- User: an account holder identified by a 16-byte UID. Examples
  follow [CPZ] Fig. 1 naming: Alice creates the group, Bob is
  added.
- Member: a user whose (UidCiphertext, ProfileKeyCiphertext,
  Role) tuple is stored in the group. Invited member: an entry
  without a ProfileKeyCiphertext (§7.9); it becomes a full
  member when that field is populated.
- Server: issuer AND verifier (KVAC, D-GRP-2). Holds
  ServerSecretParams, the group entry tuples, and
  ProfileKeyCommitments. Trusted for consistency and access
  control; untrusted for privacy (it cannot decrypt entries,
  link operations to UIDs, or forge entries without
  GroupSecretParams).
- Relationship to geryon identity keys: NONE cryptographically.
  UIDs are opaque application-assigned identifiers (D-SES-1:
  geryon has no account model), and the proof group is
  independent of the identity curves; the only tie is the §2.1
  suite binding.

### 1.4. Library boundary (D-GRP-1)

All group-element operations (Ristretto255 / Decaf448 arithmetic,
HashToG, EncodeToG, the generic-linear Schnorr NIZK engine) are
provided by libtalos_schnorr; geryon composes the protocol layer
over that API and implements NO group operation in-house (the
XEdDSA-over-libsodium shape). Work items this places on
libtalos_schnorr before M8: EncodeToG (reversible
Elligator-inverse encoding with candidate decoding, [CPZ] §6) for
both tiers; any further gaps this specification surfaces are
recorded here and fixed there.

---

## 2. Tiers, Parameters, and Hashing

### 2.1. Proof-group tiers and suite binding (D-GRP-3)

1. Pairing: Ristretto255 is the proof group for geryon_c25519;
   Decaf448 for geryon_c448. The
   hybrid suites use the QSPGS group type (QSPGS_SPEC.md) and
   hold no objects of this system. geryon-side derivations (§2.3)
   use the tier hash: SHA-256 on the 25519 tier, SHA-512 on the
   448 tier.
2. Suite binding is by FULL suite descriptor: every group object
   and proof binds app_id || protocol_version || suite_id per
   D-GEN-3; identities on different suites are NOT
   group-compatible, the group-layer analogue of cross-suite
   handshake rejection. Hybrid-suite identities are excluded
   structurally (no objects of this type exist for them); the §12
   negative matrix nonetheless asserts that classical group
   objects presented under a hybrid-suite identity fail
   (cross-TYPE rejection).
3. Proof binding: the suite string enters every FS challenge as
   OtherInfo, whose format is fixed here per RFC 8235 as two
   length-prefixed subitems (the RFC's subitem rule): (a) the
   D-GEN-3 suite-binding string; (b) a proof-type label (pi_I,
   pi_A, pi_BR, pi_BI, pi_P; exact strings fixed in §5).
4. UserID: the RFC 8235 / libtalos_schnorr UserID field carries
   fixed role strings only (server / member role labels, exact
   strings in §5), never a real user identity: presentation
   provers are anonymous.
5. The same suite string feeds the §2.3 HKDF labels, the §2.2
   generator-derivation seeds, and the §9 wire tags; suite
   binding never depends on incidental structure such as point
   sizes.

### 2.2. System parameters (D-GRP-5)

All of this section is [CPZ]-protocol material owned by geryon;
libtalos_schnorr contributes only its existing primitives
(hash_to_group, scalar_random, hash_to_scalar), and D-GRP-5
creates no new schnorr work item.

1. Generator set, per suite: G is the standard basepoint
   (RFC 9496; libtalos_schnorr's default), plus 20 NUMS
   generators: the full [CPZ] §3.1 MAC set at n = 4 (G_w,
   G_wprime, G_x0, G_x1, G_y1..G_y4, G_m1..G_m4, G_V; the three
   unused G_mi are derived anyway, for scheme fidelity) and the
   §5.8 system additions (G_a1, G_a2, G_b1, G_b2, G_j1, G_j2,
   G_j3).
2. NUMS derivation, one named seed per generator (the paper's
   own convention, "e.g., G_m1 = HashToG('m1')"):
   G_<name> = hash_to_group(suite_string || "sysparams" ||
   <name>), index 0, where suite_string is the full §2.1
   descriptor. Every suite therefore has a structurally distinct
   generator set. Seed-string table (20 names, frozen at first
   published KATs): "w", "wprime", "x0", "x1", "y1", "y2", "y3",
   "y4", "m1", "m2", "m3", "m4", "V", "a1", "a2", "b1", "b2",
   "j1", "j2", "j3"; each generator is
   hash_to_group(suite_string || "sysparams" || <name>).
3. GroupMasterKey and Derive: GroupMasterKey is {0,1}^2k per
   tier: 32 bytes on the 25519 suites, 56 bytes on the 448
   suites. Derive ([CPZ] §4.1: a single hash call, master key to
   key tuple) is instantiated as one HKDF expansion per
   encryption scheme, two domain-separated purposes (uid
   encryption -> (a1, a2); profile-key encryption -> (b1, b2)),
   okm partitioned into per-scalar wide segments and reduced to
   canonical scalars (schnorr hash_to_scalar reduction).
4. ServerSecretParams: all 16 MAC scalars (w, wprime, x0, x1,
   y1..y4 for each of iparams_A and iparams_P) are RANDOM
   (core/ rng.c) per [CPZ] §3.1 KeyGen. There is NO production
   seed-derivation path; deterministic KATs use the
   GY_TEST_HOOKS derand seam (D-PQ-3 precedent).
   ServerPublicParams are the corresponding iparams (CW, I) per
   §3.1/§5.8.
5. Label registry (frozen at first published KATs): the 20
   generator seeds, 2 Derive purposes, HashToG / HashToZq
   purpose prefixes (M1, M3, j3: distinct random oracles get
   distinct domain prefixes), and hedged proof-nonce labels
   (hedging is D-PQ-1-style hardening; [CPZ] requires only
   random nonces). Exact strings, each appended to the D-GEN-3
   suite-binding string, frozen at first published KATs:

   | Label            | Use                                     |
   |------------------|-----------------------------------------|
   | "grp-derive-uid" | Derive purpose -> (a1, a2) (§6.2)       |
   | "grp-derive-pk"  | Derive purpose -> (b1, b2) (§6.2)       |
   | "grp-m1"         | HashToG domain for M1 (two-map, §5.4)   |
   | "grp-m3"         | HashToG1 domain for M3 (single-map, §6.1 item 3) |
   | "grp-j3"         | HashToZq domain for j3 (§3.3)           |
   | "grp-pkv"        | ProfileKeyVersion derivation (§3.3)     |
   | "grp-nonce"      | hedged proof-nonce derivation           |

   The FS proof-type labels and UserID role strings are fixed in
   §5.0.

### 2.3. Hash conventions (D-GRP-4)

There is NO SHO (stateful hash object) in geryon. [CPZ]'s
normative body prescribes no hash instantiation (HashToG,
HashToZq, and Derive are random-oracle-modeled "cryptographic
hash functions"); poksho's SHO/HMAC-SHA256 appears only in the
paper's implementation section and is zkgroup engineering, out of
scope per the D-GEN-6 prescriptive-scope rule and the D-GRP-4
design posture (spec-compliant, not libsignal-compliant).

1. Fiat-Shamir challenges are computed by libtalos_schnorr (the
   gen_compute_challenge_ex/_conj family) over a 4-byte-length-
   prefixed transcript (k/m dimension binding, the m x k generator
   matrix, all V commitments, all P targets, UserID, OtherInfo),
   reduced to a canonical scalar. The transcript SHAPE is identical
   on both tiers; the HASH is curve-native per tier (corrected
   2026-09-01, D-GRP-4 amendment; the earlier "one-shot SHA-512
   both tiers" wording was inaccurate as built):
   - 255 (Ristretto255): SHA-512, reduced by
     crypto_core_ristretto255_scalar_reduce to a 32-byte scalar.
   - 448 (Decaf448): SHAKE256 with a 114-byte squeeze, reduced by
     decaf_448_scalar_decode_long to a 56-byte scalar.
   Both are the RFC 8235 construction generalized to the
   generic-linear setting: SHA-512 and the SHA-3/XOF family
   (SHAKE256) are both on the RFC's approved list, each output
   length exceeds its tier's group order (~253 and ~446 bits), and
   SHAKE256 is the natural Ed448/Decaf448 choice (RFC 8032), so
   curve and hash move together.
2. geryon-side derivations (group master key to (a1, a2, b1, b2),
   ServerSecretParams expansion, HashToZq, HashToG input
   expansion, hedged proof nonces) use core/ HKDF/HMAC with
   domain-separated info strings per D-GEN-3. The exact label set
   is defined with D-GRP-5 and the §5 transcription, and freezes
   at first published KAT vectors.
3. Hash-to-tier pairing for the geryon-side derivations follows
   §2.1 (D-GRP-3); libtalos_schnorr's internal FS-challenge hash is
   the provider's RFC-conformant curve-native choice per tier
   (SHA-512 on 255, SHAKE256 on 448; see item 1).
4. Validation consequence: geryon group objects are NOT
   byte-compatible with zkgroup, by design; see §12.

---

## 3. Data Objects (transcription of [CPZ] §5.1-5.5)

Objects are given by algebraic content; byte encodings follow
the §9 conventions, exact layouts frozen at first published
KATs. Notation is multiplicative: G^x is scalar multiplication,
products juxtapose, division is the inverse-multiply
rearrangement. All arithmetic is in the §2.1 proof group.

### 3.1. General ([CPZ] §5.2)

- UID: a 16-byte identifier for a user. [CPZ] describes a UUID;
  geryon treats it as an opaque 16-byte string assigned by the
  application (D-SES-1: no account model). UIDs never appear in
  plaintext on the group-server surface; they enter the algebra
  as M1 = HashToG(UID) and M2 = EncodeToG(UID).
- ServerSecretParams: two independent MAC secret keys (§4),
  sk_A (AuthCredentials) and sk_P (ProfileKeyCredentials), all
  16 scalars random (D-GRP-5).
- ServerPublicParams: the corresponding issuer parameters
  iparams_A = (C_W_A, I_A) and iparams_P = (C_W_P, I_P) (§4.2).

### 3.2. Authentication objects ([CPZ] §5.3, §5.9)

AuthCredential attributes:

1. M1 = HashToG(UID) (group attribute)
2. M2 = EncodeToG(UID) (group attribute, reversible encoding)
3. M3 = G_m3^m3 (scalar attribute): m3 is the redemption date,
   the §9 item 6 day-aligned uint64 reduced to a canonical
   scalar; the credential is valid on that day only.

- AuthCredential: the MAC (t, U, V) over the attributes above.
  Secret material (D-GEN-4), stored with its redemption date
  (D-GRP-7).
- AuthCredentialRequest: the redemption date alone ([CPZ] omits
  the object as trivial); an API argument in geryon, not a wire
  object.
- AuthCredentialResponse: (t, U, V, pi_I) (§5.1).
- AuthCredentialPresentation: (C_x0, C_x1, C_y1, C_y2, C_y3,
  C_V, E_A1, E_A2, redemption date, pi_A) (§5.2.1).

### 3.3. Profile-key objects ([CPZ] §5.4, §5.10)

- ProfileKey: 32 bytes, library-generated ([CPZ] §5.6 step 1;
  D-GRP-7), shared with trusted contacts, never with the
  server. Assumed high-min-entropy; the commitment's hiding
  rests on that ([CPZ] §5.10).
- ProfileKeyCredential attributes:

  1. M1 = HashToG(UID)
  2. M2 = EncodeToG(UID)
  3. M3 = HashToG1(ProfileKey, UID) (group attribute, single-map)
  4. M4 = EncodeToG(ProfileKey) (group attribute)

  Attribute names are per credential family: the auth M3 is a
  scalar (redemption date), the profile M3 is a group
  attribute. The families use distinct MAC keys (sk_A, sk_P),
  so no cross-family algebra exists.
- ProfileKeyCommitment: (J1, J2, J3) =
  (G_j1^j3 M3, G_j2^j3 M4, G_j3^j3) with
  j3 = HashToZq(ProfileKey, UID) ("grp-j3" domain, §2.2).
  Deterministic by construction: anyone holding (ProfileKey,
  UID) can recompute it.
- ProfileKeyVersion: a 32-byte non-secret identifier derived
  from (ProfileKey, UID) via tier-hash HKDF under "grp-pkv"
  (§2.2); the server-side lookup key alongside the UID. [CPZ]
  leaves the derivation open ("an identifier derived from a
  ProfileKey"); geryon binds the UID so equal ProfileKeys do
  not yield equal versions across users.
- ProfileKeyCredential: the MAC (t, U, V) over the four
  attributes. Secret material, stored per target UID with the
  D-GRP-7 replacement rule.
- ProfileKeyCredentialRequest: Elgamal public key Y = G^y,
  ciphertexts (D1, D2) = (G^r1, Y^r1 M3) and
  (E1, E2) = (G^r2, Y^r2 M4), and pi_BR (§5.3).
- ProfileKeyCredentialResponse: (S1, S2, t, U, pi_BI) (§5.3).
- ProfileKeyCredentialPresentation: (C_y1, C_y2, C_y3, C_y4,
  C_x0, C_x1, C_V, E_A1, E_A2, E_B1, E_B2, pi_P) (§5.2.2).

### 3.4. Group objects ([CPZ] §5.5)

- GroupMasterKey: 2 kappa random bytes (32/56 by tier,
  D-GRP-5), the ONLY stored group secret (D-GRP-7). Distributed
  to new and invited members over pairwise sessions via
  GROUP_KEY_DISTRIBUTION (§9 item 4); [CPZ] additionally
  recommends including a copy with every message sent within
  the group as a delivery backstop, which in geryon is
  application resend policy over the same message type. The
  departed-member retention caveat is §11.1 item 2.
- GroupSecretParams: (a1, a2, b1, b2), rederived on demand from
  GroupMasterKey via Derive (§6.2), never cached (D-GRP-7).
- GroupPublicParams: (A, B) with A = G_a1^a1 G_a2^a2 and
  B = G_b1^b1 G_b2^b2. Registered with the server as the
  group's representation, and the input to the local-only
  GroupID (D-GRP-7).
- UidCiphertext (E_A1, E_A2) and ProfileKeyCiphertext
  (E_B1, E_B2): deterministic, unique-ciphertext verifiable
  encryptions under GroupSecretParams (§6.3, §6.4); 2 group
  elements each ([CPZ] Table 1: 64 bytes on the 255 tier).
- Role: the opaque fixed-size access role, server-enforced,
  never interpreted by geryon (D-GRP-7; [CPZ] §5.5).

---

## 4. Algebraic MAC (transcription of [CPZ] §3.1)

### 4.1. Parameters

The §2.1 group G of prime order q; the §2.2 generator set G,
G_w, G_wprime, G_x0, G_x1, G_y1..G_y4, G_m1..G_m4, G_V; n = 4
attribute positions. Each position is fixed per key to always
carry a group attribute (Mi in G) or always a scalar attribute
(Mi = G_mi^mi, mi in Zq).

### 4.2. KeyGen

sk := (w, wprime, x0, x1, y1, y2, y3, y4), random scalars
(core/ rng.c; D-GRP-5, no seed path outside GY_TEST_HOOKS).
W := G_w^w is part of sk. Issuer parameters (always computed;
[CPZ] treats them as required in these protocols):

    C_W = G_w^w G_wprime^wprime
    I   = G_V / (G_x0^x0 G_x1^x1 G_y1^y1 ... G_yn'^yn')

where n' is the number of positions the key BINDS (§4.4).

### 4.3. MAC and Verify

MAC(sk, M): choose random t in Zq and random U in G, compute

    V = W * U^(x0 + x1*t) * prod_{i=1..n'} Mi^yi

and output (t, U, V). Verify(sk, M, (t, U, V)): recompute V'
per the same formula and accept iff V = V' (constant-time
comparison of canonical encodings).

t and U are random per [CPZ]'s main construction; the
derandomized variant ([CPZ] §3.1, Optimizations) is NOT used.
Deterministic KATs go through the GY_TEST_HOOKS derand seam
(D-GRP-5).

### 4.4. Key shapes per credential family

Both keys sample the full 8-scalar sk (uniform shape, D-GRP-5:
16 random scalars across the two). The bound position count n'
follows the paper's verification equations exactly:

- sk_P binds all four positions (I_P over y1..y4); attributes
  per §3.3, all group attributes.
- sk_A binds positions 1..3 (I_A over y1..y3), matching the
  [CPZ] §5.12 server equation; y4_A is sampled for the uniform
  key shape but enters no equation (reserved, the same fidelity
  posture as the unused G_mi).

---

## 5. Credentials (transcription of [CPZ] §3.2, §5.9-5.10)

### 5.0. Proof conventions (D-GRP-3/4 applied)

Every proof below is a generic-linear Schnorr NIZK executed by
libtalos_schnorr (§2.3): each statement line is an equation
P = prod_k G_k^{s_k} over public targets P, public generators
G_k, and witness scalars s_k; a division P/Q = R denotes the
rearrangement P = Q * R. Fixed strings (frozen at first
published KATs):

- Proof-type labels (FS OtherInfo subitem b, §2.1): "pi_I",
  "pi_A", "pi_BR", "pi_BI", "pi_P".
- UserID role strings: "geryon-group-server" for the issuer
  proofs (pi_I, pi_BI); "geryon-group-member" for the member
  proofs (pi_BR, pi_A, pi_P). Never a real identity (D-GRP-3).
- Proof nonces are hedged under "grp-nonce" (§2.2; D-GRP-5).

### 5.1. Issuance and the issuance proof ([CPZ] §3.2, §5.9)

Non-blind issuance (AuthCredentials; all attributes known to
both parties): the issuer computes the MAC (t, U, V) over
(M1, M2, M3) and proves correctness relative to iparams_A. t
and U are public inputs; U^t is computed by both sides.

    pi_I = PK{(w, wprime, x0, x1, y1, y2, y3) :
        C_W_A = G_w^w G_wprime^wprime  AND
        I_A = G_V / (G_x0^x0 G_x1^x1 G_y1^y1 G_y2^y2 G_y3^y3)  AND
        V = G_w^w (U^x0) (U^t)^x1 M1^y1 M2^y2 M3^y3}

The user recomputes (M1, M2) from its OWN UID and M3 from the
requested redemption date, verifies pi_I, and stores the
credential (D-GRP-7). Verification failure is a structured
error; nothing is stored.

### 5.2. Presentation (general form, [CPZ] §3.2)

To present (t, U, V) on attributes M with hidden-attribute set
H (hidden scalars Hs):

1. Choose random z in Zq; compute

       Z    = I^z
       C_x0 = G_x0^z U
       C_x1 = G_x1^z U^t
       C_yi = G_yi^z Mi         (hidden group attribute)
            = G_yi^z G_mi^mi    (hidden scalar attribute)
            = G_yi^z            (revealed attribute)
       C_V  = G_V^z V
       z0   = -z*t mod q

2. Prove

       pi = PK{(z, z0, {mi in Hs}, t) :
           Z = I^z  AND
           C_x1 = C_x0^t G_x0^z0 G_x1^z  AND
           C_yi = G_yi^z G_mi^mi (i in Hs) ;
           C_yi = G_yi^z (i revealed)}

3. Transmit (C_x0, C_x1, C_y1..C_yn', C_V, pi) plus whatever
   ciphertexts and revealed values the instantiation requires.
   Z is NEVER transmitted in either direction: the prover
   computes Z = I^z, the verifier recomputes

       Z = C_V / (W C_x0^x0 C_x1^x1 prod_{i in H} C_yi^yi
           prod_{i not in H} (C_yi Mi)^yi)

   from sk and the revealed attributes. An invalid credential
   makes the two Z values disagree and the proof fail; the
   credential check is implicit in FS verification.

### 5.2.1. AuthCredentialPresentation (pi_A, [CPZ] §5.12)

The presentation instantiates §5.2 over sk_A (M1, M2 hidden
group attributes; m3 revealed) and adds the §6.5 encryption
predicates for the UidCiphertext, sharing the same z:

1. Recompute (E_A1, E_A2) from UID and (a1, a2) (§6.3).
2. Random z; commitments C_y1 = G_y1^z M1, C_y2 = G_y2^z M2,
   C_y3 = G_y3^z, C_x0, C_x1, C_V per §5.2;
   z0 = -z*t, z1 = -z*a1.
3. Prove

       pi_A = PK{(z, a1, a2, z0, z1, t) :
           Z = I_A^z  AND
           C_x1 = C_x0^t G_x0^z0 G_x1^z  AND
           A = G_a1^a1 G_a2^a2  AND
           C_y2 / E_A2 = G_y2^z / E_A1^a2  AND
           E_A1 = C_y1^a1 G_y1^z1  AND
           C_y3 = G_y3^z}

   (lines 4 and 5: the ciphertext's plaintext is the committed
   M2, and E_A1 is well-formed).
4. Presentation = (C_x0, C_x1, C_y1, C_y2, C_y3, C_V, E_A1,
   E_A2, redemption date, pi_A).
5. Server: check the presented redemption date (day-aligned per
   §9 item 6; acceptance window is deployer policy), then with
   the presented date as m3 compute

       Z = C_V / (W_A C_x0^x0 C_x1^x1 C_y1^y1 C_y2^y2
           (C_y3 G_m3^m3)^y3)

   and verify pi_A. On success the deployer receives the
   authenticated (E_A1, E_A2) plus the stored Role (D-GRP-7).

### 5.2.2. ProfileKeyCredentialPresentation (pi_P, [CPZ] §5.13)

Instantiates §5.2 over sk_P (all four attributes hidden group
attributes) with encryption predicates for BOTH ciphertexts:

1. Random z; C_yi = G_yi^z Mi for i = 1..4; C_x0, C_x1, C_V per
   §5.2; z0 = -z*t, z1 = -z*a1, z2 = -z*b1.
2. Prove

       pi_P = PK{(z, a1, a2, b1, b2, z0, z1, z2, t) :
           Z = I_P^z  AND
           C_x1 = C_x0^t G_x0^z0 G_x1^z  AND
           A = G_a1^a1 G_a2^a2  AND
           B = G_b1^b1 G_b2^b2  AND
           C_y2 / E_A2 = G_y2^z / E_A1^a2  AND
           E_A1 = C_y1^a1 G_y1^z1  AND
           C_y4 / E_B2 = G_y4^z / E_B1^b2  AND
           E_B1 = C_y3^b1 G_y3^z2}

3. Presentation = (C_y1..C_y4, C_x0, C_x1, C_V, E_A1, E_A2,
   E_B1, E_B2, pi_P).
4. Server:

       Z = C_V / (W_P C_x0^x0 C_x1^x1 prod_{i=1..4} C_yi^yi)

   then verify pi_P.

### 5.3. Blind issuance (profile-key credentials, [CPZ] §5.10)

Request: the user generates an ephemeral Elgamal pair
(y, Y = G^y) and random r1, r2, encrypts the blind attributes

    (D1, D2) = (G^r1, Y^r1 M3)
    (E1, E2) = (G^r2, Y^r2 M4)

and proves consistency with the ProfileKeyCommitment
(J1, J2, J3):

    pi_BR = PK{(y, r1, r2, j3) :
        Y = G^y  AND  D1 = G^r1  AND  E1 = G^r2  AND
        J3 = G_j3^j3  AND
        D2 / J1 = Y^r1 / G_j1^j3  AND
        E2 / J2 = Y^r2 / G_j2^j3}

Response: the server verifies pi_BR against the STORED
commitment for (UID, ProfileKeyVersion) (§7.4), forms the
partial credential (t, U, V') over the revealed attributes
(M1, M2), encrypts it as (R1, R2) = (G^r', Y^r' V') for random
r', and exploits Elgamal homomorphism:

    (S1, S2) = (D1^y3 E1^y4 R1, D2^y3 E2^y4 R2)

which is an encryption of the full V over all four attributes.
It proves

    pi_BI = PK{(w, wprime, y1, y2, y3, y4, x0, x1, r') :
        C_W_P = G_w^w G_wprime^wprime  AND
        I_P = G_V / (G_x0^x0 G_x1^x1 G_y1^y1 G_y2^y2
              G_y3^y3 G_y4^y4)  AND
        S1 = D1^y3 E1^y4 G^r'  AND
        S2 = D2^y3 E2^y4 Y^r' G_w^w (U^x0) (U^t)^x1
             M1^y1 M2^y2}

and sends (S1, S2, t, U, pi_BI). The user verifies pi_BI,
decrypts V = S2 / S1^y, zeroizes (y, r1, r2), and stores
(t, U, V) as the ProfileKeyCredential for the target UID
(D-GRP-7 replacement rule).

---

## 6. Verifiable Encryption (transcription of [CPZ] §4, §5.11)

§6.1 fixes the provider contract; §6.2-§6.5 transcribe the
scheme: symmetric-key verifiable encryption with unique
ciphertexts, deterministic, CCA-secure in the ROM under DDH
([CPZ] §4, Theorem 10 context).

### 6.1. EncodeToG contract on libtalos_schnorr (D-GRP-1)

Requirements the encryption scheme places on the provider
(implementation handoff: libtalos_schnorr
docs/ENCODE_TO_GROUP.md):

1. Padded encode, both tiers: EncodeToG on 16-byte inputs (UIDs)
   uses the Lizard method: the input is embedded in a field
   element alongside hash-derived padding and mapped through a
   single Elligator map. Decode inverts the map (1 to 8
   field-element preimages) and the padding check identifies the
   unique preimage, so decode is self-disambiguating.
2. Raw encode, 255 tier: profile keys (32 bytes) exceed the group
   order, so EncodeToG(ProfileKey) encodes 253 bits directly.
   Decode (talos_decode_255_pk) enumerates every Elligator
   preimage internally, including the +p field-overflow
   representatives, and returns the full candidate list to the
   caller (up to TALOS_ENCODE_255_MAX_CANDIDATES = 64, [CPZ] §6),
   with the count a public function of the point. geryon's Dec
   disambiguates over the returned candidates with the
   EB1 = HashToG1(ProfileKey_c, UID)^b1 check (M3, §6.4) and
   selects the true ProfileKey. Candidate enumeration is the
   provider's; disambiguation is protocol-layer work, never the
   provider's.
3. Single-Elligator HashToG1: the profile-key attribute M3 and
   its candidate test use HashToG1, one Elligator map on a
   HASH_BYTES field element (32 bytes on the 255 tier; [CPZ] §6,
   for candidate-test performance); this is a distinct primitive
   from the two-map RFC 9496 HashToG (hash_to_group) used for M1.
   geryon realizes M3 via the provider primitive
   talos_hash_to_g1_<t>, hashing the "grp-m3" domain over the
   (ProfileKey, UID) inputs; the exact input encoding is pinned
   in §2.3.
4. Byte compatibility (255 tier): encode is deterministic, so
   oracle byte-compat with zkgroup requires the provider's
   forward map to equal the dalek / RFC 9496 map and the padding
   scheme to equal Lizard's; preimage enumeration order is
   immaterial. Verified by RFC 9496 vectors plus cross-provider
   checks (vendored decaf_255 vs libsodium ristretto255).
5. 448 tier: no upstream precedent exists (Signal is
   ristretto255-only). The padding layout over the ~446-bit field
   is DEFINED BY THE PROVIDER, in libtalos_schnorr
   docs/ENCODE_TO_GROUP.md, which is normative for the encoding
   (the same ownership as the 255 tier, where the layout is
   Lizard's, fixed provider-side by oracle compat). geryon pins
   the libtalos_schnorr version and states only its requirements:
   both 16-byte (UID) and 32-byte (profile-key) inputs supported,
   deterministic encode, self-disambiguating decode, length
   unambiguity (an encode of one input length never decodes as
   the other), and the constant-time rules of item 6. Validated
   by provider self-KATs; frozen once the first vectors publish.
   Both UIDs and profile keys fit a single Decaf448 element with
   padding, so the raw candidate path may be omitted on this
   tier.
6. Constant-time boundary (D-GRP-8):
   primitive CT (fixed 8-preimage decode, CT padding compare, CT
   candidate select, CT forward map) is the PROVIDER's contract,
   fixed in ENCODE_TO_GROUP.md §6 and covered by schnorr's timing
   harness; geryon relies on the version pin and does not restate
   those rules. geryon owns CT in its own composition code only,
   concretely the [CPZ] §6 candidate-test loop of item 2: fixed
   iteration count over all TALOS_ENCODE_255_MAX_CANDIDATES
   candidate slots returned by the provider decode (64 on the 255
   tier, 8 on the 448 tier), no early exit on match, const_memcmp
   comparisons, constant-time select of the winning plaintext. Schnorr-backed group paths join geryon's
   timing tests under the existing linked-library policy (same as
   libsodium/liboqs).

### 6.2. System parameters, KeyGen, and Derive ([CPZ] §4.1, §5.11)

Generators G_a1, G_a2 (UID scheme) and G_b1, G_b2 (ProfileKey
scheme) from §2.2. KeyGen: the GroupMasterKey k0 is 2 kappa
random bytes; Derive(k0) = (a1, a2, b1, b2) per D-GRP-5, one
HKDF expansion per scheme under "grp-derive-uid" /
"grp-derive-pk" (§2.2), okm segments reduced to canonical
scalars. Honest parties never use scalars not derived this way
([CPZ] §4.1: Derive rules out degenerate keys); geryon's API
enforces it structurally by accepting only GroupMasterKey and
rederiving (D-GRP-7). Public parameters: A = G_a1^a1 G_a2^a2,
B = G_b1^b1 G_b2^b2 (§3.4).

### 6.3. UID encryption ([CPZ] §5.11)

Enc(a1, a2, UID): M1 = HashToG(UID) ("grp-m1" domain, two-map
hash), M2 = EncodeToG(UID) (padded encode, §6.1 item 1);

    E_A1 = M1^a1
    E_A2 = E_A1^a2 M2

Deterministic, unique-ciphertext. Dec(a1, a2, E_A1, E_A2):

    M2' = E_A2 / E_A1^a2

decode M2' to UID' (self-disambiguating padded decode);
M1' = HashToG(UID'); accept and return UID' iff

    E_A1 != identity  AND  E_A1 = M1'^a1

else return the structured decryption error. Decode failure
and check failure are the SAME error (no decode oracle), and
the whole path is constant-time (D-GRP-8; §6.1 item 6).

### 6.4. ProfileKey encryption ([CPZ] §5.11)

Enc(b1, b2, ProfileKey, UID): M3 = HashToG1(ProfileKey, UID)
("grp-m3" domain, single-Elligator hash, §6.1 item 3),
M4 = EncodeToG(ProfileKey) (raw encode on the 255 tier, §6.1
item 2; padded on 448);

    E_B1 = M3^b1
    E_B2 = E_B1^b2 M4

Dec(b1, b2, E_B1, E_B2, UID): requires the UID, so paired
entries decrypt UID first (§6.3), then the ProfileKey. Compute

    M4' = E_B2 / E_B1^b2

then candidate-decode M4' via talos_decode_<t>_pk, which returns
the full [CPZ] §6 candidate list directly: on the 255 tier up to
TALOS_ENCODE_255_MAX_CANDIDATES = 64 ProfileKey candidates (the
provider enumerates preimages and +p overflow reps internally);
on the 448 tier up to 8. For each candidate ProfileKey_c compute
M3_c = HashToG1(ProfileKey_c, UID) and test E_B1 = M3_c^b1 over
the FULL fixed MAX_CANDIDATES count (no early exit, CT select;
D-GRP-8). Accept iff E_B1 != identity and exactly one candidate
matched; else the structured error.

### 6.5. Proving and verifying ([CPZ] §4.1 Prove/Verify)

Enc proofs never stand alone: they are predicate lines added to
credential presentations, sharing the presentation's z so the
attribute commitments C_yi do double duty. For the UID scheme
(witness a1, a2, z1 = -z*a1):

    A = G_a1^a1 G_a2^a2
    C_y2 / E_A2 = G_y2^z / E_A1^a2      (plaintext is M2)
    E_A1 = C_y1^a1 G_y1^z1              (E_A1 well-formed)

and analogously for the ProfileKey scheme with (b1, b2), C_y3,
C_y4, z2 = -z*b1. The concrete composed statements are §5.2.1
(pi_A) and §5.2.2 (pi_P). E_A1 acts as a DDH-based
authentication tag on the plaintext ([CPZ] §4.1 Discussion);
there is no standalone Verify entry point in geryon's API, only
presentation verification.

---

## 7. Operations (transcription of [CPZ] §5.6-5.7)

Channels: "authenticated" means the server knows the caller's
UID (normal account authentication); "unauthenticated" means an
anonymous channel, where the caller is identified only by proof.
geryon ships the cryptography of both roles (D-GRP-2); lines
reading "the server checks/stores" are the deploying
application's storage and policy duty, with the cryptographic
verification in geryon_groups_server. All client operations are
transactional per D-GRP-7 item 5.

### 7.1. GetAuthCredential (authenticated)

1. The user requests an AuthCredential for a redemption date
   (day-aligned, §9 item 6).
2. If the date is within the server's allowed window (policy,
   e.g. the next few days), the server issues
   AuthCredentialResponse = (t, U, V, pi_I) over (M1, M2, m3)
   for the authenticated UID (§5.1).
3. The user verifies pi_I (recomputing M1, M2 from its own UID)
   and stores the AuthCredential (D-GRP-7); on failure,
   structured error, nothing stored.

### 7.2. CommitToProfileKey (authenticated)

1. The user generates a random ProfileKey (library-generated,
   D-GRP-7) and derives ProfileKeyVersion and
   ProfileKeyCommitment (§3.3).
2. The user sends (ProfileKeyVersion, ProfileKeyCommitment) to
   the server.
3. The server stores the commitment under the authenticated UID
   and the ProfileKeyVersion.

### 7.3. GetProfileKeyCredential (unauthenticated)

Provisions a ProfileKeyCredential for (UID, ProfileKey) if and
only if the caller knows a ProfileKey matching the target's
stored commitment.

1. The user derives ProfileKeyVersion from the target's
   ProfileKey and builds a ProfileKeyCredentialRequest (§5.3).
2. The user sends (UID, ProfileKeyVersion, request).
3. The server looks up the stored ProfileKeyCommitment for
   (UID, ProfileKeyVersion); if present, verifies pi_BR against
   it.
4. On success the server returns
   ProfileKeyCredentialResponse = (S1, S2, t, U, pi_BI).
5. The user verifies pi_BI, decrypts V, and stores the
   ProfileKeyCredential for the target UID (§5.3; D-GRP-7).

### 7.4. AuthAsGroupMember (unauthenticated)

Authenticates the channel to a UidCiphertext within a group
without revealing the UID; used by every operation below.

1. The user rederives GroupSecretParams (D-GRP-7), recomputes
   its UidCiphertext (§6.3), and builds an
   AuthCredentialPresentation (§5.2.1).
2. The user sends GroupPublicParams and the presentation.
3. The server verifies pi_A (§5.2.1 step 5) and checks that the
   GroupPublicParams identify a stored group and that the
   UidCiphertext is a member entry of it.

### 7.5. AddGroupMember (unauthenticated)

1. AuthAsGroupMember.
2. The user encrypts the new member's (UID, ProfileKey) into
   (UidCiphertext, ProfileKeyCiphertext) (§6.3, §6.4; the
   contact's ProfileKey is a call argument, D-GRP-7), builds a
   ProfileKeyCredentialPresentation (§5.2.2) for those
   ciphertexts, and sends it with the new member's Role.
3. The server verifies pi_P and checks: (a) the authenticated
   user's Role permits adding; (b) the UidCiphertext is not
   already a full member. If it exists as an invited entry, the
   operation completes the invite (fills the
   ProfileKeyCiphertext). On success the server stores
   (UidCiphertext, ProfileKeyCiphertext, Role); else error.

### 7.6. CreateGroup (unauthenticated)

1. The user generates GroupMasterKey and derives
   GroupSecretParams / GroupPublicParams (§6.2).
2. The user sends the GroupPublicParams for the new group.
3. A variant of AddGroupMember initializes the group with the
   creator's own entry and skips the Role check.

### 7.7. FetchGroupMembers (unauthenticated)

1. AuthAsGroupMember.
2. The server returns all (UidCiphertext, ProfileKeyCiphertext)
   pairs, full and invited members alike. Client-side handling
   (decryption, invited-member detection, malformed-entry
   errors, GY_GROUP_MAX_ENTRIES bound) is D-GRP-7 item 2.

### 7.8. DeleteGroupMember (unauthenticated)

1. AuthAsGroupMember.
2. The user sends the target UidCiphertext (another member's or
   its own).
3. The server checks the authenticated user's Role permits the
   deletion; if so, removes the entry. (Local zeroization on own
   departure is D-GRP-7 item 5b; the retention caveat is §11.1
   item 2.)

### 7.9. AddInvitedGroupMember (unauthenticated)

AddGroupMember variant for a target whose ProfileKey the adder
does not know: the entry is stored WITHOUT ProfileKeyCiphertext
(and without a pi_P over profile-key attributes). The invited
member becomes full when the ProfileKeyCiphertext is populated
via AddGroupMember or UpdateProfileKey. (The inviter sends the
invited member the GroupMasterKey over a pairwise session, §3.4,
so the invitee can authenticate to the group and complete the
join.)

### 7.10. UpdateProfileKey (unauthenticated)

AddGroupMember variant in which users may replace ONLY THEIR OWN
ProfileKeyCiphertext (the server matches the authenticated
UidCiphertext), preventing rollback of other members' profile
data. Obsoletes credentials over the old ProfileKey (storage
consequence: D-GRP-7 item 3).

---

## 8. Server Side (D-GRP-2)

KVAC is keyed verification: the issuer and verifier are the same
party, the server, holding ServerSecretParams. geryon therefore
ships the server role's cryptography, under the following rules.

### 8.1. Shipped operations

geryon provides ALL five server-side cryptographic operations,
exactly the set requiring ServerSecretParams:

1. ServerSecretParams generation and ServerPublicParams
   derivation ([CPZ] §5.8).
2. AuthCredential issuance: the algebraic MAC over
   (M1, M2, redemption date) plus the issuance proof pi_I
   ([CPZ] §5.9, §3.2).
3. ProfileKeyCredentialRequest verification and blind issuance:
   verify pi_BR, produce (S1, S2, pi_BI) ([CPZ] §5.10).
4. AuthCredentialPresentation verification: recompute Z from the
   secret key and verify pi_A ([CPZ] §5.12).
5. ProfileKeyCredentialPresentation verification: verify pi_P
   ([CPZ] §5.13).

### 8.2. Statelessness

Every shipped server operation is a stateless pure function:
(params, input objects) to (output objects / accept / reject).
The library defines NO server storage interface and NO server
state machine. Group storage, ProfileKeyCommitment storage, role
enforcement ([CPZ] §5.5: server-enforced access control, not
cryptography), rate limiting, and channel handling belong to the
deploying server application.

### 8.3. Packaging

The server operations build as a separate static target
(geryon_groups_server) over the same groups/ internals as the
client target. Client binaries MUST NOT contain issuance code or
any path that consumes ServerSecretParams; the role split is
structural (enforced by a link-time symbol check), not
documentary.

### 8.4. Constant-time requirements

ServerSecretParams are long-lived secret keys. Issuance, blind
issuance, and the Z recomputation are secret-keyed operations and
carry the full constant-time discipline, including timing-harness
targets (project policy; the D-PQ-4 harness pattern).

### 8.5. Architecture

groups/ is a parallel vertical over core/ plus libtalos_schnorr
(D-GRP-1). It consumes neither kex/, ratchet/, nor session/, and
nothing in the pairwise stack consumes it. The client and server
targets are two facades over shared groups/ internals. The strict
one-layer-down rule extends accordingly; the project layering
amendment lands at M8.

---

## 9. Wire Formats and Integration (D-GRP-6)

Exact per-object layouts land with the §3-§7 transcriptions;
this section fixes the conventions they follow.

1. Surface split: geryon defines canonical byte encodings for
   the client-server group objects (every §3 object; required
   for KATs and for a geryon client against a geryon-based
   server) but NO transport or RPC framing, which belongs to the
   deploying server (D-GRP-2 statelessness). The only group data
   that crosses pairwise sessions is GroupMasterKey distribution
   (item 4); server API framing is out of scope.
2. Encoding convention: the M0 wire-helper conventions,
   unchanged: fixed-layout concatenation of canonical
   primitives, RFC 9496 element encodings (32/56 bytes by tier),
   fixed-width big-endian scalars and integers, no TLV. Variable
   length occurs in exactly one place, member-entry lists, with
   a 2-byte BE count bounded by GY_GROUP_MAX_ENTRIES (§10).
   Parsing is strict: non-canonical element encodings, wrong
   lengths, and trailing bytes are rejected.
3. Object header: every top-level object carries object-type
   byte || group-wire-version byte (0x01) || compact suite_id
   tag; nested objects are untagged. The tag is identification
   only: cryptographic suite binding lives in the KDF and FS
   transcript layer (§2.1), never in incidental wire structure.
4. Envelope integration: one new msg_type in the D-GEN-1 typed
   envelope, GROUP_KEY_DISTRIBUTION, payload = group format
   version (BE16, §10.1) followed by the GroupMasterKey, nothing
   else; the receiver learns the group's capability epoch from
   the same trusted message that carries the key, and rederives
   GroupSecretParams / GroupPublicParams (§10). The library
   defines the format, encode/decode, and validation; the
   application decides when to send and whether to accept
   (D-SES-1 boundary). Credentials and presentations never ride
   the pairwise envelope.
5. Versioning: the group wire version byte is independent of the
   pairwise protocol_version; encodings freeze at first
   published KATs (the label-registry rule).
6. Redemption date: uint64 big-endian seconds since the Unix
   epoch, MUST be a multiple of 86400 (a 00:00 UTC day
   boundary), enforced at issuance AND verification: a
   non-aligned value is rejected, never rounded. The redemption
   date is a REVEALED attribute; day granularity keeps the
   per-day anonymity bucket large ([CPZ] §5.9 daily-credential
   model). The M3 attribute encoding is the canonical scalar
   reduction of the unsigned value. Signed int64 was considered
   and rejected (D-GRP-6 item 6); the signed-prekey timestamp
   stays uint64, unchanged.

---

## 10. State, Storage, and Zeroization (D-GRP-7)

Storage model: rederive, never cache. The store callback holds
exactly one secret per group, the GroupMasterKey (2 kappa bytes,
D-GRP-5). GroupSecretParams and GroupPublicParams are rederived
on demand and no derived value is cached, in the store or in
memory across operations; derived secrets are zeroized after
each operation. The local lookup key is a GroupID in the
D-SES-3 style: the suite hash over suite_id || format_version
(BE16, §10.1) || GroupPublicParams encoding, truncated,
local-only, never on the wire. The master-key record carries the
format version alongside the key (ver || format_version ||
GroupMasterKey).

Membership state is never stored or cached by the library; the
server is authoritative. FetchGroupMembers results pass through
the API: the library decrypts entries, distinguishes full from
invited members (missing ProfileKeyCiphertext), and surfaces
malformed or inconsistent ciphertexts as structured errors.
Plaintext caching is application territory, documented as such.
Compile-time input bound (D-SES-4 pattern): at most
GY_GROUP_MAX_ENTRIES (default 1024) entries processed per fetch;
applications may lower, not raise.

Credentials are secret key material under D-GEN-4: at rest
through store callbacks with the AEAD-under-stretched-key rule,
plaintext copies zeroized. AuthCredential is stored with its
redemption date; the API exposes validity and the library
refuses to build a presentation from an expired credential.
ProfileKeyCredential is stored per target UID and replaced (old
one zeroized) when a newer credential for that UID is acquired.

ProfileKeys: the user's own ProfileKey is library-generated
([CPZ] §5.6 CommitToProfileKey step 1) and persists through a
store callback. Contacts' ProfileKeys enter as call arguments;
the library defines no contact database (D-SES-1 boundary).

Zeroization points: derived GroupSecretParams scalars after
every operation; the group record and group-scoped credentials
on leave, eviction, or local delete (device hygiene, not
revocation: a departed member may retain the key, and the rekey
posture is D-GRP-11); expired AuthCredentials on replacement or
first detected expiry; all staged material on operation failure
(group operations are transactional per the D-SES-10 pattern:
stage, commit through callbacks only at the single success
point).

Roles: the ACCESS ROLE is an opaque fixed-size value geryon
carries but never interprets. geryon_groups_server verifies
presentations and hands the deployer the authenticated
UidCiphertext plus the stored role; authorization policy is the
deployer's (D-GRP-2). "Access role" is the API term, distinct
from D-GRP-3's fixed protocol-role strings used as FS UserID
labels.

### 10.1. Group format version (D-GRP-12)

A group's FORMAT VERSION is its capability epoch: a 2-byte
big-endian value, chosen when the group is created, IMMUTABLE for
the life of the group, and BOUND into the GroupID (the suite hash
includes it, above). It is carried in the master-key record and
in the GROUP_KEY_DISTRIBUTION envelope (§9 item 4), so a joining
member learns it from the same trusted message that carries the
key.

Because the version is fixed at creation, a group created at
version N can never gain a version-(N+1) feature: no member can
introduce one, so clients that support N keep working with that
group indefinitely. A group that needs a newer feature is created
at the newer version; a client that does not support it declines
to join (GY_ERR_UNSUPPORTED) up front rather than mis-parsing a
later object. Feature rollout is therefore per-group and opt-in at
creation, with no in-place upgrade (new features mean a new
group). The library creates groups at GY_GROUP_FORMAT_VERSION and
accepts any version through GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION.

Enforcement split for version-gated features (e.g. a future member
role beyond the current set): the stateless server stays
version-agnostic and carries the global role set structurally;
per-group restriction (an adder must not use a role the group's
version does not define; a reader rejects an out-of-range role) is
the client's, keyed on the group's pinned version. With one
version defined this collapses to the global check; the split
becomes visible when a later version adds a feature.

Tamper-evidence: the version is bound into the GroupID and the
GroupID is rederived and const-compared on every load, so a
flipped version byte in a stored record is rejected
(GY_ERR_VERIFY), the same integrity path a corrupted key takes.

---

## 11. Security Considerations

Transcribed from [CPZ] §1.1 ("Security Properties") and §7.5
("System Security"); the formal treatment is [CPZ] Appendix A
(the ideal functionality F and a simulation-based proof sketch),
with the primitive reductions in [CPZ] §7.2 (encryption:
CCA-secure with unique ciphertexts under DDH in the ROM) and
§7.3 (MAC: suf-cmva under DDH plus MAC_GGM). Those analyses are
informative background; the operational consequences are
normative here. §11.1 is geryon's own posture (D-GRP-11), not
paper material.

### 11.1. Harvest-now-decrypt-later posture (D-GRP-11)

The classical group type provides NO post-quantum confidentiality
or anonymity, and no PQ retrofit of this type is planned;
deployments with HNDL requirements use a
hybrid suite, which carries the QSPGS group type (QSPGS_SPEC.md),
HNDL-safe by construction. This section and the public API
documentation state plainly:

1. HNDL exposure: every confidentiality and anonymity property
   of this subsystem rests on discrete-log assumptions in the
   proof group. Server-stored membership ciphertexts and recorded
   presentations are harvestable today and offer no protection
   against a later discrete-log (quantum) adversary;
   deterministic encryption makes candidate-UID and profile-key
   confirmation direct once the group structure falls.
2. The GroupMasterKey is long-lived and [CPZ] defines no rekey;
   departed members may retain it (D-GRP-7 leave zeroization is
   device hygiene, not revocation). Group-state exposure is
   therefore indefinite in time.
3. The scope statement mirrors the classical pairwise suites:
   size/bandwidth-priority deployments only, no PQ claims of any
   kind.

### 11.2. Core guarantees and server observation limits ([CPZ] §1.1)

Main security goals: the server can neither DECRYPT group
entries nor FORGE new entries. Around those goals, [CPZ] states
the observation and modification limits explicitly, and geryon
adopts them as documented, accepted leakage:

1. The server observes WHICH encrypted entry performs an action
   (fetching the member list, adding or deleting entries):
   pseudonymous traffic-pattern leakage per group. [CPZ]'s
   stated reason for accepting it: eliminating update leakage
   would require re-encrypting and rewriting a maximum-size
   group state with a correctness proof on every operation.
   Cross-GROUP linkage is still prevented: each group's
   (a1, a2, b1, b2) differ, so the same UID encrypts to
   unlinkable ciphertexts in different groups.
2. The server can delete ciphertexts or reinstate old ones
   (membership rollback). [CPZ] notes a possible extension
   (clients sign each group state with an incrementing version)
   and does not adopt it; geryon follows the paper (D-GRP-9
   pin) and additionally notes the extension would put
   signatures into a subsystem that deliberately has none
   (§11.4 item 2). The QSPGS type's admin-signed state is the
   geryon answer for deployments needing that integrity.
3. A malicious server can corrupt state by writing invalid or
   inconsistent ciphertexts. This yields nothing beyond denial
   of service (which the server can achieve by not answering);
   the client library's duty is to surface such entries as
   structured errors, never crashes (D-GRP-7 item 2).

### 11.3. Trust matrix (D-GRP-2 validation item)

- Honest-but-curious server: untrusted for privacy. It cannot
  decrypt entries, cannot map an entry to a UID, cannot link
  one UID across groups (§11.2 item 1), and cannot forge
  entries. It sees GroupPublicParams, entry counts, Roles,
  redemption dates presented (day-granular, §9 item 6), and the
  §11.2 item 1 action patterns.
- Malicious server, all members honest ([CPZ] §7.5): may
  deviate freely in service terms (delete members, reject adds,
  roll back state) but violates no privacy: the group remains
  confidential, and it cannot add arbitrary users because it
  lacks GroupSecretParams.
- Malicious server plus a malicious member ([CPZ] §7.5):
  between them they hold ServerSecretParams AND
  GroupSecretParams; the membership is fully exposed and the
  group arbitrarily modifiable. NO security is claimed. This is
  the same trust cliff as the departed-member caveat (§3.4,
  §11.1 item 2): recovery is a new group with a fresh
  GroupMasterKey excluding the removed parties ([CPZ] §1.1).
- Malicious users, honest server ([CPZ] §1.1, §7.5): cannot
  forge authentications, cannot violate the server's access
  control, and cannot break the consistency bindings between
  UID decryption and authentication or between UidCiphertexts
  and ProfileKeyCiphertexts (the §6.5 predicates).
- Trusted-for: the server is the consistency point (the
  authoritative state holder) and the access-control enforcer
  (Roles, rate limiting) in every row above.

### 11.4. Posture notes

1. Roles are server-enforced access control, not cryptography
   ([CPZ] §5.5); geryon carries them opaquely (D-GRP-7 item 6).
   Nothing cryptographic prevents a malicious server from
   ignoring Roles; the matrix rows above already assume that.
2. Deniability: there are NO signatures anywhere in this
   subsystem. All authentication is keyed-verification (MAC
   plus NIZK presentation), verifiable only by the
   secret-holding server, and presentations are anonymous even
   to it. Group membership and group operations are therefore
   deniable in the same offline sense as the pairwise protocol;
   this is why the §11.2 item 2 signed-state extension is not
   adopted in this type.
3. GroupMasterKey lifecycle: [CPZ] defines no rekey; removal
   with full cryptographic exclusion means creating a new group
   (§11.3). Automated rekey is named by the paper as future
   work only; geryon does not invent one (D-GRP-4 posture) and
   documents the exposure in §11.1.
4. What geryon adds on top of the paper, without changing the
   analyzed scheme: hedged proof nonces (§2.2), full-suite
   binding with fixed OtherInfo (§2.1), strict parsing (§9),
   rederive-only key handling with zeroization (§10), and the
   constant-time discipline (§6.1 item 6, §8.4). None of these
   alter the [CPZ] equations; they harden the instantiation.

---

## 12. Test Vector Requirements (D-GRP-9)

Protocol-level zkgroup byte-compat is out of scope by design
(D-GRP-4: spec-compliant, not libsignal-compliant); the group
protocol layer is validated by GROUP_SPEC-derived self-KATs plus
per-component oracles.

Normative text pin: [CPZ] is eprint 2019/1416 at its final
revision (2020-11-10, titled "Draft - November 9, 2020", the
full version of the CCS'20 publication,
DOI 10.1145/3372297.3417887); the checked-in
docs/references/signal/2019-1416.pdf is that revision, and any
re-download must match it. Signal publishes no group
specification and libsignal cites only [CPZ]; Signal's
post-paper credential extensions exist only in GPL code with no
spec and are out of scope.

Oracle scope: NO GPL zkgroup/poksho oracle is required for M8.
Encoding-layer vectors (Lizard encode/decode, single-Elligator
hash) come from the MIT dalek lizard2 branch run as a permissive
harness (ENCODE_TO_GROUP.md §8); zkgroup black-box vectors are a
named fallback only, entered into docs/TEST_ORACLES.md if and
only if that fallback is ever invoked.

Requirements: [CPZ] Table 1 size cross-checks; spec-derived
self-KATs; negative matrix (malformed proofs, wrong-group
presentations, replayed presentations, non-matching commitments,
decode-failure paths, transcript malleability: item reordering or
boundary shifts must change the FS challenge).

### 12.1. Coverage traceability

Each requirement maps to the asset that asserts it; all run under
CTest (the `*_vectors` self-KATs SKIP-77 until their frozen vector
sets are present). Both classical tiers are exercised unless noted.

| Requirement (section)                              | Asset |
|----------------------------------------------------|-------|
| Tiers / params / NUMS / Derive KATs (§2)           | tests/group/test_group_params.c (+ group_params_vectors.h) |
| Algebraic MAC, key shapes, tamper reject (§4)      | test_group_mac.c, test_group_mac_vectors.c |
| Attribute assembly, day-aligned M3 (§5.0)          | test_group_attr.c |
| Issuance proof pi_I (§5.1)                          | test_group_cred.c |
| Presentations pi_A / pi_P (§5.2)                    | test_group_pres.c, test_group_ppres.c |
| Blind issuance pi_BR / pi_BI (§5.3)                 | test_group_issue.c |
| Statement-surface self-KATs (§5, both tiers)       | test_group_stmt_vectors.c (+ group_stmt_vectors.h), test_group_vectors.c |
| NIZK prove/verify, tampered target, transcript binding (§5.0, §12) | test_group_proof.c |
| Verifiable encryption round-trip, decode-failure, tamper (§6)      | test_group_venc.c |
| §6 candidate-loop constant time                    | tests/timing/targets_group.c (target_group_pk_decrypt_255/448) |
| Independent [CPZ] verify-equation oracle (both tiers) | tools/oracles/group_kvac (verify.py + decaf448_shim.c), driven by test_group_kvac_emit.c -> test_group_kvac_oracle |
| Table 1 object sizes (both tiers)                  | test_group_sizes.c; test_group_wire.c (wire footprints) |
| Ten operations, two-party lifecycle + negatives (§7) | test_group_ops.c |
| Server target standalone; §8.4 CT                  | test_group_server.c; tests/timing/targets_group_server.c |
| Wire round-trip + strict-parse negatives (§9)      | test_group_wire.c |
| Storage / rederive / zeroization / refuse-expired / transactional (§10) | test_group_state.c, test_group_stored.c |
| Cross-group unlinkability (§11.3)                  | test_group_venc.c (same UID -> different ciphertext under two groups) |
| Server cannot forge (§11.2)                        | test_group_mac.c (wrong-key / tamper reject), the oracle |
| Server cannot decrypt (§11.2)                      | test_group_venc.c (only GroupSecretParams decrypts) |
| Malicious-server corruption -> structured error, no crash (§11.2 item 3) | test_group_ops.c (cross-group inconsistent entry -> GY_ERR_VERIFY), test_group_wire.c (strict parse), test_group_venc.c |

Negative-matrix items map as: malformed proofs / non-matching
commitments -> the cred/pres/issue tests plus test_group_server.c
(blind-issue reject); wrong-group presentations -> test_group_ops.c;
decode-failure paths -> test_group_venc.c; transcript malleability ->
test_group_proof.c (relabel -> reject) and the oracle (independent
challenge recompute).

**Replayed presentations** are deliberately NOT a library-crypto
reject: a valid presentation re-verifies by construction (the [CPZ]
scheme binds no per-presentation nonce), so replay defense is
server-state - the authoritative holder matches the presented
UidCiphertext against current membership and enforces access control
and rate limiting (§11.2 item 2, §11.3 "trusted-for"). Recording this
here keeps the matrix honest rather than asserting a guarantee the
layer does not provide.

---

## 13. References

1. [CPZ] docs/references/signal/2019-1416.pdf (normative basis;
   pinned at the final eprint revision, 2020-11-10, "Draft -
   November 9, 2020", DOI 10.1145/3372297.3417887; D-GRP-9)
2. HYBRID_SPEC.md (pairwise protocol; §2.5 boundary)
3. docs/decisions/ (register; D-GEN-3/4/6 discipline)
4. libtalos_schnorr API headers (provider, D-GRP-1)
5. libtalos_schnorr docs/ENCODE_TO_GROUP.md (EncodeToG handoff)
6. RFC 9496 (ristretto255 / decaf448 group encodings and maps)
7. Bernstein, Hamburg, Krasnova, Lange, "Elligator" (CCS'13; the
   inverse-map construction)
8. RFC 8235, Schnorr Non-interactive Zero-Knowledge Proof
   (docs/references/standards/rfc8235.txt; normative for the FS
   challenge hash requirements, §2.3)
9. eprint 2026/453, "A Quantum-Safe Private Group System for
   Signal from Key Rerandomizable Signatures" (informative;
   Signal Messenger + IBM Research, Signal's own proposed [CPZ]
   successor; adopted as the quantum-safe group type,
   QSPGS_SPEC.md)

